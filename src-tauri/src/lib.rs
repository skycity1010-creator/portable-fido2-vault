//! Tauri 後端：VaultState（Mutex 包解鎖中的 Vault）＋ commands。
//! 前端純靜態（src/），透過 window.__TAURI__.core.invoke 呼叫。

use sha2::{Digest, Sha256};
use std::sync::Mutex;
use tauri::Manager;
use tauri_plugin_dialog::DialogExt;
use zeroize::Zeroizing;

#[cfg(windows)]
use windows_sys::Win32::UI::WindowsAndMessaging::{
    GetForegroundWindow, IsIconic, IsWindowVisible, SetForegroundWindow, ShowWindow, SW_RESTORE,
};

#[cfg(feature = "mock-fido")]
use crate::fido2::MockBackend;
#[cfg(all(feature = "real-ctap", not(windows)))]
use crate::fido2::RealBackend;
#[cfg(all(feature = "real-ctap", windows))]
use crate::windows_webauthn::WindowsWebAuthnBackend;

pub mod crypto;
pub mod csv_import;
#[cfg(feature = "real-ctap")]
pub mod diag_log;
pub mod fido2;
pub mod vault;
#[cfg(all(windows, feature = "real-ctap"))]
mod webauthn_diagnostics;
#[cfg(all(windows, feature = "real-ctap"))]
mod windows_webauthn;

pub type Result<T> = std::result::Result<T, String>;

fn clipboard_text_matches(actual: &[u16], expected: &str) -> bool {
    let expected_utf16: Vec<u16> = expected.encode_utf16().collect();
    actual.len() == expected_utf16.len() + 1
        && actual[..expected_utf16.len()] == expected_utf16
        && actual[expected_utf16.len()] == 0
}

#[cfg(windows)]
mod native_clipboard {
    use super::{clipboard_text_matches, Result};
    use std::mem::size_of;

    use windows_sys::Win32::System::DataExchange::{
        CloseClipboard, EmptyClipboard, GetClipboardData, OpenClipboard,
    };
    use windows_sys::Win32::System::Memory::{GlobalLock, GlobalSize, GlobalUnlock};

    const CF_UNICODETEXT: u32 = 13;

    struct ClipboardGuard;

    impl Drop for ClipboardGuard {
        fn drop(&mut self) {
            unsafe {
                CloseClipboard();
            }
        }
    }

    pub fn clear_if_matches(owner_hwnd: isize, expected: &str) -> Result<bool> {
        unsafe {
            if OpenClipboard(owner_hwnd as _) == 0 {
                return Err("could not open system clipboard".to_string());
            }
            let _clipboard_guard = ClipboardGuard;

            let data = GetClipboardData(CF_UNICODETEXT);
            if data.is_null() {
                return Ok(false);
            }

            let expected_utf16: Vec<u16> = expected.encode_utf16().collect();
            let required_units = expected_utf16
                .len()
                .checked_add(1)
                .ok_or_else(|| "clipboard text length is invalid".to_string())?;
            let required_bytes = required_units
                .checked_mul(size_of::<u16>())
                .ok_or_else(|| "clipboard text length is invalid".to_string())?;
            if GlobalSize(data as _) < required_bytes {
                return Ok(false);
            }

            let locked = GlobalLock(data as _);
            if locked.is_null() {
                return Err("could not read system clipboard text".to_string());
            }
            let actual = std::slice::from_raw_parts(locked.cast::<u16>(), required_units);
            let matches = clipboard_text_matches(actual, expected);
            GlobalUnlock(data as _);

            if !matches {
                return Ok(false);
            }
            if EmptyClipboard() == 0 {
                return Err("could not clear system clipboard".to_string());
            }
            Ok(true)
        }
    }
}

/// 金鑰清單項目（回傳前端，不含任何機密）。
#[derive(serde::Serialize)]
pub struct KeyInfo {
    pub credential_id: String, // b64
    pub label: String,
    pub key_type: fido2::KeyKind,
    pub prompt_zh: &'static str,
}

impl From<&vault::Header> for Vec<KeyInfo> {
    fn from(h: &vault::Header) -> Self {
        h.key_slots
            .iter()
            .map(|s| KeyInfo {
                credential_id: s.credential_id.clone(),
                label: s.label.clone(),
                key_type: s.key_type,
                prompt_zh: s.key_type.prompt_zh(),
            })
            .collect()
    }
}

#[derive(serde::Serialize)]
pub struct LoginScreenInfo {
    pub has_vault: bool,
    pub keys: Vec<KeyInfo>,
    pub idle_lock_minutes: u32,
    pub brokered_key_login: bool,
}

/// Backend policy for the GUI. Keeping this pure makes the release/debug policy testable without hardware.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BackendMode {
    Hardware,
    Mock,
}

fn resolve_backend_mode(
    env_override: Option<&str>,
    debug_build: bool,
    real_ctap_compiled: bool,
    mock_compiled: bool,
) -> Result<BackendMode> {
    let requested = env_override
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_ascii_lowercase);

    match requested.as_deref() {
        Some("hw") if real_ctap_compiled => Ok(BackendMode::Hardware),
        Some("hw") => {
            Err("F2V_AUTHENTICATOR=hw requires a build with the real-ctap feature".into())
        }
        Some("mock") if mock_compiled => Ok(BackendMode::Mock),
        Some("mock") => {
            Err("F2V_AUTHENTICATOR=mock requires a build with the mock-fido feature".into())
        }
        Some(_) => Err("Unknown F2V_AUTHENTICATOR value; use 'hw' or 'mock'".into()),
        None if debug_build && mock_compiled => Ok(BackendMode::Mock),
        None if real_ctap_compiled => Ok(BackendMode::Hardware),
        None if !debug_build => Err(
            "Release GUI build is missing the real-ctap feature; refusing to use MockBackend"
                .into(),
        ),
        None if mock_compiled => Ok(BackendMode::Mock),
        None => Err("No FIDO backend is compiled; enable real-ctap or mock-fido".into()),
    }
}

/// Hardware backend construction result → GUI backend. Only the closed "WebAuthn API below v4"
/// category degrades to the key-unavailable backend; every other error stays fatal.
#[cfg_attr(not(all(windows, feature = "real-ctap")), allow(dead_code))]
fn select_hardware_backend<B: fido2::FidoBackend + 'static>(
    constructed: std::result::Result<B, fido2::BackendInitError>,
) -> Result<Box<dyn fido2::FidoBackend>> {
    match constructed {
        Ok(backend) => Ok(Box::new(backend)),
        Err(fido2::BackendInitError::WebAuthnApiBelowV4 { api_version }) => {
            log::warn!(
                "GUI FIDO backend selected: key-unavailable (windows_webauthn_api_version={api_version}, requires v4); master-password login remains available"
            );
            Ok(Box::new(fido2::UnavailableBackend::new(api_version)))
        }
        Err(error) => Err(error.to_string()),
    }
}

/// On Windows, Release hardware GUI uses the brokered WebAuthn API for standard-user launches.
/// Debug builds retain MockBackend by default; F2V_AUTHENTICATOR=hw/mock remains an explicit override.
fn make_backend(window_handle: isize) -> Result<Box<dyn fido2::FidoBackend>> {
    let env_override = std::env::var("F2V_AUTHENTICATOR").ok();
    let mode = resolve_backend_mode(
        env_override.as_deref(),
        cfg!(debug_assertions),
        cfg!(feature = "real-ctap"),
        cfg!(feature = "mock-fido"),
    )?;

    match mode {
        BackendMode::Hardware => {
            #[cfg(all(windows, feature = "real-ctap"))]
            {
                log::info!("GUI FIDO backend selected: windows-webauthn");
                select_hardware_backend(WindowsWebAuthnBackend::new(window_handle))
            }
            #[cfg(all(not(windows), feature = "real-ctap"))]
            {
                let _ = window_handle;
                log::info!("GUI FIDO backend selected: raw-ctap");
                Ok(Box::new(RealBackend::new()))
            }
            #[cfg(not(feature = "real-ctap"))]
            {
                let _ = window_handle;
                Err("Hardware FIDO backend is not compiled (missing real-ctap)".into())
            }
        }
        BackendMode::Mock => {
            log::info!("GUI FIDO backend selected: mock-fido");
            #[cfg(feature = "mock-fido")]
            {
                let kind = std::env::var("F2V_MOCK_KIND")
                    .ok()
                    .and_then(|value| fido2::KeyKind::parse(&value));
                Ok(Box::new(kind.map_or_else(MockBackend::new, |kind| {
                    MockBackend::new().with_next_kind(kind)
                })))
            }
            #[cfg(not(feature = "mock-fido"))]
            {
                Err("Mock FIDO backend is not compiled (missing mock-fido)".into())
            }
        }
    }
}

struct VaultState(Mutex<AppInner>);

struct PendingCsvImport {
    token: String,
    parsed: csv_import::ParsedCsvImport,
    entries_fingerprint: [u8; 32],
}

#[derive(serde::Serialize)]
struct CsvImportPreviewResponse {
    token: String,
    preview: csv_import::ImportPreview,
}

struct AppInner {
    vault: Option<vault::Vault>,
    backend: Box<dyn fido2::FidoBackend>,
    pending_csv_import: Option<PendingCsvImport>,
}

fn entries_fingerprint(entries: &[vault::Entry]) -> Result<[u8; 32]> {
    let serialized =
        Zeroizing::new(serde_json::to_vec(entries).map_err(|_| "無法建立匯入預覽".to_string())?);
    Ok(Sha256::digest(serialized.as_slice()).into())
}

fn new_csv_import_token() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

impl AppInner {
    fn new(window_handle: isize) -> Result<Self> {
        Ok(Self {
            vault: None,
            backend: make_backend(window_handle)?,
            pending_csv_import: None,
        })
    }
}

impl VaultState {
    fn with_lock<R>(&self, f: impl FnOnce(&mut AppInner) -> Result<R>) -> Result<R> {
        let mut g = self
            .0
            .lock()
            .map_err(|_| "state lock poisoned".to_string())?;
        f(&mut g)
    }
}

fn path_from_state_or_default() -> std::path::PathBuf {
    // portable：vault.db 與 exe 同資料夾。
    let exe = std::env::current_exe().unwrap_or_default();
    let dir = exe.parent().unwrap_or(std::path::Path::new("."));
    dir.join("vault.db")
}

fn ensure_parent_window_ready(
    require_foreground: bool,
    is_foreground: bool,
    visible: bool,
    minimized: bool,
) -> Result<()> {
    if !require_foreground || (is_foreground && visible && !minimized) {
        Ok(())
    } else {
        Err("Windows could not activate the visible FidoVault window. Bring FidoVault to the foreground and retry; no security-key operation was started.".into())
    }
}

fn restore_window_if_minimized(is_minimized: bool, restore: impl FnOnce()) {
    if is_minimized {
        restore();
    }
}

/// Activate the live top-level HWND before entering the blocking Windows
/// WebAuthn call, restoring it only when it is minimized so maximized state is preserved.
fn raise_key_operation_window(
    window: &tauri::WebviewWindow,
    require_foreground: bool,
) -> Result<isize> {
    #[cfg(windows)]
    {
        if !require_foreground {
            if let Err(error) = window.unminimize() {
                log::warn!("Could not unminimize the FIDO parent window: {error}");
            }
            if let Err(error) = window.show() {
                log::warn!("Could not show the FIDO parent window: {error}");
            }
            if let Err(error) = window.set_focus() {
                log::warn!("Could not focus the FIDO parent window: {error}");
            }
            return Ok(0);
        }

        let hwnd = window
            .hwnd()
            .map_err(|error| format!("Could not get the live FidoVault HWND: {error}"))?;
        if hwnd.0.is_null() {
            return Err(
                "The live FidoVault HWND is null; no security-key operation was started.".into(),
            );
        }

        let foreground_before = unsafe { GetForegroundWindow() };
        let minimized_before = unsafe { IsIconic(hwnd.0) != 0 };
        restore_window_if_minimized(minimized_before, || unsafe {
            ShowWindow(hwnd.0, SW_RESTORE);
        });
        let set_foreground = unsafe { SetForegroundWindow(hwnd.0) != 0 };
        let foreground_after = unsafe { GetForegroundWindow() };
        let visible = unsafe { IsWindowVisible(hwnd.0) != 0 };
        let minimized = unsafe { IsIconic(hwnd.0) != 0 };
        let is_foreground = foreground_after == hwnd.0;
        log::info!(
            "WebAuthn parent focus snapshot: hwnd={:p} foreground_before={:p} set_foreground={} foreground_after={:p} visible={} minimized={} is_foreground={}",
            hwnd.0,
            foreground_before,
            set_foreground,
            foreground_after,
            visible,
            minimized,
            is_foreground,
        );
        ensure_parent_window_ready(require_foreground, is_foreground, visible, minimized)?;
        Ok(hwnd.0 as isize)
    }

    #[cfg(not(windows))]
    {
        let _ = require_foreground;
        if let Err(error) = window.unminimize() {
            log::warn!("Could not unminimize the FIDO parent window: {error}");
        }
        if let Err(error) = window.show() {
            log::warn!("Could not show the FIDO parent window: {error}");
        }
        if let Err(error) = window.set_focus() {
            log::warn!("Could not focus the FIDO parent window: {error}");
        }
        Ok(0)
    }
}

// ─────────────────────────── commands ───────────────────────────

/// 啟動畫面資訊：是否有金庫、已註冊金鑰清單（供登入畫面）。
#[tauri::command]
fn boot_info(state: tauri::State<VaultState>) -> Result<LoginScreenInfo> {
    let path = path_from_state_or_default();
    let has_vault = path.exists();
    let keys = if has_vault {
        read_keys_from_file(&path)?
    } else {
        Vec::new()
    };
    let brokered_key_login = state.with_lock(|g| Ok(g.backend.uses_brokered_key_selection()))?;
    Ok(LoginScreenInfo {
        has_vault,
        keys,
        idle_lock_minutes: 5,
        brokered_key_login,
    })
}

/// 讀取 vault.db 的 header（不需 KEK）→ 金鑰清單。
fn read_keys_from_file(path: &std::path::Path) -> Result<Vec<KeyInfo>> {
    let buf = std::fs::read(path).map_err(|e| e.to_string())?;
    if buf.len() < 10 || &buf[..6] != crypto::VAULT_MAGIC {
        return Err("非 vault.db".into());
    }
    let header_len = u32::from_le_bytes(buf[6..10].try_into().map_err(|_| "bad len")?) as usize;
    let header_json = std::str::from_utf8(&buf[10..10 + header_len]).map_err(|e| e.to_string())?;
    let h: vault::Header = serde_json::from_str(header_json).map_err(|e| e.to_string())?;
    Ok(h.key_slots
        .iter()
        .map(|s| KeyInfo {
            credential_id: s.credential_id.clone(),
            label: s.label.clone(),
            key_type: s.key_type,
            prompt_zh: s.key_type.prompt_zh(),
        })
        .collect())
}

/// 首次執行：建立帳號（主密碼）。
#[tauri::command]
fn create_vault(state: tauri::State<VaultState>, password: String) -> Result<()> {
    if password.len() < 8 {
        return Err("主密碼至少 8 個字元".into());
    }
    let path = path_from_state_or_default();
    if path.exists() {
        return Err("vault.db 已存在（請改走登入）".into());
    }
    let v = vault::Vault::create(&path, &password).map_err(|e| e.to_string())?;
    state.with_lock(|g| {
        g.vault = Some(v);
        Ok(())
    })?;
    Ok(())
}

/// 主密碼登入。
#[tauri::command]
fn login_password(state: tauri::State<VaultState>, password: String) -> Result<Vec<vault::Entry>> {
    let path = path_from_state_or_default();
    let v = vault::Vault::open_password(&path, &password).map_err(|e| e.to_string())?;
    let entries = v.entries().to_vec();
    state.with_lock(|g| {
        g.vault = Some(v);
        Ok(())
    })?;
    Ok(entries)
}

/// FIDO2 金鑰登入。pin：PIN 型金鑰必填；其他類型忽略。
#[tauri::command]
fn login_key(
    window: tauri::WebviewWindow,
    state: tauri::State<VaultState>,
    credential_id: String,
    pin: Option<String>,
) -> Result<Vec<vault::Entry>> {
    let require_foreground = state.with_lock(|g| Ok(g.backend.uses_brokered_key_selection()))?;
    let owner_hwnd = raise_key_operation_window(&window, require_foreground)?;
    let path = path_from_state_or_default();
    let v = state.with_lock(|g| {
        g.backend.set_webauthn_parent_hwnd(owner_hwnd);
        vault::Vault::open_key(&path, &credential_id, pin.as_deref(), g.backend.as_mut())
            .map_err(|e| e.to_string())
    })?;
    let entries = v.entries().to_vec();
    state.with_lock(|g| {
        g.vault = Some(v);
        Ok(())
    })?;
    Ok(entries)
}

/// FIDO2 key login without a UI-selected key; let the active backend select from every vault slot.
#[tauri::command]
fn login_any_key(
    window: tauri::WebviewWindow,
    state: tauri::State<VaultState>,
) -> Result<Vec<vault::Entry>> {
    let require_foreground = state.with_lock(|g| Ok(g.backend.uses_brokered_key_selection()))?;
    let owner_hwnd = raise_key_operation_window(&window, require_foreground)?;
    let path = path_from_state_or_default();
    let v = state.with_lock(|g| {
        g.backend.set_webauthn_parent_hwnd(owner_hwnd);
        vault::Vault::open_any_key(&path, None, g.backend.as_mut()).map_err(|e| e.to_string())
    })?;
    let entries = v.entries().to_vec();
    state.with_lock(|g| {
        g.vault = Some(v);
        Ok(())
    })?;
    Ok(entries)
}

/// 上鎖（手動或閒置）。回傳登入畫面資訊。
#[tauri::command]
fn lock(state: tauri::State<VaultState>, reason: Option<String>) -> Result<LoginScreenInfo> {
    let (header, brokered_key_login) = state.with_lock(|g| {
        let brokered_key_login = g.backend.uses_brokered_key_selection();
        match g.vault.take() {
            Some(v) => {
                g.pending_csv_import = None;
                Ok((
                    if reason.as_deref() == Some("idle") {
                        v.auto_lock()
                    } else {
                        v.lock()
                    },
                    brokered_key_login,
                ))
            }
            None => Err("尚未解鎖".to_string()),
        }
    })?;
    Ok(LoginScreenInfo {
        has_vault: true,
        keys: (&header).into(),
        idle_lock_minutes: 5,
        brokered_key_login,
    })
}

fn with_unlocked<R>(
    state: &VaultState,
    f: impl FnOnce(&mut vault::Vault) -> Result<R>,
) -> Result<R> {
    state.with_lock(|g| match g.vault.as_mut() {
        Some(v) => f(v),
        None => Err("金庫未解鎖".to_string()),
    })
}

#[tauri::command]
fn list_entries(state: tauri::State<VaultState>) -> Result<Vec<vault::Entry>> {
    with_unlocked(&state, |v| Ok(v.entries().to_vec()))
}

#[tauri::command]
async fn preview_csv_import(
    app: tauri::AppHandle,
    window: tauri::WebviewWindow,
    state: tauri::State<'_, VaultState>,
) -> Result<Option<CsvImportPreviewResponse>> {
    let selected = app
        .dialog()
        .file()
        .set_parent(&window)
        .add_filter("CSV", &["csv"])
        .blocking_pick_file();
    let Some(selected) = selected else {
        return Ok(None);
    };
    let path = selected
        .into_path()
        .map_err(|_| "選擇的 CSV 路徑無效".to_string())?;
    let bytes = Zeroizing::new(std::fs::read(path).map_err(|_| "無法讀取 CSV 檔案".to_string())?);
    let text =
        std::str::from_utf8(bytes.as_slice()).map_err(|_| "CSV 必須使用 UTF-8 編碼".to_string())?;
    let parsed = csv_import::parse_import_csv(text)?;

    state.with_lock(|inner| {
        let vault = inner
            .vault
            .as_ref()
            .ok_or_else(|| "金庫未解鎖".to_string())?;
        let preview = csv_import::build_import_plan(vault.entries(), parsed.clone()).preview;
        let token = new_csv_import_token();
        inner.pending_csv_import = Some(PendingCsvImport {
            token: token.clone(),
            parsed,
            entries_fingerprint: entries_fingerprint(vault.entries())?,
        });
        Ok(Some(CsvImportPreviewResponse { token, preview }))
    })
}

#[tauri::command]
async fn save_csv_template(app: tauri::AppHandle, window: tauri::WebviewWindow) -> Result<bool> {
    let selected = app
        .dialog()
        .file()
        .set_parent(&window)
        .set_file_name("fido-vault-template.csv")
        .add_filter("CSV", &["csv"])
        .blocking_save_file();
    let Some(selected) = selected else {
        return Ok(false);
    };
    let path = selected
        .into_path()
        .map_err(|_| "選擇的 CSV 路徑無效".to_string())?;
    std::fs::write(path, csv_import::CSV_TEMPLATE.as_bytes())
        .map_err(|_| "無法儲存 CSV 範本".to_string())?;
    Ok(true)
}

#[tauri::command]
fn cancel_csv_import(state: tauri::State<VaultState>, token: String) -> Result<()> {
    state.with_lock(|inner| {
        if inner
            .pending_csv_import
            .as_ref()
            .is_some_and(|pending| pending.token == token)
        {
            inner.pending_csv_import = None;
        }
        Ok(())
    })
}

#[tauri::command]
fn apply_csv_import(
    state: tauri::State<VaultState>,
    token: String,
) -> Result<csv_import::ImportPreview> {
    state.with_lock(|inner| {
        let (parsed, expected_fingerprint) = inner
            .pending_csv_import
            .as_ref()
            .filter(|pending| pending.token == token)
            .map(|pending| (pending.parsed.clone(), pending.entries_fingerprint))
            .ok_or_else(|| "匯入預覽已失效，請重新選擇檔案".to_string())?;
        let vault = inner
            .vault
            .as_ref()
            .ok_or_else(|| "金庫未解鎖".to_string())?;
        if entries_fingerprint(vault.entries())? != expected_fingerprint {
            inner.pending_csv_import = None;
            return Err("金庫條目已變更，請重新預覽 CSV".into());
        }
        let plan = csv_import::build_import_plan(vault.entries(), parsed);
        let preview = inner
            .vault
            .as_mut()
            .expect("vault was checked above")
            .import_entries(&plan)
            .map_err(|error| error.to_string())?;
        inner.pending_csv_import = None;
        Ok(preview)
    })
}

#[tauri::command]
fn add_entry(
    state: tauri::State<VaultState>,
    site: String,
    account: String,
    password: String,
    notes: Option<String>,
) -> Result<vault::Entry> {
    with_unlocked(&state, |v| {
        v.add_entry(&site, &account, &password, notes.as_deref().unwrap_or(""))
            .map_err(|e| e.to_string())?;
        Ok(v.entries().last().cloned().unwrap())
    })
}

#[tauri::command]
fn update_entry(
    state: tauri::State<VaultState>,
    id: String,
    site: Option<String>,
    account: Option<String>,
    password: Option<String>,
    notes: Option<String>,
    restore_history_id: Option<String>,
) -> Result<()> {
    with_unlocked(&state, |v| {
        v.update_entry_with_restore(
            &id,
            site.as_deref(),
            account.as_deref(),
            password.as_deref(),
            notes.as_deref(),
            restore_history_id.as_deref(),
        )
        .map_err(|e| e.to_string())
    })
}

#[tauri::command]
fn delete_entry(state: tauri::State<VaultState>, id: String) -> Result<()> {
    with_unlocked(&state, |v| v.delete_entry(&id).map_err(|e| e.to_string()))
}

#[tauri::command]
fn list_audit(state: tauri::State<VaultState>) -> Result<Vec<vault::AuditEvent>> {
    with_unlocked(&state, |v| Ok(v.audit().to_vec()))
}

#[tauri::command]
fn register_key(
    window: tauri::WebviewWindow,
    state: tauri::State<VaultState>,
    pin: Option<String>,
    label: String,
) -> Result<fido2::RegisteredCredential> {
    let require_foreground = state.with_lock(|g| Ok(g.backend.uses_brokered_key_selection()))?;
    let owner_hwnd = raise_key_operation_window(&window, require_foreground)?;
    // 同一後端實例內 detect+register → 類型一致。
    state.with_lock(|g| match g.vault.as_mut() {
        Some(v) => {
            g.backend.set_webauthn_parent_hwnd(owner_hwnd);
            v.register_key_with_label(g.backend.as_mut(), pin.as_deref(), &label)
                .map_err(|e| e.to_string())
        }
        None => Err("金庫未解鎖".to_string()),
    })
}

#[tauri::command]
fn validate_key_label(state: tauri::State<VaultState>, label: String) -> Result<()> {
    with_unlocked(&state, |v| {
        v.validate_new_key_label(&label)
            .map(|_| ())
            .map_err(|e| e.to_string())
    })
}

#[tauri::command]
fn suggest_key_label(state: tauri::State<VaultState>) -> Result<String> {
    with_unlocked(&state, |v| Ok(v.suggested_key_label()))
}

#[tauri::command]
fn remove_key(state: tauri::State<VaultState>, credential_id: String) -> Result<()> {
    with_unlocked(&state, |v| {
        v.remove_key(&credential_id).map_err(|e| e.to_string())
    })
}

#[tauri::command]
fn set_idle_lock(state: tauri::State<VaultState>, minutes: u32) -> Result<()> {
    with_unlocked(&state, |v| {
        v.set_idle_lock(minutes).map_err(|e| e.to_string())
    })
}

#[tauri::command]
fn get_vault_settings(state: tauri::State<VaultState>) -> Result<vault::Settings> {
    with_unlocked(&state, |v| Ok(v.settings().clone()))
}

#[tauri::command]
fn set_password_history_limit(state: tauri::State<VaultState>, limit: u32) -> Result<()> {
    with_unlocked(&state, |v| {
        v.set_password_history_limit(limit)
            .map_err(|e| e.to_string())
    })
}

#[tauri::command]
fn clear_clipboard_if_matches(app: tauri::AppHandle, expected: String) -> Result<bool> {
    #[cfg(windows)]
    {
        let window = app
            .get_webview_window("main")
            .ok_or_else(|| "main window is unavailable".to_string())?;
        let hwnd = window
            .hwnd()
            .map_err(|_| "main window handle is unavailable".to_string())?
            .0 as isize;
        if hwnd == 0 {
            return Err("main window handle is unavailable".to_string());
        }
        native_clipboard::clear_if_matches(hwnd, &expected)
    }
    #[cfg(not(windows))]
    {
        let _ = (app, expected);
        Err("conditional clipboard clearing is only supported on Windows".to_string())
    }
}

/// 偵測金鑰（註冊前預覽：類型 + label）。**不消耗**後端狀態 → 與緊接的 register_key 一致。
#[tauri::command]
fn detect_key(state: tauri::State<VaultState>) -> Result<fido2::DetectedKey> {
    state.with_lock(|g| detected_key_preview(g.backend.as_ref()))
}

fn detected_key_preview(backend: &dyn fido2::FidoBackend) -> Result<fido2::DetectedKey> {
    if let Some(reason) = backend.key_unavailable_reason() {
        return Err(reason);
    }
    let kind = backend.peek_kind();
    Ok(fido2::DetectedKey {
        kind,
        label: format!("偵測到金鑰（{}）", kind.label_zh()),
        aaguid: [0u8; 16], // 預覽不含金鑰實作細節
    })
}

// ─────────────────────────── run ───────────────────────────

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    // 診斷 file logger（real-ctap）：GUI op 也落 fido2-diag.log → contention retry 可歸因。
    #[cfg(feature = "real-ctap")]
    diag_log::init();
    tauri::Builder::default()
        .plugin(tauri_plugin_clipboard_manager::init())
        .plugin(tauri_plugin_dialog::init())
        .setup(|app| {
            #[cfg(windows)]
            let window_handle = app
                .get_webview_window("main")
                .and_then(|window| window.hwnd().ok())
                .map(|handle| handle.0 as isize)
                .unwrap_or(0);
            #[cfg(not(windows))]
            let window_handle = 0;
            #[cfg(windows)]
            if window_handle == 0 {
                log::warn!(
                    "Main window HWND unavailable during setup; key commands will fetch and validate the live HWND before WebAuthn calls"
                );
            }
            let inner = AppInner::new(window_handle).map_err(std::io::Error::other)?;
            app.manage(VaultState(Mutex::new(inner)));
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            boot_info,
            create_vault,
            login_password,
            login_key,
            login_any_key,
            lock,
            list_entries,
            preview_csv_import,
            save_csv_template,
            cancel_csv_import,
            apply_csv_import,
            add_entry,
            update_entry,
            delete_entry,
            list_audit,
            register_key,
            validate_key_label,
            suggest_key_label,
            remove_key,
            set_idle_lock,
            get_vault_settings,
            set_password_history_limit,
            clear_clipboard_if_matches,
            detect_key
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

#[cfg(test)]
mod backend_mode_tests {
    use super::{resolve_backend_mode, BackendMode};

    #[test]
    fn unset_uses_current_build_profile_default() {
        let actual = resolve_backend_mode(
            None,
            cfg!(debug_assertions),
            cfg!(feature = "real-ctap"),
            cfg!(feature = "mock-fido"),
        );
        if cfg!(debug_assertions) && cfg!(feature = "mock-fido") {
            assert_eq!(actual, Ok(BackendMode::Mock));
        } else if cfg!(feature = "real-ctap") {
            assert_eq!(actual, Ok(BackendMode::Hardware));
        } else {
            assert!(actual.is_err());
        }
    }

    #[test]
    fn unset_debug_build_defaults_to_mock() {
        assert_eq!(
            resolve_backend_mode(None, true, true, true),
            Ok(BackendMode::Mock)
        );
    }

    #[test]
    fn unset_release_with_real_ctap_defaults_to_hardware() {
        assert_eq!(
            resolve_backend_mode(None, false, true, true),
            Ok(BackendMode::Hardware)
        );
    }

    #[test]
    fn explicit_mock_overrides_release_hardware_default() {
        assert_eq!(
            resolve_backend_mode(Some("mock"), false, true, true),
            Ok(BackendMode::Mock)
        );
    }

    #[test]
    fn explicit_hardware_requires_real_ctap() {
        assert_eq!(
            resolve_backend_mode(Some(" HW "), true, true, true),
            Ok(BackendMode::Hardware)
        );
        assert!(resolve_backend_mode(Some("hw"), false, false, true).is_err());
    }

    #[test]
    fn unavailable_mock_and_unknown_modes_are_rejected() {
        assert!(resolve_backend_mode(Some("mock"), true, true, false).is_err());
        assert!(resolve_backend_mode(Some("typo"), false, true, true).is_err());
    }

    #[test]
    fn release_without_real_ctap_does_not_silently_select_mock() {
        assert!(resolve_backend_mode(None, false, false, true).is_err());
    }
}

#[cfg(test)]
mod hardware_backend_selection_tests {
    use super::{detected_key_preview, select_hardware_backend};
    use crate::fido2::{
        BackendInitError, DetectedKey, FidoBackend, FidoError, MockBackend, RegisteredCredential,
        UnavailableBackend,
    };

    /// Stand-in for a successfully constructed hardware backend.
    struct ConstructedBackend;

    impl FidoBackend for ConstructedBackend {
        fn detect(&mut self) -> std::result::Result<DetectedKey, FidoError> {
            Err(FidoError::NoDevice)
        }
        fn register_credential(
            &mut self,
            _detected: &DetectedKey,
            _pin: Option<&str>,
        ) -> std::result::Result<RegisteredCredential, FidoError> {
            Err(FidoError::NoDevice)
        }
        fn get_prf_secret(
            &mut self,
            _credential_id: &[u8],
            _pin: Option<&str>,
        ) -> std::result::Result<[u8; 32], FidoError> {
            Err(FidoError::NoDevice)
        }
        fn info_diag(&self) -> String {
            "constructed".into()
        }
    }

    #[test]
    fn webauthn_api_below_v4_selects_key_unavailable_backend() {
        let backend = select_hardware_backend::<ConstructedBackend>(Err(
            BackendInitError::WebAuthnApiBelowV4 { api_version: 0 },
        ))
        .expect("API capability shortfall must not abort GUI startup");
        assert!(backend.uses_brokered_key_selection());
        assert_ne!(backend.info_diag(), "constructed");
        let reason = backend
            .key_unavailable_reason()
            .expect("unavailable backend must report why keys are unusable");
        assert!(reason.contains("v0"), "{reason}");
    }

    #[test]
    fn other_backend_construction_errors_remain_fatal() {
        for error in [
            FidoError::Internal("boom".into()),
            FidoError::NotSupported("Windows WebAuthn API v0 lacks HMAC-secret".into()),
            FidoError::NoDevice,
        ] {
            assert!(
                select_hardware_backend::<ConstructedBackend>(Err(BackendInitError::Fido(error)))
                    .is_err()
            );
        }
    }

    #[test]
    fn successful_construction_keeps_real_backend() {
        let backend = select_hardware_backend(Ok(ConstructedBackend)).unwrap();
        assert_eq!(backend.info_diag(), "constructed");
        assert!(backend.key_unavailable_reason().is_none());
    }

    #[test]
    fn detect_key_preview_fails_closed_when_keys_unavailable() {
        let error = detected_key_preview(&UnavailableBackend::new(0))
            .expect_err("must not pretend a key was detected");
        assert!(error.contains("主密碼"), "{error}");
        assert!(detected_key_preview(&MockBackend::new()).is_ok());
    }
}

#[cfg(test)]
mod focus_window_tests {
    use super::{ensure_parent_window_ready, restore_window_if_minimized};

    #[test]
    fn key_operation_activation_only_restores_a_minimized_window() {
        let mut restore_calls = 0;

        // A maximized window is not minimized and must keep its maximized state.
        restore_window_if_minimized(false, || restore_calls += 1);
        assert_eq!(restore_calls, 0);

        restore_window_if_minimized(true, || restore_calls += 1);
        assert_eq!(restore_calls, 1);
    }

    #[test]
    fn key_operation_requires_a_visible_unminimized_foreground_parent() {
        assert!(ensure_parent_window_ready(true, true, true, false).is_ok());
        assert!(ensure_parent_window_ready(true, false, true, false).is_err());
        assert!(ensure_parent_window_ready(true, true, false, false).is_err());
        assert!(ensure_parent_window_ready(true, true, true, true).is_err());
        assert!(ensure_parent_window_ready(false, false, false, true).is_ok());
    }
}

#[cfg(test)]
mod clipboard_match_tests {
    use super::clipboard_text_matches;

    fn terminated(text: &str) -> Vec<u16> {
        text.encode_utf16().chain(std::iter::once(0)).collect()
    }

    #[test]
    fn matches_exact_null_terminated_utf16_text_including_non_ascii() {
        assert!(clipboard_text_matches(&terminated("密碼🔐"), "密碼🔐"));
    }

    #[test]
    fn rejects_different_or_extended_clipboard_text() {
        assert!(!clipboard_text_matches(
            &terminated("replacement"),
            "expected"
        ));
        assert!(!clipboard_text_matches(
            &terminated("expected-extra"),
            "expected"
        ));
    }

    #[test]
    fn requires_a_null_terminator_after_the_expected_text() {
        let unterminated: Vec<u16> = "expected".encode_utf16().collect();
        assert!(!clipboard_text_matches(&unterminated, "expected"));
        assert!(!clipboard_text_matches(&[], ""));
    }
}
