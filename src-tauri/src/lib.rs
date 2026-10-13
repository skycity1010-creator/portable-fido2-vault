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
pub mod edition;
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
    /// 單人版的 platform slot 標記；舊版 JSON（無 platform slot）不增加欄位。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authenticator: Option<vault::SlotAuthenticator>,
    /// 有效 RP-local discovery 時的平台憑證是否屬於目前 Windows 帳號；None = 未能確認。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub platform_local: Option<bool>,
    /// 雙人版：所屬群組（單人版不輸出）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub group: Option<crypto::KeyGroup>,
    /// 雙人版：是否為該群組最後一支（UI 停用移除鈕）；false 不輸出。
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub last_in_group: bool,
}

/// header → 金鑰清單（登入畫面與金鑰管理共用）。
fn key_infos(h: &vault::Header) -> Vec<KeyInfo> {
    h.key_slots
        .iter()
        .map(|s| KeyInfo {
            credential_id: s.credential_id.clone(),
            label: s.label.clone(),
            key_type: s.key_type,
            prompt_zh: s.key_type.prompt_zh(),
            authenticator: s.authenticator,
            platform_local: None,
            group: s.group,
            last_in_group: vault::last_key_in_group(h, &s.credential_id).is_some(),
        })
        .collect()
}

fn key_infos_with_local(h: &vault::Header, local: Option<&[Vec<u8>]>) -> Vec<KeyInfo> {
    let mut infos = key_infos(h);
    if h.v == 1 {
        for info in &mut infos {
            let membership = local.and_then(|list| {
                crypto::base64_decode(&info.credential_id)
                    .ok()
                    .map(|id| list.contains(&id))
            });
            if info.authenticator.is_none() && membership == Some(true) {
                info.authenticator = Some(vault::SlotAuthenticator::Platform);
            }
            if info.authenticator.is_some() {
                info.platform_local = membership;
            }
        }
    }
    infos
}

impl From<&vault::Header> for Vec<KeyInfo> {
    fn from(h: &vault::Header) -> Self {
        key_infos(h)
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
    /// 雙人版兩步驟登入：第一步完成後的暫存（share 只在 Rust 端，drop 時清零）。
    dual_pending: Option<vault::DualPending>,
    /// 每次第一步遞增；逾時計時器只清除自己那一代的暫存。
    dual_generation: u64,
}

/// 逾時計時器：同一代且已逾時 → 取走暫存、記 `fido2-dual-timeout`（share 清零）。
fn sweep_expired_dual(g: &mut AppInner, generation: u64, now: std::time::Instant) -> bool {
    if g.dual_generation != generation {
        return false;
    }
    match g.dual_pending.as_ref() {
        Some(pending) if pending.is_expired(now) => {}
        _ => return false,
    }
    if let Some(pending) = g.dual_pending.take() {
        let _ = pending.expire();
    }
    true
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
            dual_pending: None,
            dual_generation: 0,
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

/// 產品版本（"single" / "dual"），前端依此切換雙群組控管 UI。
#[tauri::command]
fn get_edition() -> edition::Edition {
    edition::current()
}

/// 啟動畫面資訊：是否有金庫、已註冊金鑰清單（供登入畫面）。
#[tauri::command]
fn boot_info(state: tauri::State<VaultState>) -> Result<LoginScreenInfo> {
    let path = path_from_state_or_default();
    let has_vault = path.exists();
    let keys = if has_vault && edition::current() == edition::Edition::Single {
        let h = vault::Vault::read_header(&path, edition::Edition::Single)
            .map_err(|e| e.to_string())?;
        state.with_lock(|g| {
            // RP-local discovery is read-only. Failure must not prevent password login.
            let local = if g.backend.platform_status().available() {
                g.backend.list_platform_credentials().ok()
            } else {
                None
            };
            Ok(key_infos_with_local(&h, local.as_deref()))
        })?
    } else if has_vault {
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
    // 與解鎖路徑共用同一個 reader：magic/長度邊界/版本互斥都在 vault 層檢查。
    let h = vault::Vault::read_header(path, edition::current()).map_err(|e| e.to_string())?;
    Ok(key_infos(&h))
}

/// Safe, non-interactive Windows Hello capability response; never contains secrets.
#[derive(Debug, serde::Serialize)]
struct PlatformStatusInfo {
    api_ok: bool,
    uvpa: bool,
    console: bool,
    local_credential: bool,
}

fn query_platform_status(
    state: &VaultState,
    path: &std::path::Path,
    ed: edition::Edition,
) -> Result<PlatformStatusInfo> {
    require_windows_hello_single(ed)?;
    state.with_lock(|g| {
        let header = match g.vault.as_ref() {
            // Vault exposes no header accessor; use its checked persisted header.
            Some(v) => Some(vault::Vault::read_header(&v.path, ed).map_err(|e| e.to_string())?),
            None if path.exists() => {
                Some(vault::Vault::read_header(path, ed).map_err(|e| e.to_string())?)
            }
            None => None,
        };
        if let Some(h) = header.as_ref() {
            vault::check_header_edition(h, ed).map_err(|e| e.to_string())?;
        }
        let status = g.backend.platform_status();
        let mut local_credential = false;
        if status.available() {
            if let Some(h) = header {
                // RP-scoped membership also recognizes R3 marker-lost slots.
                // This is a query only: do not repair or persist the header here.
                let local = g
                    .backend
                    .list_platform_credentials()
                    .map_err(|e| e.to_string())?;
                for slot in &h.key_slots {
                    let id = crypto::base64_decode(&slot.credential_id)
                        .map_err(|_| "credential_id 解碼失敗".to_string())?;
                    local_credential |= local.contains(&id);
                }
            }
        }
        Ok(PlatformStatusInfo {
            api_ok: status.api_ok,
            uvpa: status.uvpa,
            console: status.console,
            local_credential,
        })
    })
}

fn require_windows_hello_single(ed: edition::Edition) -> Result<()> {
    if ed != edition::Edition::Single {
        return Err("Windows Hello 僅支援單人版；請使用 YubiKey 或主密碼".into());
    }
    Ok(())
}

#[tauri::command]
fn platform_status(state: tauri::State<VaultState>) -> Result<PlatformStatusInfo> {
    query_platform_status(&state, &path_from_state_or_default(), edition::current())
}

fn require_windows_hello_available(backend: &dyn fido2::FidoBackend) -> Result<()> {
    if !backend.platform_status().available() {
        return Err("Windows Hello 需要 Windows 11、WebAuthn API v8+、可用的 UVPA 與本機 Console，且斷言須支援 PRF；請使用 YubiKey 或主密碼登入".into());
    }
    Ok(())
}

fn register_windows_hello_inner(
    state: &VaultState,
    ed: edition::Edition,
    raise: impl FnOnce(bool) -> Result<isize>,
    computer_name: impl FnOnce() -> Result<String>,
) -> Result<fido2::RegisteredCredential> {
    require_windows_hello_single(ed)?;
    state.with_lock(|g| {
        let v = g.vault.as_mut().ok_or_else(|| "金庫未解鎖".to_string())?;
        require_windows_hello_available(g.backend.as_ref())?;
        let name = computer_name()?;
        let owner = raise(true)?;
        g.backend.set_webauthn_parent_hwnd(owner);
        v.register_windows_hello(g.backend.as_mut(), &name, ed)
            .map_err(|e| e.to_string())
    })
}

#[tauri::command]
fn register_windows_hello(
    window: tauri::WebviewWindow,
    state: tauri::State<VaultState>,
) -> Result<fido2::RegisteredCredential> {
    register_windows_hello_inner(
        &state,
        edition::current(),
        |required| raise_key_operation_window(&window, required),
        || {
            std::env::var("COMPUTERNAME")
                .map_err(|_| "無法取得本機電腦名稱；請使用 YubiKey 或主密碼".to_string())
        },
    )
}

fn login_windows_hello_inner(
    state: &VaultState,
    path: &std::path::Path,
    ed: edition::Edition,
    raise: impl FnOnce(bool) -> Result<isize>,
) -> Result<Vec<vault::Entry>> {
    require_windows_hello_single(ed)?;
    state.with_lock(|g| {
        require_windows_hello_available(g.backend.as_ref())?;
        let owner = raise(true)?;
        g.backend.set_webauthn_parent_hwnd(owner);
        let v = vault::Vault::open_windows_hello(path, g.backend.as_mut(), ed)
            .map_err(|e| e.to_string())?;
        let entries = v.entries().to_vec();
        // Authentication, successful persistence and publication share one lock.
        // A concurrent lock command cannot interleave and be undone by login.
        g.pending_csv_import = None;
        g.dual_pending = None;
        g.vault = Some(v);
        Ok(entries)
    })
}

#[tauri::command]
fn login_windows_hello(
    window: tauri::WebviewWindow,
    state: tauri::State<VaultState>,
) -> Result<Vec<vault::Entry>> {
    login_windows_hello_inner(
        &state,
        &path_from_state_or_default(),
        edition::current(),
        |required| raise_key_operation_window(&window, required),
    )
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
    let v = vault::Vault::create_for(&path, &password, edition::current())
        .map_err(|e| e.to_string())?;
    state.with_lock(|g| {
        g.dual_pending = None;
        g.vault = Some(v);
        Ok(())
    })?;
    Ok(())
}

/// 主密碼登入。
#[tauri::command]
fn login_password(state: tauri::State<VaultState>, password: String) -> Result<Vec<vault::Entry>> {
    login_password_inner(
        &state,
        &path_from_state_or_default(),
        &password,
        edition::current(),
    )
}

fn login_password_inner(
    state: &VaultState,
    path: &std::path::Path,
    password: &str,
    ed: edition::Edition,
) -> Result<Vec<vault::Entry>> {
    state.with_lock(|g| {
        let v = if ed == edition::Edition::Single {
            vault::Vault::open_password_with_platform(path, password, ed, g.backend.as_mut())
        } else {
            vault::Vault::open_password_for(path, password, ed)
        }
        .map_err(|e| e.to_string())?;
        let entries = v.entries().to_vec();
        // 改用主密碼登入：放棄進行中的兩步驟登入（share 清零）。
        g.dual_pending = None;
        g.vault = Some(v);
        Ok(entries)
    })
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

/// 雙人版兩步驟登入第一步的回應（不含任何機密）。
#[derive(serde::Serialize)]
struct DualBeginInfo {
    first_group: crypto::KeyGroup,
    first_label: String,
    second_group: crypto::KeyGroup,
    timeout_secs: u32,
    remaining_ms: u64,
}

fn require_dual_edition() -> Result<()> {
    if edition::current() == edition::Edition::Dual {
        Ok(())
    } else {
        Err("此功能僅限雙群組控管版".into())
    }
}

/// 雙人版金鑰登入第一步：任一群組的金鑰。成功後暫存該群組 share 並開始倒數。
#[tauri::command]
fn login_dual_begin(
    window: tauri::WebviewWindow,
    state: tauri::State<VaultState>,
    pin: Option<String>,
) -> Result<DualBeginInfo> {
    require_dual_edition()?;
    let require_foreground = state.with_lock(|g| Ok(g.backend.uses_brokered_key_selection()))?;
    let owner_hwnd = raise_key_operation_window(&window, require_foreground)?;
    let path = path_from_state_or_default();
    state.with_lock(|g| {
        // 新的第一步一律先丟棄舊的暫存（清零），避免殘留 share。
        g.dual_pending = None;
        g.backend.set_webauthn_parent_hwnd(owner_hwnd);
        let pending = vault::Vault::dual_login_begin(
            &path,
            pin.as_deref(),
            g.backend.as_mut(),
            &mut std::time::Instant::now,
        )
        .map_err(|e| e.to_string())?;
        let remaining = pending.remaining(std::time::Instant::now());
        let info = DualBeginInfo {
            first_group: pending.first_group(),
            first_label: pending.first_label().to_owned(),
            second_group: pending.first_group().other(),
            timeout_secs: pending.timeout_secs(),
            remaining_ms: remaining.as_millis() as u64,
        };
        g.dual_generation = g.dual_generation.wrapping_add(1);
        let generation = g.dual_generation;
        g.dual_pending = Some(pending);
        // Rust 端主動逾時清除，不依賴前端呼叫（§4.3、R5）。
        let app = window.app_handle().clone();
        std::thread::spawn(move || {
            std::thread::sleep(remaining + std::time::Duration::from_millis(250));
            let state = app.state::<VaultState>();
            let _ = state.with_lock(|g| {
                sweep_expired_dual(g, generation, std::time::Instant::now());
                Ok(())
            });
        });
        Ok(info)
    })
}

/// 雙人版金鑰登入第二步：只接受另一群組的金鑰。無論成功或失敗，暫存都會被取走（一次性）。
#[tauri::command]
fn login_dual_complete(
    window: tauri::WebviewWindow,
    state: tauri::State<VaultState>,
    pin: Option<String>,
) -> Result<Vec<vault::Entry>> {
    require_dual_edition()?;
    let require_foreground = state.with_lock(|g| Ok(g.backend.uses_brokered_key_selection()))?;
    let owner_hwnd = raise_key_operation_window(&window, require_foreground)?;
    let v = state.with_lock(|g| {
        let pending = g
            .dual_pending
            .take()
            .ok_or_else(|| "沒有進行中的第一步驗證，請從第一步重新開始".to_string())?;
        g.backend.set_webauthn_parent_hwnd(owner_hwnd);
        vault::Vault::dual_login_complete(
            pending,
            pin.as_deref(),
            g.backend.as_mut(),
            &mut std::time::Instant::now,
        )
        .map_err(|e| e.to_string())
    })?;
    let entries = v.entries().to_vec();
    state.with_lock(|g| {
        g.vault = Some(v);
        Ok(())
    })?;
    Ok(entries)
}

/// 雙人版：取消進行中的兩步驟登入（記 sidecar，share 清零）。沒有暫存時為 no-op。
#[tauri::command]
fn login_dual_cancel(state: tauri::State<VaultState>) -> Result<()> {
    require_dual_edition()?;
    let pending = state.with_lock(|g| Ok(g.dual_pending.take()))?;
    if let Some(pending) = pending {
        pending.cancel().map_err(|e| e.to_string())?;
    }
    Ok(())
}

/// 上鎖（手動或閒置）。回傳登入畫面資訊。
#[tauri::command]
fn lock(state: tauri::State<VaultState>, reason: Option<String>) -> Result<LoginScreenInfo> {
    let (header, brokered_key_login) = state.with_lock(|g| {
        let brokered_key_login = g.backend.uses_brokered_key_selection();
        g.dual_pending = None;
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
    group: Option<crypto::KeyGroup>,
) -> Result<fido2::RegisteredCredential> {
    let require_foreground = state.with_lock(|g| Ok(g.backend.uses_brokered_key_selection()))?;
    let owner_hwnd = raise_key_operation_window(&window, require_foreground)?;
    // 同一後端實例內 detect+register → 類型一致。
    state.with_lock(|g| match g.vault.as_mut() {
        Some(v) => {
            g.backend.set_webauthn_parent_hwnd(owner_hwnd);
            // 單人版不可帶群組、雙人版必須帶群組（vault 層 fail closed，不碰 authenticator）。
            v.register_key_for(g.backend.as_mut(), pin.as_deref(), &label, group)
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

#[derive(Debug, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case", tag = "outcome", content = "warning")]
enum KeyRemovalInfo {
    Removed,
    ManualRemovalRequired(KeyRemovalWarning),
}

#[derive(Debug, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
enum KeyRemovalWarning {
    NotLocal,
    DiscoveryFailed,
    DeleteFailed,
}

#[tauri::command]
fn remove_key(
    state: tauri::State<VaultState>,
    credential_id: String,
) -> Result<Option<KeyRemovalInfo>> {
    remove_key_inner(&state, &credential_id, edition::current())
}

fn remove_key_inner(
    state: &VaultState,
    credential_id: &str,
    ed: edition::Edition,
) -> Result<Option<KeyRemovalInfo>> {
    state.with_lock(|g| {
        let v = g.vault.as_mut().ok_or_else(|| "金庫未解鎖".to_string())?;
        if ed == edition::Edition::Dual {
            v.remove_key(credential_id).map_err(|e| e.to_string())?;
            return Ok(None); // Preserve the existing dual JSON null response.
        }
        let outcome = v
            .remove_key_with_platform(credential_id, g.backend.as_mut(), ed)
            .map_err(|e| e.to_string())?;
        Ok(match outcome {
            vault::PlatformCleanupOutcome::NotApplicable => None,
            vault::PlatformCleanupOutcome::Removed => Some(KeyRemovalInfo::Removed),
            vault::PlatformCleanupOutcome::ManualRemovalRequired(warning) => {
                Some(KeyRemovalInfo::ManualRemovalRequired(match warning {
                    vault::PlatformCleanupWarning::NotLocal => KeyRemovalWarning::NotLocal,
                    vault::PlatformCleanupWarning::DiscoveryFailed => {
                        KeyRemovalWarning::DiscoveryFailed
                    }
                    vault::PlatformCleanupWarning::DeleteFailed => KeyRemovalWarning::DeleteFailed,
                }))
            }
        })
    })
}

#[tauri::command]
fn set_dual_step_timeout(state: tauri::State<VaultState>, secs: u32) -> Result<()> {
    update_dual_step_timeout(&state, secs)
}

fn update_dual_step_timeout(state: &VaultState, secs: u32) -> Result<()> {
    with_unlocked(state, |v| {
        v.set_dual_step_timeout(secs).map_err(|e| e.to_string())
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
            get_edition,
            boot_info,
            platform_status,
            register_windows_hello,
            login_windows_hello,
            create_vault,
            login_password,
            login_key,
            login_any_key,
            login_dual_begin,
            login_dual_complete,
            login_dual_cancel,
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
            set_dual_step_timeout,
            get_vault_settings,
            set_password_history_limit,
            clear_clipboard_if_matches,
            detect_key
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

#[cfg(test)]
mod wh_d5_tests {
    use super::*;
    use fido2::{FidoBackend, FidoError, MockBackend, PlatformStatus};
    use std::sync::{Arc, Mutex};

    #[derive(Default)]
    struct Calls {
        status: usize,
        list: usize,
        create: usize,
        assert: usize,
        delete: usize,
        hwnd: Vec<isize>,
        allow: Vec<Vec<u8>>,
    }

    struct Recording {
        mock: MockBackend,
        calls: Arc<Mutex<Calls>>,
        status: PlatformStatus,
        list_error: bool,
        rogue: bool,
        delete_error: bool,
    }

    impl Recording {
        fn new() -> Self {
            Self {
                mock: MockBackend::new(),
                calls: Arc::new(Mutex::new(Calls::default())),
                status: PlatformStatus {
                    api_ok: true,
                    uvpa: true,
                    console: true,
                },
                list_error: false,
                rogue: false,
                delete_error: false,
            }
        }
    }

    impl FidoBackend for Recording {
        fn detect(&mut self) -> std::result::Result<fido2::DetectedKey, FidoError> {
            self.mock.detect()
        }
        fn register_credential(
            &mut self,
            d: &fido2::DetectedKey,
            pin: Option<&str>,
        ) -> std::result::Result<fido2::RegisteredCredential, FidoError> {
            self.mock.register_credential(d, pin)
        }
        fn get_prf_secret(
            &mut self,
            id: &[u8],
            pin: Option<&str>,
        ) -> std::result::Result<[u8; 32], FidoError> {
            self.mock.get_prf_secret(id, pin)
        }
        fn platform_status(&self) -> PlatformStatus {
            self.calls.lock().unwrap().status += 1;
            self.status
        }
        fn list_platform_credentials(&mut self) -> std::result::Result<Vec<Vec<u8>>, FidoError> {
            self.calls.lock().unwrap().list += 1;
            if self.list_error {
                return Err(FidoError::Internal("synthetic discovery failure".into()));
            }
            self.mock.list_platform_credentials()
        }
        fn register_platform_credential(
            &mut self,
            label: &str,
            exclude: &[Vec<u8>],
        ) -> std::result::Result<fido2::PlatformRegistration, FidoError> {
            self.calls.lock().unwrap().create += 1;
            self.mock.register_platform_credential(label, exclude)
        }
        fn get_platform_prf_secret(
            &mut self,
            ids: &[Vec<u8>],
        ) -> std::result::Result<(Vec<u8>, [u8; 32]), FidoError> {
            let mut c = self.calls.lock().unwrap();
            c.assert += 1;
            c.allow = ids.to_vec();
            drop(c);
            if self.rogue {
                return Ok((vec![255; 32], [0; 32]));
            }
            self.mock.get_platform_prf_secret(ids)
        }
        fn delete_platform_credential(&mut self, id: &[u8]) -> std::result::Result<(), FidoError> {
            self.calls.lock().unwrap().delete += 1;
            if self.delete_error {
                return Err(FidoError::Internal("synthetic delete failure".into()));
            }
            self.mock.delete_platform_credential(id)
        }
        fn set_webauthn_parent_hwnd(&mut self, handle: isize) {
            self.calls.lock().unwrap().hwnd.push(handle);
        }
    }

    fn fixture_root() -> std::path::PathBuf {
        std::env::var_os("TMPDIR")
            .filter(|value| !value.is_empty())
            .map(std::path::PathBuf::from)
            .unwrap_or_else(std::env::temp_dir)
    }

    struct Fixture {
        dir: std::path::PathBuf,
        path: std::path::PathBuf,
    }

    impl std::ops::Deref for Fixture {
        type Target = std::path::Path;
        fn deref(&self) -> &Self::Target {
            &self.path
        }
    }

    impl AsRef<std::path::Path> for Fixture {
        fn as_ref(&self) -> &std::path::Path {
            &self.path
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            // The directory was atomically created by this fixture, never adopted.
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    fn fixture() -> Fixture {
        fixture_in(&fixture_root())
    }

    fn fixture_in(root: &std::path::Path) -> Fixture {
        std::fs::create_dir_all(root).unwrap();
        for _ in 0..32 {
            let dir = root.join(format!("f2v-wh-d5-{:016x}", rand::random::<u64>()));
            match std::fs::create_dir(&dir) {
                Ok(()) => {
                    return Fixture {
                        path: dir.join("vault.db"),
                        dir,
                    };
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => panic!("could not create isolated D5 fixture: {error}"),
            }
        }
        panic!("could not reserve unique D5 fixture directory")
    }

    #[test]
    fn wh_d5_review_t1_fixture_honors_injected_root_and_scoped_cleanup() {
        let root = fixture_root();
        let p = fixture_in(&root);
        assert!(p.starts_with(&root), "fixture must honor the injected root");
        let dir = p.parent().unwrap().to_path_buf();
        assert!(dir.is_dir());
        std::fs::write(&p, b"synthetic scoped cleanup sentinel").unwrap();
        drop(p);
        assert!(!dir.exists(), "only this fixture directory must be cleaned");
        assert!(root.is_dir(), "the supplied root must be preserved");
    }

    fn state(v: Option<vault::Vault>, b: Recording) -> (VaultState, Arc<Mutex<Calls>>) {
        let calls = b.calls.clone();
        (
            VaultState(Mutex::new(AppInner {
                vault: v,
                backend: Box::new(b),
                pending_csv_import: None,
                dual_pending: None,
                dual_generation: 0,
            })),
            calls,
        )
    }

    #[test]
    fn wh_d5_control_unknown_removal_does_not_touch_native_or_persist() {
        let p = fixture();
        let v = vault::Vault::create_for(&p, "synthetic-D5-password", edition::Edition::Single)
            .unwrap();
        let before = std::fs::read(&p).unwrap();
        let (s, c) = state(Some(v), Recording::new());
        let result = remove_key_inner(&s, "unknown-id", edition::Edition::Single);
        assert!(result.is_err());
        assert_eq!(std::fs::read(&p).unwrap(), before);
        let c = c.lock().unwrap();
        assert_eq!((c.create, c.assert, c.delete, c.hwnd.len()), (0, 0, 0, 0));
    }

    #[test]
    fn wh_d5_control_dual_removal_preserves_null_and_skips_backend() {
        let p = fixture();
        let mut v =
            vault::Vault::create_for(&p, "synthetic-D5-password", edition::Edition::Dual).unwrap();
        for (name, group) in [
            ("a1", crypto::KeyGroup::A),
            ("a2", crypto::KeyGroup::A),
            ("b1", crypto::KeyGroup::B),
        ] {
            let mut roaming = MockBackend::new();
            let result = v.register_key_for(&mut roaming, None, name, Some(group));
            assert!(
                result.is_ok(),
                "dual synthetic registration failed: {result:?}"
            );
        }
        let id = v.keys_meta()[0].0.clone();
        let (s, c) = state(Some(v), Recording::new());
        let result = remove_key_inner(&s, &id, edition::Edition::Dual);
        assert!(result.is_ok());
        assert_eq!(
            serde_json::to_value(result.unwrap()).unwrap(),
            serde_json::Value::Null
        );
        assert_eq!(
            vault::Vault::read_header(&p, edition::Edition::Dual)
                .unwrap()
                .key_slots
                .len(),
            2
        );
        let c = c.lock().unwrap();
        assert_eq!(
            (c.status, c.list, c.create, c.assert, c.delete, c.hwnd.len()),
            (0, 0, 0, 0, 0, 0)
        );
    }

    #[test]
    fn wh_d5_control_existing_password_roaming_and_dual_paths() {
        let p = fixture();
        let mut v = vault::Vault::create_for(&p, "synthetic-D5-password", edition::Edition::Single)
            .unwrap();
        let mut roaming = MockBackend::new();
        let reg = v.register_key_with_label(&mut roaming, None, "synthetic-roaming");
        assert!(reg.is_ok());
        let id = crypto::base64_encode(&reg.unwrap().credential_id);
        v.lock();
        let (s, c) = state(None, Recording::new());
        let pw = login_password_inner(&s, &p, "synthetic-D5-password", edition::Edition::Single);
        assert!(pw.is_ok());
        let removal = remove_key_inner(&s, &id, edition::Edition::Single);
        assert!(removal.is_ok());
        assert_eq!(removal.unwrap(), None);
        let c = c.lock().unwrap();
        assert_eq!((c.create, c.assert, c.delete, c.hwnd.len()), (0, 0, 0, 0));

        let dual_path = fixture();
        let dual =
            vault::Vault::create_for(&dual_path, "synthetic-D5-password", edition::Edition::Dual);
        assert!(dual.is_ok());
        dual.unwrap().lock();
        let (ds, dc) = state(None, Recording::new());
        let dual_pw = login_password_inner(
            &ds,
            &dual_path,
            "synthetic-D5-password",
            edition::Edition::Dual,
        );
        assert!(dual_pw.is_ok());
        assert_eq!(dc.lock().unwrap().status, 0);
    }

    fn ipc_wiring_is_correct(source: &str) -> bool {
        let normalized = source.replace(char::from(13), "");
        let source = normalized.split("\n#[cfg(test)]\n").next().unwrap();
        if source
            .matches(".invoke_handler(tauri::generate_handler![")
            .count()
            != 1
        {
            return false;
        }
        let Some(commands) = source
            .split(".invoke_handler(tauri::generate_handler![")
            .nth(1)
            .and_then(|tail| tail.split("])").next())
        else {
            return false;
        };
        for command in [
            "platform_status",
            "register_windows_hello",
            "login_windows_hello",
            "login_password",
            "remove_key",
        ] {
            if !commands
                .lines()
                .any(|line| line.trim() == format!("{command},"))
            {
                return false;
            }
        }
        for (entry, helper) in [
            ("fn platform_status(state:", "query_platform_status(&state"),
            (
                "fn register_windows_hello(\n",
                "register_windows_hello_inner(",
            ),
            ("fn login_windows_hello(\n", "login_windows_hello_inner("),
            ("fn login_password(state:", "login_password_inner("),
            ("fn remove_key(\n", "remove_key_inner("),
        ] {
            if source.matches(entry).count() != 1 {
                return false;
            }
            let Some(body) = source
                .split(entry)
                .nth(1)
                .and_then(|tail| tail.split("\n}\n").next())
            else {
                return false;
            };
            if !body.contains(helper) {
                return false;
            }
        }
        true
    }

    #[test]
    fn wh_d5_control_command_registry_and_ipc_helper_wiring() {
        assert!(ipc_wiring_is_correct(include_str!("lib.rs")));
    }

    #[test]
    fn wh_d5_review_t2_wiring_oracle_rejects_disconnected_production() {
        let source = include_str!("lib.rs").replace(char::from(13), "");
        assert!(
            ipc_wiring_is_correct(&source),
            "actual command wiring must pass"
        );
        let disconnected = source.replacen(
            "remove_key_inner(&state, &credential_id, edition::current())",
            "Ok(None)",
            1,
        );
        assert_ne!(
            disconnected, source,
            "negative fixture must remove real production call"
        );
        assert!(
            !ipc_wiring_is_correct(&disconnected),
            "test text cannot certify disconnected production"
        );
    }

    #[test]
    fn wh_d5_control_dual_and_locked_refuse_without_backend_or_focus() {
        let p = fixture();
        let (s, c) = state(None, Recording::new());
        let mut focus = 0;
        let mut name = 0;
        assert!(query_platform_status(&s, &p, edition::Edition::Dual).is_err());
        assert!(register_windows_hello_inner(
            &s,
            edition::Edition::Dual,
            |_| {
                focus += 1;
                Ok(1)
            },
            || {
                name += 1;
                Ok("SYNTHETIC".into())
            }
        )
        .is_err());
        assert!(
            login_windows_hello_inner(&s, &p, edition::Edition::Dual, |_| {
                focus += 1;
                Ok(1)
            })
            .is_err()
        );
        let locked = register_windows_hello_inner(
            &s,
            edition::Edition::Single,
            |_| {
                focus += 1;
                Ok(1)
            },
            || {
                name += 1;
                Ok("SYNTHETIC".into())
            },
        );
        assert!(locked.is_err());
        assert_eq!(locked.err().unwrap(), "金庫未解鎖");
        assert_eq!((focus, name), (0, 0));
        let c = c.lock().unwrap();
        assert_eq!(
            (c.status, c.list, c.create, c.assert, c.delete, c.hwnd.len()),
            (0, 0, 0, 0, 0, 0)
        );
    }

    #[test]
    fn wh_d5_control_status_no_vault_foreign_and_lost_marker() {
        let missing = fixture();
        let (empty, ec) = state(None, Recording::new());
        let result = query_platform_status(&empty, &missing, edition::Edition::Single);
        assert!(result.is_ok());
        assert!(!result.unwrap().local_credential);
        assert_eq!(ec.lock().unwrap().list, 0);
        let p = fixture();
        let mut b = Recording::new();
        let mut v = vault::Vault::create_for(&p, "synthetic-D5-password", edition::Edition::Single)
            .unwrap();
        assert!(v
            .register_windows_hello(&mut b.mock, "SYNTHETIC", edition::Edition::Single)
            .is_ok());
        v.lock();
        let (foreign, fc) = state(None, Recording::new());
        let result = query_platform_status(&foreign, &p, edition::Edition::Single);
        assert!(result.is_ok());
        assert!(!result.unwrap().local_credential);
        assert_eq!(fc.lock().unwrap().list, 1);
        lose_marker(&p);
        let before = std::fs::read(&p).unwrap();
        let (local, lc) = state(None, b);
        let result = query_platform_status(&local, &p, edition::Edition::Single);
        assert!(result.is_ok());
        assert!(result.unwrap().local_credential);
        assert_eq!(std::fs::read(&p).unwrap(), before);
        let c = lc.lock().unwrap();
        assert_eq!((c.create, c.assert, c.delete, c.hwnd.len()), (0, 0, 0, 0));
    }

    #[test]
    fn wh_d5_control_status_unavailable_error_and_checked_header() {
        for mode in 0..5 {
            let p = fixture();
            let v = vault::Vault::create_for(&p, "synthetic-D5-password", edition::Edition::Single)
                .unwrap();
            v.lock();
            let mut b = Recording::new();
            match mode {
                0 => b.status.api_ok = false,
                1 => b.status.uvpa = false,
                2 => b.status.console = false,
                3 => b.list_error = true,
                _ => std::fs::write(&p, b"synthetic corrupt header").unwrap(),
            }
            let before = std::fs::read(&p).unwrap();
            let (s, c) = state(None, b);
            let result = query_platform_status(&s, &p, edition::Edition::Single);
            if mode >= 3 {
                assert!(
                    result.is_err(),
                    "discovery/header errors must remain errors"
                );
            } else {
                assert!(result.is_ok());
                assert!(!result.unwrap().local_credential);
            }
            let c = c.lock().unwrap();
            assert_eq!(c.list, usize::from(mode == 3));
            assert_eq!((c.create, c.assert, c.delete, c.hwnd.len()), (0, 0, 0, 0));
            assert_eq!(std::fs::read(&p).unwrap(), before);
        }
    }

    #[test]
    fn wh_d5_control_status_unlocked_uses_vault_path() {
        let p = fixture();
        let mut b = Recording::new();
        let mut v = vault::Vault::create_for(&p, "synthetic-D5-password", edition::Edition::Single)
            .unwrap();
        assert!(v
            .register_windows_hello(&mut b.mock, "SYNTHETIC", edition::Edition::Single)
            .is_ok());
        let before = std::fs::read(&p).unwrap();
        let (s, c) = state(Some(v), b);
        let unrelated = fixture();
        let result = query_platform_status(&s, &unrelated, edition::Edition::Single);
        assert!(result.is_ok());
        assert!(result.unwrap().local_credential);
        assert_eq!(std::fs::read(&p).unwrap(), before);
        let c = c.lock().unwrap();
        assert_eq!((c.create, c.assert, c.delete, c.hwnd.len()), (0, 0, 0, 0));
    }

    #[test]
    fn wh_d5_control_register_duplicate_nb_and_persist_fail() {
        for mode in 0..4 {
            let p = fixture();
            let mut b = Recording::new();
            let mut v =
                vault::Vault::create_for(&p, "synthetic-D5-password", edition::Edition::Single)
                    .unwrap();
            if mode == 0 {
                assert!(v
                    .register_windows_hello(&mut b.mock, "SYNTHETIC", edition::Edition::Single)
                    .is_ok());
            } else if mode == 1 {
                b.mock = MockBackend::new()
                    .with_platform_mode(fido2::MockPlatformMode::AssertionPrfFails);
            } else if mode == 2 {
                std::fs::create_dir(p.with_extension("db.tmp")).unwrap();
            } else {
                b.list_error = true;
            }
            let before = std::fs::read(&p).unwrap();
            let (s, c) = state(Some(v), b);
            let result = register_windows_hello_inner(
                &s,
                edition::Edition::Single,
                |_| Ok(789),
                || Ok("SYNTHETIC".into()),
            );
            assert!(result.is_err());
            assert_eq!(std::fs::read(&p).unwrap(), before);
            let c = c.lock().unwrap();
            if mode == 0 || mode == 3 {
                assert_eq!((c.create, c.assert, c.delete), (0, 0, 0));
            } else {
                assert_eq!((c.create, c.assert, c.delete), (1, 1, 1));
            }
        }
    }

    #[test]
    fn wh_d5_control_register_missing_name_and_focus_error_do_not_mutate() {
        for missing_name in [true, false] {
            let p = fixture();
            let v = vault::Vault::create_for(&p, "synthetic-D5-password", edition::Edition::Single)
                .unwrap();
            let before = std::fs::read(&p).unwrap();
            let (s, c) = state(Some(v), Recording::new());
            let mut focus = 0;
            let result = register_windows_hello_inner(
                &s,
                edition::Edition::Single,
                |_| {
                    focus += 1;
                    Err("synthetic focus refusal".into())
                },
                || {
                    if missing_name {
                        Err("synthetic missing name".into())
                    } else {
                        Ok("SYNTHETIC".into())
                    }
                },
            );
            assert!(result.is_err());
            assert_eq!(focus, usize::from(!missing_name));
            let c = c.lock().unwrap();
            assert_eq!(
                (c.list, c.create, c.assert, c.delete, c.hwnd.len()),
                (0, 0, 0, 0, 0)
            );
            assert_eq!(std::fs::read(&p).unwrap(), before);
        }
    }

    #[test]
    fn wh_d5_control_login_unavailable_before_focus() {
        for field in 0..3 {
            let p = fixture();
            let mut b = Recording::new();
            match field {
                0 => b.status.api_ok = false,
                1 => b.status.uvpa = false,
                _ => b.status.console = false,
            }
            let (s, c) = state(None, b);
            let mut focus = 0;
            let result = login_windows_hello_inner(&s, &p, edition::Edition::Single, |_| {
                focus += 1;
                Ok(1)
            });
            assert!(result.is_err());
            assert_eq!(focus, 0);
            let c = c.lock().unwrap();
            assert_eq!(
                (c.list, c.create, c.assert, c.delete, c.hwnd.len()),
                (0, 0, 0, 0, 0)
            );
        }
    }

    #[test]
    fn wh_d5_control_login_failure_never_publishes_or_clears_pending() {
        for mode in 0..5 {
            let p = fixture();
            let mut b = Recording::new();
            let mut v =
                vault::Vault::create_for(&p, "synthetic-D5-password", edition::Edition::Single)
                    .unwrap();
            assert!(v
                .register_windows_hello(&mut b.mock, "SYNTHETIC", edition::Edition::Single)
                .is_ok());
            v.lock();
            match mode {
                0 => b.rogue = true,
                1 => b.list_error = true,
                2 => b.mock = MockBackend::new(), // Foreign machine: no local intersection.
                3 => {
                    let ids = b.mock.platform_credential_ids().to_vec();
                    b.mock = MockBackend::new()
                        .with_platform_credentials(ids)
                        .with_platform_mode(fido2::MockPlatformMode::AssertionPrfFails);
                }
                _ => std::fs::create_dir(p.with_extension("db.tmp")).unwrap(),
            }
            let before = std::fs::read(&p).unwrap();
            let (s, c) = state(None, b);
            seed_pending(&s, &p);
            let result = login_windows_hello_inner(&s, &p, edition::Edition::Single, |_| Ok(1));
            assert!(result.is_err(), "failed auth/persist cannot return entries");
            s.with_lock(|g| {
                assert!(g.vault.is_none());
                assert!(g.pending_csv_import.is_some() && g.dual_pending.is_some());
                Ok(())
            })
            .unwrap();
            let c = c.lock().unwrap();
            assert_eq!((c.create, c.delete), (0, 0));
            assert_eq!(c.assert, usize::from(mode != 1 && mode != 2));
            assert_eq!(std::fs::read(&p).unwrap(), before);
        }
    }

    #[test]
    fn wh_d5_control_removal_unavailable_foreign_and_list_error() {
        for mode in 0..3 {
            let p = fixture();
            let mut b = Recording::new();
            let mut v =
                vault::Vault::create_for(&p, "synthetic-D5-password", edition::Edition::Single)
                    .unwrap();
            let reg = v.register_windows_hello(&mut b.mock, "SYNTHETIC", edition::Edition::Single);
            assert!(reg.is_ok());
            let id = crypto::base64_encode(&reg.unwrap().credential_id);
            match mode {
                0 => b.status.console = false,
                1 => b.mock = MockBackend::new(),
                _ => b.list_error = true,
            }
            let (s, c) = state(Some(v), b);
            let result = remove_key_inner(&s, &id, edition::Edition::Single);
            assert!(result.is_ok());
            let warning = if mode == 1 {
                KeyRemovalWarning::NotLocal
            } else {
                KeyRemovalWarning::DiscoveryFailed
            };
            assert_eq!(
                result.unwrap(),
                Some(KeyRemovalInfo::ManualRemovalRequired(warning))
            );
            assert!(vault::Vault::read_header(&p, edition::Edition::Single)
                .unwrap()
                .key_slots
                .is_empty());
            let c = c.lock().unwrap();
            assert_eq!((c.create, c.assert, c.delete, c.hwnd.len()), (0, 0, 0, 0));
            if mode == 0 {
                assert_eq!(c.list, 0);
            }
        }
    }

    #[test]
    fn wh_d5_removal_preserves_d4_cleanup_outcome() {
        for fail in [false, true] {
            let p = fixture();
            let mut b = Recording::new();
            let mut v =
                vault::Vault::create_for(&p, "synthetic-D5-password", edition::Edition::Single)
                    .unwrap();
            let reg = v.register_windows_hello(&mut b.mock, "SYNTHETIC", edition::Edition::Single);
            assert!(reg.is_ok());
            let id = crypto::base64_encode(&reg.unwrap().credential_id);
            b.delete_error = fail;
            let (s, c) = state(Some(v), b);
            let result = remove_key_inner(&s, &id, edition::Edition::Single);
            assert!(result.is_ok());
            assert_eq!(
                result.unwrap(),
                Some(if fail {
                    KeyRemovalInfo::ManualRemovalRequired(KeyRemovalWarning::DeleteFailed)
                } else {
                    KeyRemovalInfo::Removed
                })
            );
            assert!(vault::Vault::read_header(&p, edition::Edition::Single)
                .unwrap()
                .key_slots
                .is_empty());
            let c = c.lock().unwrap();
            assert_eq!(c.delete, 1);
            assert_eq!((c.create, c.assert, c.hwnd.len()), (0, 0, 0));
        }
    }

    fn lose_marker(p: &std::path::Path) {
        let bytes = std::fs::read(p).unwrap();
        let len = u32::from_le_bytes(bytes[6..10].try_into().unwrap()) as usize;
        let mut header: serde_json::Value = serde_json::from_slice(&bytes[10..10 + len]).unwrap();
        for slot in header["key_slots"].as_array_mut().unwrap() {
            slot.as_object_mut().unwrap().remove("authenticator");
        }
        let header = serde_json::to_vec(&header).unwrap();
        let mut rewritten = bytes[..6].to_vec();
        rewritten.extend_from_slice(&(header.len() as u32).to_le_bytes());
        rewritten.extend_from_slice(&header);
        rewritten.extend_from_slice(&bytes[10 + len..]);
        std::fs::write(p, rewritten).unwrap();
    }

    #[test]
    fn wh_d5_password_single_integrates_r3_authenticated_save() {
        let p = fixture();
        let mut b = Recording::new();
        let mut v = vault::Vault::create_for(&p, "synthetic-D5-password", edition::Edition::Single)
            .unwrap();
        assert!(v
            .register_windows_hello(&mut b.mock, "SYNTHETIC", edition::Edition::Single)
            .is_ok());
        v.lock();
        lose_marker(&p);
        let (s, c) = state(None, b);
        let result =
            login_password_inner(&s, &p, "synthetic-D5-password", edition::Edition::Single);
        assert!(result.is_ok());
        let h = vault::Vault::read_header(&p, edition::Edition::Single).unwrap();
        assert_eq!(
            h.key_slots[0].authenticator,
            Some(vault::SlotAuthenticator::Platform)
        );
        let c = c.lock().unwrap();
        assert!(c.list > 0);
        assert_eq!((c.create, c.assert, c.delete, c.hwnd.len()), (0, 0, 0, 0));
    }

    fn seed_pending(s: &VaultState, p: &std::path::Path) {
        s.with_lock(|g| {
            g.pending_csv_import = Some(PendingCsvImport {
                token: "synthetic-token".into(),
                parsed: csv_import::parse_import_csv(
                    "site,account,password,notes\nexample,synthetic,fixture,\n",
                )
                .unwrap(),
                entries_fingerprint: [0; 32],
            });
            g.dual_pending = Some(vault::DualPending::for_test(
                p.to_path_buf(),
                std::time::Instant::now(),
            ));
            Ok(())
        })
        .unwrap();
    }

    #[test]
    fn wh_d5_login_publishes_and_clears_pending_under_one_lock() {
        let p = fixture();
        let mut b = Recording::new();
        let mut v = vault::Vault::create_for(&p, "synthetic-D5-password", edition::Edition::Single)
            .unwrap();
        assert!(v
            .add_entry("synthetic-site", "synthetic-account", "synthetic-entry", "")
            .is_ok());
        assert!(v
            .register_windows_hello(&mut b.mock, "SYNTHETIC", edition::Edition::Single)
            .is_ok());
        v.lock();
        let (s, c) = state(None, b);
        seed_pending(&s, &p);
        let result = login_windows_hello_inner(&s, &p, edition::Edition::Single, |required| {
            assert!(required);
            assert!(matches!(
                s.0.try_lock(),
                Err(std::sync::TryLockError::WouldBlock)
            ));
            Ok(456)
        });
        assert!(result.is_ok(), "successful D4 login must publish entries");
        assert_eq!(result.unwrap().len(), 1);
        s.with_lock(|g| {
            assert!(g.vault.is_some());
            assert!(g.pending_csv_import.is_none() && g.dual_pending.is_none());
            assert_eq!(g.vault.as_ref().unwrap().entries().len(), 1);
            Ok(())
        })
        .unwrap();
        let c = c.lock().unwrap();
        assert_eq!((c.create, c.assert, c.delete), (0, 1, 0));
        assert_eq!(c.hwnd, vec![456]);
    }

    #[test]
    fn wh_d5_register_unavailable_refuses_before_focus() {
        for status in [
            PlatformStatus {
                api_ok: false,
                uvpa: true,
                console: true,
            },
            PlatformStatus {
                api_ok: true,
                uvpa: false,
                console: true,
            },
            PlatformStatus {
                api_ok: true,
                uvpa: true,
                console: false,
            },
        ] {
            let p = fixture();
            let v = vault::Vault::create_for(&p, "synthetic-D5-password", edition::Edition::Single)
                .unwrap();
            let before = std::fs::read(&p).unwrap();
            let mut b = Recording::new();
            b.status = status;
            let (s, c) = state(Some(v), b);
            let mut focus = 0;
            let result = register_windows_hello_inner(
                &s,
                edition::Edition::Single,
                |_| {
                    focus += 1;
                    Ok(123)
                },
                || Ok("SYNTHETIC".into()),
            );
            assert!(result.is_err(), "unavailable must refuse");
            assert_eq!(focus, 0, "refusal must not activate window");
            let error = result.err().unwrap();
            assert!(
                error.contains("Console")
                    && error.contains("v8")
                    && error.contains("YubiKey")
                    && error.contains("主密碼")
            );
            let c = c.lock().unwrap();
            assert_eq!(
                (c.list, c.create, c.assert, c.delete, c.hwnd.len()),
                (0, 0, 0, 0, 0)
            );
            assert_eq!(std::fs::read(&p).unwrap(), before);
        }
    }

    #[test]
    fn wh_d5_register_happy_uses_live_hwnd_and_d4() {
        let p = fixture();
        let v = vault::Vault::create_for(&p, "synthetic-D5-password", edition::Edition::Single)
            .unwrap();
        let (s, c) = state(Some(v), Recording::new());
        let mut focus = 0;
        let result = register_windows_hello_inner(
            &s,
            edition::Edition::Single,
            |required| {
                assert!(required);
                focus += 1;
                Ok(123)
            },
            || Ok("TRUSTED-SYNTHETIC".into()),
        );
        assert!(result.is_ok(), "registration should succeed");
        let reg = result.unwrap();
        assert_eq!(focus, 1);
        let h = vault::Vault::read_header(&p, edition::Edition::Single).unwrap();
        assert_eq!(h.key_slots.len(), 1);
        assert_eq!(
            h.key_slots[0].label,
            "Windows Hello（本機 TRUSTED-SYNTHETIC）"
        );
        assert_eq!(
            h.key_slots[0].credential_id,
            crypto::base64_encode(&reg.credential_id)
        );
        let json = serde_json::to_value(&reg).unwrap();
        assert!(json.get("creation_prf").is_none() && json.get("secret").is_none());
        let c = c.lock().unwrap();
        assert_eq!((c.create, c.assert, c.delete), (1, 1, 0));
        assert_eq!(c.hwnd, vec![123]);
    }

    #[test]
    fn wh_d5_status_locked_local_intersection_is_readonly() {
        let p = fixture();
        let mut b = Recording::new();
        let mut v = vault::Vault::create_for(&p, "synthetic-D5-password", edition::Edition::Single)
            .unwrap();
        let reg = v.register_windows_hello(&mut b.mock, "SYNTHETIC", edition::Edition::Single);
        assert!(reg.is_ok());
        v.lock();
        let before = std::fs::read(&p).unwrap();
        let (s, c) = state(None, b);
        let result = query_platform_status(&s, &p, edition::Edition::Single);
        assert!(result.is_ok());
        let info = result.unwrap();
        assert!(info.api_ok && info.uvpa && info.console && info.local_credential);
        assert_eq!(std::fs::read(&p).unwrap(), before);
        let json = serde_json::to_value(info).unwrap();
        assert_eq!(json.as_object().unwrap().len(), 4);
        let c = c.lock().unwrap();
        assert!(c.list > 0);
        assert_eq!((c.create, c.assert, c.delete, c.hwnd.len()), (0, 0, 0, 0));
    }
}

#[cfg(test)]
mod key_info_tests {
    use super::*;

    pub(super) fn header_json(v: u8, slots: serde_json::Value) -> vault::Header {
        let mut h = serde_json::json!({
            "v": v,
            "argon2": {"salt": "c2FsdA=="},
            "password_slot": {"nonce": "bm9uY2U=", "ct": "Y3Q="},
            "key_slots": slots,
            "created_at": "2026-10-11T00:00:00Z"
        });
        if v == 2 {
            h["policy"] = serde_json::json!("dual");
            h["dual_slot"] = serde_json::json!({"nonce": "bm9uY2U=", "ct": "Y3Q="});
            h["dual_step_timeout_secs"] = serde_json::json!(120);
        }
        serde_json::from_value(h).unwrap()
    }

    pub(super) fn slot(id: &str, group: Option<&str>) -> serde_json::Value {
        let mut s = serde_json::json!({
            "credential_id": id, "aaguid": "00", "label": id,
            "key_type": "touch_only", "nonce": "bm9uY2U=", "ct": "Y3Q="
        });
        if let Some(g) = group {
            s["group"] = serde_json::json!(g);
        }
        s
    }

    #[test]
    fn dual_key_infos_carry_group_and_last_in_group() {
        let h = header_json(
            2,
            serde_json::json!([
                slot("a1", Some("A")),
                slot("a2", Some("A")),
                slot("b1", Some("B"))
            ]),
        );
        let infos = key_infos(&h);
        let view: Vec<(Option<crypto::KeyGroup>, bool)> =
            infos.iter().map(|k| (k.group, k.last_in_group)).collect();
        assert_eq!(
            view,
            vec![
                (Some(crypto::KeyGroup::A), false),
                (Some(crypto::KeyGroup::A), false),
                (Some(crypto::KeyGroup::B), true),
            ]
        );
        let json = serde_json::to_value(&infos).unwrap();
        assert_eq!(json[0]["group"], "A");
        assert_eq!(json[2]["last_in_group"], true);
        assert!(json[0].get("last_in_group").is_none());
    }

    #[test]
    fn wh_d6_key_info_marks_explicit_and_verified_local_platform_without_changing_roaming_json() {
        let mut explicit = slot("b25l", None);
        explicit["authenticator"] = serde_json::json!("platform");
        let h = header_json(
            1,
            serde_json::json!([explicit, slot("dHdv", None), slot("Zm9yZWlnbg==", None)]),
        );
        let infos = key_infos_with_local(&h, Some(&[b"two".to_vec()]));
        let json = serde_json::to_value(infos).unwrap();
        assert_eq!(json[0]["authenticator"], "platform");
        assert_eq!(json[0]["platform_local"], false);
        assert_eq!(json[1]["authenticator"], "platform");
        assert_eq!(json[1]["platform_local"], true);
        assert!(json[2].get("platform_local").is_none());
        let unknown = serde_json::to_value(key_infos_with_local(&h, None)).unwrap();
        assert_eq!(unknown[0]["authenticator"], "platform");
        assert!(unknown[0].get("platform_local").is_none());
        assert!(json[2].get("authenticator").is_none());
        assert!(serde_json::to_value(key_infos(&header_json(
            1,
            serde_json::json!([slot("b25l", None)])
        )))
        .unwrap()[0]
            .get("authenticator")
            .is_none());
    }

    #[test]
    fn single_key_infos_json_shape_is_unchanged() {
        let h = header_json(1, serde_json::json!([slot("s1", None)]));
        let json = serde_json::to_value(key_infos(&h)).unwrap();
        let mut keys: Vec<&str> = json[0]
            .as_object()
            .unwrap()
            .keys()
            .map(|k| k.as_str())
            .collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            vec!["credential_id", "key_type", "label", "prompt_zh"]
        );
    }
}

#[cfg(test)]
mod d8_list_review_tests {
    use super::*;

    #[test]
    fn d8_key_list_values_order_and_duplicate_hint_match_actual_target() {
        let mut h = key_info_tests::header_json(2, serde_json::json!([]));
        assert!(key_infos(&h).is_empty());
        for slots in [
            serde_json::json!([key_info_tests::slot("a1", Some("A"))]),
            serde_json::json!([key_info_tests::slot("b1", Some("B"))]),
            serde_json::json!([
                key_info_tests::slot("dup", Some("A")),
                key_info_tests::slot("dup", Some("B")),
                key_info_tests::slot("b2", Some("B"))
            ]),
            serde_json::json!([
                key_info_tests::slot("dup", Some("A")),
                key_info_tests::slot("dup", Some("A"))
            ]),
        ] {
            h = key_info_tests::header_json(2, slots);
            assert!(vault::check_header_edition(&h, edition::Edition::Dual).is_ok());
            let infos = key_infos(&h);
            assert_eq!(infos.len(), h.key_slots.len());
            for (info, slot) in infos.iter().zip(&h.key_slots) {
                assert_eq!(info.credential_id, slot.credential_id);
                assert_eq!(info.label, slot.label);
                assert_eq!(info.key_type, slot.key_type);
                assert_eq!(info.prompt_zh, slot.key_type.prompt_zh());
                assert_eq!(info.group, slot.group);
                // A hint describes the actual first-match credential removal, not this row's group.
                assert_eq!(
                    info.last_in_group,
                    vault::last_key_in_group(&h, &slot.credential_id).is_some()
                );
            }
            if h.key_slots.len() == 3 {
                assert!(infos[0].last_in_group && infos[1].last_in_group);
                assert!(!infos[2].last_in_group);
            }
            let converted: Vec<KeyInfo> = (&h).into();
            assert_eq!(
                serde_json::to_value(converted).unwrap(),
                serde_json::to_value(infos).unwrap()
            );
        }
        let single = key_info_tests::header_json(
            1,
            serde_json::json!([
                key_info_tests::slot("s1", None),
                key_info_tests::slot("s2", None)
            ]),
        );
        let infos = key_infos(&single);
        for (info, slot) in infos.iter().zip(&single.key_slots) {
            assert_eq!(info.credential_id, slot.credential_id);
            assert_eq!(info.label, slot.label);
            assert_eq!(info.key_type, slot.key_type);
            assert_eq!(info.prompt_zh, slot.key_type.prompt_zh());
            assert!(info.group.is_none() && !info.last_in_group);
        }
    }

    #[test]
    fn d8_file_reader_and_unlocked_header_conversion_agree() {
        let d = std::env::temp_dir().join(format!("f2v-d8-list-review-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        let p = d.join("vault.db");
        // Synthetic fixture only; never target an existing file.
        assert!(!p.exists());
        let ed = edition::current();
        let mut v = vault::Vault::create_for(&p, "D8-Synthetic-Pw", ed).unwrap();
        for (label, group) in [("a", crypto::KeyGroup::A), ("b", crypto::KeyGroup::B)] {
            let mut backend = MockBackend::new();
            let group = (ed == edition::Edition::Dual).then_some(group);
            assert!(v.register_key_for(&mut backend, None, label, group).is_ok());
        }
        let h = v.lock();
        let expected: Vec<KeyInfo> = (&h).into();
        assert_eq!(
            serde_json::to_value(read_keys_from_file(&p).unwrap()).unwrap(),
            serde_json::to_value(expected).unwrap()
        );
        std::fs::remove_file(&p).unwrap();
    }
}

#[cfg(test)]
mod dual_pending_sweep_tests {
    use super::*;
    use std::time::{Duration, Instant};

    fn inner_with(pending: Option<vault::DualPending>, generation: u64) -> AppInner {
        AppInner {
            vault: None,
            backend: Box::new(MockBackend::new()),
            pending_csv_import: None,
            dual_pending: pending,
            dual_generation: generation,
        }
    }

    fn sidecar_path(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("f2v-lib-{tag}-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&d);
        let p = d.join("vault.db");
        let _ = std::fs::remove_file(vault::failures_path(&p));
        p
    }

    #[test]
    fn sweep_clears_expired_pending_of_same_generation() {
        let p = sidecar_path("sweep-expired");
        let t0 = Instant::now();
        let mut g = inner_with(Some(vault::DualPending::for_test(p.clone(), t0)), 3);
        assert!(sweep_expired_dual(&mut g, 3, t0 + Duration::from_secs(1)));
        assert!(g.dual_pending.is_none());
        let text = std::fs::read_to_string(vault::failures_path(&p)).unwrap();
        assert!(text.contains("fido2-dual-timeout"), "{text}");
    }

    #[test]
    fn sweep_keeps_pending_that_is_not_expired() {
        let p = sidecar_path("sweep-live");
        let t0 = Instant::now();
        let mut g = inner_with(
            Some(vault::DualPending::for_test(
                p.clone(),
                t0 + Duration::from_secs(60),
            )),
            3,
        );
        assert!(!sweep_expired_dual(&mut g, 3, t0));
        assert!(g.dual_pending.is_some());
        assert!(!vault::failures_path(&p).exists());
    }

    #[test]
    fn sweep_ignores_newer_generation() {
        let p = sidecar_path("sweep-newer");
        let t0 = Instant::now();
        let mut g = inner_with(Some(vault::DualPending::for_test(p.clone(), t0)), 4);
        assert!(!sweep_expired_dual(&mut g, 3, t0 + Duration::from_secs(1)));
        assert!(g.dual_pending.is_some());
    }
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

#[cfg(test)]
mod d9_settings_ipc_tests {
    use super::*;

    fn state(vault: Option<vault::Vault>) -> VaultState {
        VaultState(Mutex::new(AppInner {
            vault,
            backend: Box::new(fido2::UnavailableBackend::new(3)),
            pending_csv_import: None,
            dual_pending: None,
            dual_generation: 0,
        }))
    }

    #[test]
    fn d9_ipc_locked_session_refuses_without_accessing_settings() {
        let state = state(None);
        assert_eq!(
            update_dual_step_timeout(&state, 60).unwrap_err(),
            "金庫未解鎖"
        );
        assert_eq!(
            update_dual_step_timeout(&state, 0).unwrap_err(),
            "金庫未解鎖"
        );
        state
            .with_lock(|g| {
                assert!(g.vault.is_none());
                Ok(())
            })
            .unwrap();
    }

    #[test]
    fn d9_ipc_unlocked_session_updates_and_core_checks_bounds() {
        let dir = std::env::var_os("TMPDIR")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(std::env::temp_dir);
        let p = dir.join(format!("d9-ipc-{}.db", rand::random::<u64>()));
        let state = state(Some(
            vault::Vault::create_dual(&p, "synthetic-d9-password").unwrap(),
        ));
        assert!(update_dual_step_timeout(&state, 60).is_ok());
        state
            .with_lock(|g| {
                assert_eq!(
                    g.vault.as_ref().unwrap().settings().dual_step_timeout_secs,
                    Some(60)
                );
                Ok(())
            })
            .unwrap();
        let before = std::fs::read(&p).unwrap();
        assert!(update_dual_step_timeout(&state, 0).is_err());
        assert!(std::fs::read(&p).unwrap() == before);
        assert_eq!(
            vault::Vault::read_header(&p, edition::Edition::Dual)
                .unwrap()
                .dual_step_timeout_secs,
            Some(60)
        );
    }

    #[test]
    fn d9_ipc_command_registered_and_uses_the_tested_unlocked_guard() {
        let source = include_str!("lib.rs");
        let commands = source
            .split(".invoke_handler(tauri::generate_handler![")
            .nth(1)
            .unwrap()
            .split("])")
            .next()
            .unwrap();
        assert!(commands
            .lines()
            .any(|l| l.trim() == "set_dual_step_timeout,"));
        // Split deliberately avoids finding this test itself as the command body.
        let marker = ["fn set_dual_step_", "timeout(state:"].concat();
        let body = source
            .split(&marker)
            .nth(1)
            .expect("Tauri setter exists")
            .split("#[tauri::command]")
            .next()
            .unwrap();
        assert!(body.contains("update_dual_step_timeout(&state, secs)"));
    }
}
