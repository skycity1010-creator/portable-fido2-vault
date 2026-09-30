//! Tauri 後端：VaultState（Mutex 包解鎖中的 Vault）＋ commands。
//! 前端純靜態（src/），透過 window.__TAURI__.core.invoke 呼叫。

use std::sync::Mutex;
use tauri::Manager;

#[cfg(feature = "mock-fido")]
use crate::fido2::MockBackend;
#[cfg(all(feature = "real-ctap", not(windows)))]
use crate::fido2::RealBackend;
#[cfg(all(feature = "real-ctap", windows))]
use crate::windows_webauthn::WindowsWebAuthnBackend;

pub mod crypto;
#[cfg(feature = "real-ctap")]
pub mod diag_log;
pub mod fido2;
#[cfg(all(windows, feature = "real-ctap"))]
mod windows_webauthn;
pub mod vault;

pub type Result<T> = std::result::Result<T, String>;

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
            "Release GUI build is missing the real-ctap feature; refusing to use MockBackend".into(),
        ),
        None if mock_compiled => Ok(BackendMode::Mock),
        None => Err("No FIDO backend is compiled; enable real-ctap or mock-fido".into()),
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
                Ok(Box::new(
                    WindowsWebAuthnBackend::new(window_handle).map_err(|e| e.to_string())?,
                ))
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

struct AppInner {
    vault: Option<vault::Vault>,
    backend: Box<dyn fido2::FidoBackend>,
}

impl AppInner {
    fn new(window_handle: isize) -> Result<Self> {
        Ok(Self {
            vault: None,
            backend: make_backend(window_handle)?,
        })
    }
}

impl VaultState {
    fn with_lock<R>(&self, f: impl FnOnce(&mut AppInner) -> Result<R>) -> Result<R> {
        let mut g = self.0.lock().map_err(|_| "state lock poisoned".to_string())?;
        f(&mut g)
    }
}

fn path_from_state_or_default() -> std::path::PathBuf {
    // portable：vault.db 與 exe 同資料夾。
    let exe = std::env::current_exe().unwrap_or_default();
    let dir = exe.parent().unwrap_or(std::path::Path::new("."));
    dir.join("vault.db")
}

// ─────────────────────────── commands ───────────────────────────

/// 啟動畫面資訊：是否有金庫、已註冊金鑰清單（供登入畫面）。
#[tauri::command]
fn boot_info(state: tauri::State<VaultState>) -> Result<LoginScreenInfo> {
    let path = path_from_state_or_default();
    let has_vault = path.exists();
    let keys = if has_vault { read_keys_from_file(&path)? } else { Vec::new() };
    let _ = state; // idle 設定需解鎖後才有意義；boot 時回預設 5
    Ok(LoginScreenInfo { has_vault, keys, idle_lock_minutes: 5 })
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
    state.with_lock(|g| { g.vault = Some(v); Ok(()) })?;
    Ok(entries)
}

/// FIDO2 金鑰登入。pin：PIN 型金鑰必填；其他類型忽略。
#[tauri::command]
fn login_key(state: tauri::State<VaultState>, credential_id: String, pin: Option<String>) -> Result<Vec<vault::Entry>> {
    let path = path_from_state_or_default();
    let v = state.with_lock(|g| {
        vault::Vault::open_key(&path, &credential_id, pin.as_deref(), g.backend.as_mut())
            .map_err(|e| e.to_string())
    })?;
    let entries = v.entries().to_vec();
    state.with_lock(|g| { g.vault = Some(v); Ok(()) })?;
    Ok(entries)
}

/// 上鎖（手動或閒置）。回傳登入畫面資訊。
#[tauri::command]
fn lock(state: tauri::State<VaultState>, reason: Option<String>) -> Result<LoginScreenInfo> {
    let header = state.with_lock(|g| {
        match g.vault.take() {
            Some(v) => Ok(if reason.as_deref() == Some("idle") { v.auto_lock() } else { v.lock() }),
            None => Err("尚未解鎖".to_string()),
        }
    })?;
    Ok(LoginScreenInfo { has_vault: true, keys: (&header).into(), idle_lock_minutes: 5 })
}

fn with_unlocked<R>(state: &VaultState, f: impl FnOnce(&mut vault::Vault) -> Result<R>) -> Result<R> {
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
) -> Result<()> {
    with_unlocked(&state, |v| {
        v.update_entry(&id, site.as_deref(), account.as_deref(), password.as_deref(), notes.as_deref())
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
fn register_key(state: tauri::State<VaultState>, pin: Option<String>) -> Result<fido2::RegisteredCredential> {
    // 同一後端實例內 detect+register → 類型一致。
    state.with_lock(|g| {
        match g.vault.as_mut() {
            Some(v) => v.register_key(g.backend.as_mut(), pin.as_deref()).map_err(|e| e.to_string()),
            None => Err("金庫未解鎖".to_string()),
        }
    })
}

#[tauri::command]
fn remove_key(state: tauri::State<VaultState>, credential_id: String) -> Result<()> {
    with_unlocked(&state, |v| v.remove_key(&credential_id).map_err(|e| e.to_string()))
}

#[tauri::command]
fn set_idle_lock(state: tauri::State<VaultState>, minutes: u32) -> Result<()> {
    with_unlocked(&state, |v| v.set_idle_lock(minutes).map_err(|e| e.to_string()))
}

/// 偵測金鑰（註冊前預覽：類型 + label）。**不消耗**後端狀態 → 與緊接的 register_key 一致。
#[tauri::command]
fn detect_key(state: tauri::State<VaultState>) -> Result<fido2::DetectedKey> {
    state.with_lock(|g| {
        let kind = g.backend.peek_kind();
        Ok(fido2::DetectedKey {
            kind,
            label: format!("偵測到金鑰（{}）", kind.label_zh()),
            aaguid: [0u8; 16], // 預覽不含金鑰實作細節
        })
    })
}

// ─────────────────────────── run ───────────────────────────

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    // 診斷 file logger（real-ctap）：GUI op 也落 fido2-diag.log → contention retry 可歸因。
    #[cfg(feature = "real-ctap")]
    diag_log::init();
    tauri::Builder::default()
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
                    "Main window HWND unavailable; WebAuthn prompt will use a null parent window"
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
            lock,
            list_entries,
            add_entry,
            update_entry,
            delete_entry,
            list_audit,
            register_key,
            remove_key,
            set_idle_lock,
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
