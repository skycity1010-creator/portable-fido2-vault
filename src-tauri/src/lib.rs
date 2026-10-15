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
mod registration_cleanup_journal;
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
    /// D9-F1：第二階段因前景未交回而暫停的註冊（只在 Rust 端，drop 時秘密清零）。
    pending_registration: Option<PendingRegistrationSlot>,
    /// 每次建立新的 pending 註冊遞增；逾時計時器只清除自己那一代。
    registration_generation: u64,
    /// 只保留非機密清理失敗收據；即使 timer 或上鎖取消 pending，警告也不會遺失。
    registration_cleanup_receipts: Vec<RegistrationCleanupReceipt>,
    registration_cleanup_journal: Option<registration_cleanup_journal::Journal>,
    registration_cleanup_storage_unavailable: bool,
    /// D9-F2：目前是否有金鑰操作（WebAuthn ceremony）進行中，及其間收到的上鎖要求。
    key_op: KeyOpState,
}

/// D9-F2：金鑰操作狀態機。`active` 與 `pending_lock` 只在 `VaultState` 的短暫鎖內讀寫；
/// 鎖不會跨 ceremony 持有，所以其他指令（含主執行緒）隨時可以讀到它而不被卡住。
#[derive(Default)]
struct KeyOpState {
    active: bool,
    /// ceremony 期間收到的上鎖要求（保留 reason）；ceremony 結束、回傳前才執行。
    pending_lock: Option<Option<String>>,
    /// Pending registrations taken out of the state that still have to be cancelled through the
    /// real backend. The cancellation (platform list/delete) runs by the operation that leases the
    /// backend, **outside** the state lock, so queries on the main thread never wait for it.
    cleanups: Vec<(PendingRegistrationSlot, &'static str)>,
}

/// 第二個金鑰操作被拒的訊息（不排隊、不碰前景、不呼叫 backend）。
const KEY_OPERATION_BUSY_MSG: &str = "已有金鑰操作進行中，請先完成或取消";
/// ceremony 期間收到上鎖要求時，該 ceremony 的回應（不含任何條目）。
const KEY_OPERATION_LOCKED_MSG: &str = "金鑰操作期間已收到上鎖要求，金庫已上鎖；請重新登入";
/// 已解鎖的金庫不接受新的金鑰登入（避免登入 ceremony 期間金庫仍可讀寫、結果又以舊快照覆寫）。
const VAULT_ALREADY_UNLOCKED_MSG: &str = "金庫已解鎖；請先上鎖後再以金鑰登入";

/// pending 註冊的有效期限；逾時視同取消（Windows Hello 會刪除本次 credential）。
const PENDING_REGISTRATION_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(120);

struct PendingRegistrationSlot {
    pending: vault::PendingRegistration,
    deadline: std::time::Instant,
    /// 建立 pending 時的金庫；繼續時金庫不同 → 取消，不寫入其他金庫。
    vault_path: std::path::PathBuf,
    generation: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
struct RegistrationCleanupReceipt {
    id: String,
    generation: u64,
    reason: &'static str,
    cleanup: RegistrationCleanup,
}

/// register_key / register_windows_hello / continue_registration 的回應（不含任何秘密）。
#[derive(Debug, serde::Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
enum RegisterResult {
    Registered {
        credential: fido2::RegisteredCredential,
    },
    HandoffRequired {
        message: String,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
enum RegistrationCleanup {
    Removed,
    ManualRemovalRequired,
    Discarded,
    None,
}

#[derive(Debug, serde::Serialize)]
struct CancelRegistrationInfo {
    status: &'static str,
    cleanup: RegistrationCleanup,
}

fn record_registration_cleanup(g: &mut AppInner, generation: u64, reason: &'static str) {
    let (id, effective_reason) = match g.registration_cleanup_journal.as_ref() {
        Some(journal) => match journal.record(reason) {
            Ok(id) => (id, reason),
            Err(_) => (format!("memory-{generation}"), "storage_unavailable"),
        },
        None => (format!("memory-{generation}"), reason),
    };
    g.registration_cleanup_receipts
        .push(RegistrationCleanupReceipt {
            id,
            generation,
            reason: effective_reason,
            cleanup: RegistrationCleanup::ManualRemovalRequired,
        });
}

/// Result of cancelling one pending registration through the real backend.
struct CancelledRegistration {
    generation: u64,
    reason: &'static str,
    cleanup: RegistrationCleanup,
}

/// Cancel one pending registration (Windows Hello: delete only after the RP list proves the
/// credential is local). Touches only the backend it is handed: callers run it **outside** the
/// state lock, then publish the receipt with `record_cancelled_registration`.
fn cancel_slot_with_backend(
    backend: &mut (dyn fido2::FidoBackend + 'static),
    slot: PendingRegistrationSlot,
    reason: &'static str,
) -> CancelledRegistration {
    let generation = slot.generation;
    let cleanup = match vault::cancel_registration(backend, slot.pending) {
        vault::CancelOutcome::Removed => RegistrationCleanup::Removed,
        vault::CancelOutcome::ManualRemovalRequired => RegistrationCleanup::ManualRemovalRequired,
        vault::CancelOutcome::Discarded => RegistrationCleanup::Discarded,
    };
    CancelledRegistration {
        generation,
        reason,
        cleanup,
    }
}

/// 失敗僅留非機密收據，直到使用者確認；秘密隨 pending drop 清零。
fn record_cancelled_registration(g: &mut AppInner, done: &CancelledRegistration) {
    if done.cleanup == RegistrationCleanup::ManualRemovalRequired {
        record_registration_cleanup(g, done.generation, done.reason);
    }
}

/// Take the pending registration out of the state so that the operation that owns the backend
/// lease cancels it (outside the lock) before it returns. The caller must hold such a lease.
fn queue_pending_cancellation(g: &mut AppInner, reason: &'static str) -> bool {
    match g.pending_registration.take() {
        Some(slot) => {
            g.key_op.cleanups.push((slot, reason));
            true
        }
        None => false,
    }
}

/// What a cancellation reports when nothing was pending: the unacknowledged durable warnings
/// (journal is authoritative; unreadable storage is conservatively a warning).
fn no_pending_cleanup_status(g: &mut AppInner) -> RegistrationCleanup {
    if has_unacknowledged_cleanup(g) {
        RegistrationCleanup::ManualRemovalRequired
    } else {
        RegistrationCleanup::None
    }
}

/// Take an expired pending registration (any generation when `generation` is `None`) out of the
/// state without touching the backend; the caller cancels it off-lock.
fn take_expired_registration(
    g: &mut AppInner,
    generation: Option<u64>,
    now: std::time::Instant,
) -> Option<PendingRegistrationSlot> {
    let expired = g.pending_registration.as_ref().is_some_and(|slot| {
        now >= slot.deadline && generation.is_none_or(|generation| generation == slot.generation)
    });
    if expired {
        g.pending_registration.take()
    } else {
        None
    }
}

/// Expiry timer. The cancellation (platform list/delete) happens outside the state lock; while a
/// key operation is active the backend is leased out, the timer is skipped and the operation's
/// completion performs the catch-up (see `KeyOperationGuard::finish`).
fn sweep_expired_registration_off_lock(
    state: &VaultState,
    generation: Option<u64>,
    now: std::time::Instant,
) -> bool {
    let Ok((guard, expired)) = KeyOperationGuard::begin_native(state, |g| {
        let expired = g.pending_registration.as_ref().is_some_and(|slot| {
            now >= slot.deadline
                && generation.is_none_or(|generation| generation == slot.generation)
        });
        if expired {
            queue_pending_cancellation(g, "expired");
        }
        Ok(expired)
    }) else {
        return false;
    };
    let _ = guard.complete(|_, _| Ok(()));
    expired
}

fn require_no_pending_registration(g: &AppInner) -> Result<()> {
    if g.pending_registration.is_some() {
        return Err(
            "已有尚未完成的金鑰註冊；請先按「繼續驗證」完成，或按「取消」放棄後再註冊。".into(),
        );
    }
    Ok(())
}

/// 依註冊結果建立 pending（若需要）並轉成 IPC 回應。
fn store_registration_outcome(
    g: &mut AppInner,
    outcome: vault::RegistrationOutcome,
    vault_path: std::path::PathBuf,
    now: std::time::Instant,
) -> RegisterResult {
    match outcome {
        vault::RegistrationOutcome::Registered(credential) => {
            RegisterResult::Registered { credential }
        }
        vault::RegistrationOutcome::HandoffRequired(pending) => {
            g.registration_generation = g.registration_generation.wrapping_add(1);
            g.pending_registration = Some(PendingRegistrationSlot {
                pending,
                deadline: now + PENDING_REGISTRATION_TIMEOUT,
                vault_path,
                generation: g.registration_generation,
            });
            RegisterResult::HandoffRequired {
                message: fido2::FidoError::ForegroundHandoffRequired.to_string(),
            }
        }
    }
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

/// Per-user receipt directory. A missing, empty or relative `LOCALAPPDATA` is not trusted
/// (it could resolve against the working directory); the UI then shows "storage unavailable".
fn cleanup_journal_from_local_appdata(
    local_appdata: Option<std::ffi::OsString>,
) -> (Option<registration_cleanup_journal::Journal>, bool) {
    match local_appdata.map(std::path::PathBuf::from) {
        Some(base) if base.is_absolute() => (
            Some(registration_cleanup_journal::Journal::new(
                base.join("FidoVault").join("registration-cleanup-v1"),
            )),
            false,
        ),
        _ => (None, true),
    }
}

impl AppInner {
    fn new(window_handle: isize) -> Result<Self> {
        let (journal, storage_unavailable) =
            cleanup_journal_from_local_appdata(std::env::var_os("LOCALAPPDATA"));
        Ok(Self {
            vault: None,
            backend: make_backend(window_handle)?,
            pending_csv_import: None,
            dual_pending: None,
            dual_generation: 0,
            pending_registration: None,
            registration_generation: 0,
            registration_cleanup_receipts: Vec::new(),
            registration_cleanup_journal: journal,
            registration_cleanup_storage_unavailable: storage_unavailable,
            key_op: KeyOpState::default(),
        })
    }
}

impl VaultState {
    fn with_lock<R>(&self, f: impl FnOnce(&mut AppInner) -> Result<R>) -> Result<R> {
        #[cfg(test)]
        let mut g = match self.0.try_lock() {
            Ok(g) => g,
            Err(std::sync::TryLockError::WouldBlock) => {
                // Test-only observation point: this thread is about to block on the state lock.
                lock_wait_hook::notify();
                self.0
                    .lock()
                    .map_err(|_| "state lock poisoned".to_string())?
            }
            Err(std::sync::TryLockError::Poisoned(_)) => {
                return Err("state lock poisoned".to_string())
            }
        };
        #[cfg(not(test))]
        let mut g = self
            .0
            .lock()
            .map_err(|_| "state lock poisoned".to_string())?;
        f(&mut g)
    }
}

/// D9-F2：ceremony 進行中占位的 backend。真正的 backend 被「租出」給進行中的金鑰操作，
/// 其他指令（含主執行緒指令）因此不必等待 ceremony 持有的鎖；任何動到 authenticator 的呼叫一律拒絕。
struct BusyBackend {
    brokered: bool,
}

fn busy_fido_error() -> fido2::FidoError {
    fido2::FidoError::Internal(KEY_OPERATION_BUSY_MSG.into())
}

impl fido2::FidoBackend for BusyBackend {
    fn detect(&mut self) -> std::result::Result<fido2::DetectedKey, fido2::FidoError> {
        Err(busy_fido_error())
    }

    fn register_credential(
        &mut self,
        _detected: &fido2::DetectedKey,
        _pin: Option<&str>,
    ) -> std::result::Result<fido2::RegisteredCredential, fido2::FidoError> {
        Err(busy_fido_error())
    }

    fn get_prf_secret(
        &mut self,
        _credential_id: &[u8],
        _pin: Option<&str>,
    ) -> std::result::Result<[u8; 32], fido2::FidoError> {
        Err(busy_fido_error())
    }

    fn uses_brokered_key_selection(&self) -> bool {
        self.brokered
    }

    fn key_unavailable_reason(&self) -> Option<String> {
        Some(KEY_OPERATION_BUSY_MSG.into())
    }
}

fn lock_state_tolerant(state: &VaultState) -> std::sync::MutexGuard<'_, AppInner> {
    // A panicking ceremony must still be able to release its operation; never deadlock on poison.
    state.0.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// D9-F2：程序級（每個 `VaultState`）單一進行中的金鑰操作。每個 WebAuthn 指令在任何前景／backend
/// 動作前呼叫 `begin*`；已有進行中操作時立即回 `KEY_OPERATION_BUSY_MSG`（不排隊）。
///
/// `begin*` 在短暫的狀態鎖內檢查、占用並把 backend（及需要時的金庫）租出，之後 ceremony 與所有
/// native 呼叫（WebAuthn、平台清單／刪除、IsUVPAA）都在 **不持有狀態鎖** 的情況下執行。`complete`
/// 重新取鎖、歸還金庫、套用結果；ceremony 期間收到的上鎖要求、逾時的 pending 註冊與排入佇列的
/// pending 取消，一律在鎖外以租出的 backend 完成，最後才歸還 backend 並釋放。Drop（錯誤、panic、
/// 提前返回）走同一條收尾流程（fail closed）。
struct KeyOperationGuard<'a> {
    state: &'a VaultState,
    backend: Option<Box<dyn fido2::FidoBackend>>,
    vault: Option<vault::Vault>,
    done: bool,
}

impl<'a> KeyOperationGuard<'a> {
    /// A key operation that leases the backend and, when `lease_vault`, the unlocked vault.
    fn begin<P>(
        state: &'a VaultState,
        lease_vault: bool,
        prepare: impl FnOnce(&mut AppInner) -> Result<P>,
    ) -> Result<(Self, P)> {
        Self::begin_with(state, lease_vault, false, prepare)
    }

    /// A key **login**: refused while a vault is already unlocked, so no vault can be read or
    /// written during the ceremony and no stale snapshot can later replace newer data.
    fn begin_login<P>(
        state: &'a VaultState,
        prepare: impl FnOnce(&mut AppInner) -> Result<P>,
    ) -> Result<(Self, P)> {
        Self::begin_with(state, false, true, prepare)
    }

    /// Leases only the backend: used for any work that calls native APIs (status, list, delete,
    /// password login/creation with platform repair) so it never runs under the state lock.
    fn begin_native<P>(
        state: &'a VaultState,
        prepare: impl FnOnce(&mut AppInner) -> Result<P>,
    ) -> Result<(Self, P)> {
        Self::begin_with(state, false, false, prepare)
    }

    fn begin_with<P>(
        state: &'a VaultState,
        lease_vault: bool,
        reject_unlocked: bool,
        prepare: impl FnOnce(&mut AppInner) -> Result<P>,
    ) -> Result<(Self, P)> {
        state.with_lock(|g| {
            if g.key_op.active {
                return Err(KEY_OPERATION_BUSY_MSG.to_string());
            }
            if reject_unlocked && g.vault.is_some() {
                return Err(VAULT_ALREADY_UNLOCKED_MSG.to_string());
            }
            let prepared = prepare(g)?;
            Ok((Self::lease(state, g, lease_vault), prepared))
        })
    }

    /// Mark the operation active and lease the backend (and vault) out of the locked state.
    fn lease(state: &'a VaultState, g: &mut AppInner, lease_vault: bool) -> Self {
        g.key_op.active = true;
        g.key_op.pending_lock = None;
        let brokered = g.backend.uses_brokered_key_selection();
        let backend = std::mem::replace(&mut g.backend, Box::new(BusyBackend { brokered }));
        let vault = if lease_vault { g.vault.take() } else { None };
        Self {
            state,
            backend: Some(backend),
            vault,
            done: false,
        }
    }

    /// The leased backend and (when leased) the unlocked vault, for use outside the state lock.
    fn parts(&mut self) -> (&mut (dyn fido2::FidoBackend + 'static), Option<&mut vault::Vault>) {
        (
            self.backend
                .as_deref_mut()
                .expect("backend is leased while the operation is active"),
            self.vault.as_mut(),
        )
    }

    /// Briefly take the state lock (the backend stays leased) to read or take state.
    fn with_state<R>(&mut self, f: impl FnOnce(&mut AppInner) -> R) -> R {
        let mut g = lock_state_tolerant(self.state);
        f(&mut g)
    }

    /// Cancel a pending registration through the leased backend **outside** the state lock, then
    /// publish its receipt (if any) under a short lock.
    fn cancel_off_lock(
        &mut self,
        slot: PendingRegistrationSlot,
        reason: &'static str,
    ) -> RegistrationCleanup {
        let done = self.cancel_slots_off_lock(vec![(slot, reason)]).remove(0);
        self.with_state(|g| record_cancelled_registration(g, &done));
        done.cleanup
    }

    fn cancel_slots_off_lock(
        &mut self,
        jobs: Vec<(PendingRegistrationSlot, &'static str)>,
    ) -> Vec<CancelledRegistration> {
        jobs.into_iter()
            .map(|(slot, reason)| {
                let generation = slot.generation;
                let backend = self.backend.as_deref_mut();
                let attempt = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    backend.map(|backend| cancel_slot_with_backend(backend, slot, reason))
                }));
                match attempt {
                    Ok(Some(done)) => done,
                    // A panicking or missing backend: fail closed with a durable warning.
                    _ => CancelledRegistration {
                        generation,
                        reason,
                        cleanup: RegistrationCleanup::ManualRemovalRequired,
                    },
                }
            })
            .collect()
    }

    /// Work that must follow an operation: a lock request that arrived meanwhile, a pending
    /// registration whose deadline passed while the one-shot timer was skipped (the backend was
    /// leased), and every queued cancellation. Runs under the state lock but only *moves* things
    /// (no native call); the returned cancellations are executed outside the lock.
    fn follow_up_work(g: &mut AppInner) -> Vec<(PendingRegistrationSlot, &'static str)> {
        if let Some(reason) = g.key_op.pending_lock.take() {
            let _ = lock_locked(g, reason.as_deref());
        } else if let Some(slot) = take_expired_registration(g, None, std::time::Instant::now()) {
            g.key_op.cleanups.push((slot, "expired"));
        }
        std::mem::take(&mut g.key_op.cleanups)
    }

    /// Return the vault, publish the result (`publish` gets whether a lock request arrived during
    /// the operation), run the follow-up work, then give the backend back and release.
    fn finish<R>(
        &mut self,
        publish: Option<impl FnOnce(&mut AppInner, bool) -> Result<R>>,
        discard_login_on_late_lock: bool,
        after_first_lock: impl FnOnce(),
    ) -> Option<Result<R>> {
        if self.done {
            return None;
        }
        let mut result = None;
        // follow_up_work consumes pending_lock. Retain a local sticky observation until the
        // response is finalized: a lock during native cleanup must invalidate login entries.
        let mut lock_requested = false;
        let mut jobs = {
            let mut g = lock_state_tolerant(self.state);
            if let Some(vault) = self.vault.take() {
                // The lock is only deferred, never dropped, while leased: nothing else may fill it.
                if g.vault.is_none() {
                    g.vault = Some(vault);
                }
            }
            let deferred_lock = g.key_op.pending_lock.is_some();
            lock_requested |= deferred_lock;
            if let Some(publish) = publish {
                result = Some(publish(&mut g, deferred_lock));
            }
            Self::follow_up_work(&mut g)
        };
        // The real caller passes a no-op; the test seam deterministically exercises a lock
        // arriving even when no native cleanup jobs were queued.
        after_first_lock();
        loop {
            let finished = self.cancel_slots_off_lock(jobs);
            let mut g = lock_state_tolerant(self.state);
            for done in &finished {
                record_cancelled_registration(&mut g, done);
            }
            lock_requested |= g.key_op.pending_lock.is_some();
            jobs = Self::follow_up_work(&mut g);
            if jobs.is_empty() {
                // This decision and active=false share the final short lock. Drop any prepared
                // secret-bearing response if lock was requested at ANY point in the operation.
                if discard_login_on_late_lock && lock_requested {
                    result = Some(Err(KEY_OPERATION_LOCKED_MSG.to_string()));
                }
                if let Some(backend) = self.backend.take() {
                    g.backend = backend;
                }
                g.key_op.active = false;
                self.done = true;
                break;
            }
        }
        result
    }

    fn complete<R>(mut self, f: impl FnOnce(&mut AppInner, bool) -> Result<R>) -> Result<R> {
        self.finish(Some(f), false, || {})
            .expect("a guard is completed exactly once")
    }

    fn complete_login(
        mut self,
        opened: Result<vault::Vault>,
        reset: impl FnOnce(&mut AppInner),
    ) -> Result<Vec<vault::Entry>> {
        self.finish(Some(|g: &mut AppInner, deferred_lock| {
            publish_login(g, opened, deferred_lock, reset)
        }), true, || {})
            .expect("a guard is completed exactly once")
    }
}

impl Drop for KeyOperationGuard<'_> {
    fn drop(&mut self) {
        if self.done {
            return;
        }
        // Panic / early return: same fail-closed epilogue, and never panic out of Drop.
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            self.finish(None::<fn(&mut AppInner, bool) -> Result<()>>, false, || {})
        }));
        if !self.done {
            let mut g = lock_state_tolerant(self.state);
            if let Some(backend) = self.backend.take() {
                g.backend = backend;
            }
            g.key_op.active = false;
            self.done = true;
        }
    }
}

/// Publish a freshly opened vault (login result) unless a lock request arrived meanwhile.
fn publish_login(
    g: &mut AppInner,
    opened: Result<vault::Vault>,
    deferred_lock: bool,
    reset: impl FnOnce(&mut AppInner),
) -> Result<Vec<vault::Entry>> {
    let v = opened?;
    if deferred_lock {
        // The user asked to lock while the key prompt was open: discard the unlock.
        drop(v.lock());
        return Err(KEY_OPERATION_LOCKED_MSG.to_string());
    }
    let entries = v.entries().to_vec();
    reset(g);
    queue_pending_cancellation(g, "implicit");
    g.vault = Some(v);
    Ok(entries)
}

fn require_key_operation_idle(g: &AppInner) -> Result<()> {
    if g.key_op.active {
        return Err(KEY_OPERATION_BUSY_MSG.to_string());
    }
    Ok(())
}

/// Every read or write of the unlocked vault goes through this check first: nothing may be read
/// or changed while a key operation runs, nor after a lock request has been recorded.
fn require_vault_readable(g: &AppInner) -> Result<()> {
    if g.key_op.active {
        return Err(KEY_OPERATION_BUSY_MSG.to_string());
    }
    if g.key_op.pending_lock.is_some() {
        return Err(KEY_OPERATION_LOCKED_MSG.to_string());
    }
    Ok(())
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
#[tauri::command(async)]
fn boot_info(state: tauri::State<VaultState>) -> Result<LoginScreenInfo> {
    boot_info_inner(&state, &path_from_state_or_default(), edition::current())
}

fn boot_info_inner(
    state: &VaultState,
    path: &std::path::Path,
    ed: edition::Edition,
) -> Result<LoginScreenInfo> {
    let has_vault = path.exists();
    let keys = if has_vault && ed == edition::Edition::Single {
        let h = vault::Vault::read_header(path, edition::Edition::Single)
            .map_err(|e| e.to_string())?;
        // RP-local discovery is read-only and runs on the leased backend, outside the state lock.
        // Failure (or a busy backend) must not prevent password login.
        let local = match KeyOperationGuard::begin_native(state, |_| Ok(())) {
            Ok((mut guard, ())) => {
                let local = {
                    let (backend, _) = guard.parts();
                    if backend.platform_status().available() {
                        backend.list_platform_credentials().ok()
                    } else {
                        None
                    }
                };
                let _ = guard.complete(|_, _| Ok(()));
                local
            }
            Err(_) => None,
        };
        key_infos_with_local(&h, local.as_deref())
    } else if has_vault {
        read_keys_from_file(path)?
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
    // The header read is plain file I/O under the short lock; every native call (IsUVPAA, session
    // queries, RP-scoped credential listing) runs on the leased backend with the lock released.
    let (mut guard, header) = KeyOperationGuard::begin_native(state, |g| {
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
        Ok(header)
    })?;
    let info = (|| -> Result<PlatformStatusInfo> {
        let (backend, _) = guard.parts();
        let status = backend.platform_status();
        let mut local_credential = false;
        if status.available() {
            if let Some(h) = header {
                // RP-scoped membership also recognizes R3 marker-lost slots.
                // This is a query only: do not repair or persist the header here.
                let local = backend.list_platform_credentials().map_err(|e| e.to_string())?;
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
    })();
    guard.complete(|_, _| info)
}

fn require_windows_hello_single(ed: edition::Edition) -> Result<()> {
    if ed != edition::Edition::Single {
        return Err("Windows Hello 僅支援單人版；請使用 YubiKey 或主密碼".into());
    }
    Ok(())
}

#[tauri::command(async)]
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
) -> Result<RegisterResult> {
    register_windows_hello_inner_with_clock(
        state,
        ed,
        raise,
        computer_name,
        std::time::Instant::now,
    )
}

fn register_windows_hello_inner_with_clock(
    state: &VaultState,
    ed: edition::Edition,
    raise: impl FnOnce(bool) -> Result<isize>,
    computer_name: impl FnOnce() -> Result<String>,
    mut clock: impl FnMut() -> std::time::Instant,
) -> Result<RegisterResult> {
    require_windows_hello_single(ed)?;
    let (mut guard, stale) = KeyOperationGuard::begin(state, true, |g| {
        if g.vault.is_none() {
            return Err("金庫未解鎖".to_string());
        }
        let now = clock();
        // An expired pending is taken out here and cancelled off-lock below.
        let stale = take_expired_registration(g, None, now);
        require_no_pending_registration(g)?;
        Ok(stale)
    })?;
    // From here on the state lock is not held: the WebAuthn call may block for a long time.
    let ceremony = (|| -> Result<_> {
        if let Some(slot) = stale {
            guard.cancel_off_lock(slot, "expired");
        }
        require_windows_hello_available(&*guard.parts().0)?;
        let name = computer_name()?;
        let owner = raise(true)?;
        let (backend, vault) = guard.parts();
        backend.set_webauthn_parent_hwnd(owner);
        let v = vault.ok_or_else(|| "金庫未解鎖".to_string())?;
        let vault_path = v.path.clone();
        let outcome = v.begin_register_windows_hello(backend, &name, ed);
        let cleanup_report = v.take_registration_cleanup_report();
        Ok((vault_path, outcome, cleanup_report))
    })();
    guard.complete(|g, deferred_lock| {
        let (vault_path, outcome, cleanup_report) = ceremony?;
        let outcome = match outcome {
            Ok(outcome) => outcome,
            Err(error) => {
                g.registration_generation = g.registration_generation.wrapping_add(1);
                let generation = g.registration_generation;
                record_registration_failure_cleanup(g, generation, cleanup_report);
                return Err(error.to_string());
            }
        };
        // 註冊第一階段可能等待使用者操作；pending 的完整期限從返回後起算。
        let result = store_registration_outcome(g, outcome, vault_path, clock());
        if deferred_lock && matches!(result, RegisterResult::HandoffRequired { .. }) {
            // The deferred lock cancels the pending registration right after this returns.
            return Err(KEY_OPERATION_LOCKED_MSG.to_string());
        }
        Ok(result)
    })
}

#[tauri::command(async)]
fn register_windows_hello(
    window: tauri::WebviewWindow,
    state: tauri::State<VaultState>,
) -> Result<RegisterResult> {
    let result = register_windows_hello_inner(
        &state,
        edition::current(),
        |required| raise_key_operation_window(&window, required),
        || {
            std::env::var("COMPUTERNAME")
                .map_err(|_| "無法取得本機電腦名稱；請使用 YubiKey 或主密碼".to_string())
        },
    )?;
    schedule_registration_sweep(&window, &state, &result);
    Ok(result)
}

/// 新建立的 pending 註冊：Rust 端在期限後主動取消（不依賴前端），秘密清零。
fn schedule_registration_sweep(
    window: &tauri::WebviewWindow,
    state: &VaultState,
    result: &RegisterResult,
) {
    if !matches!(result, RegisterResult::HandoffRequired { .. }) {
        return;
    }
    let Ok(Some((generation, deadline))) = state.with_lock(|g| {
        Ok(g.pending_registration
            .as_ref()
            .map(|slot| (slot.generation, slot.deadline)))
    }) else {
        return;
    };
    let app = window.app_handle().clone();
    std::thread::spawn(move || {
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        std::thread::sleep(remaining + std::time::Duration::from_millis(250));
        let state = app.state::<VaultState>();
        sweep_expired_registration_off_lock(&state, Some(generation), std::time::Instant::now());
    });
}

/// The vault layer separately reports deletion failure for a proven newly-created
/// platform credential without replacing the primary error or inferring from generic FIDO errors.
fn record_registration_failure_cleanup(
    g: &mut AppInner,
    generation: u64,
    report: Option<vault::RegistrationCleanupReport>,
) {
    match report {
        Some(vault::RegistrationCleanupReport::DeleteFailed) => {
            record_registration_cleanup(g, generation, "continue_error")
        }
        Some(vault::RegistrationCleanupReport::NotAttempted) => {
            record_registration_cleanup(g, generation, "unverified")
        }
        Some(vault::RegistrationCleanupReport::Removed) | None => {}
    }
}

/// D9-F1：使用者按「繼續驗證」。點擊本身讓 FidoVault 成為前景；與註冊相同先確認 live HWND
/// 為前景，再以全新一般斷言完成 pending 註冊（不放寬任何守門）。
fn continue_registration_inner(
    state: &VaultState,
    ed: edition::Edition,
    raise: impl FnOnce(bool) -> Result<isize>,
    mut clock: impl FnMut() -> std::time::Instant,
) -> Result<RegisterResult> {
    let (mut guard, expired_at_start) = KeyOperationGuard::begin(state, true, |g| {
        let Some(vault_path) = g.vault.as_ref().map(|v| v.path.clone()) else {
            return Err("金庫未解鎖".to_string());
        };
        let Some(slot) = g.pending_registration.as_ref() else {
            return Err(if !has_unacknowledged_cleanup(g) {
                "沒有待完成的金鑰註冊；請重新註冊".to_string()
            } else {
                "沒有待完成的金鑰註冊；本次建立的 Windows Hello 憑證未能自動刪除，請到「設定 → 帳戶 → 通行金鑰」只刪除本次測試項目。".to_string()
            });
        };
        if clock() >= slot.deadline || slot.vault_path != vault_path {
            // Cancelled below, by the operation that owns the backend lease (outside the lock).
            return Ok(true);
        }
        if slot.pending.is_platform() {
            require_windows_hello_single(ed)?;
        }
        Ok(false)
    })?;
    // The state lock is not held while the foreground is confirmed or the assertion runs.
    let ceremony = (|| -> Result<_> {
        if expired_at_start {
            let slot = guard.with_state(|g| g.pending_registration.take());
            let cleanup = match slot {
                Some(slot) => guard.cancel_off_lock(slot, "implicit"),
                None => RegistrationCleanup::None,
            };
            return Err(format!(
                "註冊確認已逾時或金庫已變更，已取消本次註冊（金庫未新增金鑰槽）。{}",
                if cleanup == RegistrationCleanup::ManualRemovalRequired {
                    "本次建立的 Windows Hello 憑證未能自動刪除，請到「設定 → 帳戶 → 通行金鑰」只刪除本次測試項目。"
                } else {
                    ""
                }
            ));
        }
        // 視窗無法成為前景時保留 pending，使用者可再按一次或取消。
        let owner = raise(true)?;
        // 前景確認本身可能跨過期限；在消耗 pending 前再核對即時時鐘。
        enum Taken {
            Missing,
            Expired(PendingRegistrationSlot),
            Live(PendingRegistrationSlot),
        }
        let taken = guard.with_state(|g| match g.pending_registration.take() {
            None => Taken::Missing,
            Some(slot) if clock() >= slot.deadline => Taken::Expired(slot),
            Some(slot) => Taken::Live(slot),
        });
        let slot = match taken {
            Taken::Missing => return Err("沒有待完成的金鑰註冊；請重新註冊".to_string()),
            Taken::Expired(slot) => {
                let cleanup = guard.cancel_off_lock(slot, "implicit");
                return Err(format!(
                    "註冊確認已逾時，已取消本次註冊（金庫未新增金鑰槽）。{}",
                    if cleanup == RegistrationCleanup::ManualRemovalRequired {
                        "本次建立的 Windows Hello 憑證未能自動刪除，請到「設定 → 帳戶 → 通行金鑰」只刪除本次測試項目。"
                    } else {
                        ""
                    }
                ));
            }
            Taken::Live(slot) => slot,
        };
        let PendingRegistrationSlot {
            pending,
            deadline,
            vault_path,
            generation,
        } = slot;
        let (backend, vault) = guard.parts();
        backend.set_webauthn_parent_hwnd(owner);
        let v = vault.ok_or_else(|| "金庫未解鎖".to_string())?;
        let outcome = v.continue_registration(backend, pending, ed);
        let cleanup_report = v.take_registration_cleanup_report();
        Ok((outcome, cleanup_report, deadline, vault_path, generation))
    })();
    guard.complete(|g, deferred_lock| {
        let (outcome, cleanup_report, deadline, vault_path, generation) = ceremony?;
        let outcome = match outcome {
            Ok(outcome) => outcome,
            Err(error) => {
                record_registration_failure_cleanup(g, generation, cleanup_report);
                return Err(error.to_string());
            }
        };
        match outcome {
            vault::RegistrationOutcome::Registered(credential) => {
                Ok(RegisterResult::Registered { credential })
            }
            vault::RegistrationOutcome::HandoffRequired(pending) => {
                // 再按一次即可；期限不延長。
                g.pending_registration = Some(PendingRegistrationSlot {
                    pending,
                    deadline,
                    vault_path,
                    generation,
                });
                if deferred_lock {
                    // The deferred lock cancels this pending registration right after we return.
                    return Err(KEY_OPERATION_LOCKED_MSG.to_string());
                }
                Ok(RegisterResult::HandoffRequired {
                    message: fido2::FidoError::ForegroundHandoffRequired.to_string(),
                })
            }
        }
    })
}

#[tauri::command(async)]
fn continue_registration(
    window: tauri::WebviewWindow,
    state: tauri::State<VaultState>,
) -> Result<RegisterResult> {
    continue_registration_inner(
        &state,
        edition::current(),
        |required| raise_key_operation_window(&window, required),
        std::time::Instant::now,
    )
}

fn cancel_registration_inner(state: &VaultState) -> Result<CancelRegistrationInfo> {
    // The pending registration is taken under the short lock; the platform list/delete that
    // proves and removes the credential runs on the leased backend with the lock released.
    let (mut guard, (slot, idle_status)) = KeyOperationGuard::begin_native(state, |g| {
        Ok(match g.pending_registration.take() {
            Some(slot) => (Some(slot), RegistrationCleanup::None),
            None => (None, no_pending_cleanup_status(g)),
        })
    })?;
    let cleanup = match slot {
        Some(slot) => guard.cancel_off_lock(slot, "implicit"),
        None => idle_status,
    };
    guard.complete(|_, _| {
        Ok(CancelRegistrationInfo {
            status: "cancelled",
            cleanup,
        })
    })
}

#[tauri::command(async)]
fn cancel_registration(state: tauri::State<VaultState>) -> Result<CancelRegistrationInfo> {
    cancel_registration_inner(&state)
}

fn registration_cleanup_status_inner(
    state: &VaultState,
) -> Result<Vec<RegistrationCleanupReceipt>> {
    state.with_lock(registration_cleanup_status_inner_unlocked)
}

fn cleanup_reason_tag(reason: &str) -> &'static str {
    match reason {
        "expired" => "expired",
        "locked" => "locked",
        "implicit" => "implicit",
        "continue_error" => "continue_error",
        "unverified" => "unverified",
        _ => "unknown",
    }
}

/// Journal-backed receipts are authoritative: a successful listing replaces every durable
/// entry of the in-memory cache (so acknowledgements by another process are honoured and
/// receipts from a previous process appear). Memory-only fallbacks (`memory-*`) are kept.
/// An unreadable journal or missing storage adds a conservative, unacknowledgeable notice.
fn registration_cleanup_status_inner_unlocked(
    g: &mut AppInner,
) -> Result<Vec<RegistrationCleanupReceipt>> {
    let mut unavailable = g.registration_cleanup_storage_unavailable;
    if let Some(journal) = &g.registration_cleanup_journal {
        match journal.list() {
            Ok(records) => {
                let previous = std::mem::take(&mut g.registration_cleanup_receipts);
                let generations: std::collections::HashMap<&str, u64> = previous
                    .iter()
                    .map(|receipt| (receipt.id.as_str(), receipt.generation))
                    .collect();
                let mut synced: Vec<RegistrationCleanupReceipt> = previous
                    .iter()
                    .filter(|receipt| receipt.id.starts_with("memory-"))
                    .cloned()
                    .collect();
                for record in records {
                    let generation = generations.get(record.id.as_str()).copied().unwrap_or(0);
                    synced.push(RegistrationCleanupReceipt {
                        id: record.id,
                        generation,
                        reason: cleanup_reason_tag(&record.reason),
                        cleanup: RegistrationCleanup::ManualRemovalRequired,
                    });
                }
                g.registration_cleanup_receipts = synced;
            }
            Err(_) => unavailable = true,
        }
    }
    let mut receipts = g.registration_cleanup_receipts.clone();
    if unavailable {
        receipts.push(RegistrationCleanupReceipt {
            id: "journal-unavailable".into(),
            generation: 0,
            reason: "storage_unavailable",
            cleanup: RegistrationCleanup::ManualRemovalRequired,
        });
    }
    Ok(receipts)
}

fn has_unacknowledged_cleanup(g: &mut AppInner) -> bool {
    registration_cleanup_status_inner_unlocked(g).map_or(true, |receipts| !receipts.is_empty())
}

#[tauri::command]
fn registration_cleanup_status(
    state: tauri::State<VaultState>,
) -> Result<Vec<RegistrationCleanupReceipt>> {
    registration_cleanup_status_inner(&state)
}

fn acknowledge_registration_cleanup_inner(state: &VaultState, id: &str) -> Result<()> {
    state.with_lock(|g| {
        if id == "journal-unavailable" {
            return Err("清理收據儲存位置無法讀取，請先修復儲存問題".into());
        }
        let receipts = registration_cleanup_status_inner_unlocked(g)?;
        if !receipts.iter().any(|r| r.id == id) {
            return Err("找不到待確認的清理通知".into());
        }
        if !id.starts_with("memory-") {
            g.registration_cleanup_journal
                .as_ref()
                .ok_or_else(|| "清理收據儲存位置無法讀取".to_string())?
                .ack(id)
                .map_err(|_| "無法儲存清理通知確認，請重試".to_string())?;
        }
        g.registration_cleanup_receipts.retain(|r| r.id != id);
        Ok(())
    })
}

#[tauri::command]
fn acknowledge_registration_cleanup(state: tauri::State<VaultState>, id: String) -> Result<()> {
    acknowledge_registration_cleanup_inner(&state, &id)
}

fn login_windows_hello_inner(
    state: &VaultState,
    path: &std::path::Path,
    ed: edition::Edition,
    raise: impl FnOnce(bool) -> Result<isize>,
) -> Result<Vec<vault::Entry>> {
    require_windows_hello_single(ed)?;
    let (mut guard, ()) = KeyOperationGuard::begin_login(state, |_| Ok(()))?;
    let opened = (|| -> Result<vault::Vault> {
        // The capability probe is a native call: it runs on the leased backend, off the lock.
        require_windows_hello_available(&*guard.parts().0)?;
        let owner = raise(true)?;
        let (backend, _) = guard.parts();
        backend.set_webauthn_parent_hwnd(owner);
        vault::Vault::open_windows_hello(path, backend, ed).map_err(|e| e.to_string())
    })();
    // Late lock requests during lock-free cleanup also discard the result.
    guard.complete_login(opened, |g| {
        g.pending_csv_import = None;
        g.dual_pending = None;
    })
}

#[tauri::command(async)]
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
#[tauri::command(async)]
fn create_vault(state: tauri::State<VaultState>, password: String) -> Result<()> {
    create_vault_inner(
        &state,
        &path_from_state_or_default(),
        &password,
        edition::current(),
    )
}

fn create_vault_inner(
    state: &VaultState,
    path: &std::path::Path,
    password: &str,
    ed: edition::Edition,
) -> Result<()> {
    create_vault_inner_with_hook(state, path, password, ed, || {})
}

/// `after_reservation` runs right after the creation has been reserved (before any exists/KDF/file
/// work); tests use it to park the first creation.
fn create_vault_inner_with_hook(
    state: &VaultState,
    path: &std::path::Path,
    password: &str,
    ed: edition::Edition,
    after_reservation: impl FnOnce(),
) -> Result<()> {
    // The reservation is taken before any exists/KDF/file work and held until the vault is
    // published: it excludes every other creation and every key operation.
    let (guard, ()) = KeyOperationGuard::begin_native(state, |_| Ok(()))?;
    after_reservation();
    let created = (|| -> Result<vault::Vault> {
        if password.len() < 8 {
            return Err("主密碼至少 8 個字元".into());
        }
        if path.exists() {
            return Err("vault.db 已存在（請改走登入）".into());
        }
        vault::Vault::create_for(path, password, ed).map_err(|e| e.to_string())
    })();
    guard.complete(|g, deferred_lock| {
        let v = created?;
        if deferred_lock {
            drop(v.lock());
            return Err(KEY_OPERATION_LOCKED_MSG.to_string());
        }
        g.dual_pending = None;
        queue_pending_cancellation(g, "implicit");
        g.vault = Some(v);
        Ok(())
    })
}

/// 主密碼登入。
#[tauri::command(async)]
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
    // Platform repair may call native list APIs: the backend is leased, the lock is released.
    let (mut guard, ()) = KeyOperationGuard::begin_native(state, |_| Ok(()))?;
    let opened = (|| -> Result<vault::Vault> {
        if ed == edition::Edition::Single {
            vault::Vault::open_password_with_platform(path, password, ed, guard.parts().0)
        } else {
            vault::Vault::open_password_for(path, password, ed)
        }
        .map_err(|e| e.to_string())
    })();
    guard.complete_login(opened, |g| g.dual_pending = None)
}

/// FIDO2 金鑰登入。pin：PIN 型金鑰必填；其他類型忽略。
#[tauri::command(async)]
fn login_key(
    window: tauri::WebviewWindow,
    state: tauri::State<VaultState>,
    credential_id: String,
    pin: Option<String>,
) -> Result<Vec<vault::Entry>> {
    login_key_inner(
        &state,
        &path_from_state_or_default(),
        &credential_id,
        pin.as_deref(),
        |required| raise_key_operation_window(&window, required),
    )
}

fn login_key_inner(
    state: &VaultState,
    path: &std::path::Path,
    credential_id: &str,
    pin: Option<&str>,
    raise: impl FnOnce(bool) -> Result<isize>,
) -> Result<Vec<vault::Entry>> {
    let (mut guard, require_foreground) = KeyOperationGuard::begin_login(state, |g| {
        Ok(g.backend.uses_brokered_key_selection())
    })?;
    let opened = (|| -> Result<vault::Vault> {
        let owner_hwnd = raise(require_foreground)?;
        let (backend, _) = guard.parts();
        backend.set_webauthn_parent_hwnd(owner_hwnd);
        vault::Vault::open_key(path, credential_id, pin, backend).map_err(|e| e.to_string())
    })();
    guard.complete_login(opened, |_| {})
}

/// FIDO2 key login without a UI-selected key; let the active backend select from every vault slot.
#[tauri::command(async)]
fn login_any_key(
    window: tauri::WebviewWindow,
    state: tauri::State<VaultState>,
) -> Result<Vec<vault::Entry>> {
    login_any_key_inner(&state, &path_from_state_or_default(), |required| {
        raise_key_operation_window(&window, required)
    })
}

fn login_any_key_inner(
    state: &VaultState,
    path: &std::path::Path,
    raise: impl FnOnce(bool) -> Result<isize>,
) -> Result<Vec<vault::Entry>> {
    let (mut guard, require_foreground) = KeyOperationGuard::begin_login(state, |g| {
        Ok(g.backend.uses_brokered_key_selection())
    })?;
    let opened = (|| -> Result<vault::Vault> {
        let owner_hwnd = raise(require_foreground)?;
        let (backend, _) = guard.parts();
        backend.set_webauthn_parent_hwnd(owner_hwnd);
        vault::Vault::open_any_key(path, None, backend).map_err(|e| e.to_string())
    })();
    guard.complete_login(opened, |_| {})
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
#[tauri::command(async)]
fn login_dual_begin(
    window: tauri::WebviewWindow,
    state: tauri::State<VaultState>,
    pin: Option<String>,
) -> Result<DualBeginInfo> {
    require_dual_edition()?;
    let app = window.app_handle().clone();
    login_dual_begin_inner(
        &state,
        &path_from_state_or_default(),
        pin.as_deref(),
        |required| raise_key_operation_window(&window, required),
        move |generation, remaining| {
            // Rust 端主動逾時清除，不依賴前端呼叫（§4.3、R5）。
            std::thread::spawn(move || {
                std::thread::sleep(remaining + std::time::Duration::from_millis(250));
                let state = app.state::<VaultState>();
                let _ = state.with_lock(|g| {
                    sweep_expired_dual(g, generation, std::time::Instant::now());
                    Ok(())
                });
            });
        },
    )
}

fn login_dual_begin_inner(
    state: &VaultState,
    path: &std::path::Path,
    pin: Option<&str>,
    raise: impl FnOnce(bool) -> Result<isize>,
    schedule_expiry: impl FnOnce(u64, std::time::Duration),
) -> Result<DualBeginInfo> {
    let (mut guard, require_foreground) = KeyOperationGuard::begin_login(state, |g| {
        Ok(g.backend.uses_brokered_key_selection())
    })?;
    let begun = (|| -> Result<_> {
        let owner_hwnd = raise(require_foreground)?;
        let (backend, _) = guard.parts();
        backend.set_webauthn_parent_hwnd(owner_hwnd);
        vault::Vault::dual_login_begin(path, pin, backend, &mut std::time::Instant::now)
            .map_err(|e| e.to_string())
    })();
    guard.complete(|g, deferred_lock| {
        // 新的第一步一律先丟棄舊的暫存（清零），避免殘留 share。
        g.dual_pending = None;
        let pending = begun?;
        if deferred_lock {
            return Err(KEY_OPERATION_LOCKED_MSG.to_string());
        }
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
        schedule_expiry(generation, remaining);
        Ok(info)
    })
}

/// 雙人版金鑰登入第二步：只接受另一群組的金鑰。無論成功或失敗，暫存都會被取走（一次性）。
#[tauri::command(async)]
fn login_dual_complete(
    window: tauri::WebviewWindow,
    state: tauri::State<VaultState>,
    pin: Option<String>,
) -> Result<Vec<vault::Entry>> {
    require_dual_edition()?;
    login_dual_complete_inner(&state, pin.as_deref(), |required| {
        raise_key_operation_window(&window, required)
    })
}

fn login_dual_complete_inner(
    state: &VaultState,
    pin: Option<&str>,
    raise: impl FnOnce(bool) -> Result<isize>,
) -> Result<Vec<vault::Entry>> {
    let (mut guard, require_foreground) = KeyOperationGuard::begin_login(state, |g| {
        Ok(g.backend.uses_brokered_key_selection())
    })?;
    let opened = (|| -> Result<vault::Vault> {
        let owner_hwnd = raise(require_foreground)?;
        // 取走第一步暫存（一次性）；前景失敗時暫存保留，使用者可重試。
        let pending = guard.with_state(|g| {
            g.dual_pending
                .take()
                .ok_or_else(|| "沒有進行中的第一步驗證，請從第一步重新開始".to_string())
        })?;
        let (backend, _) = guard.parts();
        backend.set_webauthn_parent_hwnd(owner_hwnd);
        vault::Vault::dual_login_complete(pending, pin, backend, &mut std::time::Instant::now)
            .map_err(|e| e.to_string())
    })();
    guard.complete_login(opened, |_| {})
}

/// 雙人版：取消進行中的兩步驟登入（記 sidecar，share 清零）。沒有暫存時為 no-op。
#[tauri::command]
fn login_dual_cancel(state: tauri::State<VaultState>) -> Result<()> {
    require_dual_edition()?;
    login_dual_cancel_inner(&state)
}

/// Refused while a key operation runs: a "successful" cancel must never be followed by that
/// operation still publishing (or storing) its result. The UI's own in-flight lock is no
/// substitute for this IPC-level contract.
fn login_dual_cancel_inner(state: &VaultState) -> Result<()> {
    let pending = state.with_lock(|g| {
        require_key_operation_idle(g)?;
        Ok(g.dual_pending.take())
    })?;
    if let Some(pending) = pending {
        pending.cancel().map_err(|e| e.to_string())?;
    }
    Ok(())
}

/// 上鎖（手動或閒置）。回傳登入畫面資訊。
#[tauri::command(async)]
fn lock(state: tauri::State<VaultState>, reason: Option<String>) -> Result<LoginScreenInfo> {
    lock_inner(&state, reason)
}

fn lock_inner(state: &VaultState, reason: Option<String>) -> Result<LoginScreenInfo> {
    lock_inner_at(
        state,
        reason,
        &path_from_state_or_default(),
        edition::current(),
    )
}

/// 上鎖（手動或閒置）。金鑰操作進行中時不等待、不阻塞：只記錄「待上鎖」，由該操作在回傳前完成上鎖；
/// 此時登入畫面資訊改由金庫檔頭取得（不需要被借出的 backend／金庫）。
fn lock_inner_at(
    state: &VaultState,
    reason: Option<String>,
    path: &std::path::Path,
    ed: edition::Edition,
) -> Result<LoginScreenInfo> {
    enum Locked {
        Now(vault::Header, bool),
        Deferred(bool),
    }
    let (outcome, cleanup_guard) = state.with_lock(|g| {
        if g.key_op.active {
            g.key_op.pending_lock = Some(reason.clone());
            return Ok((Ok(Locked::Deferred(g.backend.uses_brokered_key_selection())), None));
        }
        let locked = lock_locked(g, reason.as_deref())
            .map(|(header, brokered)| Locked::Now(header, brokered));
        // A pending registration was abandoned: its platform credential is deleted by a short
        // lease of the backend, after this lock is released.
        let cleanup_guard =
            (!g.key_op.cleanups.is_empty()).then(|| KeyOperationGuard::lease(state, g, false));
        Ok((locked, cleanup_guard))
    })?;
    if let Some(guard) = cleanup_guard {
        let _ = guard.complete(|_, _| Ok(()));
    }
    let outcome = outcome?;
    Ok(match outcome {
        Locked::Now(header, brokered_key_login) => LoginScreenInfo {
            has_vault: true,
            keys: (&header).into(),
            idle_lock_minutes: 5,
            brokered_key_login,
        },
        Locked::Deferred(brokered_key_login) => LoginScreenInfo {
            has_vault: path.exists(),
            keys: vault::Vault::read_header(path, ed)
                .map(|header| key_infos(&header))
                .unwrap_or_default(),
            idle_lock_minutes: 5,
            brokered_key_login,
        },
    })
}

/// The immediate lock: abandon pending work, drop and lock the unlocked vault. The abandoned
/// pending registration is queued (`key_op.cleanups`); whoever holds the backend lease deletes
/// its platform credential outside the lock.
fn lock_locked(g: &mut AppInner, reason: Option<&str>) -> Result<(vault::Header, bool)> {
    let brokered_key_login = g.backend.uses_brokered_key_selection();
    g.dual_pending = None;
    // 上鎖/登出：放棄未完成的註冊（Windows Hello 刪除本次 credential，秘密清零）。
    queue_pending_cancellation(g, "locked");
    match g.vault.take() {
        Some(v) => {
            g.pending_csv_import = None;
            Ok((
                if reason == Some("idle") {
                    v.auto_lock()
                } else {
                    v.lock()
                },
                brokered_key_login,
            ))
        }
        None => Err("尚未解鎖".to_string()),
    }
}

fn with_unlocked<R>(
    state: &VaultState,
    f: impl FnOnce(&mut vault::Vault) -> Result<R>,
) -> Result<R> {
    state.with_lock(|g| {
        // Busy / lock-pending is decided first: a present vault is only trusted when no key
        // operation is running and no lock request is waiting to be executed.
        require_vault_readable(g)?;
        match g.vault.as_mut() {
            Some(v) => f(v),
            None => Err("金庫未解鎖".to_string()),
        }
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
        require_vault_readable(inner)?;
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
    apply_csv_import_inner(&state, token)
}

fn apply_csv_import_inner(state: &VaultState, token: String) -> Result<csv_import::ImportPreview> {
    state.with_lock(|inner| {
        require_key_operation_idle(inner)?;
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

#[tauri::command(async)]
fn register_key(
    window: tauri::WebviewWindow,
    state: tauri::State<VaultState>,
    pin: Option<String>,
    label: String,
    group: Option<crypto::KeyGroup>,
) -> Result<RegisterResult> {
    let result = register_key_inner(
        &state,
        |required| raise_key_operation_window(&window, required),
        pin.as_deref(),
        &label,
        group,
    )?;
    schedule_registration_sweep(&window, &state, &result);
    Ok(result)
}

fn register_key_inner(
    state: &VaultState,
    raise: impl FnOnce(bool) -> Result<isize>,
    pin: Option<&str>,
    label: &str,
    group: Option<crypto::KeyGroup>,
) -> Result<RegisterResult> {
    let (mut guard, (require_foreground, stale)) = KeyOperationGuard::begin(state, true, |g| {
        // An expired pending is taken out here and cancelled off-lock below.
        let stale = take_expired_registration(g, None, std::time::Instant::now());
        require_no_pending_registration(g)?;
        Ok((g.backend.uses_brokered_key_selection(), stale))
    })?;
    // 同一後端實例內 detect+register → 類型一致。
    let ceremony = (|| -> Result<_> {
        if let Some(slot) = stale {
            guard.cancel_off_lock(slot, "expired");
        }
        let owner_hwnd = raise(require_foreground)?;
        let (backend, vault) = guard.parts();
        let v = vault.ok_or_else(|| "金庫未解鎖".to_string())?;
        backend.set_webauthn_parent_hwnd(owner_hwnd);
        // 單人版不可帶群組、雙人版必須帶群組（vault 層 fail closed，不碰 authenticator）。
        let outcome = v
            .begin_register_key_for(backend, pin, label, group)
            .map_err(|e| e.to_string())?;
        Ok((outcome, v.path.clone()))
    })();
    guard.complete(|g, deferred_lock| {
        let (outcome, vault_path) = ceremony?;
        let result = store_registration_outcome(g, outcome, vault_path, std::time::Instant::now());
        if deferred_lock && matches!(result, RegisterResult::HandoffRequired { .. }) {
            return Err(KEY_OPERATION_LOCKED_MSG.to_string());
        }
        Ok(result)
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

#[tauri::command(async)]
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
    // The vault and backend are leased: platform discovery/deletion and the vault save run with the
    // state lock released.
    let (mut guard, ()) = KeyOperationGuard::begin(state, true, |g| {
        if g.vault.is_none() {
            return Err("金庫未解鎖".to_string());
        }
        // 金鑰清單即將改變：先放棄未完成的註冊（由本操作在鎖外取消）。
        queue_pending_cancellation(g, "implicit");
        Ok(())
    })?;
    let removed = (|| -> Result<Option<KeyRemovalInfo>> {
        let (backend, vault) = guard.parts();
        let v = vault.ok_or_else(|| "金庫未解鎖".to_string())?;
        if ed == edition::Edition::Dual {
            v.remove_key(credential_id).map_err(|e| e.to_string())?;
            return Ok(None); // Preserve the existing dual JSON null response.
        }
        let outcome = v
            .remove_key_with_platform(credential_id, backend, ed)
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
    })();
    guard.complete(|_, _| removed)
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
#[tauri::command(async)]
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
            continue_registration,
            cancel_registration,
            registration_cleanup_status,
            acknowledge_registration_cleanup,
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

/// Test-only, per-thread hook fired when `with_lock` must wait for another holder.
/// Lets a test prove a worker is genuinely queued on the state mutex (no sleeps).
#[cfg(test)]
mod lock_wait_hook {
    use std::cell::RefCell;
    thread_local! {
        static HOOK: RefCell<Option<Box<dyn Fn()>>> = RefCell::new(None);
    }
    pub fn set(hook: impl Fn() + 'static) {
        HOOK.with(|h| *h.borrow_mut() = Some(Box::new(hook)));
    }
    pub fn notify() {
        HOOK.with(|h| {
            if let Some(hook) = h.borrow().as_ref() {
                hook();
            }
        });
    }
}

#[cfg(test)]
mod wh_d5_tests {
    use super::*;
    use fido2::{FidoBackend, FidoError, MockBackend, PlatformStatus};
    use std::sync::{Arc, Mutex};

    /// In-lock cancellation through `g.backend`; kept for tests of the receipt rules only.
    fn cancel_pending_registration_with_reason(
        g: &mut AppInner,
        reason: &'static str,
    ) -> RegistrationCleanup {
        let Some(slot) = g.pending_registration.take() else {
            return no_pending_cleanup_status(g);
        };
        let done = cancel_slot_with_backend(g.backend.as_mut(), slot, reason);
        record_cancelled_registration(g, &done);
        done.cleanup
    }

    /// 已逾時的 pending 註冊視同取消（in-lock，僅供測試；正式路徑一律走 `*_off_lock`）。
    fn sweep_expired_registration(
        g: &mut AppInner,
        generation: Option<u64>,
        now: std::time::Instant,
    ) -> bool {
        if g.key_op.active {
            // The real backend is leased out; the operation (or its completion) owns the cleanup.
            return false;
        }
        let expired = g.pending_registration.as_ref().is_some_and(|slot| {
            now >= slot.deadline && generation.is_none_or(|generation| generation == slot.generation)
        });
        if expired {
            cancel_pending_registration_with_reason(g, "expired");
        }
        expired
    }


    #[derive(Default)]
    struct Calls {
        status: usize,
        list: usize,
        create: usize,
        assert: usize,
        delete: usize,
        hwnd: Vec<isize>,
        allow: Vec<Vec<u8>>,
        // D9-F1 R4 runtime fault injection (test-only; mutable after the backend is boxed).
        force_unavailable: bool,
        list_fail_from: Option<usize>,
        list_empty: bool,
        clock_ms: Option<Arc<std::sync::atomic::AtomicU64>>,
        assert_error_from: Option<usize>,
        wrong_prf_from: Option<usize>,
        // D9-F2 R2: park the calling thread inside a native call (the leased/unlocked phase).
        hold_status: Option<Arc<Hold>>,
        hold_list: Option<Arc<Hold>>,
        hold_delete: Option<Arc<Hold>>,
    }

    /// Parks the thread that calls `park` until the test releases it (20 s safety timeout).
    struct Hold {
        entered: Mutex<std::sync::mpsc::Sender<()>>,
        release: Mutex<std::sync::mpsc::Receiver<()>>,
    }

    impl Hold {
        fn park(&self) {
            let _ = self.entered.lock().unwrap().send(());
            let _ = self
                .release
                .lock()
                .unwrap()
                .recv_timeout(std::time::Duration::from_secs(20));
        }
    }

    struct HoldTicket {
        entered: std::sync::mpsc::Receiver<()>,
        release: std::sync::mpsc::Sender<()>,
    }

    fn new_hold() -> (Arc<Hold>, HoldTicket) {
        let (entered_tx, entered) = std::sync::mpsc::channel();
        let (release, release_rx) = std::sync::mpsc::channel();
        (
            Arc::new(Hold {
                entered: Mutex::new(entered_tx),
                release: Mutex::new(release_rx),
            }),
            HoldTicket { entered, release },
        )
    }

    struct Recording {
        mock: MockBackend,
        calls: Arc<Mutex<Calls>>,
        status: PlatformStatus,
        list_error: bool,
        rogue: bool,
        rogue_after_first: bool,
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
                rogue_after_first: false,
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
        fn prf_supported(&self) -> bool {
            self.mock.prf_supported()
        }
        fn platform_status(&self) -> PlatformStatus {
            let mut c = self.calls.lock().unwrap();
            c.status += 1;
            if c.force_unavailable {
                return PlatformStatus {
                    api_ok: false,
                    uvpa: false,
                    console: false,
                };
            }
            let hold = c.hold_status.clone();
            drop(c);
            if let Some(hold) = hold {
                hold.park();
            }
            self.status
        }
        fn list_platform_credentials(&mut self) -> std::result::Result<Vec<Vec<u8>>, FidoError> {
            let hold = {
                let mut c = self.calls.lock().unwrap();
                c.list += 1;
                c.hold_list.clone()
            };
            if let Some(hold) = hold {
                hold.park();
            }
            let c = self.calls.lock().unwrap();
            if self.list_error || c.list_fail_from.is_some_and(|from| c.list >= from) {
                return Err(FidoError::Internal("synthetic discovery failure".into()));
            }
            if c.list_empty {
                return Ok(Vec::new());
            }
            drop(c);
            self.mock.list_platform_credentials()
        }
        fn register_platform_credential(
            &mut self,
            label: &str,
            exclude: &[Vec<u8>],
        ) -> std::result::Result<fido2::PlatformRegistration, FidoError> {
            let mut c = self.calls.lock().unwrap();
            c.create += 1;
            // Controlled ceremony seam: the first phase "takes" 200 synthetic seconds.
            if let Some(clock) = &c.clock_ms {
                clock.fetch_add(200_000, std::sync::atomic::Ordering::SeqCst);
            }
            drop(c);
            self.mock.register_platform_credential(label, exclude)
        }
        fn get_platform_prf_secret(
            &mut self,
            ids: &[Vec<u8>],
        ) -> std::result::Result<(Vec<u8>, [u8; 32]), FidoError> {
            let mut c = self.calls.lock().unwrap();
            c.assert += 1;
            let assertion_count = c.assert;
            c.allow = ids.to_vec();
            let assert_error = c
                .assert_error_from
                .is_some_and(|from| assertion_count >= from);
            let wrong_prf = c.wrong_prf_from.is_some_and(|from| assertion_count >= from);
            drop(c);
            if assert_error {
                return Err(FidoError::NoDevice);
            }
            if wrong_prf {
                // Correct credential, different PRF output.
                return Ok((ids[0].clone(), [0x5a; 32]));
            }
            if self.rogue || (self.rogue_after_first && assertion_count > 1) {
                return Ok((vec![255; 32], [0; 32]));
            }
            self.mock.get_platform_prf_secret(ids)
        }
        fn delete_platform_credential(&mut self, id: &[u8]) -> std::result::Result<(), FidoError> {
            let hold = {
                let mut c = self.calls.lock().unwrap();
                c.delete += 1;
                c.hold_delete.clone()
            };
            if let Some(hold) = hold {
                hold.park();
            }
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
                pending_registration: None,
                registration_generation: 0,
                registration_cleanup_receipts: Vec::new(),
                registration_cleanup_journal: None,
                registration_cleanup_storage_unavailable: false,
                key_op: KeyOpState::default(),
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
            // D9-F2: the state lock is deliberately NOT held across the foreground/WebAuthn
            // phase (it used to be: that froze every main-thread command). The operation is
            // instead marked in flight; publication below still happens under one lock.
            assert!(matches!(s.0.try_lock(), Ok(g) if g.key_op.active));
            // The "one lock" promise (publication and clearing of pending state are a single step)
            // is pinned by `d9f2_r2_login_publication_is_never_observed_half_done` (a sampler on
            // the state lock) and its negative control for a publication split across two locks.
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
        let RegisterResult::Registered { credential: reg } = result.unwrap() else {
            panic!("registration should not require a foreground handoff");
        };
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

    // ── D9-F1：註冊第二階段前景交接（IPC 層） ──

    fn d9f1_hello_state(times: usize) -> (Fixture, VaultState, Arc<Mutex<Calls>>) {
        let p = fixture();
        let v = vault::Vault::create_for(&p, "synthetic-D9F1-password", edition::Edition::Single)
            .unwrap();
        let mut b = Recording::new();
        b.mock = MockBackend::new()
            .with_platform_handoff(fido2::MockHandoffRefusal::OwnerNotForeground, times);
        let (s, c) = state(Some(v), b);
        (p, s, c)
    }

    fn d9f1_hello_handoff(s: &VaultState) -> Result<RegisterResult> {
        register_windows_hello_inner(
            s,
            edition::Edition::Single,
            |_| Ok(789),
            || Ok("SYNTHETIC".into()),
        )
    }

    fn d9f1_has_pending(s: &VaultState) -> bool {
        s.with_lock(|g| Ok(g.pending_registration.is_some()))
            .unwrap()
    }

    #[test]
    fn d9f1_hello_handoff_stores_pending_and_blocks_new_registration() {
        let (p, s, c) = d9f1_hello_state(1);
        let before = std::fs::read(&p).unwrap();
        let result = d9f1_hello_handoff(&s);
        assert!(
            matches!(&result, Ok(RegisterResult::HandoffRequired { .. })),
            "{result:?}"
        );
        assert_eq!(
            serde_json::to_value(result.unwrap()).unwrap(),
            serde_json::json!({
                "status": "handoff_required",
                "message": FidoError::ForegroundHandoffRequired.to_string(),
            })
        );
        assert!(d9f1_has_pending(&s));
        assert_eq!(std::fs::read(&p).unwrap(), before);
        assert_eq!(
            c.lock().unwrap().delete,
            0,
            "handoff keeps the new credential"
        );

        let mut focus = 0;
        let again = register_windows_hello_inner(
            &s,
            edition::Edition::Single,
            |_| {
                focus += 1;
                Ok(789)
            },
            || Ok("SYNTHETIC".into()),
        );
        assert!(matches!(&again, Err(m) if m.contains("取消")), "{again:?}");
        let roaming = register_key_inner(
            &s,
            |_| {
                focus += 1;
                Ok(789)
            },
            None,
            "synthetic-roaming",
            None,
        );
        assert!(
            matches!(&roaming, Err(m) if m.contains("取消")),
            "{roaming:?}"
        );
        assert_eq!(
            focus, 0,
            "a pending registration refuses before any focus change"
        );
        let c = c.lock().unwrap();
        assert_eq!((c.create, c.delete), (1, 0));
    }

    #[test]
    fn d9f1_r2_hello_deadline_starts_when_first_ceremony_returns() {
        use std::sync::atomic::{AtomicU64, Ordering};
        let (_p, state, calls) = d9f1_hello_state(1);
        // The synthetic clock only advances inside MakeCredential (Recording seam), so a
        // deadline computed from a clock read before the ceremony is exactly 200 s early.
        let synthetic_ms = Arc::new(AtomicU64::new(0));
        calls.lock().unwrap().clock_ms = Some(Arc::clone(&synthetic_ms));
        let base = std::time::Instant::now();
        let clock = || base + std::time::Duration::from_millis(synthetic_ms.load(Ordering::SeqCst));
        let result = register_windows_hello_inner_with_clock(
            &state,
            edition::Edition::Single,
            |_| Ok(789),
            || Ok("SYNTHETIC".into()),
            clock,
        );
        assert!(
            matches!(&result, Ok(RegisterResult::HandoffRequired { .. })),
            "{result:?}"
        );
        let deadline = state
            .with_lock(|g| Ok(g.pending_registration.as_ref().unwrap().deadline))
            .unwrap();
        assert_eq!(
            deadline,
            base + std::time::Duration::from_secs(200) + PENDING_REGISTRATION_TIMEOUT,
            "pending deadline must start after the first ceremony returns"
        );
        assert_eq!(calls.lock().unwrap().delete, 0);
    }

    #[test]
    fn d9f1_continue_success_registers_with_fresh_foreground_and_clears_pending() {
        let (p, s, c) = d9f1_hello_state(1);
        assert!(d9f1_hello_handoff(&s).is_ok());
        let mut required = Vec::new();
        let result = continue_registration_inner(
            &s,
            edition::Edition::Single,
            |r| {
                required.push(r);
                Ok(790)
            },
            std::time::Instant::now,
        );
        assert!(
            matches!(&result, Ok(RegisterResult::Registered { .. })),
            "{result:?}"
        );
        let json = serde_json::to_value(result.unwrap()).unwrap();
        assert_eq!(json["status"], "registered");
        assert_eq!(
            json["credential"]["label"],
            "Windows Hello（本機 SYNTHETIC）"
        );
        assert!(json.get("message").is_none() && json["credential"].get("creation_prf").is_none());
        assert_eq!(required, vec![true]);
        assert!(!d9f1_has_pending(&s));
        let h = vault::Vault::read_header(&p, edition::Edition::Single).unwrap();
        assert_eq!(h.key_slots.len(), 1);
        let c = c.lock().unwrap();
        assert_eq!(
            c.hwnd,
            vec![789, 790],
            "continue uses the freshly raised live HWND"
        );
        assert_eq!((c.create, c.delete), (1, 0));
    }

    #[test]
    fn d9f1_continue_handoff_again_keeps_pending_without_extending_deadline() {
        let (_p, s, c) = d9f1_hello_state(2);
        assert!(d9f1_hello_handoff(&s).is_ok());
        let deadline = s
            .with_lock(|g| Ok(g.pending_registration.as_ref().map(|slot| slot.deadline)))
            .unwrap();
        let result = continue_registration_inner(
            &s,
            edition::Edition::Single,
            |_| Ok(790),
            std::time::Instant::now,
        );
        assert!(
            matches!(&result, Ok(RegisterResult::HandoffRequired { .. })),
            "{result:?}"
        );
        let after = s
            .with_lock(|g| Ok(g.pending_registration.as_ref().map(|slot| slot.deadline)))
            .unwrap();
        assert!(deadline.is_some() && after == deadline);
        assert_eq!(c.lock().unwrap().delete, 0);
    }

    #[test]
    fn d9f1_continue_after_timeout_cancels_and_deletes_without_focus() {
        let (p, s, c) = d9f1_hello_state(1);
        assert!(d9f1_hello_handoff(&s).is_ok());
        let before = std::fs::read(&p).unwrap();
        let mut focus = 0;
        let late = std::time::Instant::now()
            + PENDING_REGISTRATION_TIMEOUT
            + std::time::Duration::from_secs(1);
        let result = continue_registration_inner(
            &s,
            edition::Edition::Single,
            |_| {
                focus += 1;
                Ok(790)
            },
            || late,
        );
        assert!(
            matches!(&result, Err(m) if m.contains("逾時")),
            "{result:?}"
        );
        assert_eq!(focus, 0);
        assert!(!d9f1_has_pending(&s));
        assert_eq!(std::fs::read(&p).unwrap(), before);
        assert_eq!(
            c.lock().unwrap().delete,
            1,
            "expired platform pending is deleted"
        );
    }

    #[test]
    fn d9f1_r2_queued_continue_rejects_deadline_passed_while_waiting_for_lock() {
        use std::sync::atomic::{AtomicU64, Ordering};
        let (_p, state, calls) = d9f1_hello_state(1);
        assert!(d9f1_hello_handoff(&state).is_ok());
        let initial_assertions = calls.lock().unwrap().assert;
        let state = Arc::new(state);
        let held = state.0.lock().unwrap();
        let base = std::time::Instant::now();
        let ticks = Arc::new(AtomicU64::new(0));
        let (waiting_tx, waiting_rx) = std::sync::mpsc::channel();
        let (clock_tx, clock_rx) = std::sync::mpsc::channel::<u64>();
        let worker = Arc::clone(&state);
        let worker_ticks = Arc::clone(&ticks);
        let task = std::thread::spawn(move || {
            // Fires only when with_lock's try_lock reports WouldBlock in this thread.
            lock_wait_hook::set(move || {
                let _ = waiting_tx.send(());
            });
            let mut focus_calls = 0;
            let result = continue_registration_inner(
                &worker,
                edition::Edition::Single,
                |_| {
                    focus_calls += 1;
                    Ok(790)
                },
                || {
                    let now = worker_ticks.load(Ordering::SeqCst);
                    let _ = clock_tx.send(now);
                    base + std::time::Duration::from_millis(now)
                },
            );
            (result, focus_calls)
        });
        // Deterministic synchronisation: proceed only once the worker is genuinely blocked on
        // the state mutex. Not reaching that point is a test failure, never a silent pass.
        let reached = waiting_rx.recv_timeout(std::time::Duration::from_secs(30));
        assert!(reached.is_ok(), "worker never queued on the state lock");
        // Everything the IPC did before blocking is complete; any clock read so far was
        // necessarily outside the lock (a stale time-of-check).
        let early = clock_rx.try_recv();
        assert!(
            early.is_err(),
            "clock was read before the state lock: {early:?}"
        );
        let mut held = held;
        held.pending_registration.as_mut().unwrap().deadline =
            base + std::time::Duration::from_millis(10);
        ticks.store(20, Ordering::SeqCst);
        drop(held);
        let (result, focus_calls) = task.join().unwrap();
        assert!(
            matches!(&result, Err(message) if message.contains("逾時")),
            "{result:?}"
        );
        assert_eq!(focus_calls, 0, "an expired pending must not raise focus");
        assert_eq!(
            clock_rx.try_iter().next(),
            Some(20),
            "first clock read happens under the lock"
        );
        let c = calls.lock().unwrap();
        assert_eq!((c.assert, c.delete), (initial_assertions, 1));
    }

    #[test]
    fn d9f1_r2_continue_rejects_deadline_crossed_during_raise() {
        let (_p, state, calls) = d9f1_hello_state(1);
        assert!(d9f1_hello_handoff(&state).is_ok());
        let initial_assertions = calls.lock().unwrap().assert;
        let base = std::time::Instant::now();
        let ticks = std::cell::Cell::new(0_u64);
        state
            .with_lock(|g| {
                g.pending_registration.as_mut().unwrap().deadline =
                    base + std::time::Duration::from_millis(10);
                Ok(())
            })
            .unwrap();
        let mut focus_calls = 0;
        let result = continue_registration_inner(
            &state,
            edition::Edition::Single,
            |_| {
                focus_calls += 1;
                ticks.set(20);
                Ok(790)
            },
            || base + std::time::Duration::from_millis(ticks.get()),
        );
        assert!(
            matches!(&result, Err(message) if message.contains("逾時")),
            "{result:?}"
        );
        assert_eq!(focus_calls, 1);
        let c = calls.lock().unwrap();
        assert_eq!((c.assert, c.delete), (initial_assertions, 1));
    }

    #[test]
    fn d9f1_r2_timer_failed_cleanup_remains_visible_to_cancel_and_continue() {
        let p = fixture();
        let v = vault::Vault::create_for(&p, "synthetic-D9F1-password", edition::Edition::Single)
            .unwrap();
        let mut b = Recording::new();
        b.mock = MockBackend::new()
            .with_platform_handoff(fido2::MockHandoffRefusal::OwnerNotForeground, 1);
        b.delete_error = true;
        let (state, calls) = state(Some(v), b);
        assert!(d9f1_hello_handoff(&state).is_ok());
        let expired = state
            .with_lock(|g| {
                let slot = g.pending_registration.as_ref().unwrap();
                let generation = slot.generation;
                let deadline = slot.deadline;
                Ok(sweep_expired_registration(g, Some(generation), deadline))
            })
            .unwrap();
        assert!(expired);
        let status = cancel_registration_inner(&state).unwrap();
        assert_eq!(status.cleanup, RegistrationCleanup::ManualRemovalRequired);
        let result = continue_registration_inner(
            &state,
            edition::Edition::Single,
            |_| unreachable!("expired pending must not raise focus"),
            std::time::Instant::now,
        );
        assert!(
            matches!(&result, Err(message) if message.contains("通行金鑰")),
            "{result:?}"
        );
        assert_eq!(calls.lock().unwrap().delete, 1, "no double delete");
    }

    #[test]
    fn d9f1_r2_lock_failed_cleanup_receipt_survives_login() {
        let p = fixture();
        let v = vault::Vault::create_for(&p, "synthetic-D9F1-password", edition::Edition::Single)
            .unwrap();
        let mut b = Recording::new();
        b.mock = MockBackend::new()
            .with_platform_handoff(fido2::MockHandoffRefusal::OwnerNotForeground, 1);
        b.delete_error = true;
        let (state, calls) = state(Some(v), b);
        assert!(d9f1_hello_handoff(&state).is_ok());
        assert!(lock_inner(&state, None).is_ok());
        assert!(login_password_inner(
            &state,
            &p,
            "synthetic-D9F1-password",
            edition::Edition::Single
        )
        .is_ok());
        let receipts = state
            .with_lock(|g| Ok(g.registration_cleanup_receipts.clone()))
            .unwrap();
        assert_eq!(receipts.len(), 1);
        assert_eq!(
            receipts[0].cleanup,
            RegistrationCleanup::ManualRemovalRequired
        );
        assert_eq!(receipts[0].reason, "locked");
        assert_eq!(calls.lock().unwrap().delete, 1);
    }

    #[test]
    fn d9f1_r2_lazy_sweep_then_new_pending_keeps_old_failure_receipt() {
        let p = fixture();
        let v = vault::Vault::create_for(&p, "synthetic-D9F1-password", edition::Edition::Single)
            .unwrap();
        let mut b = Recording::new();
        b.mock = MockBackend::new()
            .with_platform_handoff(fido2::MockHandoffRefusal::OwnerNotForeground, 2);
        b.delete_error = true;
        let (state, calls) = state(Some(v), b);
        assert!(d9f1_hello_handoff(&state).is_ok());
        state
            .with_lock(|g| {
                g.pending_registration.as_mut().unwrap().deadline = std::time::Instant::now();
                Ok(())
            })
            .unwrap();
        assert!(d9f1_hello_handoff(&state).is_ok());
        let (first, second) = state
            .with_lock(|g| {
                Ok((
                    g.registration_cleanup_receipts.first().cloned(),
                    g.pending_registration.as_ref().map(|p| p.generation),
                ))
            })
            .unwrap();
        assert!(matches!(
            first.as_ref(),
            Some(RegistrationCleanupReceipt {
                cleanup: RegistrationCleanup::ManualRemovalRequired,
                reason: "expired",
                ..
            })
        ));
        assert!(second.is_some_and(|generation| generation != first.unwrap().generation));
        assert_eq!(calls.lock().unwrap().delete, 1);
    }

    #[test]
    fn d9f1_r2_cleanup_receipt_query_and_exact_generation_acknowledgement() {
        let p = fixture();
        let v = vault::Vault::create_for(&p, "synthetic-D9F1-password", edition::Edition::Single)
            .unwrap();
        let mut b = Recording::new();
        b.mock = MockBackend::new()
            .with_platform_handoff(fido2::MockHandoffRefusal::OwnerNotForeground, 1);
        b.delete_error = true;
        let (state, calls) = state(Some(v), b);
        assert!(d9f1_hello_handoff(&state).is_ok());
        assert!(lock_inner(&state, None).is_ok());
        let receipts = registration_cleanup_status_inner(&state).unwrap();
        let json = serde_json::to_value(&receipts).unwrap();
        assert_eq!(json.as_array().unwrap().len(), 1);
        assert_eq!(json[0]["reason"], "locked");
        assert_eq!(json[0]["cleanup"], "manual_removal_required");
        assert_eq!(
            json[0].as_object().unwrap().len(),
            4,
            "no credential or secret may leave IPC"
        );
        let id = receipts[0].id.clone();
        assert!(acknowledge_registration_cleanup_inner(&state, "invalid-id").is_err());
        assert_eq!(registration_cleanup_status_inner(&state).unwrap().len(), 1);
        assert!(acknowledge_registration_cleanup_inner(&state, &id).is_ok());
        assert!(registration_cleanup_status_inner(&state)
            .unwrap()
            .is_empty());
        assert_eq!(calls.lock().unwrap().delete, 1);
    }

    #[test]
    fn d9f1_r3_continue_failure_cleanup_warning_is_recorded() {
        let p = fixture();
        let v = vault::Vault::create_for(&p, "synthetic-D9F1-password", edition::Edition::Single)
            .unwrap();
        let (state, _) = state(Some(v), Recording::new());
        state
            .with_lock(|g| {
                record_registration_failure_cleanup(g, 96, None);
                record_registration_failure_cleanup(
                    g,
                    96,
                    Some(vault::RegistrationCleanupReport::Removed),
                );
                assert!(
                    g.registration_cleanup_receipts.is_empty(),
                    "ordinary error has no orphan warning"
                );
                record_registration_failure_cleanup(
                    g,
                    96,
                    Some(vault::RegistrationCleanupReport::DeleteFailed),
                );
                record_registration_failure_cleanup(
                    g,
                    97,
                    Some(vault::RegistrationCleanupReport::NotAttempted),
                );
                assert!(g
                    .registration_cleanup_receipts
                    .iter()
                    .any(|r| r.generation == 97 && r.reason == "unverified"));
                assert!(g
                    .registration_cleanup_receipts
                    .iter()
                    .any(|r| r.generation == 96
                        && r.reason == "continue_error"
                        && r.cleanup == RegistrationCleanup::ManualRemovalRequired));
                Ok(())
            })
            .unwrap();
    }

    #[test]
    fn d9f1_r3_cleanup_journal_survives_restart_and_acks_exact_record() {
        let root = fixture_root().join(format!(
            "cleanup-journal-test-{:016x}",
            rand::random::<u64>()
        ));
        let journal = registration_cleanup_journal::Journal::new(root.clone());
        let first = journal.record("expired").unwrap();
        let second = journal.record("locked").unwrap();
        assert_ne!(first, second);
        let restarted = registration_cleanup_journal::Journal::new(root);
        let records = restarted.list().unwrap();
        assert_eq!(records.len(), 2);
        assert!(records
            .iter()
            .any(|r| r.id == first && r.reason == "expired"));
        assert!(records
            .iter()
            .any(|r| r.id == second && r.reason == "locked"));
        assert!(restarted.ack("../escape").is_err());
        restarted.ack(&first).unwrap();
        let remaining = registration_cleanup_journal::Journal::new(restarted.root().to_path_buf())
            .list()
            .unwrap();
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].id, second);
    }

    #[test]
    fn d9f1_r3_failed_cleanup_is_visible_to_fresh_app_state() {
        let root = fixture_root().join(format!("receipt-restart-{:016x}", rand::random::<u64>()));
        let p = fixture_in(&root);
        let v = vault::Vault::create_for(&p, "synthetic-D9F1-password", edition::Edition::Single)
            .unwrap();
        let mut b = Recording::new();
        b.mock = MockBackend::new()
            .with_platform_handoff(fido2::MockHandoffRefusal::OwnerNotForeground, 1);
        b.delete_error = true;
        let (first_state, _) = state(Some(v), b);
        first_state
            .with_lock(|g| {
                g.registration_cleanup_journal = Some(registration_cleanup_journal::Journal::new(
                    root.join("receipts"),
                ));
                Ok(())
            })
            .unwrap();
        assert!(d9f1_hello_handoff(&first_state).is_ok());
        assert!(lock_inner(&first_state, None).is_ok());
        let first = registration_cleanup_status_inner(&first_state).unwrap();
        assert_eq!(first.len(), 1);
        assert_eq!(first[0].cleanup, RegistrationCleanup::ManualRemovalRequired);
        let (restarted, _) = state(None, Recording::new());
        restarted
            .with_lock(|g| {
                g.registration_cleanup_journal = Some(registration_cleanup_journal::Journal::new(
                    root.join("receipts"),
                ));
                Ok(())
            })
            .unwrap();
        let reopened = registration_cleanup_status_inner(&restarted).unwrap();
        assert_eq!(
            reopened.len(),
            1,
            "warning must survive a fresh process state"
        );
        assert_eq!(reopened[0].id, first[0].id);
        assert!(acknowledge_registration_cleanup_inner(&restarted, "wrong-id").is_err());
        assert!(acknowledge_registration_cleanup_inner(&restarted, &reopened[0].id).is_ok());
        assert!(registration_cleanup_status_inner(&restarted)
            .unwrap()
            .is_empty());
        assert!(
            registration_cleanup_status_inner(&first_state)
                .unwrap()
                .is_empty(),
            "another process must not keep displaying an acknowledged receipt"
        );
    }

    #[test]
    fn d9f1_r3_continue_delete_failure_reports_durable_receipt() {
        let root = fixture_root().join(format!("continue-failure-{:016x}", rand::random::<u64>()));
        let p = fixture_in(&root);
        let v = vault::Vault::create_for(&p, "synthetic-D9F1-password", edition::Edition::Single)
            .unwrap();
        let mut b = Recording::new();
        b.mock = MockBackend::new()
            .with_platform_handoff(fido2::MockHandoffRefusal::OwnerNotForeground, 1);
        b.delete_error = true;
        b.rogue_after_first = true;
        let (first_state, calls) = state(Some(v), b);
        first_state
            .with_lock(|g| {
                g.registration_cleanup_journal = Some(registration_cleanup_journal::Journal::new(
                    root.join("receipts"),
                ));
                Ok(())
            })
            .unwrap();
        assert!(d9f1_hello_handoff(&first_state).is_ok());
        let result = continue_registration_inner(
            &first_state,
            edition::Edition::Single,
            |_| Ok(1),
            std::time::Instant::now,
        );
        assert!(result.is_err());
        assert!(!d9f1_has_pending(&first_state));
        let receipts = registration_cleanup_status_inner(&first_state).unwrap();
        assert_eq!(receipts.len(), 1);
        assert_eq!(receipts[0].reason, "continue_error");
        assert_eq!(
            receipts[0].cleanup,
            RegistrationCleanup::ManualRemovalRequired
        );
        assert_eq!(calls.lock().unwrap().delete, 1);
        let (restarted, _) = state(None, Recording::new());
        restarted
            .with_lock(|g| {
                g.registration_cleanup_journal = Some(registration_cleanup_journal::Journal::new(
                    root.join("receipts"),
                ));
                Ok(())
            })
            .unwrap();
        assert_eq!(
            registration_cleanup_status_inner(&restarted).unwrap()[0].id,
            receipts[0].id
        );
    }

    #[test]
    fn d9f1_r3_journal_write_failure_does_not_prevent_lock_and_warns() {
        let root = fixture_root().join(format!("receipt-denied-{:016x}", rand::random::<u64>()));
        std::fs::create_dir_all(&root).unwrap();
        let blocked = root.join("not-a-directory");
        std::fs::write(&blocked, b"test").unwrap();
        let p = fixture_in(&root);
        let v = vault::Vault::create_for(&p, "synthetic-D9F1-password", edition::Edition::Single)
            .unwrap();
        let mut b = Recording::new();
        b.mock = MockBackend::new()
            .with_platform_handoff(fido2::MockHandoffRefusal::OwnerNotForeground, 1);
        b.delete_error = true;
        let (state, calls) = state(Some(v), b);
        state
            .with_lock(|g| {
                g.registration_cleanup_journal =
                    Some(registration_cleanup_journal::Journal::new(blocked.clone()));
                Ok(())
            })
            .unwrap();
        assert!(d9f1_hello_handoff(&state).is_ok());
        assert!(
            lock_inner(&state, None).is_ok(),
            "storage failure must not block lock"
        );
        let notices = registration_cleanup_status_inner(&state).unwrap();
        assert!(notices.iter().any(|r| r.reason == "storage_unavailable"
            && r.cleanup == RegistrationCleanup::ManualRemovalRequired));
        assert_eq!(calls.lock().unwrap().delete, 1);
        std::fs::remove_file(blocked).unwrap();
    }

    // ── D9-F1 R4：journal 為權威狀態、前置失敗保守通知 ──

    fn d9f1_r4_root(tag: &str) -> std::path::PathBuf {
        fixture_root().join(format!("d9f1-r4-{tag}-{:016x}", rand::random::<u64>()))
    }

    fn d9f1_r4_attach_journal(s: &VaultState, root: &std::path::Path) {
        s.with_lock(|g| {
            g.registration_cleanup_journal = Some(registration_cleanup_journal::Journal::new(
                root.join("receipts"),
            ));
            Ok(())
        })
        .unwrap();
    }

    fn d9f1_r4_journal_state(
        root: &std::path::Path,
        handoffs: usize,
        delete_error: bool,
    ) -> (Fixture, VaultState, Arc<Mutex<Calls>>) {
        let p = fixture_in(root);
        let v = vault::Vault::create_for(&p, "synthetic-D9F1-password", edition::Edition::Single)
            .unwrap();
        let mut b = Recording::new();
        b.mock = MockBackend::new()
            .with_platform_handoff(fido2::MockHandoffRefusal::OwnerNotForeground, handoffs);
        b.delete_error = delete_error;
        let (s, c) = state(Some(v), b);
        d9f1_r4_attach_journal(&s, root);
        (p, s, c)
    }

    #[test]
    fn d9f1_r4_restart_journal_is_authoritative_for_cancel_and_continue() {
        let root = d9f1_r4_root("restart");
        let (p, first, _) = d9f1_r4_journal_state(&root, 1, true);
        assert!(d9f1_hello_handoff(&first).is_ok());
        assert!(lock_inner(&first, None).is_ok());
        drop(first);
        // Fresh process: same vault and journal, no pending, empty in-memory receipts.
        let v = vault::Vault::open_password(&p, "synthetic-D9F1-password").unwrap();
        let (restarted, calls) = state(Some(v), Recording::new());
        d9f1_r4_attach_journal(&restarted, &root);
        let cancelled = cancel_registration_inner(&restarted).unwrap();
        assert_eq!(
            cancelled.cleanup,
            RegistrationCleanup::ManualRemovalRequired,
            "an unacknowledged durable warning must not be downgraded to none after restart"
        );
        let resumed = continue_registration_inner(
            &restarted,
            edition::Edition::Single,
            |_| unreachable!("no pending: must not raise focus"),
            std::time::Instant::now,
        );
        assert!(
            matches!(&resumed, Err(m) if m.contains("通行金鑰")),
            "{resumed:?}"
        );
        let c = calls.lock().unwrap();
        assert_eq!((c.create, c.assert, c.delete), (0, 0, 0));
        drop(c);
        drop(p);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn d9f1_r4_cross_process_ack_is_honored_by_original_cancel_and_continue() {
        let root = d9f1_r4_root("cross-ack");
        let (p, original, _) = d9f1_r4_journal_state(&root, 1, true);
        assert!(d9f1_hello_handoff(&original).is_ok());
        assert!(lock_inner(&original, None).is_ok());
        assert!(login_password_inner(
            &original,
            &p,
            "synthetic-D9F1-password",
            edition::Edition::Single
        )
        .is_ok());
        let (other, _) = state(None, Recording::new());
        d9f1_r4_attach_journal(&other, &root);
        let receipts = registration_cleanup_status_inner(&other).unwrap();
        assert_eq!(receipts.len(), 1);
        assert!(acknowledge_registration_cleanup_inner(&other, &receipts[0].id).is_ok());
        let cancelled = cancel_registration_inner(&original).unwrap();
        assert_eq!(
            cancelled.cleanup,
            RegistrationCleanup::None,
            "an acknowledged receipt must not be reported again by another process"
        );
        let resumed = continue_registration_inner(
            &original,
            edition::Edition::Single,
            |_| unreachable!("no pending: must not raise focus"),
            std::time::Instant::now,
        );
        assert!(
            matches!(&resumed, Err(m) if !m.contains("通行金鑰")),
            "{resumed:?}"
        );
        drop(p);
        let _ = std::fs::remove_dir_all(&root);
    }

    fn d9f1_r4_assert_unverified_receipt(s: &VaultState, root: &std::path::Path, case: &str) {
        let receipts = registration_cleanup_status_inner(s).unwrap();
        assert!(
            receipts.iter().any(|r| r.reason == "unverified"
                && r.cleanup == RegistrationCleanup::ManualRemovalRequired),
            "{case}: {receipts:?}"
        );
        let (fresh, _) = state(None, Recording::new());
        d9f1_r4_attach_journal(&fresh, root);
        let reopened = registration_cleanup_status_inner(&fresh).unwrap();
        assert!(
            reopened.iter().any(|r| r.reason == "unverified"),
            "{case}: warning must survive restart: {reopened:?}"
        );
    }

    fn d9f1_r4_continue_precondition_case(case: &str, inject: impl FnOnce(&mut Calls)) {
        let root = d9f1_r4_root(case);
        let (p, s, calls) = d9f1_r4_journal_state(&root, 1, false);
        assert!(d9f1_hello_handoff(&s).is_ok());
        let asserts_before = calls.lock().unwrap().assert;
        inject(&mut calls.lock().unwrap());
        let result = continue_registration_inner(
            &s,
            edition::Edition::Single,
            |_| Ok(790),
            std::time::Instant::now,
        );
        assert!(result.is_err(), "{case}: {result:?}");
        assert!(!d9f1_has_pending(&s), "{case}");
        {
            let c = calls.lock().unwrap();
            assert_eq!(
                c.assert, asserts_before,
                "{case}: no assertion without preconditions"
            );
            assert_eq!(
                c.delete, 0,
                "{case}: unproven credential must never be deleted"
            );
        }
        d9f1_r4_assert_unverified_receipt(&s, &root, case);
        drop(p);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn d9f1_r4_continue_platform_unavailable_leaves_durable_warning() {
        d9f1_r4_continue_precondition_case("unavailable", |c| c.force_unavailable = true);
    }

    #[test]
    fn d9f1_r4_continue_discovery_error_leaves_durable_warning() {
        d9f1_r4_continue_precondition_case("discovery", |c| c.list_fail_from = Some(c.list + 1));
    }

    #[test]
    fn d9f1_r4_continue_membership_unproven_leaves_durable_warning() {
        d9f1_r4_continue_precondition_case("membership", |c| c.list_empty = true);
    }

    #[test]
    fn d9f1_r4_begin_post_create_discovery_failure_leaves_durable_warning() {
        let root = d9f1_r4_root("begin-discovery");
        let (p, s, calls) = d9f1_r4_journal_state(&root, 1, false);
        // List #1 (before MakeCredential) succeeds; list #2 (ownership proof) fails.
        calls.lock().unwrap().list_fail_from = Some(2);
        let result = d9f1_hello_handoff(&s);
        assert!(result.is_err(), "{result:?}");
        assert!(!d9f1_has_pending(&s));
        {
            let c = calls.lock().unwrap();
            assert_eq!((c.create, c.assert, c.delete), (1, 0, 0));
        }
        d9f1_r4_assert_unverified_receipt(&s, &root, "begin-discovery");
        drop(p);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn d9f1_r4_existing_slot_id_is_never_reported_as_new_orphan() {
        // A pending that names an already-registered credential is not evidence of a new
        // credential: neither delete nor an orphan receipt may be produced.
        let root = d9f1_r4_root("existing-id");
        let (p, s, calls) = d9f1_r4_journal_state(&root, 0, false);
        let registered = d9f1_hello_handoff(&s);
        assert!(
            matches!(&registered, Ok(RegisterResult::Registered { .. })),
            "{registered:?}"
        );
        let RegisterResult::Registered { credential } = registered.unwrap() else {
            unreachable!()
        };
        let forged = vault::PendingRegistration::Platform {
            credential,
            creation_prf: Zeroizing::new([7; 32]),
            label: "forged".into(),
        };
        s.with_lock(|g| {
            g.pending_registration = Some(PendingRegistrationSlot {
                pending: forged,
                deadline: std::time::Instant::now() + PENDING_REGISTRATION_TIMEOUT,
                vault_path: p.to_path_buf(),
                generation: 900,
            });
            Ok(())
        })
        .unwrap();
        let deletes_before = calls.lock().unwrap().delete;
        let result = continue_registration_inner(
            &s,
            edition::Edition::Single,
            |_| Ok(790),
            std::time::Instant::now,
        );
        assert!(result.is_err(), "{result:?}");
        assert_eq!(calls.lock().unwrap().delete, deletes_before);
        assert!(registration_cleanup_status_inner(&s).unwrap().is_empty());
        drop(p);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn d9f1_r2_old_generation_sweep_cannot_cancel_new_pending() {
        let (_p, state, calls) = d9f1_hello_state(2);
        assert!(d9f1_hello_handoff(&state).is_ok());
        let first_generation = state
            .with_lock(|g| {
                let slot = g.pending_registration.as_mut().unwrap();
                slot.deadline = std::time::Instant::now();
                Ok(slot.generation)
            })
            .unwrap();
        assert!(state
            .with_lock(|g| Ok(sweep_expired_registration(
                g,
                Some(first_generation),
                std::time::Instant::now()
            )))
            .unwrap());
        assert!(d9f1_hello_handoff(&state).is_ok());
        let new_deadline = state
            .with_lock(|g| Ok(g.pending_registration.as_ref().unwrap().deadline))
            .unwrap();
        let swept = state
            .with_lock(|g| {
                Ok(sweep_expired_registration(
                    g,
                    Some(first_generation),
                    new_deadline,
                ))
            })
            .unwrap();
        assert!(!swept);
        assert!(d9f1_has_pending(&state));
        assert_eq!(calls.lock().unwrap().delete, 1);
    }

    #[test]
    fn d9f1_r2_sweep_and_cancel_race_delete_at_most_once() {
        use std::sync::{Arc, Barrier};
        let (_p, state, calls) = d9f1_hello_state(1);
        assert!(d9f1_hello_handoff(&state).is_ok());
        let (generation, deadline) = state
            .with_lock(|g| {
                let slot = g.pending_registration.as_ref().unwrap();
                Ok((slot.generation, slot.deadline))
            })
            .unwrap();
        let state = Arc::new(state);
        let barrier = Arc::new(Barrier::new(3));
        let swept = {
            let state = Arc::clone(&state);
            let barrier = Arc::clone(&barrier);
            std::thread::spawn(move || {
                barrier.wait();
                state
                    .with_lock(|g| Ok(sweep_expired_registration(g, Some(generation), deadline)))
                    .unwrap()
            })
        };
        let cancelled = {
            let state = Arc::clone(&state);
            let barrier = Arc::clone(&barrier);
            std::thread::spawn(move || {
                barrier.wait();
                cancel_registration_inner(&state).unwrap().cleanup
            })
        };
        barrier.wait();
        let swept = swept.join().unwrap();
        let cancelled = cancelled.join().unwrap();
        assert!(
            matches!(
                (swept, cancelled),
                (true, RegistrationCleanup::None) | (false, RegistrationCleanup::Removed)
            ),
            "exactly one cleanup winner: swept={swept} cancelled={cancelled:?}"
        );
        assert!(!d9f1_has_pending(&state));
        let c = calls.lock().unwrap();
        assert_eq!(
            (c.delete, c.hwnd.len()),
            (1, 1),
            "one delete, no extra focus"
        );
        drop(c);
        assert!(registration_cleanup_status_inner(&state)
            .unwrap()
            .is_empty());
    }

    #[test]
    fn d9f1_r4_sweep_and_cancel_exact_results_in_both_orders() {
        for sweep_first in [true, false] {
            let (_p, state, calls) = d9f1_hello_state(1);
            assert!(d9f1_hello_handoff(&state).is_ok());
            let asserts = calls.lock().unwrap().assert;
            let (generation, deadline) = state
                .with_lock(|g| {
                    let slot = g.pending_registration.as_ref().unwrap();
                    Ok((slot.generation, slot.deadline))
                })
                .unwrap();
            let sweep = |s: &VaultState| {
                s.with_lock(|g| Ok(sweep_expired_registration(g, Some(generation), deadline)))
                    .unwrap()
            };
            let (swept, cancelled) = if sweep_first {
                let swept = sweep(&state);
                (swept, cancel_registration_inner(&state).unwrap().cleanup)
            } else {
                let cancelled = cancel_registration_inner(&state).unwrap().cleanup;
                (sweep(&state), cancelled)
            };
            let expected = if sweep_first {
                (true, RegistrationCleanup::None)
            } else {
                (false, RegistrationCleanup::Removed)
            };
            assert_eq!((swept, cancelled), expected, "sweep_first={sweep_first}");
            let c = calls.lock().unwrap();
            assert_eq!(
                (c.assert, c.delete),
                (asserts, 1),
                "sweep_first={sweep_first}"
            );
        }
    }

    #[test]
    fn d9f1_r4_local_appdata_must_be_absolute_for_the_journal() {
        let (journal, unavailable) = cleanup_journal_from_local_appdata(None);
        assert!(journal.is_none() && unavailable);
        for untrusted in ["", "relative\\AppData", "relative/AppData"] {
            let (journal, unavailable) = cleanup_journal_from_local_appdata(Some(untrusted.into()));
            assert!(
                journal.is_none() && unavailable,
                "{untrusted:?} must not be trusted"
            );
        }
        let absolute = fixture_root();
        let (journal, unavailable) =
            cleanup_journal_from_local_appdata(Some(absolute.clone().into()));
        assert!(!unavailable);
        assert_eq!(
            journal.unwrap().root(),
            absolute.join("FidoVault").join("registration-cleanup-v1")
        );
    }

    fn d9f1_r5_write_failure_case(
        tag: &str,
        inject: impl FnOnce(&mut registration_cleanup_journal::TestFaults),
        restart_reason: &str,
    ) {
        let root = d9f1_r4_root(tag);
        let (p, s, calls) = d9f1_r4_journal_state(&root, 1, true);
        s.with_lock(|g| {
            inject(&mut g.registration_cleanup_journal.as_ref().unwrap().faults());
            Ok(())
        })
        .unwrap();
        assert!(d9f1_hello_handoff(&s).is_ok());
        assert!(
            lock_inner(&s, None).is_ok(),
            "{tag}: storage failure must not block lock"
        );
        let now = registration_cleanup_status_inner(&s).unwrap();
        assert!(
            now.iter()
                .any(|r| r.reason == "storage_unavailable" && r.id.starts_with("memory-")),
            "{tag}: in-process fallback warning: {now:?}"
        );
        assert_eq!(
            cancel_registration_inner(&s).unwrap().cleanup,
            RegistrationCleanup::ManualRemovalRequired,
            "{tag}"
        );
        assert_eq!(calls.lock().unwrap().delete, 1, "{tag}");
        let (fresh, _) = state(None, Recording::new());
        d9f1_r4_attach_journal(&fresh, &root);
        let reopened = registration_cleanup_status_inner(&fresh).unwrap();
        assert!(
            reopened.iter().any(|r| r.reason == restart_reason),
            "{tag}: the failed receipt must stay a conservative warning after restart: {reopened:?}"
        );
        drop(p);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn d9f1_r4_journal_write_failure_warns_now_and_after_restart() {
        d9f1_r5_write_failure_case("after-create", |f| f.fail_after_create = true, "unknown");
    }

    #[test]
    fn d9f1_r5_journal_partial_write_warns_now_and_after_restart() {
        d9f1_r5_write_failure_case("partial", |f| f.partial_write = Some(3), "unknown");
    }

    #[test]
    fn d9f1_r5_journal_sync_failure_warns_now_and_after_restart() {
        d9f1_r5_write_failure_case("sync", |f| f.fail_sync = true, "locked");
    }

    /// End-to-end matrix: {begin, continue} x {assertion error, PRF mismatch, persist failure}
    /// x {delete ok, delete fails}. Checks the primary error, exact calls, slot rollback, the
    /// durable receipt, no-pending cancel and a fresh process.
    #[test]
    fn d9f1_r5_terminal_cleanup_matrix_is_durable_end_to_end() {
        let primary_assert = vault::VaultError::Fido(FidoError::NoDevice).to_string();
        let primary_prf = vault::VaultError::Fido(FidoError::PlatformPrfUnsupported).to_string();
        for phase in ["begin", "continue"] {
            for failure in ["assertion", "prf", "persist"] {
                for delete_fails in [false, true] {
                    let case = format!("{phase}/{failure}/delete_fails={delete_fails}");
                    let root = d9f1_r4_root(&format!("matrix-{phase}-{failure}-{delete_fails}"));
                    let handoffs = usize::from(phase == "continue");
                    let (p, s, calls) = d9f1_r4_journal_state(&root, handoffs, delete_fails);
                    // The failing assertion is the first (begin) or the second (continue).
                    let ordinal = 1 + handoffs;
                    let arm = |calls: &Arc<Mutex<Calls>>| {
                        let mut c = calls.lock().unwrap();
                        match failure {
                            "assertion" => c.assert_error_from = Some(ordinal),
                            "prf" => c.wrong_prf_from = Some(ordinal),
                            _ => {}
                        }
                    };
                    let tmp = p.with_extension("db.tmp");
                    let result = if phase == "begin" {
                        arm(&calls);
                        if failure == "persist" {
                            std::fs::create_dir(&tmp).unwrap();
                        }
                        d9f1_hello_handoff(&s).map(|_| ())
                    } else {
                        assert!(
                            matches!(
                                d9f1_hello_handoff(&s),
                                Ok(RegisterResult::HandoffRequired { .. })
                            ),
                            "{case}"
                        );
                        arm(&calls);
                        if failure == "persist" {
                            std::fs::create_dir(&tmp).unwrap();
                        }
                        continue_registration_inner(
                            &s,
                            edition::Edition::Single,
                            |_| Ok(790),
                            std::time::Instant::now,
                        )
                        .map(|_| ())
                    };
                    let error = result.expect_err(&case);
                    match failure {
                        "assertion" => assert_eq!(error, primary_assert, "{case}"),
                        "prf" => assert_eq!(error, primary_prf, "{case}"),
                        _ => assert!(error.starts_with("檔案錯誤"), "{case}: {error}"),
                    }
                    if failure == "persist" {
                        std::fs::remove_dir(&tmp).unwrap();
                    }
                    {
                        let c = calls.lock().unwrap();
                        assert_eq!(
                            (c.create, c.delete),
                            (1, 1),
                            "{case}: one credential, one delete"
                        );
                        assert_eq!(c.assert, ordinal, "{case}: no extra assertion");
                    }
                    assert!(!d9f1_has_pending(&s), "{case}");
                    let header = vault::Vault::read_header(&p, edition::Edition::Single).unwrap();
                    assert!(header.key_slots.is_empty(), "{case}: slot rolled back");
                    let receipts = registration_cleanup_status_inner(&s).unwrap();
                    let cancelled = cancel_registration_inner(&s).unwrap().cleanup;
                    let (fresh, _) = state(None, Recording::new());
                    d9f1_r4_attach_journal(&fresh, &root);
                    let reopened = registration_cleanup_status_inner(&fresh).unwrap();
                    if delete_fails {
                        assert!(
                            receipts.iter().any(|r| r.reason == "continue_error"),
                            "{case}: {receipts:?}"
                        );
                        assert_eq!(
                            cancelled,
                            RegistrationCleanup::ManualRemovalRequired,
                            "{case}"
                        );
                        assert!(
                            reopened.iter().any(|r| r.reason == "continue_error"),
                            "{case}: {reopened:?}"
                        );
                    } else {
                        assert!(
                            receipts.is_empty(),
                            "{case}: Removed must not leave a receipt: {receipts:?}"
                        );
                        assert_eq!(cancelled, RegistrationCleanup::None, "{case}");
                        assert!(reopened.is_empty(), "{case}: {reopened:?}");
                    }
                    drop(p);
                    let _ = std::fs::remove_dir_all(&root);
                }
            }
        }
    }

    #[test]
    fn d9f1_r5_sync_keeps_memory_fallbacks_and_generations() {
        let root = d9f1_r4_root("memory-generation");
        let (p, s, _) = d9f1_r4_journal_state(&root, 1, false);
        s.with_lock(|g| {
            g.registration_cleanup_receipts
                .push(RegistrationCleanupReceipt {
                    id: "memory-5".into(),
                    generation: 5,
                    reason: "storage_unavailable",
                    cleanup: RegistrationCleanup::ManualRemovalRequired,
                });
            record_registration_cleanup(g, 77, "expired");
            Ok(())
        })
        .unwrap();
        for round in 0..2 {
            let receipts = registration_cleanup_status_inner(&s).unwrap();
            assert_eq!(
                receipts.len(),
                2,
                "round {round}: no loss, no duplicates: {receipts:?}"
            );
            assert!(
                receipts
                    .iter()
                    .any(|r| r.id == "memory-5" && r.generation == 5),
                "round {round}: memory fallback must survive journal sync"
            );
            assert!(
                receipts.iter().any(|r| !r.id.starts_with("memory-")
                    && r.generation == 77
                    && r.reason == "expired"),
                "round {round}: durable receipt keeps its generation: {receipts:?}"
            );
        }
        drop(p);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn d9f1_r2_wrong_vault_or_repeated_continue_never_reasserts() {
        let (_p, state, calls) = d9f1_hello_state(1);
        assert!(d9f1_hello_handoff(&state).is_ok());
        let initial_asserts = calls.lock().unwrap().assert;
        state
            .with_lock(|g| {
                g.pending_registration.as_mut().unwrap().vault_path =
                    std::path::PathBuf::from("other-vault.db");
                Ok(())
            })
            .unwrap();
        let mut focus_calls = 0;
        let result = continue_registration_inner(
            &state,
            edition::Edition::Single,
            |_| {
                focus_calls += 1;
                Ok(123)
            },
            std::time::Instant::now,
        );
        assert!(
            matches!(&result, Err(message) if message.contains("金庫已變更")),
            "{result:?}"
        );
        let second = continue_registration_inner(
            &state,
            edition::Edition::Single,
            |_| {
                focus_calls += 1;
                Ok(123)
            },
            std::time::Instant::now,
        );
        assert!(second.is_err());
        assert_eq!(focus_calls, 0);
        let c = calls.lock().unwrap();
        assert_eq!((c.assert, c.delete), (initial_asserts, 1));
    }

    #[test]
    fn d9f1_r2_successful_continue_consumes_pending_once() {
        let (_p, state, calls) = d9f1_hello_state(1);
        assert!(d9f1_hello_handoff(&state).is_ok());
        assert!(matches!(
            continue_registration_inner(
                &state,
                edition::Edition::Single,
                |_| Ok(790),
                std::time::Instant::now
            ),
            Ok(RegisterResult::Registered { .. })
        ));
        let assertions = calls.lock().unwrap().assert;
        let mut focus_calls = 0;
        let again = continue_registration_inner(
            &state,
            edition::Edition::Single,
            |_| {
                focus_calls += 1;
                Ok(790)
            },
            std::time::Instant::now,
        );
        assert!(again.is_err());
        assert_eq!(focus_calls, 0);
        assert_eq!(calls.lock().unwrap().assert, assertions);
    }

    #[test]
    fn d9f1_cancel_reports_each_cleanup_value() {
        for delete_error in [false, true] {
            let p = fixture();
            let v =
                vault::Vault::create_for(&p, "synthetic-D9F1-password", edition::Edition::Single)
                    .unwrap();
            let mut b = Recording::new();
            b.mock = MockBackend::new()
                .with_platform_handoff(fido2::MockHandoffRefusal::OwnerNotForeground, 1);
            b.delete_error = delete_error;
            let (s, c) = state(Some(v), b);
            assert!(d9f1_hello_handoff(&s).is_ok());
            let info = cancel_registration_inner(&s);
            assert!(info.is_ok());
            let json = serde_json::to_value(info.unwrap()).unwrap();
            let expected = if delete_error {
                "manual_removal_required"
            } else {
                "removed"
            };
            assert_eq!(
                json,
                serde_json::json!({"status": "cancelled", "cleanup": expected})
            );
            assert!(!d9f1_has_pending(&s));
            assert_eq!(
                c.lock().unwrap().delete,
                1,
                "cancel attempts the delete once"
            );
            let none = serde_json::to_value(cancel_registration_inner(&s).unwrap()).unwrap();
            // R2 contract: until explicit acknowledgement, failed cleanup is retained;
            // successful cleanup still reports none when repeated.
            let repeated = if delete_error {
                "manual_removal_required"
            } else {
                "none"
            };
            assert_eq!(
                none,
                serde_json::json!({"status": "cancelled", "cleanup": repeated})
            );
        }

        let p = fixture();
        let v = vault::Vault::create_for(&p, "synthetic-D9F1-password", edition::Edition::Single)
            .unwrap();
        let mut b = Recording::new();
        b.mock = MockBackend::new()
            .with_next_kind(fido2::KeyKind::TouchOnly)
            .with_roaming_handoff(fido2::MockHandoffRefusal::ForegroundHandoffRequired, 1);
        let (s, c) = state(Some(v), b);
        let result = register_key_inner(&s, |_| Ok(5), None, "synthetic-roaming", None);
        assert!(
            matches!(&result, Ok(RegisterResult::HandoffRequired { .. })),
            "{result:?}"
        );
        let json = serde_json::to_value(cancel_registration_inner(&s).unwrap()).unwrap();
        assert_eq!(
            json,
            serde_json::json!({"status": "cancelled", "cleanup": "discarded"})
        );
        assert_eq!(c.lock().unwrap().delete, 0);
    }

    #[test]
    fn d9f1_roaming_register_then_continue_completes_slot() {
        let p = fixture();
        let v = vault::Vault::create_for(&p, "synthetic-D9F1-password", edition::Edition::Single)
            .unwrap();
        let mut b = Recording::new();
        b.mock = MockBackend::new()
            .with_next_kind(fido2::KeyKind::TouchOnly)
            .with_roaming_handoff(fido2::MockHandoffRefusal::ForegroundHandoffRequired, 1);
        let (s, c) = state(Some(v), b);
        let result = register_key_inner(&s, |_| Ok(5), None, "synthetic-roaming", None);
        assert!(
            matches!(&result, Ok(RegisterResult::HandoffRequired { .. })),
            "{result:?}"
        );
        assert!(d9f1_has_pending(&s));
        let result = continue_registration_inner(
            &s,
            edition::Edition::Single,
            |_| Ok(6),
            std::time::Instant::now,
        );
        assert!(
            matches!(&result, Ok(RegisterResult::Registered { credential }) if credential.label == "synthetic-roaming"),
            "{result:?}"
        );
        assert_eq!(
            vault::Vault::read_header(&p, edition::Edition::Single)
                .unwrap()
                .key_slots
                .len(),
            1
        );
        assert_eq!(c.lock().unwrap().hwnd, vec![5, 6]);
    }

    #[test]
    fn d9f1_lock_login_and_remove_cancel_pending_with_platform_delete() {
        // lock
        let (_p, s, c) = d9f1_hello_state(1);
        assert!(d9f1_hello_handoff(&s).is_ok());
        assert!(lock_inner(&s, None).is_ok());
        assert!(!d9f1_has_pending(&s));
        assert_eq!(c.lock().unwrap().delete, 1);

        // successful login replacing the session
        let (p, s, c) = d9f1_hello_state(1);
        assert!(d9f1_hello_handoff(&s).is_ok());
        let login =
            login_password_inner(&s, &p, "synthetic-D9F1-password", edition::Edition::Single);
        assert!(login.is_ok(), "{:?}", login.err());
        assert!(!d9f1_has_pending(&s));
        assert_eq!(c.lock().unwrap().delete, 1);

        // key removal changes the key list
        let (_p, s, c) = d9f1_hello_state(1);
        assert!(d9f1_hello_handoff(&s).is_ok());
        let removal = remove_key_inner(&s, "unknown-id", edition::Edition::Single);
        assert!(removal.is_err());
        assert!(!d9f1_has_pending(&s));
        assert_eq!(c.lock().unwrap().delete, 1);
    }

    #[test]
    fn d9f1_dual_edition_refuses_hello_pending_continue_before_focus() {
        let (_p, s, c) = d9f1_hello_state(1);
        assert!(d9f1_hello_handoff(&s).is_ok());
        let asserts = c.lock().unwrap().assert;
        let mut focus = 0;
        let result = continue_registration_inner(
            &s,
            edition::Edition::Dual,
            |_| {
                focus += 1;
                Ok(790)
            },
            std::time::Instant::now,
        );
        assert!(
            matches!(&result, Err(m) if m.contains("單人版")),
            "{result:?}"
        );
        assert_eq!(focus, 0);
        assert_eq!(
            c.lock().unwrap().assert,
            asserts,
            "no assertion in dual edition"
        );
    }

    #[test]
    fn d9f1_registration_ipcs_are_registered_and_wired() {
        let source = include_str!("lib.rs").replace(char::from(13), "");
        let commands = source
            .split(".invoke_handler(tauri::generate_handler![")
            .nth(1)
            .unwrap()
            .split("])")
            .next()
            .unwrap();
        for (command, helper) in [
            ("continue_registration", "continue_registration_inner("),
            ("cancel_registration", "cancel_registration_inner(&state)"),
            (
                "registration_cleanup_status",
                "registration_cleanup_status_inner(&state)",
            ),
            (
                "acknowledge_registration_cleanup",
                "acknowledge_registration_cleanup_inner(&state",
            ),
        ] {
            assert!(
                commands.lines().any(|l| l.trim() == format!("{command},")),
                "{command} must be registered"
            );
            // Concatenated marker so this test does not find itself.
            let marker = ["fn ", command, "(\n"].concat();
            let alt = ["fn ", command, "(state:"].concat();
            let body = source
                .split(&marker)
                .nth(1)
                .or_else(|| source.split(&alt).nth(1))
                .expect("command exists")
                .split("#[tauri::command]")
                .next()
                .unwrap();
            assert!(body.contains(helper), "{command} must call {helper}");
        }
        let continue_body = source
            .split(&["fn continue_registration", "(\n"].concat())
            .nth(1)
            .unwrap()
            .split("\n}\n")
            .next()
            .unwrap();
        assert!(continue_body.contains("raise_key_operation_window(&window, required)"));
    }

    #[test]
    fn d9f1_no_new_active_foreground_api_calls() {
        fn production(source: &str, marker: &str) -> String {
            let source = source.replace(char::from(13), "");
            source.split(marker).next().unwrap().to_owned()
        }
        let lib = production(include_str!("lib.rs"), "\n#[cfg(test)]\n");
        let webauthn = production(
            include_str!("windows_webauthn.rs"),
            "\n#[cfg(test)]\nmod tests {",
        );
        // Existing, reviewed calls only: the raise helper and the broker monitor.
        assert_eq!(lib.matches("SetForegroundWindow(").count(), 1);
        assert_eq!(lib.matches("ShowWindow(").count(), 1);
        assert_eq!(webauthn.matches("SetForegroundWindow(").count(), 1);
        assert_eq!(webauthn.matches(".activate(").count(), 1);
        for source in [&lib, &webauthn] {
            for forbidden in [
                "AllowSetForegroundWindow",
                "AttachThreadInput",
                "BringWindowToTop",
                "SwitchToThisWindow",
                "SetActiveWindow",
                "keybd_event",
                "SendInput",
                "ASFW_ANY",
                "LockSetForegroundWindow",
            ] {
                assert!(!source.contains(forbidden), "{forbidden}");
            }
        }
        // The D9-F1 additions are passive: no activation inside them.
        for (start, end) in [
            ("fn continuation_refusal_error(", "\n}\n"),
            ("fn foreground_owner_details(", "\n}\n"),
            ("fn log_foreground_owner(", "\n}\n"),
            ("fn log_pre_api_refusal<T>(", "\n}\n"),
        ] {
            let body = webauthn
                .split(start)
                .nth(1)
                .unwrap()
                .split(end)
                .next()
                .unwrap();
            assert!(
                !body.contains("activate") && !body.contains("SetForeground"),
                "{start}"
            );
        }
    }
    #[test]
    fn d9f2_substituted_platform_attestation_leaves_no_slot_and_a_durable_warning() {
        let p = fixture();
        let v = vault::Vault::create_for(&p, "synthetic-D9F2-password", edition::Edition::Single)
            .unwrap();
        let mut b = Recording::new();
        b.mock = MockBackend::new().with_platform_mode(fido2::MockPlatformMode::Substituted);
        let (s, c) = state(Some(v), b);
        let before = std::fs::read(&p).unwrap();
        let result = d9f1_hello_handoff(&s);
        assert!(
            matches!(&result, Err(m) if m.contains("安全性金鑰完成")),
            "{result:?}"
        );
        assert_eq!(std::fs::read(&p).unwrap(), before, "no slot is written");
        assert!(!d9f1_has_pending(&s));
        {
            let c = c.lock().unwrap();
            assert_eq!(
                (c.create, c.assert, c.delete),
                (1, 0, 0),
                "no platform delete for a non-local credential"
            );
        }
        let receipts = s
            .with_lock(|g| Ok(g.registration_cleanup_receipts.clone()))
            .unwrap();
        assert_eq!(receipts.len(), 1, "{receipts:?}");
        assert_eq!(receipts[0].reason, "unverified");
        assert_eq!(
            receipts[0].cleanup,
            RegistrationCleanup::ManualRemovalRequired
        );
    }

    // ───────────── D9-F2：WebAuthn 指令移出主執行緒 ─────────────

    #[derive(Clone, Copy, PartialEq, Eq)]
    enum Gate {
        RoamingAssertion,
        PlatformRegister,
    }

    /// Delegates to `Recording`, but parks the calling thread inside one ceremony call until the
    /// test releases it (or panics there on request). One-shot: only the first call parks.
    struct GateBackend {
        inner: Recording,
        gate: Gate,
        armed: Arc<std::sync::atomic::AtomicBool>,
        panic_instead: bool,
        entered: std::sync::mpsc::Sender<()>,
        release: std::sync::mpsc::Receiver<()>,
    }

    impl GateBackend {
        fn hold(&self, at: Gate) {
            if self.gate != at || !self.armed.swap(false, std::sync::atomic::Ordering::SeqCst) {
                return;
            }
            let _ = self.entered.send(());
            let _ = self
                .release
                .recv_timeout(std::time::Duration::from_secs(20));
            if self.panic_instead {
                panic!("synthetic backend panic inside ceremony");
            }
        }
    }

    impl FidoBackend for GateBackend {
        fn detect(&mut self) -> std::result::Result<fido2::DetectedKey, FidoError> {
            self.inner.detect()
        }
        fn register_credential(
            &mut self,
            d: &fido2::DetectedKey,
            pin: Option<&str>,
        ) -> std::result::Result<fido2::RegisteredCredential, FidoError> {
            self.inner.register_credential(d, pin)
        }
        fn get_prf_secret(
            &mut self,
            id: &[u8],
            pin: Option<&str>,
        ) -> std::result::Result<[u8; 32], FidoError> {
            self.hold(Gate::RoamingAssertion);
            self.inner.get_prf_secret(id, pin)
        }
        fn prf_supported(&self) -> bool {
            self.inner.prf_supported()
        }
        fn platform_status(&self) -> PlatformStatus {
            self.inner.platform_status()
        }
        fn list_platform_credentials(&mut self) -> std::result::Result<Vec<Vec<u8>>, FidoError> {
            self.inner.list_platform_credentials()
        }
        fn register_platform_credential(
            &mut self,
            label: &str,
            exclude: &[Vec<u8>],
        ) -> std::result::Result<fido2::PlatformRegistration, FidoError> {
            self.hold(Gate::PlatformRegister);
            self.inner.register_platform_credential(label, exclude)
        }
        fn get_platform_prf_secret(
            &mut self,
            ids: &[Vec<u8>],
        ) -> std::result::Result<(Vec<u8>, [u8; 32]), FidoError> {
            self.inner.get_platform_prf_secret(ids)
        }
        fn delete_platform_credential(&mut self, id: &[u8]) -> std::result::Result<(), FidoError> {
            self.inner.delete_platform_credential(id)
        }
        fn set_webauthn_parent_hwnd(&mut self, handle: isize) {
            self.inner.set_webauthn_parent_hwnd(handle)
        }
    }

    struct Gated {
        p: Fixture,
        state: Arc<VaultState>,
        calls: Arc<Mutex<Calls>>,
        entered: std::sync::mpsc::Receiver<()>,
        release: std::sync::mpsc::Sender<()>,
        key_id: String,
    }

    /// `login`: locked vault with one roaming key (gate in the assertion). Otherwise an unlocked
    /// vault for registration (gate in the platform makeCredential).
    fn gated(gate: Gate, panic_instead: bool, mock: Option<MockBackend>) -> Gated {
        let p = fixture();
        let mut v =
            vault::Vault::create_for(&p, "synthetic-D9F2-password", edition::Edition::Single)
                .unwrap();
        let mut key_id = String::new();
        let login = gate == Gate::RoamingAssertion;
        if login {
            let mut roaming = MockBackend::new();
            let reg = v
                .register_key_with_label(&mut roaming, None, "synthetic-roaming")
                .unwrap();
            key_id = crypto::base64_encode(&reg.credential_id);
        }
        let v = if login {
            v.lock();
            None
        } else {
            Some(v)
        };
        let mut inner = Recording::new();
        if let Some(mock) = mock {
            inner.mock = mock;
        }
        let calls = inner.calls.clone();
        let (entered_tx, entered) = std::sync::mpsc::channel();
        let (release, release_rx) = std::sync::mpsc::channel();
        let backend = GateBackend {
            inner,
            gate,
            armed: Arc::new(std::sync::atomic::AtomicBool::new(true)),
            panic_instead,
            entered: entered_tx,
            release: release_rx,
        };
        let (state, _) = state(v, Recording::new());
        state
            .with_lock(|g| {
                g.backend = Box::new(backend);
                Ok(())
            })
            .unwrap();
        Gated {
            p,
            state: Arc::new(state),
            calls,
            entered,
            release,
            key_id,
        }
    }

    /// Runs `f` on a helper thread; `None` = it did not return within 2 seconds.
    fn within<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> Option<T> {
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _ = tx.send(f());
        });
        rx.recv_timeout(std::time::Duration::from_secs(2)).ok()
    }

    fn spawn_login(g: &Gated) -> std::thread::JoinHandle<Result<Vec<vault::Entry>>> {
        let state = Arc::clone(&g.state);
        let path = g.p.path.clone();
        let id = g.key_id.clone();
        let task =
            std::thread::spawn(move || login_key_inner(&state, &path, &id, None, |_| Ok(790)));
        g.entered
            .recv_timeout(std::time::Duration::from_secs(30))
            .expect("the ceremony never reached the backend");
        task
    }

    fn spawn_register(g: &Gated) -> std::thread::JoinHandle<Result<RegisterResult>> {
        let state = Arc::clone(&g.state);
        let task = std::thread::spawn(move || d9f1_hello_handoff(&state));
        g.entered
            .recv_timeout(std::time::Duration::from_secs(30))
            .expect("the ceremony never reached the backend");
        task
    }

    fn key_op_snapshot(state: &Arc<VaultState>) -> Option<(bool, bool, bool)> {
        let state = Arc::clone(state);
        within(move || {
            state
                .with_lock(|g| {
                    Ok((
                        g.key_op.active,
                        g.key_op.pending_lock.is_some(),
                        g.vault.is_some(),
                    ))
                })
                .unwrap()
        })
    }

    #[test]
    fn d9f2_main_thread_style_commands_return_while_a_login_ceremony_is_parked() {
        let g = gated(Gate::RoamingAssertion, false, None);
        let task = spawn_login(&g);
        let st = Arc::clone(&g.state);
        let list = within(move || with_unlocked(&st, |v| Ok(v.entries().len())));
        let st = Arc::clone(&g.state);
        let settings = within(move || with_unlocked(&st, |v| Ok(v.settings().clone())));
        let st = Arc::clone(&g.state);
        let status = within(move || {
            query_platform_status(&st, std::path::Path::new("D:/nonexistent/none.db"), edition::Edition::Single)
        });
        let st = Arc::clone(&g.state);
        let path = g.p.path.clone();
        let locked = within(move || lock_inner_at(&st, None, &path, edition::Edition::Single));
        let snapshot = key_op_snapshot(&g.state);
        g.release.send(()).unwrap();
        let login = task.join().unwrap();
        assert!(list.is_some(), "list_entries waited for the ceremony");
        assert!(settings.is_some(), "get_vault_settings waited for the ceremony");
        assert!(status.is_some(), "platform_status waited for the ceremony");
        assert!(locked.is_some(), "lock waited for the ceremony");
        // While the ceremony runs the vault is not unlocked: the answer is "busy", never a
        // misleading "locked" that would flip the UI.
        assert_eq!(list.unwrap().unwrap_err(), KEY_OPERATION_BUSY_MSG);
        assert_eq!(settings.unwrap().unwrap_err(), KEY_OPERATION_BUSY_MSG);
        assert_eq!(status.unwrap().unwrap_err(), KEY_OPERATION_BUSY_MSG);
        assert!(locked.unwrap().is_ok(), "lock during a ceremony is deferred, not an error");
        assert_eq!(snapshot, Some((true, true, false)));
        // The deferred lock discards the login result and exposes no entries.
        assert_eq!(login.unwrap_err(), KEY_OPERATION_LOCKED_MSG);
        assert_eq!(key_op_snapshot(&g.state), Some((false, false, false)));
    }

    #[test]
    fn d9f2_lock_during_login_returns_login_screen_info_and_keeps_the_vault_locked() {
        let g = gated(Gate::RoamingAssertion, false, None);
        let task = spawn_login(&g);
        let st = Arc::clone(&g.state);
        let path = g.p.path.clone();
        let info = within(move || lock_inner_at(&st, Some("idle".into()), &path, edition::Edition::Single));
        g.release.send(()).unwrap();
        let login = task.join().unwrap();
        let info = info.expect("lock must not wait for the ceremony").unwrap();
        assert!(info.has_vault);
        assert_eq!(info.keys.len(), 1, "login screen lists the vault keys");
        assert!(login.is_err());
        let snapshot = key_op_snapshot(&g.state);
        assert_eq!(snapshot, Some((false, false, false)));
    }

    #[test]
    fn d9f2_lock_during_successful_registration_locks_before_the_response() {
        let g = gated(Gate::PlatformRegister, false, None);
        let task = spawn_register(&g);
        let st = Arc::clone(&g.state);
        let list = within(move || with_unlocked(&st, |v| Ok(v.entries().len())));
        let st = Arc::clone(&g.state);
        let path = g.p.path.clone();
        let locked = within(move || lock_inner_at(&st, None, &path, edition::Edition::Single));
        g.release.send(()).unwrap();
        let registered = task.join().unwrap();
        assert_eq!(
            list.expect("list_entries waited for the ceremony").unwrap_err(),
            KEY_OPERATION_BUSY_MSG
        );
        assert!(locked.expect("lock waited for the ceremony").is_ok());
        assert!(
            matches!(&registered, Ok(RegisterResult::Registered { .. })),
            "{registered:?}"
        );
        assert_eq!(key_op_snapshot(&g.state), Some((false, false, false)));
        let header = vault::Vault::read_header(&g.p, edition::Edition::Single).unwrap();
        assert_eq!(header.key_slots.len(), 1, "the completed registration is persisted");
    }

    #[test]
    fn d9f2_lock_during_registration_handoff_cancels_pending_with_existing_cleanup() {
        let mock = MockBackend::new()
            .with_platform_handoff(fido2::MockHandoffRefusal::OwnerNotForeground, 1);
        let g = gated(Gate::PlatformRegister, false, Some(mock));
        let task = spawn_register(&g);
        let st = Arc::clone(&g.state);
        let path = g.p.path.clone();
        let locked = within(move || lock_inner_at(&st, None, &path, edition::Edition::Single));
        g.release.send(()).unwrap();
        let result = task.join().unwrap();
        assert!(locked.expect("lock waited for the ceremony").is_ok());
        assert_eq!(result.unwrap_err(), KEY_OPERATION_LOCKED_MSG);
        assert_eq!(key_op_snapshot(&g.state), Some((false, false, false)));
        assert!(!d9f1_has_pending(&g.state), "locking cancels the pending registration");
        assert_eq!(g.calls.lock().unwrap().delete, 1, "RP-proven local credential is deleted");
        let header = vault::Vault::read_header(&g.p, edition::Edition::Single).unwrap();
        assert!(header.key_slots.is_empty());
    }

    #[test]
    fn d9f2_second_key_operation_is_rejected_without_focus_or_backend() {
        let g = gated(Gate::RoamingAssertion, false, None);
        let task = spawn_login(&g);
        let before = {
            let c = g.calls.lock().unwrap();
            (c.status, c.list, c.create, c.assert, c.delete, c.hwnd.len())
        };
        let raised = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let mut outcomes: Vec<(&str, Option<String>)> = Vec::new();
        macro_rules! second {
            ($name:expr, $call:expr) => {{
                let st = Arc::clone(&g.state);
                let raised = Arc::clone(&raised);
                let path = g.p.path.clone();
                let id = g.key_id.clone();
                let _ = (&st, &raised, &path, &id);
                let out = within(move || {
                    let raise = |_: bool| {
                        raised.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                        Ok(1)
                    };
                    let _ = &raise;
                    $call(&st, &path, &id, raise)
                });
                outcomes.push(($name, out.map(|r: Result<()>| r.unwrap_err())));
            }};
        }
        second!("login_key", |st: &VaultState, path: &std::path::Path, id: &str, raise| {
            login_key_inner(st, path, id, None, raise).map(|_| ())
        });
        second!("login_any_key", |st: &VaultState, path: &std::path::Path, _id: &str, raise| {
            login_any_key_inner(st, path, raise).map(|_| ())
        });
        second!("login_windows_hello", |st: &VaultState, path: &std::path::Path, _id: &str, raise| {
            login_windows_hello_inner(st, path, edition::Edition::Single, raise).map(|_| ())
        });
        second!("register_windows_hello", |st: &VaultState, _p: &std::path::Path, _id: &str, raise| {
            register_windows_hello_inner(
                st,
                edition::Edition::Single,
                raise,
                || Ok("SYNTHETIC".into()),
            )
            .map(|_| ())
        });
        second!("register_key", |st: &VaultState, _p: &std::path::Path, _id: &str, raise| {
            register_key_inner(st, raise, None, "synthetic-label", None).map(|_| ())
        });
        second!("continue_registration", |st: &VaultState, _p: &std::path::Path, _id: &str, raise| {
            continue_registration_inner(
                st,
                edition::Edition::Single,
                raise,
                std::time::Instant::now,
            )
            .map(|_| ())
        });
        second!("login_dual_begin", |st: &VaultState, path: &std::path::Path, _id: &str, raise| {
            login_dual_begin_inner(st, path, None, raise, |_, _| {}).map(|_| ())
        });
        second!("login_dual_complete", |st: &VaultState, _p: &std::path::Path, _id: &str, raise| {
            login_dual_complete_inner(st, None, raise).map(|_| ())
        });
        let after = {
            let c = g.calls.lock().unwrap();
            (c.status, c.list, c.create, c.assert, c.delete, c.hwnd.len())
        };
        g.release.send(()).unwrap();
        let first = task.join().unwrap();
        for (name, outcome) in &outcomes {
            assert_eq!(
                outcome.as_deref(),
                Some(KEY_OPERATION_BUSY_MSG),
                "{name} must be rejected immediately"
            );
        }
        assert_eq!(
            raised.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "a rejected operation never touches the foreground"
        );
        assert_eq!(before, after, "a rejected operation never reaches the backend");
        assert!(first.is_ok(), "the original ceremony is unaffected: {first:?}");
        assert_eq!(key_op_snapshot(&g.state), Some((false, false, true)));
    }

    #[test]
    fn d9f2_guard_is_released_after_error_and_after_panic() {
        // Error path.
        let g = gated(Gate::RoamingAssertion, false, None);
        g.release.send(()).unwrap();
        let wrong = login_key_inner(&g.state, &g.p, "bm90LWEta2V5", None, |_| Ok(1));
        assert!(wrong.is_err());
        assert_eq!(key_op_snapshot(&g.state), Some((false, false, false)));
        let ok = login_key_inner(&g.state, &g.p, &g.key_id, None, |_| Ok(1));
        assert!(ok.is_ok(), "{ok:?}");

        // Raise failure (no backend call) also releases.
        let g = gated(Gate::RoamingAssertion, false, None);
        let refused = login_key_inner(&g.state, &g.p, &g.key_id, None, |_| Err("no foreground".into()));
        assert_eq!(refused.unwrap_err(), "no foreground");
        assert_eq!(key_op_snapshot(&g.state), Some((false, false, false)));

        // Panic inside the ceremony: guard released, real backend restored, vault still locked.
        let g = gated(Gate::RoamingAssertion, true, None);
        g.release.send(()).unwrap();
        let state = Arc::clone(&g.state);
        let path = g.p.path.clone();
        let id = g.key_id.clone();
        let panicked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            login_key_inner(&state, &path, &id, None, |_| Ok(1))
        }));
        assert!(panicked.is_err());
        assert_eq!(key_op_snapshot(&g.state), Some((false, false, false)));
        let restored = {
            let st = Arc::clone(&g.state);
            within(move || st.with_lock(|g| Ok(g.backend.key_unavailable_reason())))
        };
        assert_eq!(restored.map(|r| r.unwrap()), Some(None), "real backend must be back");
        let again = login_key_inner(&g.state, &g.p, &g.key_id, None, |_| Ok(1));
        assert!(again.is_ok(), "{again:?}");
    }

    #[test]
    fn d9f2_panic_after_a_deferred_lock_still_locks_and_releases() {
        let g = gated(Gate::PlatformRegister, true, None);
        let state = Arc::clone(&g.state);
        let task = std::thread::spawn(move || {
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| d9f1_hello_handoff(&state)))
        });
        g.entered
            .recv_timeout(std::time::Duration::from_secs(30))
            .expect("the ceremony never reached the backend");
        let st = Arc::clone(&g.state);
        let path = g.p.path.clone();
        let locked = within(move || lock_inner_at(&st, None, &path, edition::Edition::Single));
        g.release.send(()).unwrap();
        assert!(task.join().unwrap().is_err(), "the synthetic panic propagates");
        assert!(locked.expect("lock waited for the ceremony").is_ok());
        // Fail closed: the unlocked vault that was leased to the panicking ceremony is locked.
        assert_eq!(key_op_snapshot(&g.state), Some((false, false, false)));
    }

    #[test]
    fn d9f2_vault_changing_commands_are_rejected_while_a_key_operation_is_active() {
        let g = gated(Gate::RoamingAssertion, false, None);
        let task = spawn_login(&g);
        let fresh = fixture();
        let (st, p) = (Arc::clone(&g.state), g.p.path.clone());
        let login_pw = within(move || {
            login_password_inner(&st, &p, "synthetic-D9F2-password", edition::Edition::Single)
        });
        let (st, f) = (Arc::clone(&g.state), fresh.path.clone());
        let create = within(move || {
            create_vault_inner(&st, &f, "synthetic-password-8", edition::Edition::Single)
        });
        let (st, p) = (Arc::clone(&g.state), g.p.path.clone());
        let id = g.key_id.clone();
        let remove = within(move || {
            let _ = &p;
            remove_key_inner(&st, &id, edition::Edition::Single)
        });
        let st = Arc::clone(&g.state);
        let cancel = within(move || cancel_registration_inner(&st));
        let st = Arc::clone(&g.state);
        let csv = within(move || apply_csv_import_inner(&st, "token".into()));
        let snapshot = key_op_snapshot(&g.state);
        g.release.send(()).unwrap();
        let first = task.join().unwrap();
        assert_eq!(login_pw.expect("login_password queued behind the ceremony").unwrap_err(), KEY_OPERATION_BUSY_MSG);
        assert_eq!(create.expect("create_vault queued behind the ceremony").unwrap_err(), KEY_OPERATION_BUSY_MSG);
        assert!(!fresh.path.exists(), "create_vault must not create a file while busy");
        assert_eq!(remove.expect("remove_key queued behind the ceremony").unwrap_err(), KEY_OPERATION_BUSY_MSG);
        assert_eq!(cancel.expect("cancel_registration queued").unwrap_err(), KEY_OPERATION_BUSY_MSG);
        assert_eq!(csv.expect("apply_csv_import queued").unwrap_err(), KEY_OPERATION_BUSY_MSG);
        // The rejected login_password did not publish a vault: only the ceremony's own result did.
        assert_eq!(snapshot, Some((true, false, false)));
        assert!(first.is_ok());
        assert_eq!(key_op_snapshot(&g.state), Some((false, false, true)));
        let header = vault::Vault::read_header(&g.p, edition::Edition::Single).unwrap();
        assert_eq!(header.key_slots.len(), 1, "remove_key changed nothing");
    }


    // ───────────── D9-F2 R2：審查阻擋項回歸測試 ─────────────

    fn r2_counts(calls: &Arc<Mutex<Calls>>) -> (usize, usize, usize, usize, usize, usize) {
        let c = calls.lock().unwrap();
        (c.status, c.list, c.create, c.assert, c.delete, c.hwnd.len())
    }

    /// Unlocked single-edition vault that owns one roaming key, plus a recording backend.
    fn r2_unlocked_vault() -> (Fixture, Arc<VaultState>, Arc<Mutex<Calls>>, String) {
        let p = fixture();
        let mut v =
            vault::Vault::create_for(&p, "synthetic-R2-password", edition::Edition::Single)
                .unwrap();
        let mut roaming = MockBackend::new();
        let reg = v
            .register_key_with_label(&mut roaming, None, "synthetic-roaming")
            .unwrap();
        let key_id = crypto::base64_encode(&reg.credential_id);
        let (s, calls) = state(Some(v), Recording::new());
        (p, Arc::new(s), calls, key_id)
    }

    #[test]
    fn d9f2_r2_s1_every_key_login_is_refused_while_the_vault_is_unlocked() {
        let (p, s, calls, key_id) = r2_unlocked_vault();
        let raised = std::sync::atomic::AtomicUsize::new(0);
        let raise = |_: bool| {
            raised.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(1)
        };
        let before = r2_counts(&calls);
        let outcomes: Vec<(&str, std::result::Result<(), String>)> = vec![
            (
                "login_key",
                login_key_inner(&s, &p, &key_id, None, raise).map(|_| ()),
            ),
            ("login_any_key", login_any_key_inner(&s, &p, raise).map(|_| ())),
            (
                "login_windows_hello",
                login_windows_hello_inner(&s, &p, edition::Edition::Single, raise).map(|_| ()),
            ),
            (
                "login_dual_begin",
                login_dual_begin_inner(&s, &p, None, raise, |_, _| {}).map(|_| ()),
            ),
            (
                "login_dual_complete",
                login_dual_complete_inner(&s, None, raise).map(|_| ()),
            ),
        ];
        for (name, outcome) in outcomes {
            let message = outcome.err().unwrap_or_default();
            assert!(
                message.contains("金庫已解鎖"),
                "{name} must refuse a new key login while the vault is unlocked, got {message:?}"
            );
        }
        assert_eq!(raised.load(std::sync::atomic::Ordering::SeqCst), 0);
        assert_eq!(before, r2_counts(&calls), "a refused login never reaches the backend");
        assert_eq!(key_op_snapshot(&s), Some((false, false, true)));

        // Nothing can later overwrite the vault with an older snapshot: a write made now survives
        // a lock + key login (which re-reads the file).
        with_unlocked(&s, |v| {
            v.add_entry("synthetic-site", "synthetic-account", "synthetic-pw", "")
                .map_err(|e| e.to_string())
        })
        .unwrap();
        lock_inner_at(&s, None, &p, edition::Edition::Single).unwrap();
        let entries = login_key_inner(&s, &p, &key_id, None, |_| Ok(1)).unwrap();
        assert_eq!(entries.len(), 1, "the entry written while unlocked is not lost");
    }

    #[test]
    fn d9f2_r2_s1_readers_and_writers_refuse_while_an_operation_or_deferred_lock_is_pending() {
        let (p, s, _calls, _) = r2_unlocked_vault();
        with_unlocked(&s, |v| {
            v.add_entry("synthetic-site", "synthetic-account", "synthetic-pw", "")
                .map_err(|e| e.to_string())
        })
        .unwrap();
        let on_disk = std::fs::read(&p).unwrap();
        for (active, pending_lock) in [(true, None), (true, Some(None)), (false, Some(None))] {
            s.with_lock(|g| {
                g.key_op.active = active;
                g.key_op.pending_lock = pending_lock.clone();
                Ok(())
            })
            .unwrap();
            let label = format!("active={active} pending_lock={pending_lock:?}");
            let results: Vec<(&str, std::result::Result<(), String>)> = vec![
                ("list_entries", with_unlocked(&s, |v| Ok(v.entries().len())).map(|_| ())),
                (
                    "add_entry",
                    with_unlocked(&s, |v| {
                        v.add_entry("later", "later", "later", "")
                            .map(|_| ())
                            .map_err(|e| e.to_string())
                    }),
                ),
                (
                    "get_vault_settings",
                    with_unlocked(&s, |v| Ok(v.settings().clone())).map(|_| ()),
                ),
                (
                    "set_idle_lock",
                    with_unlocked(&s, |v| v.set_idle_lock(7).map_err(|e| e.to_string())),
                ),
                ("list_audit", with_unlocked(&s, |v| Ok(v.audit().len())).map(|_| ())),
            ];
            for (name, result) in results {
                assert!(
                    result.is_err(),
                    "{name} returned data / accepted a write while {label}"
                );
                if active {
                    assert_eq!(result.unwrap_err(), KEY_OPERATION_BUSY_MSG, "{name} {label}");
                }
            }
        }
        s.with_lock(|g| {
            g.key_op.active = false;
            g.key_op.pending_lock = None;
            Ok(())
        })
        .unwrap();
        assert_eq!(std::fs::read(&p).unwrap(), on_disk, "no write reached the vault file");
        assert_eq!(with_unlocked(&s, |v| Ok(v.entries().len())).unwrap(), 1);
    }

    fn r2_hello_pending_state(
        delete_error: bool,
    ) -> (Fixture, Arc<VaultState>, Arc<Mutex<Calls>>) {
        let p = fixture();
        let v = vault::Vault::create_for(&p, "synthetic-R2-password", edition::Edition::Single)
            .unwrap();
        let mut b = Recording::new();
        b.mock = MockBackend::new()
            .with_platform_handoff(fido2::MockHandoffRefusal::OwnerNotForeground, 1);
        b.delete_error = delete_error;
        let (s, calls) = state(Some(v), b);
        let s = Arc::new(s);
        assert!(d9f1_hello_handoff(&s).is_ok());
        assert!(d9f1_has_pending(&s));
        (p, s, calls)
    }

    #[test]
    fn d9f2_r2_s2_expiry_missed_while_an_operation_was_active_is_completed_by_the_operation() {
        for delete_error in [false, true] {
            for panics in [false, true] {
                let case = format!("delete_error={delete_error} panics={panics}");
                let (_p, s, calls) = r2_hello_pending_state(delete_error);
                let early = std::time::Instant::now();
                let deadline = early + std::time::Duration::from_millis(300);
                let generation = s
                    .with_lock(|g| {
                        let slot = g.pending_registration.as_mut().unwrap();
                        slot.deadline = deadline;
                        Ok(slot.generation)
                    })
                    .unwrap();
                let state_ref = Arc::clone(&s);
                let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    continue_registration_inner(
                        &s,
                        edition::Edition::Single,
                        |_| {
                            while std::time::Instant::now() < deadline {
                                std::thread::sleep(std::time::Duration::from_millis(20));
                            }
                            // The one-shot expiry timer fires now, while this operation is active.
                            let swept = sweep_expired_registration_off_lock(
                                &state_ref,
                                Some(generation),
                                std::time::Instant::now(),
                            );
                            assert!(!swept, "the timer cannot clean while the backend is leased");
                            if panics {
                                panic!("synthetic panic after the skipped timer");
                            }
                            Err("no foreground".into())
                        },
                        // The operation itself still believes the pending is alive.
                        move || early,
                    )
                }));
                assert_eq!(outcome.is_err(), panics, "{case}");
                assert!(
                    !d9f1_has_pending(&s),
                    "{case}: the pending registration must not outlive its deadline"
                );
                assert_eq!(calls.lock().unwrap().delete, 1, "{case}: the credential is deleted once");
                let receipts = s
                    .with_lock(|g| Ok(g.registration_cleanup_receipts.clone()))
                    .unwrap();
                if delete_error {
                    assert_eq!(receipts.len(), 1, "{case}: {receipts:?}");
                    assert_eq!(receipts[0].reason, "expired", "{case}");
                    assert_eq!(receipts[0].cleanup, RegistrationCleanup::ManualRemovalRequired);
                } else {
                    assert!(receipts.is_empty(), "{case}: {receipts:?}");
                }
                assert_eq!(key_op_snapshot(&s), Some((false, false, true)), "{case}");
            }
        }
    }

    /// One parked native call, plus everything that must stay alive while it is parked.
    struct L2Case {
        name: &'static str,
        state: Arc<VaultState>,
        ticket: HoldTicket,
        task: std::thread::JoinHandle<()>,
        _keep: Vec<Fixture>,
    }

    fn l2_spawn(
        name: &'static str,
        state: Arc<VaultState>,
        ticket: HoldTicket,
        keep: Vec<Fixture>,
        op: impl FnOnce(Arc<VaultState>) + Send + 'static,
    ) -> L2Case {
        let worker_state = Arc::clone(&state);
        let task = std::thread::spawn(move || op(worker_state));
        // Generous: some scenarios run an Argon2id derivation (slow in debug builds, and slower
        // still while the whole suite runs in parallel) before reaching the parked native call.
        ticket
            .entered
            .recv_timeout(std::time::Duration::from_secs(240))
            .unwrap_or_else(|_| panic!("{name}: the native call was never reached"));
        L2Case {
            name,
            state,
            ticket,
            task,
            _keep: keep,
        }
    }

    fn l2_case(name: &'static str) -> L2Case {
        let single = edition::Edition::Single;
        match name {
            "deferred_lock_cleanup_in_complete" => {
                let (p, s, c) = d9f1_hello_state(1);
                let (hold, ticket) = new_hold();
                c.lock().unwrap().hold_delete = Some(hold);
                let path = p.path.clone();
                l2_spawn(name, Arc::new(s), ticket, vec![p], move |s| {
                    let locker = Arc::clone(&s);
                    let _ = register_windows_hello_inner(
                        &s,
                        single,
                        move |_| {
                            lock_inner_at(&locker, None, &path, single).unwrap();
                            Ok(1)
                        },
                        || Ok("SYNTHETIC".into()),
                    );
                })
            }
            "continue_timeout_cleanup" => {
                let (p, s, c) = r2_hello_pending_state(false);
                let (hold, ticket) = new_hold();
                c.lock().unwrap().hold_delete = Some(hold);
                l2_spawn(name, s, ticket, vec![p], move |s| {
                    let base = std::time::Instant::now();
                    let mut n = 0;
                    let _ = continue_registration_inner(&s, single, |_| Ok(1), move || {
                        n += 1;
                        if n == 1 {
                            base
                        } else {
                            base + std::time::Duration::from_secs(100_000)
                        }
                    });
                })
            }
            "platform_status_list" => {
                let (p, s, c) = d9f1_hello_state(1);
                let (hold, ticket) = new_hold();
                c.lock().unwrap().hold_list = Some(hold);
                let path = p.path.clone();
                l2_spawn(name, Arc::new(s), ticket, vec![p], move |s| {
                    let _ = query_platform_status(&s, &path, single);
                })
            }
            "idle_lock_with_pending" => {
                let (p, s, c) = r2_hello_pending_state(false);
                let (hold, ticket) = new_hold();
                c.lock().unwrap().hold_delete = Some(hold);
                let path = p.path.clone();
                l2_spawn(name, s, ticket, vec![p], move |s| {
                    let _ = lock_inner_at(&s, None, &path, single);
                })
            }
            "remove_key_platform_delete" => {
                let p = fixture();
                let mut b = Recording::new();
                let mut v =
                    vault::Vault::create_for(&p, "synthetic-R2-password", single).unwrap();
                v.register_windows_hello(&mut b.mock, "SYNTHETIC", single).unwrap();
                let id = vault::Vault::read_header(&p, single).unwrap().key_slots[0]
                    .credential_id
                    .clone();
                let (s, c) = state(Some(v), b);
                let (hold, ticket) = new_hold();
                c.lock().unwrap().hold_delete = Some(hold);
                l2_spawn(name, Arc::new(s), ticket, vec![p], move |s| {
                    let _ = remove_key_inner(&s, &id, single);
                })
            }
            "cancel_registration_delete" => {
                let (p, s, c) = r2_hello_pending_state(false);
                let (hold, ticket) = new_hold();
                c.lock().unwrap().hold_delete = Some(hold);
                l2_spawn(name, s, ticket, vec![p], move |s| {
                    let _ = cancel_registration_inner(&s);
                })
            }
            "expiry_timer_delete" => {
                let (p, s, c) = r2_hello_pending_state(false);
                let generation = s
                    .with_lock(|g| {
                        let slot = g.pending_registration.as_mut().unwrap();
                        slot.deadline = std::time::Instant::now();
                        Ok(slot.generation)
                    })
                    .unwrap();
                let (hold, ticket) = new_hold();
                c.lock().unwrap().hold_delete = Some(hold);
                l2_spawn(name, s, ticket, vec![p], move |s| {
                    let _ = sweep_expired_registration_off_lock(
                        &s,
                        Some(generation),
                        std::time::Instant::now(),
                    );
                })
            }
            "boot_info_list" => {
                let (p, s, c) = d9f1_hello_state(1);
                let (hold, ticket) = new_hold();
                c.lock().unwrap().hold_list = Some(hold);
                let path = p.path.clone();
                l2_spawn(name, Arc::new(s), ticket, vec![p], move |s| {
                    let _ = boot_info_inner(&s, &path, single);
                })
            }
            "create_vault_cancels_pending" => {
                let (p, s, c) = r2_hello_pending_state(false);
                let (hold, ticket) = new_hold();
                c.lock().unwrap().hold_delete = Some(hold);
                let fresh = fixture();
                let target = fresh.path.clone();
                l2_spawn(name, s, ticket, vec![p, fresh], move |s| {
                    let _ = create_vault_inner(&s, &target, "synthetic-password-8", single);
                })
            }
            "login_password_cancels_pending" => {
                let (p, s, c) = r2_hello_pending_state(false);
                let (hold, ticket) = new_hold();
                c.lock().unwrap().hold_delete = Some(hold);
                let path = p.path.clone();
                l2_spawn(name, s, ticket, vec![p], move |s| {
                    let _ = login_password_inner(&s, &path, "synthetic-R2-password", single);
                })
            }
            other => panic!("unknown scenario {other}"),
        }
    }

    #[test]
    fn d9f2_r2_l2_native_work_never_parks_main_thread_style_queries() {
        let mut stuck = Vec::new();
        for name in [
            "deferred_lock_cleanup_in_complete",
            "continue_timeout_cleanup",
            "platform_status_list",
            "idle_lock_with_pending",
            "remove_key_platform_delete",
            "cancel_registration_delete",
            "expiry_timer_delete",
            "boot_info_list",
            "create_vault_cancels_pending",
            "login_password_cancels_pending",
        ] {
            let case = l2_case(name);
            let probe = Arc::clone(&case.state);
            let answered = within(move || {
                let _ = with_unlocked(&probe, |v| Ok(v.entries().len()));
                let _ = with_unlocked(&probe, |v| Ok(v.settings().clone()));
                let _ = registration_cleanup_status_inner(&probe);
            });
            if answered.is_none() {
                stuck.push(case.name);
            }
            case.ticket.release.send(()).unwrap();
            case.task.join().unwrap();
        }
        assert!(
            stuck.is_empty(),
            "main-thread style queries waited for native work in: {stuck:?}"
        );
    }

    #[test]
    fn d9f2_r3_lock_during_post_publication_cleanup_never_returns_entries() {
        let (p, state, calls) = r2_hello_pending_state(false);
        let (hold, ticket) = new_hold();
        calls.lock().unwrap().hold_delete = Some(hold);
        let path = p.path.clone();
        let worker_state = Arc::clone(&state);
        let worker = std::thread::spawn(move || {
            login_password_inner(&worker_state, &path, "synthetic-R2-password", edition::Edition::Single)
        });
        ticket.entered.recv_timeout(std::time::Duration::from_secs(30)).expect("cleanup not reached");
        let locked = lock_inner_at(&state, Some("manual".into()), &p.path, edition::Edition::Single);
        ticket.release.send(()).unwrap();
        assert!(locked.is_ok(), "lock should be acknowledged while native cleanup is active");
        let response = worker.join().unwrap();
        assert_eq!(response.err().as_deref(), Some(KEY_OPERATION_LOCKED_MSG),
            "a late lock must discard a prepared login result, never return secret entries");
        assert_eq!(key_op_snapshot(&state), Some((false, false, false)));
        assert!(with_unlocked(&state, |v| Ok(v.entries().len())).is_err());
    }

    #[test]
    fn d9f2_r3_lock_in_empty_cleanup_gap_discards_login_before_return() {
        let (p, state, _, _) = r2_unlocked_vault();
        lock_inner_at(&state, None, &p.path, edition::Edition::Single).unwrap();
        let (mut guard, ()) = KeyOperationGuard::begin_login(&state, |_| Ok(())).unwrap();
        let opened = vault::Vault::open_password_for(&p.path, "synthetic-R2-password", edition::Edition::Single)
            .map_err(|e| e.to_string());
        let result = guard.finish(
            Some(|g: &mut AppInner, deferred| publish_login(g, opened, deferred, |_| {})),
            true,
            || {
                // No queued native work: lock exactly after publication drops the state lock.
                lock_inner_at(&state, Some("manual".into()), &p.path, edition::Edition::Single).unwrap();
            },
        ).unwrap();
        assert_eq!(result.err().as_deref(), Some(KEY_OPERATION_LOCKED_MSG));
        assert_eq!(key_op_snapshot(&state), Some((false, false, false)));
        assert!(with_unlocked(&state, |v| Ok(v.entries().len())).is_err());
    }

    #[test]
    fn d9f2_r2_l3_dual_cancel_is_rejected_while_a_key_operation_is_active() {
        let p = fixture();
        let (s, _c) = state(None, Recording::new());
        let seed = |s: &VaultState| {
            s.with_lock(|g| {
                g.dual_pending = Some(vault::DualPending::for_test(
                    p.path.clone(),
                    std::time::Instant::now(),
                ));
                Ok(())
            })
            .unwrap();
        };
        let has_pending = |s: &VaultState| s.with_lock(|g| Ok(g.dual_pending.is_some())).unwrap();

        // Cancel issued from inside a running first step.
        let mid_begin: Arc<Mutex<Option<std::result::Result<(), String>>>> =
            Arc::new(Mutex::new(None));
        let slot = Arc::clone(&mid_begin);
        let s = Arc::new(s);
        let canceller = Arc::clone(&s);
        let begun = login_dual_begin_inner(
            &s,
            &p.path,
            None,
            move |_| {
                *slot.lock().unwrap() = Some(login_dual_cancel_inner(&canceller));
                Err("stop before the backend".into())
            },
            |_, _| {},
        );
        assert!(begun.is_err());
        assert_eq!(
            mid_begin.lock().unwrap().take().unwrap().err().as_deref(),
            Some(KEY_OPERATION_BUSY_MSG),
            "cancel during the first step must report busy, not success"
        );

        // Cancel issued from inside a running second step: the stored first step survives.
        seed(&s);
        let mid_complete: Arc<Mutex<Option<std::result::Result<(), String>>>> =
            Arc::new(Mutex::new(None));
        let slot = Arc::clone(&mid_complete);
        let canceller = Arc::clone(&s);
        let completed = login_dual_complete_inner(&s, None, move |_| {
            *slot.lock().unwrap() = Some(login_dual_cancel_inner(&canceller));
            Err("stop before the backend".into())
        });
        assert!(completed.is_err());
        assert_eq!(
            mid_complete.lock().unwrap().take().unwrap().err().as_deref(),
            Some(KEY_OPERATION_BUSY_MSG),
            "cancel during the second step must report busy, not a no-op success"
        );
        assert!(has_pending(&s), "the rejected cancel left the first step untouched");

        // Idle: cancel works as before.
        assert!(login_dual_cancel_inner(&s).is_ok());
        assert!(!has_pending(&s));
    }

    #[test]
    fn d9f2_r2_l1_second_create_is_refused_while_the_first_holds_the_reservation() {
        let (s, _c) = state(None, Recording::new());
        let s = Arc::new(s);
        let fx = fixture();
        let (entered_tx, entered) = std::sync::mpsc::channel::<()>();
        let (release, release_rx) = std::sync::mpsc::channel::<()>();
        let (first_state, first_path) = (Arc::clone(&s), fx.path.clone());
        let first = std::thread::spawn(move || {
            create_vault_inner_with_hook(
                &first_state,
                &first_path,
                "synthetic-password-A1",
                edition::Edition::Single,
                move || {
                    let _ = entered_tx.send(());
                    let _ = release_rx.recv_timeout(std::time::Duration::from_secs(20));
                },
            )
        });
        entered
            .recv_timeout(std::time::Duration::from_secs(30))
            .expect("the first creation never reached its reservation point");
        let (second_state, second_path) = (Arc::clone(&s), fx.path.clone());
        let second = within(move || {
            create_vault_inner(
                &second_state,
                &second_path,
                "synthetic-password-B2",
                edition::Edition::Single,
            )
        });
        let list = {
            let st = Arc::clone(&s);
            within(move || with_unlocked(&st, |v| Ok(v.entries().len())))
        };
        let file_exists_while_parked = fx.path.exists();
        release.send(()).unwrap();
        let first = first.join().unwrap();
        let second = second.expect("the second creation must be refused immediately");
        assert_eq!(second.err().as_deref(), Some(KEY_OPERATION_BUSY_MSG));
        assert!(list.is_some(), "a main-thread style query must not wait for the creation");
        assert!(!file_exists_while_parked, "no file work happens before the reservation holder runs");
        assert!(first.is_ok(), "{first:?}");
        // The memory state and the disk agree on one creation.
        assert_eq!(key_op_snapshot(&s), Some((false, false, true)));
        let in_memory = s
            .with_lock(|g| Ok(g.vault.take().unwrap().lock()))
            .unwrap();
        let on_disk = vault::Vault::read_header(&fx.path, edition::Edition::Single).unwrap();
        assert_eq!(
            serde_json::to_string(&in_memory).unwrap(),
            serde_json::to_string(&on_disk).unwrap()
        );
    }

    #[test]
    fn d9f2_r2_l1_two_concurrent_creates_on_one_path_succeed_exactly_once() {
        let (s, _c) = state(None, Recording::new());
        let s = Arc::new(s);
        let fx = fixture();
        let barrier = Arc::new(std::sync::Barrier::new(2));
        let workers: Vec<_> = ["synthetic-password-A1", "synthetic-password-B2"]
            .into_iter()
            .map(|password| {
                let (s, path, barrier) = (Arc::clone(&s), fx.path.clone(), Arc::clone(&barrier));
                std::thread::spawn(move || {
                    barrier.wait();
                    create_vault_inner(&s, &path, password, edition::Edition::Single)
                })
            })
            .collect();
        let results: Vec<_> = workers.into_iter().map(|w| w.join().unwrap()).collect();
        assert_eq!(
            results.iter().filter(|r| r.is_ok()).count(),
            1,
            "{results:?}"
        );
        let in_memory = s
            .with_lock(|g| Ok(g.vault.take().expect("the winner is published").lock()))
            .unwrap();
        let on_disk = vault::Vault::read_header(&fx.path, edition::Edition::Single).unwrap();
        assert_eq!(
            serde_json::to_string(&in_memory).unwrap(),
            serde_json::to_string(&on_disk).unwrap(),
            "the in-memory vault must be the one that is on disk"
        );
    }

    fn r2_torn_publication(g: &AppInner) -> bool {
        g.vault.is_some() && (g.pending_csv_import.is_some() || g.dual_pending.is_some())
    }

    #[test]
    fn d9f2_r2_login_publication_is_never_observed_half_done() {
        // Positive: a sampler hammering the state lock across a whole Hello login never sees the
        // vault published while the pending state it must clear is still there.
        let p = fixture();
        let mut b = Recording::new();
        let mut v = vault::Vault::create_for(&p, "synthetic-R2-password", edition::Edition::Single)
            .unwrap();
        v.register_windows_hello(&mut b.mock, "SYNTHETIC", edition::Edition::Single)
            .unwrap();
        v.lock();
        let (s, _c) = state(None, b);
        seed_pending(&s, &p);
        let s = Arc::new(s);
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let sampler = {
            let (s, stop) = (Arc::clone(&s), Arc::clone(&stop));
            std::thread::spawn(move || {
                let (mut samples, mut torn, mut published) = (0usize, 0usize, 0usize);
                while !stop.load(std::sync::atomic::Ordering::SeqCst) {
                    s.with_lock(|g| {
                        samples += 1;
                        torn += usize::from(r2_torn_publication(g));
                        published += usize::from(g.vault.is_some());
                        Ok(())
                    })
                    .unwrap();
                }
                (samples, torn, published)
            })
        };
        let login = login_windows_hello_inner(&s, &p, edition::Edition::Single, |_| Ok(5));
        // Make sure the sampler also observes the settled state.
        std::thread::sleep(std::time::Duration::from_millis(50));
        stop.store(true, std::sync::atomic::Ordering::SeqCst);
        let (samples, torn, published) = sampler.join().unwrap();
        assert!(login.is_ok(), "{login:?}");
        assert!(samples > 0 && published > 0, "the sampler must have seen the published vault");
        assert_eq!(torn, 0, "publication and clearing of pending state must be one step");
    }

    #[test]
    fn d9f2_r2_negative_control_split_publication_is_detected_by_the_same_observer() {
        let p = fixture();
        let (s, _c) = state(None, Recording::new());
        seed_pending(&s, &p);
        let s = Arc::new(s);
        let reached = Arc::new(std::sync::Barrier::new(2));
        let resume = Arc::new(std::sync::Barrier::new(2));
        let publisher = {
            let (s, reached, resume, path) =
                (Arc::clone(&s), Arc::clone(&reached), Arc::clone(&resume), p.path.clone());
            std::thread::spawn(move || {
                let vault = vault::Vault::create_for(
                    &path.with_file_name("split.db"),
                    "synthetic-R2-password",
                    edition::Edition::Single,
                )
                .unwrap();
                // Deliberately wrong: publish under one lock, clear pending under another.
                s.with_lock(|g| {
                    g.vault = Some(vault);
                    Ok(())
                })
                .unwrap();
                reached.wait();
                resume.wait();
                s.with_lock(|g| {
                    g.pending_csv_import = None;
                    g.dual_pending = None;
                    Ok(())
                })
                .unwrap();
            })
        };
        reached.wait();
        let torn = s.with_lock(|g| Ok(r2_torn_publication(g))).unwrap();
        resume.wait();
        publisher.join().unwrap();
        assert!(torn, "the observer must catch a publication split across two locks");
    }

    /// D9-F2 inventory (see docs/plans/windows-hello-single.md §13). Every IPC is classified; a
    /// command that can reach `FidoBackend`/WebAuthn (UI, CTAP transaction, platform list/delete,
    /// UVPA query) must not run on the Tauri main thread.
    const D9F2_WEBAUTHN_COMMANDS: &[&str] = &[
        "boot_info",
        "platform_status",
        "register_windows_hello",
        "login_windows_hello",
        "create_vault",
        "login_password",
        "login_key",
        "login_any_key",
        "login_dual_begin",
        "login_dual_complete",
        "lock",
        "register_key",
        "continue_registration",
        "cancel_registration",
        "remove_key",
        "detect_key",
    ];

    /// Reviewed: never touches the backend (state/vault/journal/dialog/clipboard only).
    const D9F2_NON_WEBAUTHN_COMMANDS: &[&str] = &[
        "get_edition",
        "login_dual_cancel",
        "list_entries",
        "preview_csv_import",
        "save_csv_template",
        "cancel_csv_import",
        "apply_csv_import",
        "add_entry",
        "update_entry",
        "delete_entry",
        "list_audit",
        "registration_cleanup_status",
        "acknowledge_registration_cleanup",
        "validate_key_label",
        "suggest_key_label",
        "set_idle_lock",
        "set_dual_step_timeout",
        "get_vault_settings",
        "set_password_history_limit",
        "clear_clipboard_if_matches",
    ];

    fn d9f2_production_source() -> String {
        let source = include_str!("lib.rs").replace(char::from(13), "");
        source.split("\n#[cfg(test)]\n").next().unwrap().to_owned()
    }

    /// `Some(true)` = off the main thread (`async fn` or `#[tauri::command(async)]`).
    fn d9f2_command_is_off_main_thread(source: &str, name: &str) -> Option<bool> {
        for (needle, async_fn) in [
            (format!("\nasync fn {name}("), true),
            (format!("\nfn {name}("), false),
        ] {
            let Some(pos) = source.find(&needle) else {
                continue;
            };
            let attribute = source[..pos].trim_end().lines().last()?.trim();
            if !attribute.starts_with("#[tauri::command") {
                return None;
            }
            return Some(async_fn || attribute == "#[tauri::command(async)]");
        }
        None
    }

    fn d9f2_registered_commands(source: &str) -> Vec<String> {
        source
            .split(".invoke_handler(tauri::generate_handler![")
            .nth(1)
            .unwrap()
            .split("])")
            .next()
            .unwrap()
            .lines()
            .map(|line| line.trim().trim_end_matches(',').to_owned())
            .filter(|line| !line.is_empty())
            .collect()
    }

    #[test]
    fn d9f2_every_webauthn_command_runs_off_the_main_thread() {
        let source = d9f2_production_source();
        let mut registered = d9f2_registered_commands(&source);
        registered.sort();
        let mut classified: Vec<String> = D9F2_WEBAUTHN_COMMANDS
            .iter()
            .chain(D9F2_NON_WEBAUTHN_COMMANDS)
            .map(|name| name.to_string())
            .collect();
        classified.sort();
        assert_eq!(
            registered, classified,
            "a new or removed IPC must be classified as WebAuthn-reaching or not"
        );
        for name in D9F2_WEBAUTHN_COMMANDS {
            assert_eq!(
                d9f2_command_is_off_main_thread(&source, name),
                Some(true),
                "{name} reaches WebAuthn and must be #[tauri::command(async)] or async fn"
            );
        }
    }

    #[test]
    fn d9f2_non_webauthn_commands_do_not_touch_the_backend() {
        let source = d9f2_production_source();
        for name in D9F2_NON_WEBAUTHN_COMMANDS {
            let body = d9f2_function_text(&source, name);
            for forbidden in [
                "backend",
                "KeyOperationGuard",
                "raise_key_operation_window",
                "FidoBackend",
            ] {
                assert!(
                    !body.contains(forbidden),
                    "{name} is classified as non-WebAuthn but mentions {forbidden}"
                );
            }
        }
    }

    /// Text of the function whose signature starts with `fn name(`, up to its closing brace.
    fn d9f2_function_text(source: &str, name: &str) -> String {
        let marker = ["fn ", name, "("].concat();
        source
            .split(marker.as_str())
            .nth(1)
            .unwrap_or_else(|| panic!("{name} not found"))
            .split("
}
")
            .next()
            .unwrap()
            .to_owned()
    }

    fn d9f2_strip_comments(text: &str) -> String {
        text.lines()
            .map(|line| line.find("//").map_or(line, |at| &line[..at]))
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// Free functions called (not methods, not `path::calls`) in `body`.
    fn d9f2_free_callees(body: &str) -> std::collections::BTreeSet<String> {
        let chars: Vec<char> = body.chars().collect();
        let mut found = std::collections::BTreeSet::new();
        let mut i = 0;
        while i < chars.len() {
            if chars[i].is_alphabetic() || chars[i] == '_' {
                let start = i;
                while i < chars.len() && (chars[i].is_alphanumeric() || chars[i] == '_') {
                    i += 1;
                }
                let preceded_by_path_or_method = start > 0 && matches!(chars[start - 1], '.' | ':');
                if i < chars.len() && chars[i] == '(' && !preceded_by_path_or_method {
                    found.insert(chars[start..i].iter().collect());
                }
            } else {
                i += 1;
            }
        }
        found
    }

    const D9F2_BACKEND_MARKERS: &[&str] = &[
        "backend",
        "KeyOperationGuard",
        "raise_key_operation_window",
        "FidoBackend",
        "platform_status",
        "list_platform_credentials",
        "delete_platform_credential",
    ];

    /// Every marker mentioned by `name` or by any free function it (transitively) calls.
    fn d9f2_backend_reach(source: &str, name: &str) -> Vec<(String, &'static str)> {
        let mut seen = std::collections::BTreeSet::new();
        let mut queue = vec![name.to_owned()];
        let mut hits = Vec::new();
        while let Some(current) = queue.pop() {
            if !seen.insert(current.clone()) {
                continue;
            }
            let marker = ["fn ", current.as_str(), "("].concat();
            if !source.contains(marker.as_str()) {
                continue; // not a function defined in this file
            }
            let body = d9f2_strip_comments(&d9f2_function_text(source, &current));
            for marker in D9F2_BACKEND_MARKERS {
                if body.contains(marker) {
                    hits.push((current.clone(), *marker));
                }
            }
            queue.extend(d9f2_free_callees(&body));
        }
        hits
    }

    #[test]
    fn d9f2_non_webauthn_commands_reach_no_backend_through_helpers() {
        let source = d9f2_production_source();
        for name in D9F2_NON_WEBAUTHN_COMMANDS {
            let hits = d9f2_backend_reach(&source, name);
            assert!(
                hits.is_empty(),
                "{name} is classified as non-WebAuthn but reaches the backend through {hits:?}"
            );
        }
    }

    #[test]
    fn d9f2_helper_reach_scanner_follows_calls_and_ignores_comments_and_methods() {
        let sample = "fn cmd() {\n    helper();\n}\n\nfn helper() {\n    inner(); // backend in a comment\n    x.method();\n}\n\nfn inner() {\n    g.backend.platform_status();\n}\n\nfn method() {\n    backend;\n}\n";
        let hits = d9f2_backend_reach(sample, "cmd");
        assert!(hits.iter().any(|(f, m)| f == "inner" && *m == "backend"), "{hits:?}");
        assert!(hits.iter().all(|(f, _)| f != "helper" && f != "method"), "{hits:?}");
        let clean = "fn cmd() {\n    helper();\n}\n\nfn helper() {\n    let a = 1; // backend\n}\n";
        assert!(d9f2_backend_reach(clean, "cmd").is_empty());
    }

    #[test]
    fn d9f2_contract_detector_distinguishes_sync_async_and_unattributed_functions() {
        let sample = "#[tauri::command]\nfn plain(a: u8) {}\n\n#[tauri::command(async)]\nfn pooled(a: u8) {}\n\n#[tauri::command]\nasync fn native(a: u8) {}\n\nfn helper() {}\n";
        assert_eq!(d9f2_command_is_off_main_thread(sample, "plain"), Some(false));
        assert_eq!(d9f2_command_is_off_main_thread(sample, "pooled"), Some(true));
        assert_eq!(d9f2_command_is_off_main_thread(sample, "native"), Some(true));
        assert_eq!(d9f2_command_is_off_main_thread(sample, "helper"), None);
        assert_eq!(d9f2_command_is_off_main_thread(sample, "missing"), None);
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
            pending_registration: None,
            registration_generation: 0,
            registration_cleanup_receipts: Vec::new(),
            registration_cleanup_journal: None,
            registration_cleanup_storage_unavailable: false,
            key_op: KeyOpState::default(),
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
            pending_registration: None,
            registration_generation: 0,
            registration_cleanup_receipts: Vec::new(),
            registration_cleanup_journal: None,
            registration_cleanup_storage_unavailable: false,
            key_op: KeyOpState::default(),
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
