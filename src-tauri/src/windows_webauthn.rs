//! Windows GUI FIDO backend based on Microsoft's WebAuthn API.
//! The raw CTAP backend remains available for the CLI and diagnostics.

use crate::fido2::{DetectedKey, FidoBackend, FidoError, KeyKind, RegisteredCredential};
use crate::webauthn_diagnostics::{
    capability_record, diagnose, FailureStage, Operation, OperationDiagnostics,
};
use std::{
    collections::HashSet,
    ffi::c_void,
    ptr, slice,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};
use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, HWND, LPARAM};
use windows_sys::Win32::Networking::WindowsWebServices::*;
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS,
};
use windows_sys::Win32::System::RemoteDesktop::ProcessIdToSessionId;
use windows_sys::Win32::System::SystemInformation::GetSystemDirectoryW;
use windows_sys::Win32::System::Threading::{
    GetCurrentProcessId, OpenProcess, QueryFullProcessImageNameW, PROCESS_QUERY_LIMITED_INFORMATION,
};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    EnumWindows, GetClassNameW, GetForegroundWindow, GetWindowTextW, GetWindowThreadProcessId,
    IsIconic, IsWindow, IsWindowVisible, SetForegroundWindow, ShowWindow, SW_RESTORE,
};

const RP_ID: &str = "fido-vault.local";
const ORIGIN: &str = "https://fido-vault.local";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ClientDataOperation {
    Create,
    Get,
}

fn client_data_json(operation: ClientDataOperation, challenge: &[u8]) -> Vec<u8> {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;

    let ceremony = match operation {
        ClientDataOperation::Create => "webauthn.create",
        ClientDataOperation::Get => "webauthn.get",
    };
    serde_json::json!({
        "type": ceremony,
        "challenge": URL_SAFE_NO_PAD.encode(challenge),
        "origin": ORIGIN,
    })
    .to_string()
    .into_bytes()
}

fn hmac_secret_api_supported(api_version: u32) -> bool {
    // API v4 added get-assertion HMAC-secret/PRF salt input and output fields.
    api_version >= 4
}

fn raw_hmac_secret_flag() -> u32 {
    WEBAUTHN_AUTHENTICATOR_HMAC_SECRET_VALUES_FLAG
}

fn validate_owner_foreground(owner: HWND, foreground: HWND) -> Result<HWND, FidoError> {
    if owner.is_null() {
        Err(FidoError::Internal(
            "Windows WebAuthn parent HWND is unavailable; the security-key operation was not started.".into(),
        ))
    } else if owner == foreground {
        Ok(owner)
    } else {
        Err(FidoError::Internal(
            "Windows WebAuthn was not started because its owner window is not foreground. Bring FidoVault to the foreground and retry.".into(),
        ))
    }
}

#[derive(Clone, Copy)]
struct WindowsSecurityDialogCandidate<'a> {
    title: &'a str,
    class_name: &'a str,
    process_path: &'a str,
    system_directory: &'a str,
    visible: bool,
    current_session: u32,
    window_session: u32,
    is_new_window: bool,
    is_new_process: bool,
}

fn is_new_windows_security_dialog(candidate: WindowsSecurityDialogCandidate<'_>) -> bool {
    let title_matches = candidate
        .title
        .trim()
        .eq_ignore_ascii_case("Windows Security")
        || candidate
            .title
            .trim()
            .eq_ignore_ascii_case("Windows 安全性");
    let normalize_path = |path: &str| path.replace('/', "\\").trim_end_matches('\\').to_owned();
    let expected_path = format!(
        "{}\\CredentialUIBroker.exe",
        normalize_path(candidate.system_directory)
    );

    candidate.visible
        && candidate.current_session == candidate.window_session
        && candidate.is_new_window
        && candidate.is_new_process
        && title_matches
        && candidate
            .class_name
            .eq_ignore_ascii_case("Credential Dialog Xaml Host")
        && normalize_path(candidate.process_path).eq_ignore_ascii_case(&expected_path)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct WindowIdentity {
    hwnd: isize,
    process_id: u32,
    thread_id: u32,
}

fn is_new_window_identity(identity: WindowIdentity, baseline: &HashSet<WindowIdentity>) -> bool {
    !baseline.contains(&identity)
}

fn select_unique_candidate(candidates: &[WindowIdentity]) -> Option<WindowIdentity> {
    if candidates.len() == 1 {
        Some(candidates[0])
    } else {
        None
    }
}

struct BrokerBaseline {
    system_directory: String,
    session: u32,
    windows: HashSet<WindowIdentity>,
    processes: HashSet<u32>,
}

#[derive(Clone)]
struct AcceptedBroker {
    identity: WindowIdentity,
    baseline: Arc<BrokerBaseline>,
}

struct RegistrationContinuation {
    owner: WindowIdentity,
    credential_id: Vec<u8>,
    broker: Option<AcceptedBroker>,
}

type CreationResult =
    Result<(RegisteredCredential, WindowIdentity, Option<AcceptedBroker>), FidoError>;

fn complete_registration(
    pending: &mut Option<RegistrationContinuation>,
    result: CreationResult,
) -> Result<RegisteredCredential, FidoError> {
    *pending = None;
    result.map(|(registration, owner, broker)| {
        *pending = Some(RegistrationContinuation {
            owner,
            credential_id: registration.credential_id.clone(),
            broker,
        });
        registration
    })
}

#[derive(Debug, PartialEq, Eq)]
enum HandoffOutcome {
    Ordinary,
    OwnerForeground,
    Recovered,
}

#[derive(Debug, PartialEq, Eq)]
enum HandoffRefusal {
    Credential,
    Owner,
    UnobservedBroker,
    Foreground,
    Broker,
    Activation,
}

impl HandoffRefusal {
    fn reason(&self) -> &'static str {
        match self {
            Self::Credential => "credential-or-owner-input-changed",
            Self::Owner => "owner-invalid",
            Self::UnobservedBroker => "broker-not-observed",
            Self::Foreground => "foreground-not-associated-broker",
            Self::Broker => "broker-revalidation-failed",
            Self::Activation => "activation-failed",
        }
    }
}

fn prepare_continuation(
    pending: &mut Option<RegistrationContinuation>,
    owner: isize,
    credential_ids: &[Vec<u8>],
    system: &mut impl ForegroundSystem,
) -> Result<HandoffOutcome, HandoffRefusal> {
    let Some(context) = pending.take() else {
        return Ok(HandoffOutcome::Ordinary);
    };
    if owner != context.owner.hwnd || credential_ids != [context.credential_id] {
        return Err(HandoffRefusal::Credential);
    }
    if !valid_owner(system, context.owner) {
        return Err(HandoffRefusal::Owner);
    }
    let foreground = system.foreground();
    if foreground == owner {
        if system.minimized(owner) {
            return Err(HandoffRefusal::Owner);
        }
        return Ok(HandoffOutcome::OwnerForeground);
    }
    let broker = context.broker.ok_or(HandoffRefusal::UnobservedBroker)?;
    if foreground != broker.identity.hwnd {
        return Err(HandoffRefusal::Foreground);
    }
    if !current_broker(system, &broker) {
        return Err(HandoffRefusal::Broker);
    }
    if system.minimized(owner) {
        if !current_broker(system, &broker)
            || !valid_owner(system, context.owner)
            || system.foreground() != broker.identity.hwnd
        {
            return Err(HandoffRefusal::Broker);
        }
        system.restore(owner);
        if !valid_owner(system, context.owner) || system.minimized(owner) {
            return Err(HandoffRefusal::Owner);
        }
        if system.foreground() == owner {
            return Ok(HandoffOutcome::Recovered);
        }
    }
    // All potentially blocking identity queries precede this last activation
    // sample. No retry or focus bypass; the later API guard remains separate.
    if !current_broker(system, &broker) || !valid_owner(system, context.owner) {
        return Err(HandoffRefusal::Broker);
    }
    if system.identity(context.owner.hwnd) != Some(context.owner)
        || system.identity(broker.identity.hwnd) != Some(broker.identity)
    {
        return Err(HandoffRefusal::Broker);
    }
    if system.foreground() != broker.identity.hwnd {
        return Err(HandoffRefusal::Foreground);
    }
    if !system.activate(owner) {
        return Err(HandoffRefusal::Activation);
    }
    if system.foreground() != owner
        || !valid_owner(system, context.owner)
        || system.minimized(owner)
    {
        return Err(HandoffRefusal::Activation);
    }
    Ok(HandoffOutcome::Recovered)
}

fn valid_owner(system: &mut impl ForegroundSystem, owner: WindowIdentity) -> bool {
    let pid = system.current_pid();
    owner.hwnd != 0
        && owner.process_id == pid
        && system.identity(owner.hwnd) == Some(owner)
        && system.visible(owner.hwnd)
        && system.session(pid).is_some()
}

fn checked_owner(
    system: &mut impl ForegroundSystem,
    hwnd: isize,
) -> Result<WindowIdentity, FidoError> {
    system
        .identity(hwnd)
        .filter(|owner| valid_owner(system, *owner) && !system.minimized(hwnd))
        .ok_or_else(|| {
            FidoError::Internal(
                "Windows WebAuthn owner is stale, hidden, minimized or not owned by this process"
                    .into(),
            )
        })
}

fn checked_owner_snapshot(
    system: &mut impl ForegroundSystem,
    expected: WindowIdentity,
) -> Result<WindowIdentity, FidoError> {
    let current = checked_owner(system, expected.hwnd)?;
    if current != expected {
        return Err(FidoError::Internal(
            "Windows WebAuthn owner identity changed before the API call".into(),
        ));
    }
    Ok(current)
}

fn current_broker(system: &mut impl ForegroundSystem, broker: &AcceptedBroker) -> bool {
    let pid = system.current_pid();
    system.session(pid) == Some(broker.baseline.session)
        && broker_candidates(system, &broker.baseline)
            .ok()
            .and_then(|candidates| select_unique_candidate(&candidates))
            == Some(broker.identity)
        && trusted_broker(system, &broker.baseline, broker.identity)
}

// Native observations and mutations are injected together, so tests execute the
// same identity policy and ordering as production without calling Windows UI.
trait ForegroundSystem {
    fn identity(&mut self, hwnd: isize) -> Option<WindowIdentity>;
    fn foreground(&mut self) -> isize;
    fn windows(&mut self) -> Result<Vec<isize>, ()>;
    fn visible(&mut self, hwnd: isize) -> bool;
    fn minimized(&mut self, hwnd: isize) -> bool;
    fn session(&mut self, pid: u32) -> Option<u32>;
    fn path(&mut self, pid: u32) -> Option<String>;
    fn title(&mut self, hwnd: isize) -> Option<String>;
    fn class(&mut self, hwnd: isize) -> Option<String>;
    fn current_pid(&mut self) -> u32;
    fn restore(&mut self, hwnd: isize);
    fn activate(&mut self, hwnd: isize) -> bool;
}

struct NativeForegroundSystem;

impl ForegroundSystem for NativeForegroundSystem {
    fn identity(&mut self, hwnd: isize) -> Option<WindowIdentity> {
        if hwnd == 0 || unsafe { IsWindow(hwnd as HWND) } == 0 {
            None
        } else {
            window_identity(hwnd as HWND)
        }
    }
    fn foreground(&mut self) -> isize {
        (unsafe { GetForegroundWindow() }) as isize
    }
    fn windows(&mut self) -> Result<Vec<isize>, ()> {
        top_level_windows().map(|windows| windows.into_iter().map(|hwnd| hwnd as isize).collect())
    }
    fn visible(&mut self, hwnd: isize) -> bool {
        (unsafe { IsWindowVisible(hwnd as HWND) }) != 0
    }
    fn minimized(&mut self, hwnd: isize) -> bool {
        (unsafe { IsIconic(hwnd as HWND) }) != 0
    }
    fn session(&mut self, pid: u32) -> Option<u32> {
        process_session(pid)
    }
    fn path(&mut self, pid: u32) -> Option<String> {
        process_image_path(pid)
    }
    fn title(&mut self, hwnd: isize) -> Option<String> {
        window_text(hwnd as HWND)
    }
    fn class(&mut self, hwnd: isize) -> Option<String> {
        window_class(hwnd as HWND)
    }
    fn current_pid(&mut self) -> u32 {
        unsafe { GetCurrentProcessId() }
    }
    fn restore(&mut self, hwnd: isize) {
        unsafe {
            ShowWindow(hwnd as HWND, SW_RESTORE);
        }
    }
    fn activate(&mut self, hwnd: isize) -> bool {
        (unsafe { SetForegroundWindow(hwnd as HWND) }) != 0
    }
}

fn observe_broker(
    system: &mut impl ForegroundSystem,
    baseline: &BrokerBaseline,
    identity: WindowIdentity,
) -> Result<bool, ()> {
    if system.identity(identity.hwnd) != Some(identity) {
        return Err(());
    }
    let session = system.session(identity.process_id).ok_or(())?;
    let path = system.path(identity.process_id).ok_or(())?;
    let title = system.title(identity.hwnd).ok_or(())?;
    let class_name = system.class(identity.hwnd).ok_or(())?;
    let matches = is_new_windows_security_dialog(WindowsSecurityDialogCandidate {
        title: &title,
        class_name: &class_name,
        process_path: &path,
        system_directory: &baseline.system_directory,
        visible: system.visible(identity.hwnd),
        current_session: baseline.session,
        window_session: session,
        is_new_window: is_new_window_identity(identity, &baseline.windows),
        is_new_process: !baseline.processes.contains(&identity.process_id),
    });
    if system.identity(identity.hwnd) != Some(identity) {
        return Err(());
    }
    Ok(matches)
}

fn trusted_broker(
    system: &mut impl ForegroundSystem,
    baseline: &BrokerBaseline,
    identity: WindowIdentity,
) -> bool {
    observe_broker(system, baseline, identity) == Ok(true)
}

fn broker_candidates(
    system: &mut impl ForegroundSystem,
    baseline: &BrokerBaseline,
) -> Result<Vec<WindowIdentity>, ()> {
    let mut candidates = Vec::new();
    for hwnd in system.windows()? {
        if !system.visible(hwnd) {
            continue;
        }
        // Positive ordinary class evidence avoids slow process queries. Unknown
        // class/title is conservative: it cannot prove an unrelated window.
        let class = system.class(hwnd).ok_or(())?;
        if !class.eq_ignore_ascii_case("Credential Dialog Xaml Host") {
            continue;
        }
        let title = system.title(hwnd).ok_or(())?;
        if !title.trim().eq_ignore_ascii_case("Windows Security")
            && !title
                .trim()
                .eq_ignore_ascii_case("Windows \u{5b89}\u{5168}\u{6027}")
        {
            continue;
        }
        let identity = system.identity(hwnd).ok_or(())?;
        if observe_broker(system, baseline, identity)? {
            candidates.push(identity);
        }
    }
    Ok(candidates)
}

fn capture_broker(
    system: &mut impl ForegroundSystem,
    baseline: Arc<BrokerBaseline>,
    candidate: WindowIdentity,
) -> Option<AcceptedBroker> {
    if broker_candidates(system, &baseline)
        .ok()
        .and_then(|candidates| select_unique_candidate(&candidates))
        != Some(candidate)
        || !trusted_broker(system, &baseline, candidate)
        || system.foreground() != candidate.hwnd
        || system.identity(candidate.hwnd) != Some(candidate)
        || !system.visible(candidate.hwnd)
    {
        return None;
    }
    Some(AcceptedBroker {
        identity: candidate,
        baseline,
    })
}

fn record_broker(
    system: &mut impl ForegroundSystem,
    baseline: Arc<BrokerBaseline>,
    candidate: WindowIdentity,
    cancelled: &AtomicBool,
    accepted: &Mutex<Option<AcceptedBroker>>,
) {
    if cancelled.load(Ordering::Acquire) {
        return;
    }
    if let Some(broker) = capture_broker(system, baseline, candidate) {
        if let Ok(mut result) = accepted.lock() {
            if !cancelled.load(Ordering::Acquire) {
                *result = Some(broker);
            }
        }
    }
}

#[derive(Default)]
struct MonitorPolicy {
    stopped: bool,
}
impl MonitorPolicy {
    fn observe(
        &mut self,
        system: &mut impl ForegroundSystem,
        owner: isize,
        baseline: Arc<BrokerBaseline>,
        cancelled: &AtomicBool,
        accepted: &Mutex<Option<AcceptedBroker>>,
    ) -> bool {
        if !self.stopped {
            self.stopped = monitor_observe(system, owner, baseline, cancelled, accepted);
        }
        self.stopped
    }
}

// true is terminal, including ambiguity or any incomplete observation.
fn monitor_observe(
    system: &mut impl ForegroundSystem,
    owner: isize,
    baseline: Arc<BrokerBaseline>,
    cancelled: &AtomicBool,
    accepted: &Mutex<Option<AcceptedBroker>>,
) -> bool {
    if cancelled.load(Ordering::Acquire) {
        return true;
    }
    let Ok(candidates) = broker_candidates(system, &baseline) else {
        return true;
    };
    if candidates.len() > 1 {
        return true;
    }
    let Some(candidate) = select_unique_candidate(&candidates) else {
        return system.foreground() != owner;
    };
    let foreground = system.foreground();
    if foreground == candidate.hwnd {
        record_broker(system, baseline, candidate, cancelled, accepted);
        return true;
    }
    if !should_attempt_dialog_activation(
        owner,
        candidate.hwnd,
        foreground,
        cancelled.load(Ordering::Acquire),
    ) {
        return true;
    }
    if broker_candidates(system, &baseline)
        .ok()
        .and_then(|c| select_unique_candidate(&c))
        != Some(candidate)
    {
        return true;
    }
    if cancelled.load(Ordering::Acquire) || system.identity(candidate.hwnd) != Some(candidate) {
        return true;
    }
    // Best effort: Windows may change identity/focus after the final sample.
    if !should_attempt_dialog_activation(
        owner,
        candidate.hwnd,
        system.foreground(),
        cancelled.load(Ordering::Acquire),
    ) {
        return true;
    }
    system.activate(candidate.hwnd);
    if system.foreground() == candidate.hwnd {
        record_broker(system, baseline, candidate, cancelled, accepted);
    }
    true
}

fn should_attempt_dialog_activation(
    owner: isize,
    dialog: isize,
    foreground: isize,
    cancelled: bool,
) -> bool {
    !cancelled && dialog != owner && foreground == owner
}

fn focus_monitor_timeout() -> Duration {
    Duration::from_millis(OP_TIMEOUT_MS as u64 + 2_000)
}

unsafe extern "system" fn collect_top_level_window(
    hwnd: HWND,
    lparam: LPARAM,
) -> windows_sys::core::BOOL {
    if lparam == 0 {
        return 0;
    }
    let windows = &mut *(lparam as *mut Vec<HWND>);
    windows.push(hwnd);
    1
}

fn top_level_windows() -> Result<Vec<HWND>, ()> {
    let mut windows = Vec::new();
    let complete = unsafe {
        EnumWindows(
            Some(collect_top_level_window),
            (&mut windows as *mut Vec<HWND>) as LPARAM,
        )
    };
    if complete != 0 {
        Ok(windows)
    } else {
        Err(())
    }
}

fn window_identity(hwnd: HWND) -> Option<WindowIdentity> {
    let mut process_id = 0;
    let thread_id = unsafe { GetWindowThreadProcessId(hwnd, &mut process_id) };
    (thread_id != 0 && process_id != 0).then_some(WindowIdentity {
        hwnd: hwnd as isize,
        process_id,
        thread_id,
    })
}

fn baseline_window_identities(
    system: &mut impl ForegroundSystem,
) -> Result<HashSet<WindowIdentity>, ()> {
    system
        .windows()?
        .into_iter()
        .map(|hwnd| system.identity(hwnd).ok_or(()))
        .collect()
}

fn credential_broker_process_ids() -> Option<HashSet<u32>> {
    let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
    if snapshot.is_null() || snapshot as isize == -1 {
        return None;
    }
    let _snapshot = ProcessHandle(snapshot);
    let mut entry = PROCESSENTRY32W {
        dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
        ..Default::default()
    };
    if unsafe { Process32FirstW(snapshot, &mut entry) } == 0 {
        return None;
    }

    let mut process_ids = HashSet::new();
    loop {
        let name_length = entry
            .szExeFile
            .iter()
            .position(|character| *character == 0)
            .unwrap_or(entry.szExeFile.len());
        if String::from_utf16_lossy(&entry.szExeFile[..name_length])
            .eq_ignore_ascii_case("CredentialUIBroker.exe")
        {
            process_ids.insert(entry.th32ProcessID);
        }
        if unsafe { Process32NextW(snapshot, &mut entry) } == 0 {
            break;
        }
    }
    Some(process_ids)
}

fn system_directory() -> Option<String> {
    let mut buffer = vec![0u16; 32_768];
    let length = unsafe { GetSystemDirectoryW(buffer.as_mut_ptr(), buffer.len() as u32) } as usize;
    if length == 0 || length >= buffer.len() {
        return None;
    }
    Some(String::from_utf16_lossy(&buffer[..length]))
}

fn process_session(process_id: u32) -> Option<u32> {
    let mut session_id = 0;
    (unsafe { ProcessIdToSessionId(process_id, &mut session_id) } != 0).then_some(session_id)
}

struct ProcessHandle(HANDLE);

impl Drop for ProcessHandle {
    fn drop(&mut self) {
        unsafe { CloseHandle(self.0) };
    }
}

fn process_image_path(process_id: u32) -> Option<String> {
    let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, process_id) };
    if handle.is_null() {
        return None;
    }
    let _handle = ProcessHandle(handle);
    let mut buffer = vec![0u16; 32_768];
    let mut length = buffer.len() as u32;
    if unsafe { QueryFullProcessImageNameW(handle, 0, buffer.as_mut_ptr(), &mut length) } == 0
        || length == 0
        || length as usize > buffer.len()
    {
        return None;
    }
    Some(String::from_utf16_lossy(&buffer[..length as usize]))
}

fn window_text(hwnd: HWND) -> Option<String> {
    let mut buffer = [0u16; 256];
    let length = unsafe { GetWindowTextW(hwnd, buffer.as_mut_ptr(), buffer.len() as i32) };
    if length <= 0 || length as usize >= buffer.len() - 1 {
        None
    } else {
        Some(String::from_utf16_lossy(&buffer[..length as usize]))
    }
}

fn window_class(hwnd: HWND) -> Option<String> {
    let mut buffer = [0u16; 256];
    let length = unsafe { GetClassNameW(hwnd, buffer.as_mut_ptr(), buffer.len() as i32) };
    if length <= 0 || length as usize >= buffer.len() - 1 {
        None
    } else {
        Some(String::from_utf16_lossy(&buffer[..length as usize]))
    }
}

struct WebAuthnForegroundMonitor {
    cancelled: Arc<AtomicBool>,
    armed: Arc<AtomicBool>,
    accepted: Arc<Mutex<Option<AcceptedBroker>>>,
    worker: Option<JoinHandle<()>>,
}

impl WebAuthnForegroundMonitor {
    fn stop(&mut self) {
        self.cancelled.store(true, Ordering::Release);
        if let Some(worker) = self.worker.take() {
            if worker.join().is_err() {
                if let Ok(mut accepted) = self.accepted.lock() {
                    *accepted = None;
                }
                log::warn!("[WebAuthN-handoff] reason=monitor-worker-failed");
            }
        }
    }

    fn finish(mut self) -> Option<AcceptedBroker> {
        self.stop();
        self.accepted.lock().ok()?.take()
    }

    fn prepare(owner_hwnd: HWND, operation: &'static str) -> Option<Self> {
        let system_directory = system_directory().or_else(|| {
            log::warn!("[WebAuthN-focus] could not determine the Windows system directory");
            None
        })?;
        let current_session = process_session(unsafe { GetCurrentProcessId() }).or_else(|| {
            log::warn!("[WebAuthN-focus] could not determine the current Windows session");
            None
        })?;
        let baseline_windows = baseline_window_identities(&mut NativeForegroundSystem).ok()?;
        let baseline_broker_processes = credential_broker_process_ids().or_else(|| {
            log::warn!("[WebAuthN-focus] could not snapshot existing broker processes");
            None
        })?;
        log::info!(
            "[WebAuthN-focus] prepared operation={} session={} baseline_windows={} baseline_broker_processes={}",
            operation,
            current_session,
            baseline_windows.len(),
            baseline_broker_processes.len(),
        );

        let cancelled = Arc::new(AtomicBool::new(false));
        let armed = Arc::new(AtomicBool::new(false));
        let worker_cancelled = Arc::clone(&cancelled);
        let worker_armed = Arc::clone(&armed);
        let accepted = Arc::new(Mutex::new(None));
        let worker_accepted = Arc::clone(&accepted);
        let baseline = Arc::new(BrokerBaseline {
            system_directory: system_directory.clone(),
            session: current_session,
            windows: baseline_windows.clone(),
            processes: baseline_broker_processes.clone(),
        });
        let owner_hwnd_value = owner_hwnd as isize;
        let worker = match thread::Builder::new()
            .name("webauthn-security-dialog-focus".into())
            .spawn(move || {
                while !worker_armed.load(Ordering::Acquire) {
                    if worker_cancelled.load(Ordering::Acquire) {
                        return;
                    }
                    thread::sleep(Duration::from_millis(5));
                }

                let deadline = Instant::now() + focus_monitor_timeout();
                let mut policy = MonitorPolicy::default();
                while !worker_cancelled.load(Ordering::Acquire) && Instant::now() < deadline {
                    if policy.observe(&mut NativeForegroundSystem, owner_hwnd_value, Arc::clone(&baseline), &worker_cancelled, &worker_accepted) { return; }
                    thread::sleep(Duration::from_millis(100));
                }
                log::debug!(
                    "[WebAuthN-focus] operation={} monitor ended without finding a new trusted dialog",
                    operation,
                );
            })
        {
            Ok(worker) => worker,
            Err(error) => {
                log::warn!("[WebAuthN-focus] failed to start dialog monitor: {error}");
                return None;
            }
        };

        Some(Self {
            cancelled,
            armed,
            accepted,
            worker: Some(worker),
        })
    }

    fn arm(&self) {
        self.armed.store(true, Ordering::Release);
    }
}

impl Drop for WebAuthnForegroundMonitor {
    fn drop(&mut self) {
        self.stop();
    }
}

fn vault_hmac_salt() -> [u8; 32] {
    crate::crypto::prf_salt_bytes()
}

const OP_TIMEOUT_MS: u32 = 90_000;
const MAX_API_BUFFER: usize = 1024 * 1024;

/// Uses Windows' brokered WebAuthn path so standard-user GUI launches do not open raw HID.
pub struct WindowsWebAuthnBackend {
    hwnd: isize,
    api_version: u32,
    continuation: Option<RegistrationContinuation>,
}

impl WindowsWebAuthnBackend {
    pub fn new(hwnd: isize) -> Result<Self, FidoError> {
        let api_version = unsafe { WebAuthNGetApiVersionNumber() };
        let process_id = unsafe { GetCurrentProcessId() };
        log::info!(
            "[WebAuthN-capability] {}",
            capability_record(
                Some(api_version),
                Some(process_id),
                process_session(process_id)
            ),
        );
        if !hmac_secret_api_supported(api_version) {
            return Err(FidoError::NotSupported(format!(
                "Windows WebAuthn API v{api_version} lacks HMAC-secret assertion support (requires v4+)"
            )));
        }
        Ok(Self {
            hwnd,
            api_version,
            continuation: None,
        })
    }

    fn hwnd(&self) -> Result<HWND, FidoError> {
        if self.hwnd == 0 {
            Err(FidoError::Internal(
                "Windows WebAuthn parent HWND was not supplied by the live FidoVault window."
                    .into(),
            ))
        } else {
            Ok(self.hwnd as HWND)
        }
    }

    fn foreground_owner_hwnd(
        &self,
        owner_identity: WindowIdentity,
    ) -> Result<(HWND, HWND), FidoError> {
        let owner = self.hwnd()?;
        if owner as isize != owner_identity.hwnd {
            return Err(FidoError::Internal(
                "Windows WebAuthn owner changed before the API call".into(),
            ));
        }
        checked_owner_snapshot(&mut NativeForegroundSystem, owner_identity)?;
        // Best-effort preflight: Windows may still change foreground after this sample.
        let foreground = unsafe { GetForegroundWindow() };
        match validate_owner_foreground(owner, foreground) {
            Ok(owner) => Ok((owner, foreground)),
            Err(error) => {
                log::warn!(
                    "Windows WebAuthn refused before API call: owner={:p} foreground={:p}",
                    owner,
                    foreground,
                );
                Err(error)
            }
        }
    }

    fn make_credential(
        &mut self,
        detected: &DetectedKey,
    ) -> Result<RegisteredCredential, FidoError> {
        self.continuation = None;
        let result = diagnose(
            Operation::MakeCredential,
            |diagnostic| self.make_credential_with_diagnostics(detected, diagnostic),
            |record| log::info!("[WebAuthN-operation] {}", record),
        );
        complete_registration(&mut self.continuation, result)
    }

    fn make_credential_with_diagnostics(
        &self,
        detected: &DetectedKey,
        diagnostic: &mut OperationDiagnostics,
    ) -> CreationResult {
        diagnostic.failure_stage = Some(FailureStage::Preflight);
        let challenge = random_bytes(32);
        let mut client_json = client_data_json(ClientDataOperation::Create, &challenge);
        let client_data = make_client_data(&mut client_json)?;

        let rp_id = wide(RP_ID);
        let rp_name = wide("FidoVault");
        let user_name = wide("vault-user");
        let user_display_name = wide("FidoVault user");
        let mut user_id = random_bytes(16);
        let rp = WEBAUTHN_RP_ENTITY_INFORMATION {
            dwVersion: WEBAUTHN_RP_ENTITY_INFORMATION_CURRENT_VERSION,
            pwszId: rp_id.as_ptr(),
            pwszName: rp_name.as_ptr(),
            pwszIcon: ptr::null(),
        };
        let user = WEBAUTHN_USER_ENTITY_INFORMATION {
            dwVersion: WEBAUTHN_USER_ENTITY_INFORMATION_CURRENT_VERSION,
            cbId: user_id.len() as u32,
            pbId: user_id.as_mut_ptr(),
            pwszName: user_name.as_ptr(),
            pwszIcon: ptr::null(),
            pwszDisplayName: user_display_name.as_ptr(),
        };
        let mut cose_parameter = WEBAUTHN_COSE_CREDENTIAL_PARAMETER {
            dwVersion: WEBAUTHN_COSE_CREDENTIAL_PARAMETER_CURRENT_VERSION,
            pwszCredentialType: WEBAUTHN_CREDENTIAL_TYPE_PUBLIC_KEY,
            lAlg: WEBAUTHN_COSE_ALGORITHM_ECDSA_P256_WITH_SHA256,
        };
        let cose_parameters = WEBAUTHN_COSE_CREDENTIAL_PARAMETERS {
            cCredentialParameters: 1,
            pCredentialParameters: &mut cose_parameter,
        };

        let mut hmac_secret_requested: windows_sys::core::BOOL = 1;
        let mut hmac_secret_extension = WEBAUTHN_EXTENSION {
            pwszExtensionIdentifier: WEBAUTHN_EXTENSIONS_IDENTIFIER_HMAC_SECRET,
            cbExtension: std::mem::size_of::<windows_sys::core::BOOL>() as u32,
            pvExtension: (&mut hmac_secret_requested as *mut windows_sys::core::BOOL)
                .cast::<c_void>(),
        };
        let extensions = WEBAUTHN_EXTENSIONS {
            cExtensions: 1,
            pExtensions: &mut hmac_secret_extension,
        };
        let options = WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS {
            dwVersion: WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS_VERSION_5,
            dwTimeoutMilliseconds: OP_TIMEOUT_MS,
            Extensions: extensions,
            dwAuthenticatorAttachment: WEBAUTHN_AUTHENTICATOR_ATTACHMENT_CROSS_PLATFORM,
            dwUserVerificationRequirement: WEBAUTHN_USER_VERIFICATION_REQUIREMENT_PREFERRED,
            dwAttestationConveyancePreference: WEBAUTHN_ATTESTATION_CONVEYANCE_PREFERENCE_NONE,
            bRequireResidentKey: 0,
            bPreferResidentKey: 1,
            ..Default::default()
        };

        let mut attestation = ptr::null_mut();
        let owner_for_prepare = self.hwnd()?;
        let owner_identity =
            checked_owner(&mut NativeForegroundSystem, owner_for_prepare as isize)?;
        let focus_monitor = WebAuthnForegroundMonitor::prepare(owner_for_prepare, "MakeCredential");
        let (owner_hwnd, foreground_before_api) = self.foreground_owner_hwnd(owner_identity)?;
        if let Some(monitor) = focus_monitor.as_ref() {
            monitor.arm();
        }
        let hr = unsafe {
            WebAuthNAuthenticatorMakeCredential(
                owner_hwnd,
                &rp,
                &user,
                &cose_parameters,
                &client_data,
                &options,
                &mut attestation,
            )
        };
        let accepted_broker = focus_monitor.and_then(WebAuthnForegroundMonitor::finish);
        log::info!(
            "Windows WebAuthn MakeCredential owner snapshot captured immediately before API: owner={:p} foreground={:p}",
            owner_hwnd,
            foreground_before_api,
        );
        diagnostic.failure_stage = Some(FailureStage::Api);
        if hr < 0 {
            if !attestation.is_null() {
                unsafe { WebAuthNFreeCredentialAttestation(attestation) };
            }
            return Err(api_error("makeCredential", hr));
        }
        diagnostic.failure_stage = Some(FailureStage::Response);
        if attestation.is_null() {
            return Err(FidoError::Internal(
                "Windows WebAuthn API returned no credential attestation".into(),
            ));
        }
        let attestation = AttestationGuard(attestation);
        let att = unsafe { &*attestation.0 };
        let hmac_creation_confirmed = hmac_secret_enabled(&att.Extensions);
        diagnostic.hmac_creation_confirmed = Some(hmac_creation_confirmed);
        if !hmac_creation_confirmed {
            return Err(FidoError::PrfNotConfirmed);
        }
        let credential_id =
            unsafe { copy_api_bytes(att.pbCredentialId, att.cbCredentialId, "credential ID")? };
        if credential_id.is_empty() {
            return Err(FidoError::Internal(
                "Windows WebAuthn API returned an empty credential ID".into(),
            ));
        }
        let authenticator_data = unsafe {
            copy_api_bytes(
                att.pbAuthenticatorData,
                att.cbAuthenticatorData,
                "authenticator data",
            )?
        };
        let aaguid = aaguid_from_authenticator_data(&authenticator_data);

        Ok((
            RegisteredCredential {
                credential_id,
                aaguid,
                label: detected.label.clone(),
                kind: detected.kind,
            },
            owner_identity,
            accepted_broker,
        ))
    }

    fn get_hmac_secret(&mut self, credential_id: &[u8]) -> Result<[u8; 32], FidoError> {
        self.get_hmac_secret_for_any(&[credential_id.to_vec()])
            .map(|(_, secret)| secret)
    }

    fn get_hmac_secret_for_any(
        &mut self,
        credential_ids: &[Vec<u8>],
    ) -> Result<(Vec<u8>, [u8; 32]), FidoError> {
        diagnose(
            Operation::GetAssertion,
            |diagnostic| self.get_hmac_secret_for_any_with_diagnostics(credential_ids, diagnostic),
            |record| log::info!("[WebAuthN-operation] {}", record),
        )
    }

    fn get_hmac_secret_for_any_with_diagnostics(
        &mut self,
        credential_ids: &[Vec<u8>],
        diagnostic: &mut OperationDiagnostics,
    ) -> Result<(Vec<u8>, [u8; 32]), FidoError> {
        diagnostic.failure_stage = Some(FailureStage::Preflight);
        let mut continuation = self.continuation.take();
        let mut system = NativeForegroundSystem;
        let owner_identity = system
            .identity(self.hwnd)
            .filter(|owner| valid_owner(&mut system, *owner))
            .ok_or_else(|| {
                FidoError::Internal("Windows WebAuthn owner identity is unavailable".into())
            })?;
        let preparation =
            prepare_continuation(&mut continuation, self.hwnd, credential_ids, &mut system);
        match preparation {
            Ok(outcome) => log::info!("[WebAuthN-handoff] outcome={:?}", outcome),
            Err(refusal) => {
                log::warn!("[WebAuthN-handoff] reason={}", refusal.reason());
                return Err(FidoError::Internal(format!(
                    "Windows WebAuthn continuation refused: {}",
                    refusal.reason()
                )));
            }
        }
        validate_credential_ids(credential_ids)?;
        let challenge = random_bytes(32);
        let mut client_json = client_data_json(ClientDataOperation::Get, &challenge);
        let client_data = make_client_data(&mut client_json)?;

        let mut salt = vault_hmac_salt();
        let mut hmac_salt = WEBAUTHN_HMAC_SECRET_SALT {
            cbFirst: salt.len() as u32,
            pbFirst: salt.as_mut_ptr(),
            cbSecond: 0,
            pbSecond: ptr::null_mut(),
        };
        let mut salt_values = WEBAUTHN_HMAC_SECRET_SALT_VALUES {
            pGlobalHmacSalt: &mut hmac_salt,
            cCredWithHmacSecretSaltList: 0,
            pCredWithHmacSecretSaltList: ptr::null_mut(),
        };
        let mut credential_entries: Vec<WEBAUTHN_CREDENTIAL> = credential_ids
            .iter()
            .map(|credential_id| WEBAUTHN_CREDENTIAL {
                dwVersion: WEBAUTHN_CREDENTIAL_CURRENT_VERSION,
                cbId: credential_id.len() as u32,
                pbId: credential_id.as_ptr() as *mut u8,
                pwszCredentialType: WEBAUTHN_CREDENTIAL_TYPE_PUBLIC_KEY,
            })
            .collect();
        let credential_list = WEBAUTHN_CREDENTIALS {
            cCredentials: credential_entries.len() as u32,
            pCredentials: credential_entries.as_mut_ptr(),
        };
        let options = WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS {
            dwVersion: WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS_VERSION_6,
            dwTimeoutMilliseconds: OP_TIMEOUT_MS,
            CredentialList: credential_list,
            dwAuthenticatorAttachment: WEBAUTHN_AUTHENTICATOR_ATTACHMENT_CROSS_PLATFORM,
            dwUserVerificationRequirement: WEBAUTHN_USER_VERIFICATION_REQUIREMENT_PREFERRED,
            dwFlags: raw_hmac_secret_flag(),
            pHmacSecretSaltValues: &mut salt_values,
            ..Default::default()
        };

        let rp_id = wide(RP_ID);
        let mut assertion = ptr::null_mut();
        let owner_for_prepare = self.hwnd()?;
        let focus_monitor = WebAuthnForegroundMonitor::prepare(owner_for_prepare, "GetAssertion");
        let (owner_hwnd, foreground_before_api) = self.foreground_owner_hwnd(owner_identity)?;
        if let Some(monitor) = focus_monitor.as_ref() {
            monitor.arm();
        }
        let hr = unsafe {
            WebAuthNAuthenticatorGetAssertion(
                owner_hwnd,
                rp_id.as_ptr(),
                &client_data,
                &options,
                &mut assertion,
            )
        };
        drop(focus_monitor);
        log::info!(
            "Windows WebAuthn GetAssertion owner snapshot captured immediately before API: owner={:p} foreground={:p}",
            owner_hwnd,
            foreground_before_api,
        );
        diagnostic.failure_stage = Some(FailureStage::Api);
        if hr < 0 {
            if !assertion.is_null() {
                unsafe { WebAuthNFreeAssertion(assertion) };
            }
            return Err(api_error("getAssertion", hr));
        }
        diagnostic.failure_stage = Some(FailureStage::Response);
        if assertion.is_null() {
            return Err(FidoError::Internal(
                "Windows WebAuthn API returned no assertion".into(),
            ));
        }
        let assertion = AssertionGuard(assertion);
        let result = unsafe { &*assertion.0 };
        if result.pHmacSecret.is_null() {
            diagnostic.output_present = Some(false);
            return Err(FidoError::Internal(
                "security key returned no hmac-secret output".into(),
            ));
        }
        let selected_id = unsafe {
            copy_api_bytes(
                result.Credential.pbId as *const u8,
                result.Credential.cbId,
                "selected credential ID",
            )?
        };
        let selected_id = validate_selected_credential_id(credential_ids, &selected_id);
        diagnostic.credential_match = Some(selected_id.is_ok());
        let selected_id = selected_id?;
        let output = unsafe { &*result.pHmacSecret };
        diagnostic.output_present = Some(!output.pbFirst.is_null());
        diagnostic.output_length = Some(output.cbFirst);
        if output.cbFirst != 32 || output.pbFirst.is_null() {
            return Err(FidoError::Internal(format!(
                "Windows WebAuthn API returned an invalid hmac-secret length ({})",
                output.cbFirst
            )));
        }
        let bytes = unsafe { slice::from_raw_parts(output.pbFirst, 32) };
        let mut secret = [0u8; 32];
        secret.copy_from_slice(bytes);
        Ok((selected_id, secret))
    }
}

impl FidoBackend for WindowsWebAuthnBackend {
    fn set_webauthn_parent_hwnd(&mut self, handle: isize) {
        self.continuation = None;
        self.hwnd = handle;
    }

    fn detect(&mut self) -> Result<DetectedKey, FidoError> {
        self.continuation = None;
        // The broker owns device selection and prompts during makeCredential/getAssertion.
        Ok(DetectedKey {
            kind: KeyKind::WindowsManaged,
            label: "Windows WebAuthn 安全金鑰".into(),
            aaguid: [0; 16],
        })
    }

    fn register_credential(
        &mut self,
        detected: &DetectedKey,
        _pin: Option<&str>,
    ) -> Result<RegisteredCredential, FidoError> {
        self.make_credential(detected)
    }

    fn get_prf_secret(
        &mut self,
        credential_id: &[u8],
        _pin: Option<&str>,
    ) -> Result<[u8; 32], FidoError> {
        self.get_hmac_secret(credential_id)
    }

    fn get_prf_secret_for_any(
        &mut self,
        credential_ids: &[Vec<u8>],
        _pin: Option<&str>,
    ) -> Result<(Vec<u8>, [u8; 32]), FidoError> {
        self.get_hmac_secret_for_any(credential_ids)
    }

    fn uses_brokered_key_selection(&self) -> bool {
        true
    }

    fn peek_kind(&self) -> KeyKind {
        KeyKind::WindowsManaged
    }

    fn prf_supported(&self) -> bool {
        hmac_secret_api_supported(self.api_version)
    }

    fn enrollment_count(&mut self) -> Option<Result<usize, String>> {
        self.continuation = None;
        // The Windows WebAuthn API intentionally owns the UV flow and does not expose CTAP BioEnrollment.
        None
    }

    fn info_diag(&self) -> String {
        format!(
            "Windows WebAuthn API version={}; hmac-secret raw-salt",
            self.api_version
        )
    }
}

struct AttestationGuard(*mut WEBAUTHN_CREDENTIAL_ATTESTATION);
impl Drop for AttestationGuard {
    fn drop(&mut self) {
        unsafe { WebAuthNFreeCredentialAttestation(self.0) };
    }
}

struct AssertionGuard(*mut WEBAUTHN_ASSERTION);
impl Drop for AssertionGuard {
    fn drop(&mut self) {
        unsafe { WebAuthNFreeAssertion(self.0) };
    }
}

fn make_client_data(json: &mut [u8]) -> Result<WEBAUTHN_CLIENT_DATA, FidoError> {
    if json.is_empty() || json.len() > MAX_API_BUFFER {
        return Err(FidoError::Internal(
            "clientDataJSON length is invalid".into(),
        ));
    }
    Ok(WEBAUTHN_CLIENT_DATA {
        dwVersion: WEBAUTHN_CLIENT_DATA_CURRENT_VERSION,
        cbClientDataJSON: json.len() as u32,
        pbClientDataJSON: json.as_mut_ptr(),
        pwszHashAlgId: WEBAUTHN_HASH_ALGORITHM_SHA_256,
    })
}

fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}

fn random_bytes(len: usize) -> Vec<u8> {
    use rand::RngCore;
    let mut bytes = vec![0u8; len];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    bytes
}

fn aaguid_from_authenticator_data(data: &[u8]) -> [u8; 16] {
    let mut aaguid = [0u8; 16];
    // AuthenticatorData: rpIdHash[32], flags[1], signCount[4], then AAGUID[16] if AT=1.
    if data.len() >= 53 && data[32] & 0x40 != 0 {
        aaguid.copy_from_slice(&data[37..53]);
    }
    aaguid
}

unsafe fn copy_api_bytes(ptr: *const u8, len: u32, what: &str) -> Result<Vec<u8>, FidoError> {
    let len = len as usize;
    if len > MAX_API_BUFFER || (len > 0 && ptr.is_null()) {
        return Err(FidoError::Internal(format!(
            "Windows WebAuthn API returned invalid {what}"
        )));
    }
    if len == 0 {
        return Ok(Vec::new());
    }
    Ok(slice::from_raw_parts(ptr, len).to_vec())
}

unsafe fn api_wide_string(ptr: *const u16) -> Option<String> {
    if ptr.is_null() {
        return None;
    }
    let mut len = 0usize;
    while len < 512 && *ptr.add(len) != 0 {
        len += 1;
    }
    if len == 512 {
        return None;
    }
    Some(String::from_utf16_lossy(slice::from_raw_parts(ptr, len)))
}

fn validate_credential_ids(credential_ids: &[Vec<u8>]) -> Result<(), FidoError> {
    if credential_ids.is_empty() {
        return Err(FidoError::NoDevice);
    }
    if credential_ids.len() > u32::MAX as usize
        || credential_ids
            .iter()
            .any(|id| id.is_empty() || id.len() > MAX_API_BUFFER || id.len() > u32::MAX as usize)
    {
        return Err(FidoError::Internal(
            "credential allow-list contains an invalid ID or count".into(),
        ));
    }
    Ok(())
}

fn validate_selected_credential_id(
    requested_ids: &[Vec<u8>],
    selected_id: &[u8],
) -> Result<Vec<u8>, FidoError> {
    validate_credential_ids(requested_ids)?;
    if selected_id.is_empty() || !requested_ids.iter().any(|id| id.as_slice() == selected_id) {
        return Err(FidoError::Internal(
            "Windows WebAuthn returned a credential outside the requested allow-list".into(),
        ));
    }
    Ok(selected_id.to_vec())
}

fn hmac_secret_enabled(extensions: &WEBAUTHN_EXTENSIONS) -> bool {
    if extensions.cExtensions == 0
        || extensions.cExtensions > 32
        || extensions.pExtensions.is_null()
    {
        return false;
    }
    for index in 0..extensions.cExtensions as usize {
        let extension = unsafe { &*extensions.pExtensions.add(index) };
        let identifier = unsafe { api_wide_string(extension.pwszExtensionIdentifier) };
        if identifier.as_deref() == Some("hmac-secret")
            && extension.cbExtension >= std::mem::size_of::<windows_sys::core::BOOL>() as u32
            && !extension.pvExtension.is_null()
        {
            return unsafe { *extension.pvExtension.cast::<windows_sys::core::BOOL>() != 0 };
        }
    }
    false
}

fn api_error(operation: &str, hr: windows_sys::core::HRESULT) -> FidoError {
    let name = unsafe { api_wide_string(WebAuthNGetErrorName(hr)) }
        .unwrap_or_else(|| "unknown WebAuthn error".into());
    FidoError::Internal(format!(
        "Windows WebAuthn {operation} failed: {name} (HRESULT 0x{:08X})",
        hr as u32
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    use serde_json::Value;

    #[derive(Clone)]
    struct TestWindow {
        identity: WindowIdentity,
        visible: bool,
        minimized: bool,
        maximized: bool,
        session: u32,
        path: String,
        title: String,
        class: String,
    }

    struct TestSystem {
        windows: Vec<TestWindow>,
        foreground: isize,
        activation_succeeds: bool,
        foreground_sequence: std::collections::VecDeque<isize>,
        restore_succeeds: bool,
        broker_path_reads: usize,
        owner_change_on_broker_path: Option<(usize, WindowIdentity)>,
        enumeration_failed: bool,
        inaccessible_hwnd: Option<isize>,
        unknown_metadata: bool,
        cancel_on_path: Option<Arc<AtomicBool>>,
        inaccessible_session: Option<u32>,
        inaccessible_pid: Option<u32>,
        owner_sessions: std::collections::VecDeque<Option<u32>>,
        broker_drift_on_path: bool,
        trace: Vec<&'static str>,
    }

    impl TestSystem {
        fn window(&self, hwnd: isize) -> Option<&TestWindow> {
            self.windows
                .iter()
                .find(|window| window.identity.hwnd == hwnd)
        }
    }

    impl ForegroundSystem for TestSystem {
        fn identity(&mut self, hwnd: isize) -> Option<WindowIdentity> {
            self.trace.push("identity");
            if self.inaccessible_hwnd == Some(hwnd) {
                return None;
            }
            self.window(hwnd).map(|w| w.identity)
        }
        fn foreground(&mut self) -> isize {
            self.trace.push("foreground");
            if let Some(hwnd) = self.foreground_sequence.pop_front() {
                self.foreground = hwnd;
            }
            self.foreground
        }
        fn windows(&mut self) -> Result<Vec<isize>, ()> {
            if self.enumeration_failed {
                return Err(());
            }
            Ok(self.windows.iter().map(|w| w.identity.hwnd).collect())
        }
        fn visible(&mut self, hwnd: isize) -> bool {
            self.window(hwnd).is_some_and(|w| w.visible)
        }
        fn minimized(&mut self, hwnd: isize) -> bool {
            self.window(hwnd).is_some_and(|w| w.minimized)
        }
        fn session(&mut self, pid: u32) -> Option<u32> {
            if self.inaccessible_session == Some(pid) {
                return None;
            }
            if pid == 10 {
                if let Some(value) = self.owner_sessions.pop_front() {
                    return value;
                }
            }
            self.windows
                .iter()
                .find(|w| w.identity.process_id == pid)
                .map(|w| w.session)
        }
        fn path(&mut self, pid: u32) -> Option<String> {
            if let Some(cancelled) = &self.cancel_on_path {
                cancelled.store(true, Ordering::Release);
            }
            if self.inaccessible_pid == Some(pid) {
                return None;
            }
            let old_path = self
                .windows
                .iter()
                .find(|w| w.identity.process_id == pid)
                .map(|w| w.path.clone());
            if pid == 20 {
                if self.broker_drift_on_path && self.broker_path_reads == 3 {
                    self.windows[1].identity.thread_id = 99;
                }
                self.broker_path_reads += 1;
                if let Some((read, identity)) = self.owner_change_on_broker_path {
                    if read == self.broker_path_reads {
                        self.windows[0].identity = identity;
                    }
                }
            }
            old_path
        }
        fn title(&mut self, hwnd: isize) -> Option<String> {
            if self.unknown_metadata && hwnd == 3 {
                return None;
            }
            self.window(hwnd).map(|w| w.title.clone())
        }
        fn class(&mut self, hwnd: isize) -> Option<String> {
            if self.unknown_metadata && hwnd == 3 {
                return None;
            }
            self.window(hwnd).map(|w| w.class.clone())
        }
        fn current_pid(&mut self) -> u32 {
            10
        }
        fn restore(&mut self, hwnd: isize) {
            self.trace.push("restore");
            if self.restore_succeeds {
                let window = self
                    .windows
                    .iter_mut()
                    .find(|w| w.identity.hwnd == hwnd)
                    .unwrap();
                window.minimized = false;
                window.maximized = false;
            }
        }
        fn activate(&mut self, hwnd: isize) -> bool {
            self.trace.push("activate");
            if self.activation_succeeds {
                self.foreground = hwnd;
            }
            self.activation_succeeds
        }
    }

    fn handoff_fixture() -> (
        TestSystem,
        Arc<BrokerBaseline>,
        WindowIdentity,
        WindowIdentity,
    ) {
        let owner = WindowIdentity {
            hwnd: 1,
            process_id: 10,
            thread_id: 11,
        };
        let broker = WindowIdentity {
            hwnd: 2,
            process_id: 20,
            thread_id: 21,
        };
        let system = TestSystem {
            windows: vec![
                TestWindow {
                    identity: owner,
                    visible: true,
                    minimized: false,
                    maximized: true,
                    session: 2,
                    path: "vault.exe".into(),
                    title: "FidoVault".into(),
                    class: "owner".into(),
                },
                TestWindow {
                    identity: broker,
                    visible: true,
                    minimized: false,
                    maximized: false,
                    session: 2,
                    path: r"C:\Windows\System32\CredentialUIBroker.exe".into(),
                    title: "Windows Security".into(),
                    class: "Credential Dialog Xaml Host".into(),
                },
            ],
            foreground: broker.hwnd,
            activation_succeeds: true,
            foreground_sequence: Default::default(),
            restore_succeeds: true,
            broker_path_reads: 0,
            owner_change_on_broker_path: None,
            enumeration_failed: false,
            inaccessible_hwnd: None,
            unknown_metadata: false,
            cancel_on_path: None,
            inaccessible_session: None,
            inaccessible_pid: None,
            owner_sessions: Default::default(),
            broker_drift_on_path: false,
            trace: Vec::new(),
        };
        let baseline = Arc::new(BrokerBaseline {
            system_directory: r"C:\Windows\System32".into(),
            session: 2,
            windows: HashSet::from([owner]),
            processes: HashSet::new(),
        });
        (system, baseline, owner, broker)
    }

    #[test]
    fn handoff_review_worker_branches_and_permanent_disqualification() {
        for fault in 0..7 {
            let (mut system, baseline, owner, broker) = handoff_fixture();
            let mut other = system.windows[1].clone();
            other.identity = WindowIdentity {
                hwnd: 3,
                process_id: 30,
                thread_id: 31,
            };
            system.windows.push(other);
            match fault {
                0 => system.enumeration_failed = true,
                1 => system.inaccessible_hwnd = Some(3),
                2 => system.inaccessible_pid = Some(30),
                3 => system.unknown_metadata = true,
                4 => system.windows[2].session = 3,
                6 => system.inaccessible_session = Some(30),
                _ => (),
            }
            if fault == 4 {
                system.windows[2].class = "ordinary".into();
            }
            let cancelled = AtomicBool::new(false);
            let accepted = Mutex::new(None);
            let mut policy = MonitorPolicy::default();
            let terminal = policy.observe(
                &mut system,
                owner.hwnd,
                Arc::clone(&baseline),
                &cancelled,
                &accepted,
            );
            assert!(terminal);
            if fault != 4 {
                assert!(accepted.lock().unwrap().is_none());
            } else {
                assert_eq!(accepted.lock().unwrap().as_ref().unwrap().identity, broker);
            }
            // The production worker returns on terminal; disappearing B cannot
            // trigger another observation/publication in this monitor.
            system.windows.pop();
            system.enumeration_failed = false;
            system.inaccessible_hwnd = None;
            system.inaccessible_pid = None;
            system.inaccessible_session = None;
            system.unknown_metadata = false;
            assert!(policy.observe(&mut system, owner.hwnd, baseline, &cancelled, &accepted));
            if fault != 4 {
                assert!(accepted.lock().unwrap().is_none());
            }
            assert!(!system.trace.contains(&"activate"));
        }
        for already_foreground in [true, false] {
            let (mut system, baseline, owner, broker) = handoff_fixture();
            if !already_foreground {
                system.foreground = owner.hwnd;
            }
            let accepted = Mutex::new(None);
            assert!(monitor_observe(
                &mut system,
                owner.hwnd,
                baseline,
                &AtomicBool::new(false),
                &accepted
            ));
            assert_eq!(accepted.lock().unwrap().as_ref().unwrap().identity, broker);
            assert_eq!(system.trace.contains(&"activate"), !already_foreground);
        }
    }

    #[test]
    fn handoff_review_worker_cancel_late_publication_and_isolation() {
        for late in [false, true] {
            let (mut system, baseline, owner, _) = handoff_fixture();
            let cancelled = Arc::new(AtomicBool::new(!late));
            if late {
                system.cancel_on_path = Some(Arc::clone(&cancelled));
            }
            let accepted = Mutex::new(None);
            let unrelated_instance = Mutex::<Option<AcceptedBroker>>::new(None);
            assert!(monitor_observe(
                &mut system,
                owner.hwnd,
                baseline,
                &cancelled,
                &accepted
            ));
            assert!(accepted.lock().unwrap().is_none());
            assert!(unrelated_instance.lock().unwrap().is_none());
            assert!(!system.trace.contains(&"activate"));
        }
    }

    #[test]
    fn handoff_review_localized_title_and_successful_owner_session() {
        let (mut system, baseline, owner, broker) = handoff_fixture();
        system.windows[1].title = "Windows \u{5b89}\u{5168}\u{6027}".into();
        let mut pending = test_pending(&mut system, baseline, owner, broker);
        assert!(pending.as_ref().unwrap().broker.is_some());
        system.foreground = owner.hwnd;
        system.owner_sessions = [Some(2), None, None].into();
        assert_eq!(
            prepare_continuation(&mut pending, owner.hwnd, &[vec![7, 8]], &mut system),
            Ok(HandoffOutcome::OwnerForeground)
        );
        assert_eq!(system.owner_sessions.len(), 2);
        assert!(pending.is_none());
    }

    #[test]
    fn handoff_review_baseline_must_be_complete() {
        let (mut system, _, _, _) = handoff_fixture();
        system.enumeration_failed = true;
        assert!(baseline_window_identities(&mut system).is_err());
        system.enumeration_failed = false;
        system.inaccessible_hwnd = Some(2);
        assert!(baseline_window_identities(&mut system).is_err());
    }

    #[test]
    fn handoff_review_s2_inaccessible_competitor_refuses_capture() {
        let (mut system, baseline, owner, broker) = handoff_fixture();
        let mut other = system.windows[1].clone();
        other.identity = WindowIdentity {
            hwnd: 3,
            process_id: 30,
            thread_id: 31,
        };
        system.windows.push(other);
        system.inaccessible_pid = Some(30);
        let observation = capture_broker(&mut system, baseline, broker);
        assert!(
            observation.is_none(),
            "incomplete competitor is not proof of uniqueness"
        );
        let mut pending = None;
        complete_registration(&mut pending, Ok((test_registration(), owner, observation))).unwrap();
        assert_eq!(
            prepare_continuation(&mut pending, owner.hwnd, &[vec![7, 8]], &mut system),
            Err(HandoffRefusal::UnobservedBroker)
        );
        assert!(pending.is_none());
        assert!(!system.trace.contains(&"activate"));
    }

    #[test]
    fn handoff_review_l1_owner_session_failure_refuses() {
        let (mut system, baseline, owner, broker) = handoff_fixture();
        let mut pending = test_pending(&mut system, baseline, owner, broker);
        system.foreground = owner.hwnd;
        system.owner_sessions = [Some(2), None, None].into();
        assert!(valid_owner(&mut system, owner));
        assert_eq!(
            system.owner_sessions.len(),
            2,
            "same PID requires exactly one successful query"
        );
        system.owner_sessions = [None].into();
        assert_eq!(
            prepare_continuation(&mut pending, owner.hwnd, &[vec![7, 8]], &mut system),
            Err(HandoffRefusal::Owner)
        );
        assert!(pending.is_none());
        assert!(!system.trace.contains(&"activate"));
    }

    #[test]
    fn handoff_review_s1_metadata_identity_drift_refuses() {
        let (mut system, baseline, owner, broker) = handoff_fixture();
        let mut pending = test_pending(&mut system, baseline, owner, broker);
        system.broker_path_reads = 0;
        system.broker_drift_on_path = true;
        system.trace.clear();
        assert_eq!(
            prepare_continuation(&mut pending, owner.hwnd, &[vec![7, 8]], &mut system),
            Err(HandoffRefusal::Broker)
        );
        assert!(pending.is_none());
        assert!(!system.trace.contains(&"activate"));
    }

    #[test]
    fn handoff_capture_retains_only_the_revalidated_unique_new_broker() {
        let (mut system, baseline, _, broker) = handoff_fixture();
        let accepted = capture_broker(&mut system, baseline, broker);
        assert_eq!(accepted.map(|proof| proof.identity), Some(broker));
        assert!(!system.trace.contains(&"activate"));
    }

    fn test_registration() -> RegisteredCredential {
        RegisteredCredential {
            credential_id: vec![7, 8],
            aaguid: [0; 16],
            label: "test".into(),
            kind: KeyKind::WindowsManaged,
        }
    }

    #[test]
    fn handoff_successful_validated_creation_publishes_bound_context() {
        let (mut system, baseline, owner, broker) = handoff_fixture();
        let accepted = capture_broker(&mut system, baseline, broker).unwrap();
        let mut pending = None;
        let registration = complete_registration(
            &mut pending,
            Ok((test_registration(), owner, Some(accepted))),
        )
        .unwrap();
        let context = pending.expect("validated creation must publish one continuation");
        assert_eq!(context.owner, owner);
        assert_eq!(context.credential_id, registration.credential_id);
        assert_eq!(context.broker.unwrap().identity, broker);
    }

    fn test_pending(
        system: &mut TestSystem,
        baseline: Arc<BrokerBaseline>,
        owner: WindowIdentity,
        broker: WindowIdentity,
    ) -> Option<RegistrationContinuation> {
        let accepted = capture_broker(system, baseline, broker).unwrap();
        let mut pending = None;
        complete_registration(
            &mut pending,
            Ok((test_registration(), owner, Some(accepted))),
        )
        .unwrap();
        pending
    }

    #[test]
    fn handoff_successful_first_ceremony_recovers_only_its_broker_for_second() {
        let (mut system, baseline, owner, broker) = handoff_fixture();
        assert!(validate_owner_foreground(owner.hwnd as HWND, owner.hwnd as HWND).is_ok());
        let mut pending = test_pending(&mut system, baseline, owner, broker);
        system.trace.clear();
        assert_eq!(
            prepare_continuation(&mut pending, owner.hwnd, &[vec![7, 8]], &mut system),
            Ok(HandoffOutcome::Recovered)
        );
        assert!(pending.is_none());
        assert!(validate_owner_foreground(owner.hwnd as HWND, system.foreground as HWND).is_ok());
        assert_eq!(
            system
                .trace
                .iter()
                .filter(|event| **event == "activate")
                .count(),
            1
        );
        assert!(
            !system.trace.contains(&"restore"),
            "visible maximized/nonminimized state is preserved"
        );
        assert!(system.windows[0].maximized);
        let activation = system
            .trace
            .iter()
            .position(|event| *event == "activate")
            .unwrap();
        assert_eq!(system.trace[activation - 1], "foreground");
        assert!(system.trace[activation + 1..].contains(&"foreground"));
    }

    #[test]
    fn handoff_parent_update_clears_even_same_hwnd_context() {
        for hwnd in [1, 3, 0] {
            let (mut system, baseline, owner, broker) = handoff_fixture();
            let pending = test_pending(&mut system, baseline, owner, broker);
            let mut backend = WindowsWebAuthnBackend {
                hwnd: owner.hwnd,
                api_version: 4,
                continuation: pending,
            };
            backend.set_webauthn_parent_hwnd(hwnd);
            assert!(
                backend.continuation.is_none(),
                "every explicit owner update ends continuation"
            );
        }
    }

    #[test]
    fn handoff_other_detection_clears_context() {
        let (mut system, baseline, owner, broker) = handoff_fixture();
        let pending = test_pending(&mut system, baseline, owner, broker);
        let mut backend = WindowsWebAuthnBackend {
            hwnd: owner.hwnd,
            api_version: 4,
            continuation: pending,
        };
        backend.detect().unwrap();
        assert!(backend.continuation.is_none());
    }

    #[test]
    fn handoff_restores_only_a_minimized_valid_associated_owner() {
        let (mut system, baseline, owner, broker) = handoff_fixture();
        let mut pending = test_pending(&mut system, baseline, owner, broker);
        system.windows[0].minimized = true;
        system.trace.clear();
        assert_eq!(
            prepare_continuation(&mut pending, owner.hwnd, &[vec![7, 8]], &mut system),
            Ok(HandoffOutcome::Recovered)
        );
        assert_eq!(
            system
                .trace
                .iter()
                .filter(|event| **event == "restore")
                .count(),
            1
        );
        assert!(!system.windows[0].minimized);
    }

    #[test]
    fn handoff_other_enrollment_query_clears_context() {
        let (mut system, baseline, owner, broker) = handoff_fixture();
        let pending = test_pending(&mut system, baseline, owner, broker);
        let mut backend = WindowsWebAuthnBackend {
            hwnd: owner.hwnd,
            api_version: 4,
            continuation: pending,
        };
        assert!(backend.enrollment_count().is_none());
        assert!(backend.continuation.is_none());
    }

    #[test]
    fn handoff_unknown_unrelated_or_changed_foreground_never_activates() {
        for sequence in [vec![0], vec![3], vec![2, 3]] {
            let (mut system, baseline, owner, broker) = handoff_fixture();
            let mut pending = test_pending(&mut system, baseline, owner, broker);
            system.foreground_sequence = sequence.into();
            system.trace.clear();
            assert_eq!(
                prepare_continuation(&mut pending, owner.hwnd, &[vec![7, 8]], &mut system),
                Err(HandoffRefusal::Foreground)
            );
            assert!(pending.is_none());
            assert!(!system.trace.contains(&"activate"));
            assert!(!system.trace.contains(&"restore"));
        }
    }

    #[test]
    fn handoff_missing_or_ambiguous_observation_is_not_authority() {
        for ambiguous in [false, true] {
            let (mut system, baseline, owner, broker) = handoff_fixture();
            if ambiguous {
                let mut other = system.windows[1].clone();
                other.identity = WindowIdentity {
                    hwnd: 3,
                    process_id: 30,
                    thread_id: 31,
                };
                system.windows.push(other);
            } else {
                system.windows.pop();
            }
            let observation = capture_broker(&mut system, baseline, broker);
            assert!(observation.is_none());
            let mut pending = None;
            complete_registration(&mut pending, Ok((test_registration(), owner, observation)))
                .unwrap();
            system.trace.clear();
            assert_eq!(
                prepare_continuation(&mut pending, owner.hwnd, &[vec![7, 8]], &mut system),
                Err(HandoffRefusal::UnobservedBroker)
            );
            assert!(!system.trace.contains(&"activate"));
            assert!(pending.is_none());
        }
    }

    #[test]
    fn handoff_revalidates_broker_identity_session_path_visibility_and_uniqueness() {
        for change in 0..8 {
            let (mut system, baseline, owner, broker) = handoff_fixture();
            let mut pending = test_pending(&mut system, baseline, owner, broker);
            match change {
                0 => system.windows[1].identity.process_id = 30,
                1 => system.windows[1].identity.thread_id = 31,
                2 => system.windows[1].session = 3,
                3 => system.windows[1].path = r"C:\Temp\CredentialUIBroker.exe".into(),
                4 => system.windows[1].visible = false,
                5 => {
                    system.windows.pop();
                }
                6 => system.windows[1].class = "other".into(),
                _ => {
                    let mut other = system.windows[1].clone();
                    other.identity = WindowIdentity {
                        hwnd: 3,
                        process_id: 30,
                        thread_id: 31,
                    };
                    system.windows.push(other);
                }
            }
            system.trace.clear();
            assert_eq!(
                prepare_continuation(&mut pending, owner.hwnd, &[vec![7, 8]], &mut system),
                Err(HandoffRefusal::Broker),
                "change {change}"
            );
            assert!(pending.is_none());
            assert!(!system.trace.contains(&"activate"));
        }
    }

    #[test]
    fn handoff_rejects_stale_hidden_foreign_or_null_owner() {
        for change in 0..5 {
            let (mut system, baseline, owner, broker) = handoff_fixture();
            let mut pending = test_pending(&mut system, baseline, owner, broker);
            match change {
                0 => system.windows[0].visible = false,
                1 => system.windows[0].identity.thread_id = 99,
                2 => system.windows[0].identity.process_id = 99,
                3 => {
                    system.windows.remove(0);
                }
                _ => pending.as_mut().unwrap().owner.hwnd = 0,
            }
            system.trace.clear();
            let handle = pending.as_ref().unwrap().owner.hwnd;
            assert_eq!(
                prepare_continuation(&mut pending, handle, &[vec![7, 8]], &mut system),
                Err(HandoffRefusal::Owner)
            );
            assert!(pending.is_none());
            assert!(!system.trace.contains(&"activate"));
            let expected = WindowIdentity {
                hwnd: handle,
                ..owner
            };
            assert!(checked_owner_snapshot(&mut system, expected).is_err());
        }
    }

    #[test]
    fn handoff_credential_multiple_ids_and_owner_mismatch_consume_context() {
        for (handle, ids) in [
            (1, vec![vec![9]]),
            (1, vec![vec![7, 8], vec![9]]),
            (1, vec![]),
            (3, vec![vec![7, 8]]),
        ] {
            let (mut system, baseline, owner, broker) = handoff_fixture();
            let mut pending = test_pending(&mut system, baseline, owner, broker);
            system.trace.clear();
            assert_eq!(
                prepare_continuation(&mut pending, handle, &ids, &mut system),
                Err(HandoffRefusal::Credential)
            );
            assert!(pending.is_none());
            assert_eq!(
                prepare_continuation(&mut pending, owner.hwnd, &[vec![7, 8]], &mut system),
                Ok(HandoffOutcome::Ordinary)
            );
            assert!(!system.trace.contains(&"activate"));
            assert!(
                validate_owner_foreground(owner.hwnd as HWND, system.foreground as HWND).is_err()
            );
        }
    }

    #[test]
    fn handoff_activation_failure_or_wrong_native_snapshot_aborts_and_cannot_replay() {
        for false_return in [false, true] {
            let (mut system, baseline, owner, broker) = handoff_fixture();
            let mut pending = test_pending(&mut system, baseline, owner, broker);
            system.activation_succeeds = !false_return;
            if !false_return {
                system.foreground_sequence = vec![2, 2, 3].into();
            }
            system.trace.clear();
            assert_eq!(
                prepare_continuation(&mut pending, owner.hwnd, &[vec![7, 8]], &mut system),
                Err(HandoffRefusal::Activation)
            );
            assert!(pending.is_none());
            assert_eq!(
                system
                    .trace
                    .iter()
                    .filter(|event| **event == "activate")
                    .count(),
                1
            );
            system.trace.clear();
            assert_eq!(
                prepare_continuation(&mut pending, owner.hwnd, &[vec![7, 8]], &mut system),
                Ok(HandoffOutcome::Ordinary)
            );
            assert!(!system.trace.contains(&"activate"));
        }
    }

    #[test]
    fn handoff_owner_already_foreground_and_ordinary_login_require_no_activation() {
        let (mut system, baseline, owner, broker) = handoff_fixture();
        let mut pending = test_pending(&mut system, baseline, owner, broker);
        system.foreground = owner.hwnd;
        system.trace.clear();
        assert_eq!(
            prepare_continuation(&mut pending, owner.hwnd, &[vec![7, 8]], &mut system),
            Ok(HandoffOutcome::OwnerForeground)
        );
        assert_eq!(
            prepare_continuation(&mut pending, owner.hwnd, &[vec![7, 8]], &mut system),
            Ok(HandoffOutcome::Ordinary)
        );
        assert!(!system.trace.contains(&"activate"));
        assert!(!system.trace.contains(&"restore"));
        system.foreground = broker.hwnd;
        assert!(validate_owner_foreground(owner.hwnd as HWND, system.foreground as HWND).is_err());
    }

    #[test]
    fn handoff_first_error_cancel_unconfirmed_or_parse_error_leaves_no_context() {
        for error in [
            FidoError::Internal("cancel".into()),
            FidoError::Internal("API error".into()),
            FidoError::PrfNotConfirmed,
            FidoError::Internal("parse error".into()),
        ] {
            let (mut system, baseline, owner, broker) = handoff_fixture();
            let mut pending = test_pending(&mut system, baseline, owner, broker);
            assert!(complete_registration(&mut pending, Err(error)).is_err());
            assert!(pending.is_none());
        }
    }

    #[test]
    fn handoff_monitor_result_is_taken_after_join_and_only_once() {
        let (mut system, baseline, _, broker) = handoff_fixture();
        let proof = capture_broker(&mut system, baseline, broker).unwrap();
        let accepted = Arc::new(Mutex::new(None));
        let worker_result = Arc::clone(&accepted);
        let monitor = WebAuthnForegroundMonitor {
            cancelled: Arc::new(AtomicBool::new(false)),
            armed: Arc::new(AtomicBool::new(true)),
            accepted: Arc::clone(&accepted),
            worker: Some(thread::spawn(move || {
                *worker_result.lock().unwrap() = Some(proof);
            })),
        };
        assert_eq!(monitor.finish().unwrap().identity, broker);
        assert!(accepted.lock().unwrap().is_none());
    }

    #[test]
    fn handoff_monitor_worker_error_discards_observation() {
        let (mut system, baseline, _, broker) = handoff_fixture();
        let proof = capture_broker(&mut system, baseline, broker).unwrap();
        let monitor = WebAuthnForegroundMonitor {
            cancelled: Arc::new(AtomicBool::new(false)),
            armed: Arc::new(AtomicBool::new(true)),
            accepted: Arc::new(Mutex::new(Some(proof))),
            worker: Some(thread::spawn(|| panic!("synthetic monitor failure"))),
        };
        assert!(monitor.finish().is_none());
    }

    #[test]
    fn handoff_owner_changed_during_broker_revalidation_is_never_activated() {
        let (mut system, baseline, owner, broker) = handoff_fixture();
        let mut pending = test_pending(&mut system, baseline, owner, broker);
        system.broker_path_reads = 0;
        system.owner_change_on_broker_path = Some((
            3,
            WindowIdentity {
                thread_id: 99,
                ..owner
            },
        ));
        system.trace.clear();
        assert_eq!(
            prepare_continuation(&mut pending, owner.hwnd, &[vec![7, 8]], &mut system),
            Err(HandoffRefusal::Broker)
        );
        assert!(!system.trace.contains(&"activate"));
        assert!(pending.is_none());
    }

    #[test]
    fn handoff_capture_refuses_preexisting_hidden_or_changed_candidates_and_cancel() {
        for change in 0..5 {
            let (mut system, mut baseline, _, broker) = handoff_fixture();
            match change {
                0 => {
                    Arc::get_mut(&mut baseline).unwrap().windows.insert(broker);
                }
                1 => {
                    Arc::get_mut(&mut baseline)
                        .unwrap()
                        .processes
                        .insert(broker.process_id);
                }
                2 => system.windows[1].visible = false,
                3 => system.windows[1].identity.thread_id = 99,
                _ => system.foreground = 3,
            }
            assert!(capture_broker(&mut system, baseline, broker).is_none());
        }
        let (mut system, baseline, _, broker) = handoff_fixture();
        let cancelled = AtomicBool::new(true);
        let channel = Mutex::new(None);
        record_broker(
            &mut system,
            Arc::clone(&baseline),
            broker,
            &cancelled,
            &channel,
        );
        assert!(channel.lock().unwrap().is_none());
        cancelled.store(false, Ordering::Release);
        record_broker(&mut system, baseline, broker, &cancelled, &channel);
        assert_eq!(channel.lock().unwrap().as_ref().unwrap().identity, broker);
    }

    #[test]
    fn handoff_restore_failure_and_focus_change_after_restore_abort() {
        for restore_fails in [false, true] {
            let (mut system, baseline, owner, broker) = handoff_fixture();
            let mut pending = test_pending(&mut system, baseline, owner, broker);
            system.windows[0].minimized = true;
            system.restore_succeeds = !restore_fails;
            if !restore_fails {
                system.foreground_sequence = vec![2, 2, 3, 3].into();
            }
            system.trace.clear();
            let expected = if restore_fails {
                HandoffRefusal::Owner
            } else {
                HandoffRefusal::Foreground
            };
            assert_eq!(
                prepare_continuation(&mut pending, owner.hwnd, &[vec![7, 8]], &mut system),
                Err(expected)
            );
            assert!(pending.is_none());
            assert!(!system.trace.contains(&"activate"));
            assert_eq!(
                system
                    .trace
                    .iter()
                    .filter(|event| **event == "restore")
                    .count(),
                1
            );
        }
    }

    struct CeremonyBackend {
        system: TestSystem,
        baseline: Arc<BrokerBaseline>,
        owner: WindowIdentity,
        broker: WindowIdentity,
        pending: Option<RegistrationContinuation>,
        first_error: Option<FidoError>,
        second_error: bool,
        get_calls: usize,
    }

    impl FidoBackend for CeremonyBackend {
        fn detect(&mut self) -> Result<DetectedKey, FidoError> {
            self.pending = None;
            Ok(DetectedKey {
                kind: KeyKind::WindowsManaged,
                label: "test".into(),
                aaguid: [0; 16],
            })
        }
        fn register_credential(
            &mut self,
            _: &DetectedKey,
            _: Option<&str>,
        ) -> Result<RegisteredCredential, FidoError> {
            self.pending = None;
            self.system.foreground = self.owner.hwnd;
            validate_owner_foreground(self.owner.hwnd as HWND, self.system.foreground as HWND)?;
            let result = if let Some(error) = self.first_error.take() {
                Err(error)
            } else {
                // Synthetic native success/focus loss, followed by real capture policy.
                self.system.foreground = self.broker.hwnd;
                let observation =
                    capture_broker(&mut self.system, Arc::clone(&self.baseline), self.broker);
                Ok((test_registration(), self.owner, observation))
            };
            complete_registration(&mut self.pending, result)
        }
        fn get_prf_secret(&mut self, id: &[u8], _: Option<&str>) -> Result<[u8; 32], FidoError> {
            self.get_calls += 1;
            prepare_continuation(
                &mut self.pending,
                self.owner.hwnd,
                &[id.to_vec()],
                &mut self.system,
            )
            .map_err(|refusal| FidoError::Internal(refusal.reason().into()))?;
            checked_owner_snapshot(&mut self.system, self.owner)?;
            validate_owner_foreground(self.owner.hwnd as HWND, self.system.foreground as HWND)?;
            if self.second_error {
                Err(FidoError::Internal("synthetic second API failure".into()))
            } else {
                Ok([0xA5; 32])
            }
        }
        fn prf_supported(&self) -> bool {
            true
        }
    }

    fn ceremony_backend(first_error: Option<FidoError>, second_error: bool) -> CeremonyBackend {
        let (system, baseline, owner, broker) = handoff_fixture();
        CeremonyBackend {
            system,
            baseline,
            owner,
            broker,
            pending: None,
            first_error,
            second_error,
            get_calls: 0,
        }
    }

    fn fixture_vault() -> (crate::vault::Vault, std::path::PathBuf) {
        let nonce: u64 = rand::random();
        let dir = std::env::temp_dir().join(format!(
            "pfv-handoff-fixture-{}-{nonce:016x}",
            std::process::id()
        ));
        std::fs::create_dir(&dir).unwrap();
        let path = dir.join("mock-vault.db");
        (
            crate::vault::Vault::create(&path, "fixture-only-password").unwrap(),
            dir,
        )
    }

    #[test]
    fn handoff_vault_canceled_first_ceremony_prevents_second() {
        let (mut vault, dir) = fixture_vault();
        let before = std::fs::read(&vault.path).unwrap();
        for error in [
            FidoError::Internal("cancel".into()),
            FidoError::PrfNotConfirmed,
            FidoError::Internal("invalid response".into()),
        ] {
            let mut backend = ceremony_backend(Some(error), false);
            assert!(vault
                .register_key_with_label(&mut backend, None, "New")
                .is_err());
            assert_eq!(backend.get_calls, 0);
            assert!(backend.pending.is_none());
            assert!(vault.keys_meta().is_empty());
            assert_eq!(std::fs::read(&vault.path).unwrap(), before);
        }
        std::fs::remove_file(&vault.path).unwrap();
        std::fs::remove_dir(dir).unwrap();
    }

    #[test]
    fn handoff_vault_second_failure_preserves_existing_slots_and_file() {
        let (mut vault, dir) = fixture_vault();
        vault
            .register_key_with_label(&mut crate::fido2::MockBackend::new(), None, "Existing")
            .unwrap();
        let slots = vault.keys_meta();
        let audit_length = vault.audit().len();
        let before = std::fs::read(&vault.path).unwrap();
        for activation_fails in [false, true] {
            let mut backend = ceremony_backend(None, true);
            backend.system.activation_succeeds = !activation_fails;
            assert!(vault
                .register_key_with_label(&mut backend, None, "New")
                .is_err());
            assert_eq!(backend.get_calls, 1);
            assert!(backend.pending.is_none());
            assert_eq!(vault.keys_meta(), slots);
            assert_eq!(vault.audit().len(), audit_length);
            assert_eq!(std::fs::read(&vault.path).unwrap(), before);
        }
        std::fs::remove_file(&vault.path).unwrap();
        std::fs::remove_dir(dir).unwrap();
    }

    #[test]
    fn handoff_vault_success_uses_two_ceremonies_and_appends_after_secret() {
        let (mut vault, dir) = fixture_vault();
        let mut backend = ceremony_backend(None, false);
        vault
            .register_key_with_label(&mut backend, None, "New")
            .unwrap();
        assert_eq!(backend.get_calls, 1);
        assert!(backend.pending.is_none());
        assert_eq!(vault.keys_meta().len(), 1);
        assert_eq!(
            backend
                .system
                .trace
                .iter()
                .filter(|event| **event == "activate")
                .count(),
            1
        );
        std::fs::remove_file(&vault.path).unwrap();
        std::fs::remove_dir(dir).unwrap();
    }

    #[test]
    fn windows_backend_advertises_brokered_key_selection_ui() {
        let backend = WindowsWebAuthnBackend {
            hwnd: 0,
            api_version: 4,
            continuation: None,
        };
        assert!(backend.uses_brokered_key_selection());
    }

    #[test]
    fn windows_api_call_requires_its_owner_to_be_foreground() {
        let owner = 1usize as HWND;
        let foreground = 2usize as HWND;
        assert!(validate_owner_foreground(owner, owner).is_ok());
        assert!(validate_owner_foreground(owner, foreground).is_err());
    }

    #[test]
    fn only_a_new_same_session_system_windows_security_dialog_is_selected() {
        assert!(is_new_windows_security_dialog(
            WindowsSecurityDialogCandidate {
                title: "Windows 安全性",
                class_name: "Credential Dialog Xaml Host",
                process_path: r"C:\Windows\System32\CredentialUIBroker.exe",
                system_directory: r"C:\Windows\System32",
                visible: true,
                current_session: 2,
                window_session: 2,
                is_new_window: true,
                is_new_process: true,
            }
        ));

        let non_candidates = [
            (
                "Windows 安全性",
                "Credential Dialog Xaml Host",
                r"C:\Temp\CredentialUIBroker.exe",
                true,
                2,
                2,
                true,
            ),
            (
                "Other prompt",
                "Credential Dialog Xaml Host",
                r"C:\Windows\System32\CredentialUIBroker.exe",
                true,
                2,
                2,
                true,
            ),
            (
                "Windows 安全性",
                "Other Window",
                r"C:\Windows\System32\CredentialUIBroker.exe",
                true,
                2,
                2,
                true,
            ),
            (
                "Windows 安全性",
                "Credential Dialog Xaml Host",
                r"C:\Windows\System32\CredentialUIBroker.exe",
                false,
                2,
                2,
                true,
            ),
            (
                "Windows 安全性",
                "Credential Dialog Xaml Host",
                r"C:\Windows\System32\CredentialUIBroker.exe",
                true,
                2,
                3,
                true,
            ),
            (
                "Windows 安全性",
                "Credential Dialog Xaml Host",
                r"C:\Windows\System32\CredentialUIBroker.exe",
                true,
                2,
                2,
                false,
            ),
        ];
        for (title, class_name, path, visible, current_session, window_session, is_new) in
            non_candidates
        {
            assert!(!is_new_windows_security_dialog(
                WindowsSecurityDialogCandidate {
                    title,
                    class_name,
                    process_path: path,
                    system_directory: r"C:\Windows\System32",
                    visible,
                    current_session,
                    window_session,
                    is_new_window: is_new,
                    is_new_process: true,
                }
            ));
        }
    }

    #[test]
    fn broker_dialog_requires_new_process_and_new_window_identity() {
        let trusted = WindowsSecurityDialogCandidate {
            title: "Windows 安全性",
            class_name: "Credential Dialog Xaml Host",
            process_path: r"C:\Windows\System32\CredentialUIBroker.exe",
            system_directory: r"C:\Windows\System32",
            visible: true,
            current_session: 2,
            window_session: 2,
            is_new_window: true,
            is_new_process: true,
        };
        assert!(is_new_windows_security_dialog(trusted));
        assert!(!is_new_windows_security_dialog(
            WindowsSecurityDialogCandidate {
                is_new_process: false,
                ..trusted
            }
        ));
        assert!(!is_new_windows_security_dialog(
            WindowsSecurityDialogCandidate {
                is_new_window: false,
                ..trusted
            }
        ));
    }

    #[test]
    fn hidden_or_reused_window_identity_is_not_new() {
        let existing = WindowIdentity {
            hwnd: 0x1203ce,
            process_id: 1492,
            thread_id: 2844,
        };
        let baseline = HashSet::from([existing]);
        assert!(!is_new_window_identity(existing, &baseline));
        assert!(is_new_window_identity(
            WindowIdentity {
                hwnd: existing.hwnd,
                process_id: 2000,
                thread_id: 3000,
            },
            &baseline,
        ));
    }

    #[test]
    fn ambiguous_broker_candidates_are_not_activated() {
        let first = WindowIdentity {
            hwnd: 0x1203ce,
            process_id: 1492,
            thread_id: 2844,
        };
        let second = WindowIdentity {
            hwnd: 0xf03fc,
            process_id: 11064,
            thread_id: 9552,
        };
        assert_eq!(select_unique_candidate(&[first]), Some(first));
        assert_eq!(select_unique_candidate(&[first, second]), None);
        assert_eq!(select_unique_candidate(&[]), None);
    }

    #[test]
    fn activation_is_skipped_after_focus_changes_or_monitor_cancels() {
        let owner = 0x1d056c;
        let dialog = 0x1203ce;
        assert!(should_attempt_dialog_activation(
            owner, dialog, owner, false
        ));
        assert!(!should_attempt_dialog_activation(
            owner, dialog, 0xabc, false
        ));
        assert!(!should_attempt_dialog_activation(
            owner, dialog, dialog, false
        ));
        assert!(!should_attempt_dialog_activation(
            owner, dialog, owner, true
        ));
    }

    #[test]
    fn focus_monitor_lifetime_covers_webauthn_timeout() {
        assert!(focus_monitor_timeout() >= Duration::from_millis(OP_TIMEOUT_MS as u64));
    }

    #[test]
    fn windows_api_call_rejects_missing_owner_hwnd() {
        let missing = ptr::null_mut();
        assert!(validate_owner_foreground(missing, missing).is_err());
    }

    #[test]
    fn backend_uses_the_live_owner_hwnd_set_by_the_command() {
        let mut backend = WindowsWebAuthnBackend {
            hwnd: 0,
            api_version: 4,
            continuation: None,
        };
        let live_hwnd = 1usize as isize;
        backend.set_webauthn_parent_hwnd(live_hwnd);
        assert_eq!(backend.hwnd().unwrap(), live_hwnd as HWND);
    }

    #[test]
    fn backend_rejects_missing_live_owner_hwnd_instead_of_using_foreground_window() {
        let backend = WindowsWebAuthnBackend {
            hwnd: 0,
            api_version: 4,
            continuation: None,
        };
        assert!(backend.hwnd().is_err());
    }

    #[test]
    fn multi_credential_assertion_returns_the_selected_registered_id() {
        let candidates = vec![vec![1, 2, 3], vec![4, 5, 6]];
        assert_eq!(
            validate_selected_credential_id(&candidates, &[4, 5, 6]).unwrap(),
            vec![4, 5, 6]
        );
        assert!(validate_selected_credential_id(&candidates, &[9]).is_err());
        assert!(validate_selected_credential_id(&[], &[1]).is_err());
    }

    #[test]
    fn create_client_data_uses_stable_rp_origin_and_challenge() {
        let challenge = [0x5a; 32];
        let value: Value =
            serde_json::from_slice(&client_data_json(ClientDataOperation::Create, &challenge))
                .unwrap();
        assert_eq!(value["type"], "webauthn.create");
        assert_eq!(value["challenge"], URL_SAFE_NO_PAD.encode(challenge));
        assert_eq!(value["origin"], ORIGIN);
        assert_eq!(ORIGIN, format!("https://{RP_ID}"));
    }

    #[test]
    fn get_client_data_uses_authentication_type() {
        let value: Value =
            serde_json::from_slice(&client_data_json(ClientDataOperation::Get, &[1, 2, 3]))
                .unwrap();
        assert_eq!(value["type"], "webauthn.get");
        assert_eq!(value["challenge"], URL_SAFE_NO_PAD.encode([1, 2, 3]));
    }

    #[test]
    fn prf_hmac_secret_requires_windows_api_version_four() {
        assert!(!hmac_secret_api_supported(0));
        assert!(!hmac_secret_api_supported(3));
        assert!(hmac_secret_api_supported(4));
        assert!(hmac_secret_api_supported(9));
    }

    #[test]
    fn hmac_secret_uses_the_existing_raw_vault_salt() {
        assert_eq!(vault_hmac_salt(), crate::crypto::prf_salt_bytes());
        assert_eq!(vault_hmac_salt().len(), 32);
        assert_eq!(
            raw_hmac_secret_flag(),
            WEBAUTHN_AUTHENTICATOR_HMAC_SECRET_VALUES_FLAG
        );
    }

    #[test]
    fn aaguid_is_read_only_when_attested_credential_data_is_present() {
        let mut auth_data = vec![0u8; 53];
        auth_data[32] = 0x40;
        auth_data[37..53].copy_from_slice(&[0xA5; 16]);
        assert_eq!(aaguid_from_authenticator_data(&auth_data), [0xA5; 16]);

        auth_data[32] = 0;
        assert_eq!(aaguid_from_authenticator_data(&auth_data), [0; 16]);
    }

    #[test]
    fn registration_requires_positive_hmac_secret_extension_output() {
        let id = wide("hmac-secret");
        let mut enabled: windows_sys::core::BOOL = 1;
        let mut extension = WEBAUTHN_EXTENSION {
            pwszExtensionIdentifier: id.as_ptr(),
            cbExtension: std::mem::size_of::<windows_sys::core::BOOL>() as u32,
            pvExtension: (&mut enabled as *mut windows_sys::core::BOOL).cast::<c_void>(),
        };
        let extensions = WEBAUTHN_EXTENSIONS {
            cExtensions: 1,
            pExtensions: &mut extension,
        };
        assert!(hmac_secret_enabled(&extensions));
        let mut disabled: windows_sys::core::BOOL = 0;
        let mut disabled_extension = WEBAUTHN_EXTENSION {
            pwszExtensionIdentifier: id.as_ptr(),
            cbExtension: std::mem::size_of::<windows_sys::core::BOOL>() as u32,
            pvExtension: (&mut disabled as *mut windows_sys::core::BOOL).cast::<c_void>(),
        };
        let disabled_extensions = WEBAUTHN_EXTENSIONS {
            cExtensions: 1,
            pExtensions: &mut disabled_extension,
        };
        assert!(!hmac_secret_enabled(&disabled_extensions));
    }
}
