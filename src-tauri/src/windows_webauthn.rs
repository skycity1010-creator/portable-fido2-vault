//! Windows GUI FIDO backend based on Microsoft's WebAuthn API.
//! The raw CTAP backend remains available for the CLI and diagnostics.

use crate::fido2::{DetectedKey, FidoBackend, FidoError, KeyKind, RegisteredCredential};
use crate::webauthn_diagnostics::{
    capability_record, diagnose, monitor_record, ContinuationDiagnostics, ContinuationStatus,
    FailureStage, MonitorStop, NativeSessionEvidence, Operation, OperationDiagnostics, QueryStatus,
    SessionProtocol, SessionState, WindowScalars,
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
use windows_sys::Win32::System::RemoteDesktop::{
    ProcessIdToSessionId, WTSActive, WTSClientProtocolType, WTSConnectState, WTSFreeMemory,
    WTSQuerySessionInformationW, WTS_INFO_CLASS,
};
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
    session: u32,
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

#[derive(Default)]
struct BrokerObservation {
    broker: Option<AcceptedBroker>,
    // Private policy evidence, never populated from the diagnostic channel.
    passive_safe: bool,
}
#[cfg(test)]
impl From<Option<AcceptedBroker>> for BrokerObservation {
    fn from(broker: Option<AcceptedBroker>) -> Self {
        Self {
            broker,
            passive_safe: true,
        }
    }
}
struct RegistrationContinuation {
    owner: WindowIdentity,
    credential_id: Vec<u8>,
    broker: Option<AcceptedBroker>,
    passive_safe: bool,
}

type CreationResult = Result<(RegisteredCredential, WindowIdentity, BrokerObservation), FidoError>;

fn complete_registration(
    pending: &mut Option<RegistrationContinuation>,
    result: CreationResult,
) -> Result<RegisteredCredential, FidoError> {
    *pending = None;
    result.map(|(registration, owner, observation)| {
        *pending = Some(RegistrationContinuation {
            owner,
            credential_id: registration.credential_id.clone(),
            broker: observation.broker,
            passive_safe: observation.passive_safe,
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
    PassiveSession,
    PassiveDeadline,
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
            Self::PassiveSession => "passive-session-ineligible",
            Self::PassiveDeadline => "passive-deadline",
        }
    }
}

#[cfg(test)]
fn prepare_continuation(
    pending: &mut Option<RegistrationContinuation>,
    owner: isize,
    credential_ids: &[Vec<u8>],
    system: &mut impl ForegroundSystem,
) -> Result<HandoffOutcome, HandoffRefusal> {
    prepare_continuation_recorded(
        pending,
        owner,
        credential_ids,
        system,
        &mut ContinuationDiagnostics::default(),
    )
}

fn prepare_continuation_recorded(
    pending: &mut Option<RegistrationContinuation>,
    owner: isize,
    credential_ids: &[Vec<u8>],
    system: &mut impl ForegroundSystem,
    diagnostic: &mut ContinuationDiagnostics,
) -> Result<HandoffOutcome, HandoffRefusal> {
    let started = system.monotonic();
    let result =
        prepare_continuation_inner(pending, owner, credential_ids, system, started, diagnostic);
    diagnostic.elapsed_ms = system
        .monotonic()
        .saturating_duration_since(started)
        .as_millis()
        .min(u64::MAX as u128) as u64;
    diagnostic.status = Some(match &result {
        Ok(HandoffOutcome::Ordinary) => ContinuationStatus::Ordinary,
        Ok(HandoffOutcome::OwnerForeground) if diagnostic.native.is_some() => {
            ContinuationStatus::PassiveReturn
        }
        Ok(HandoffOutcome::OwnerForeground) => ContinuationStatus::OwnerForeground,
        Ok(HandoffOutcome::Recovered) => ContinuationStatus::Recovered,
        Err(HandoffRefusal::Credential) => ContinuationStatus::Credential,
        Err(HandoffRefusal::Owner) => ContinuationStatus::Owner,
        Err(HandoffRefusal::UnobservedBroker) => ContinuationStatus::UnobservedBroker,
        Err(HandoffRefusal::Foreground) => ContinuationStatus::Foreground,
        Err(HandoffRefusal::Broker) => ContinuationStatus::Broker,
        Err(HandoffRefusal::Activation) => ContinuationStatus::Activation,
        Err(HandoffRefusal::PassiveSession) => ContinuationStatus::Session,
        Err(HandoffRefusal::PassiveDeadline) => ContinuationStatus::Deadline,
    });
    result
}

// Carries creation authority separately from the diagnostic record. Only a
// successful, consumed continuation can supply a creation-bound identity.
fn prepare_assertion_continuation(
    pending: &mut Option<RegistrationContinuation>,
    owner: isize,
    credential_ids: &[Vec<u8>],
    system: &mut impl ForegroundSystem,
    diagnostic: &mut ContinuationDiagnostics,
) -> Result<(HandoffOutcome, Option<WindowIdentity>), HandoffRefusal> {
    let creation_owner = pending.as_ref().map(|context| context.owner);
    prepare_continuation_recorded(pending, owner, credential_ids, system, diagnostic)
        .map(|outcome| (outcome, creation_owner))
}

fn assertion_owner_baseline(
    system: &mut impl ForegroundSystem,
    hwnd: isize,
    creation_owner: Option<WindowIdentity>,
) -> Result<WindowIdentity, FidoError> {
    if let Some(expected) = creation_owner {
        if expected.hwnd != hwnd || expected.session == 0 {
            return Err(FidoError::Internal(
                "Windows WebAuthn creation owner is unavailable".into(),
            ));
        }
        return checked_owner_snapshot(system, expected);
    }
    // Ordinary login establishes its own fresh owner baseline.
    system
        .identity(hwnd)
        .filter(|owner| valid_owner(system, *owner))
        .ok_or_else(|| FidoError::Internal("Windows WebAuthn owner identity is unavailable".into()))
}

fn identity_scalars(identity: Option<WindowIdentity>, hwnd: isize) -> WindowScalars {
    WindowScalars {
        hwnd: (hwnd != 0).then_some(hwnd),
        pid: identity.map(|i| i.process_id),
        tid: identity.map(|i| i.thread_id),
        session: identity.map(|i| i.session),
    }
}

fn diagnostic_foreground(
    diagnostic: &mut ContinuationDiagnostics,
    hwnd: isize,
    observed_owner: Option<WindowScalars>,
) {
    // An unrelated sample refuses immediately; do not block on its metadata.
    diagnostic.foreground = observed_owner
        .filter(|observed| observed.hwnd == Some(hwnd))
        .unwrap_or_else(|| identity_scalars(None, hwnd));
}

fn valid_owner_recorded(
    system: &mut impl ForegroundSystem,
    owner: WindowIdentity,
    diagnostic: &mut ContinuationDiagnostics,
) -> bool {
    let pid = system.current_pid();
    let identity = system.identity(owner.hwnd);
    diagnostic.owner = identity_scalars(identity, owner.hwnd);
    let visible = system.visible(owner.hwnd);
    diagnostic.owner_visible = Some(visible);
    let session = system.session(pid);
    // Re-read identity after potentially blocking session metadata.
    let final_identity = system.identity(owner.hwnd);
    diagnostic.owner = identity_scalars(final_identity, owner.hwnd);
    if final_identity.is_some_and(|identity| identity.process_id == pid)
        && final_identity.map(|identity| identity.session) != session
    {
        // Conflicting native metadata is unknown, never a fabricated session.
        diagnostic.owner.session = None;
    }
    let identity_matches = identity == Some(owner)
        && final_identity == Some(owner)
        && owner.process_id == pid
        && session == Some(owner.session)
        && system.owner_ids(owner.hwnd) == Some((owner.process_id, owner.thread_id));
    diagnostic.identity_match = Some(identity_matches);
    let current_visible = visible && system.visible(owner.hwnd);
    diagnostic.owner_visible = Some(current_visible);
    owner.hwnd != 0
        && owner.process_id == pid
        && identity_matches
        && current_visible
        && session == Some(owner.session)
}

fn prepare_continuation_inner(
    pending: &mut Option<RegistrationContinuation>,
    owner: isize,
    credential_ids: &[Vec<u8>],
    system: &mut impl ForegroundSystem,
    started: Instant,
    diagnostic: &mut ContinuationDiagnostics,
) -> Result<HandoffOutcome, HandoffRefusal> {
    let Some(context) = pending.take() else {
        return Ok(HandoffOutcome::Ordinary);
    };
    if owner != context.owner.hwnd || credential_ids != [context.credential_id] {
        return Err(HandoffRefusal::Credential);
    }
    // Capture the unobserved branch's initial sample before blocking owner
    // metadata can turn an initial NULL into a late "ordinary" owner pass.
    // The accepted-broker branch retains its original observation order.
    let initial_foreground = context.broker.is_none().then(|| system.foreground());
    if let Some(foreground) = initial_foreground {
        diagnostic_foreground(diagnostic, foreground, None);
    }
    if !valid_owner_recorded(system, context.owner, diagnostic) {
        return Err(HandoffRefusal::Owner);
    }
    let foreground = match initial_foreground {
        Some(0) => 0,
        Some(foreground) if foreground != owner => foreground,
        _ => system.foreground(),
    };
    let observed_owner = diagnostic.owner;
    diagnostic_foreground(diagnostic, foreground, Some(observed_owner));
    diagnostic.owner_minimized = Some(system.minimized(owner));
    if foreground == owner {
        if system.minimized(owner) {
            return Err(HandoffRefusal::Owner);
        }
        return Ok(HandoffOutcome::OwnerForeground);
    }
    let Some(broker) = context.broker else {
        if foreground != 0 || !context.passive_safe {
            return Err(HandoffRefusal::UnobservedBroker);
        }
        if initial_foreground != Some(0) {
            return Err(HandoffRefusal::UnobservedBroker);
        }
        return passive_owner_return(system, context.owner, started, diagnostic);
    };
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

// Budget starts before eligibility metadata; a blocking native query can return
// late, but can never grant a late success. Only NULL samples permit another poll.
fn passive_owner_return(
    system: &mut impl ForegroundSystem,
    owner: WindowIdentity,
    started: Instant,
    diagnostic: &mut ContinuationDiagnostics,
) -> Result<HandoffOutcome, HandoffRefusal> {
    let deadline = started + Duration::from_millis(1000);
    let poll = Duration::from_millis(20);
    // No waiting is authorized until native active RDP and owner evidence agree.
    passive_eligibility(system, owner, deadline, diagnostic)?;
    loop {
        if deadline.saturating_duration_since(system.monotonic()) < poll {
            return Err(HandoffRefusal::PassiveDeadline);
        }
        system.wait(poll);
        // Refresh all eligibility evidence after each wait, before the new sample.
        passive_eligibility(system, owner, deadline, diagnostic)?;
        let foreground = system.foreground();
        let observed_owner = diagnostic.owner;
        diagnostic_foreground(diagnostic, foreground, Some(observed_owner));
        if system.monotonic() >= deadline {
            return Err(HandoffRefusal::PassiveDeadline);
        }
        if foreground == owner.hwnd {
            return Ok(HandoffOutcome::OwnerForeground);
        }
        if foreground != 0 {
            return Err(HandoffRefusal::Foreground);
        }
    }
}

fn passive_eligibility(
    system: &mut impl ForegroundSystem,
    owner: WindowIdentity,
    deadline: Instant,
    diagnostic: &mut ContinuationDiagnostics,
) -> Result<(), HandoffRefusal> {
    if system.monotonic() >= deadline {
        return Err(HandoffRefusal::PassiveDeadline);
    }
    if owner.session == 0 {
        return Err(HandoffRefusal::Owner);
    }
    let owner_valid = valid_owner_recorded(system, owner, diagnostic);
    let minimized = system.minimized(owner.hwnd);
    diagnostic.owner_minimized = Some(minimized);
    if !owner_valid || minimized {
        return Err(HandoffRefusal::Owner);
    }
    if system.monotonic() >= deadline {
        return Err(HandoffRefusal::PassiveDeadline);
    }
    let evidence = system.native_session(owner.session, deadline);
    diagnostic.native = Some(evidence);
    if system.monotonic() >= deadline {
        return Err(HandoffRefusal::PassiveDeadline);
    }
    if !evidence.active_rdp() {
        return Err(HandoffRefusal::PassiveSession);
    }
    // Identity/session and visibility are validated again after native metadata.
    let owner_valid = valid_owner_recorded(system, owner, diagnostic);
    let minimized = system.minimized(owner.hwnd);
    diagnostic.owner_minimized = Some(minimized);
    if !owner_valid || minimized {
        return Err(HandoffRefusal::Owner);
    }
    if system.monotonic() >= deadline {
        return Err(HandoffRefusal::PassiveDeadline);
    }
    Ok(())
}

fn query_native_session(
    session: u32,
    deadline: Instant,
    query_protocol: impl FnOnce(u32) -> Result<u16, QueryStatus>,
    query_state: impl FnOnce(u32) -> Result<i32, QueryStatus>,
    now: impl FnOnce() -> Instant,
) -> NativeSessionEvidence {
    let protocol = query_protocol(session);
    // Failed/unknown/non-RDP protocol cannot authorize another blocking query.
    let state = if protocol == Ok(2) && now() < deadline {
        query_state(session)
    } else {
        Err(QueryStatus::NotQueried)
    };
    session_evidence(protocol, state)
}

fn session_evidence(
    protocol: Result<u16, QueryStatus>,
    state: Result<i32, QueryStatus>,
) -> NativeSessionEvidence {
    NativeSessionEvidence {
        protocol: match protocol {
            Ok(0) => SessionProtocol::Console,
            Ok(1) => SessionProtocol::Legacy,
            Ok(2) => SessionProtocol::Rdp,
            _ => SessionProtocol::Unknown,
        },
        state: match state {
            Ok(value) if value == WTSActive => SessionState::Active,
            Ok(1..=9) => SessionState::Inactive,
            _ => SessionState::Unknown,
        },
        protocol_query: protocol
            .map(|_| QueryStatus::Valid)
            .unwrap_or_else(|status| status),
        state_query: state
            .map(|_| QueryStatus::Valid)
            .unwrap_or_else(|status| status),
    }
}

// The BOOL and byte count are native API output, not environment heuristics.
unsafe fn parse_wts<T: Copy>(
    success: i32,
    buffer: *const u16,
    bytes: u32,
) -> Result<T, QueryStatus> {
    if success == 0 {
        return Err(QueryStatus::NativeFailure);
    }
    if buffer.is_null() {
        return Err(QueryStatus::NullBuffer);
    }
    if bytes as usize != std::mem::size_of::<T>() {
        return Err(QueryStatus::InvalidLength);
    }
    Ok(unsafe { ptr::read_unaligned(buffer.cast::<T>()) })
}

struct WtsAllocation(*mut u16);
impl Drop for WtsAllocation {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                WTSFreeMemory(self.0.cast());
            }
        }
    }
}
fn query_wts<T: Copy>(session: u32, class: WTS_INFO_CLASS) -> Result<T, QueryStatus> {
    let mut buffer = ptr::null_mut();
    let mut bytes = 0;
    let success = unsafe {
        WTSQuerySessionInformationW(ptr::null_mut(), session, class, &mut buffer, &mut bytes)
    };
    let allocation = WtsAllocation(buffer);
    // Free every non-NULL allocation even when BOOL/length validation fails.
    unsafe { parse_wts(success, allocation.0, bytes) }
}

fn valid_owner(system: &mut impl ForegroundSystem, owner: WindowIdentity) -> bool {
    let pid = system.current_pid();
    owner.hwnd != 0
        && owner.process_id == pid
        && system.identity(owner.hwnd) == Some(owner)
        && system.visible(owner.hwnd)
        && system.session(pid) == Some(owner.session)
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
    // All session metadata is complete. Revalidate the creation-bound IDs
    // without another session query before the final foreground sample.
    if !system.visible(expected.hwnd)
        || system.minimized(expected.hwnd)
        || system.owner_ids(expected.hwnd) != Some((expected.process_id, expected.thread_id))
    {
        return Err(FidoError::Internal(
            "Windows WebAuthn owner changed after metadata validation".into(),
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
    fn monotonic(&mut self) -> Instant;
    fn wait(&mut self, duration: Duration);
    fn native_session(&mut self, session: u32, deadline: Instant) -> NativeSessionEvidence;
    fn identity(&mut self, hwnd: isize) -> Option<WindowIdentity>;
    fn owner_ids(&mut self, hwnd: isize) -> Option<(u32, u32)>;
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
    fn monotonic(&mut self) -> Instant {
        Instant::now()
    }
    fn wait(&mut self, duration: Duration) {
        thread::sleep(duration);
    }
    fn native_session(&mut self, session: u32, deadline: Instant) -> NativeSessionEvidence {
        query_native_session(
            session,
            deadline,
            |session| query_wts::<u16>(session, WTSClientProtocolType),
            |session| query_wts::<i32>(session, WTSConnectState),
            Instant::now,
        )
    }
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
    fn owner_ids(&mut self, hwnd: isize) -> Option<(u32, u32)> {
        if hwnd == 0 || unsafe { IsWindow(hwnd as HWND) } == 0 {
            return None;
        }
        let mut process_id = 0;
        let thread_id = unsafe { GetWindowThreadProcessId(hwnd as HWND, &mut process_id) };
        (process_id != 0 && thread_id != 0).then_some((process_id, thread_id))
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
) -> MonitorStop {
    if cancelled.load(Ordering::Acquire) {
        return MonitorStop::Cancelled;
    }
    let Some(broker) = capture_broker(system, baseline, candidate) else {
        return MonitorStop::CandidateChanged;
    };
    let Ok(mut result) = accepted.lock() else {
        return MonitorStop::ChannelFailed;
    };
    if cancelled.load(Ordering::Acquire) {
        return MonitorStop::Cancelled;
    }
    *result = Some(broker);
    MonitorStop::Accepted
}

#[derive(Default)]
struct MonitorPolicy {
    stopped: bool,
    reason: Option<MonitorStop>,
    passive_safe: bool,
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
            self.reason = monitor_observe_reason(
                system,
                owner,
                baseline,
                cancelled,
                accepted,
                &mut self.passive_safe,
            );
            self.stopped = self.reason.is_some();
        }
        self.stopped
    }
}

#[cfg(test)]
fn monitor_observe(
    system: &mut impl ForegroundSystem,
    owner: isize,
    baseline: Arc<BrokerBaseline>,
    cancelled: &AtomicBool,
    accepted: &Mutex<Option<AcceptedBroker>>,
) -> bool {
    monitor_observe_reason(system, owner, baseline, cancelled, accepted, &mut false).is_some()
}

fn monitor_observe_reason(
    system: &mut impl ForegroundSystem,
    owner: isize,
    baseline: Arc<BrokerBaseline>,
    cancelled: &AtomicBool,
    accepted: &Mutex<Option<AcceptedBroker>>,
    passive_safe: &mut bool,
) -> Option<MonitorStop> {
    if cancelled.load(Ordering::Acquire) {
        *passive_safe = false;
        return Some(MonitorStop::Cancelled);
    }
    let Ok(candidates) = broker_candidates(system, &baseline) else {
        *passive_safe = false;
        return Some(MonitorStop::Incomplete);
    };
    if cancelled.load(Ordering::Acquire) {
        *passive_safe = false;
        return Some(MonitorStop::Cancelled);
    }
    if candidates.len() > 1 {
        *passive_safe = false;
        return Some(MonitorStop::Ambiguous);
    }
    let Some(candidate) = select_unique_candidate(&candidates) else {
        // Complete absence is policy evidence; terminal disqualification cannot
        // be undone by a later disappearing competitor or diagnostic label.
        let foreground = system.foreground();
        *passive_safe = foreground == owner || foreground == 0;
        return (foreground != owner).then_some(MonitorStop::ForegroundLost);
    };
    *passive_safe = false;
    let foreground = system.foreground();
    if foreground == candidate.hwnd {
        return Some(record_broker(
            system, baseline, candidate, cancelled, accepted,
        ));
    }
    if !should_attempt_dialog_activation(
        owner,
        candidate.hwnd,
        foreground,
        cancelled.load(Ordering::Acquire),
    ) {
        return Some(if cancelled.load(Ordering::Acquire) {
            MonitorStop::Cancelled
        } else {
            MonitorStop::ForegroundLost
        });
    }
    if broker_candidates(system, &baseline)
        .ok()
        .and_then(|c| select_unique_candidate(&c))
        != Some(candidate)
    {
        return Some(MonitorStop::CandidateChanged);
    }
    if cancelled.load(Ordering::Acquire) {
        return Some(MonitorStop::Cancelled);
    }
    if system.identity(candidate.hwnd) != Some(candidate) {
        return Some(MonitorStop::CandidateChanged);
    }
    if !should_attempt_dialog_activation(
        owner,
        candidate.hwnd,
        system.foreground(),
        cancelled.load(Ordering::Acquire),
    ) {
        return Some(if cancelled.load(Ordering::Acquire) {
            MonitorStop::Cancelled
        } else {
            MonitorStop::ForegroundLost
        });
    }
    system.activate(candidate.hwnd);
    if system.foreground() == candidate.hwnd {
        Some(record_broker(
            system, baseline, candidate, cancelled, accepted,
        ))
    } else {
        Some(MonitorStop::ActivationFailed)
    }
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
        session: process_session(process_id)?,
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

struct MonitorWorkerChannels<'a> {
    cancelled: &'a AtomicBool,
    api_returned: &'a AtomicBool,
    armed: &'a AtomicBool,
    accepted: &'a Mutex<Option<AcceptedBroker>>,
    passive_safe: &'a AtomicBool,
    reason: &'a Mutex<Option<MonitorStop>>,
}

fn run_monitor_worker(
    system: &mut impl ForegroundSystem,
    owner: isize,
    baseline: Arc<BrokerBaseline>,
    channels: MonitorWorkerChannels<'_>,
) {
    while !channels.armed.load(Ordering::Acquire) {
        if channels.cancelled.load(Ordering::Acquire) {
            channels.passive_safe.store(false, Ordering::Release);
            if let Ok(mut reason) = channels.reason.lock() {
                *reason = Some(if channels.api_returned.load(Ordering::Acquire) {
                    MonitorStop::ApiReturnedBeforeArm
                } else {
                    MonitorStop::CancelledBeforeArm
                });
            }
            return;
        }
        system.wait(Duration::from_millis(5));
    }
    let deadline = system.monotonic() + focus_monitor_timeout();
    let mut policy = MonitorPolicy::default();
    while !channels.cancelled.load(Ordering::Acquire) && system.monotonic() < deadline {
        let terminal = policy.observe(
            system,
            owner,
            Arc::clone(&baseline),
            channels.cancelled,
            channels.accepted,
        );
        channels
            .passive_safe
            .store(policy.passive_safe, Ordering::Release);
        if terminal {
            let terminal_reason = if policy.reason == Some(MonitorStop::Cancelled)
                && channels.api_returned.load(Ordering::Acquire)
            {
                Some(MonitorStop::ApiReturned)
            } else {
                policy.reason
            };
            if let Ok(mut reason) = channels.reason.lock() {
                *reason = terminal_reason;
            }
            return;
        }
        system.wait(Duration::from_millis(100));
    }
    let reason = if channels.cancelled.load(Ordering::Acquire) {
        if channels.api_returned.load(Ordering::Acquire) {
            MonitorStop::ApiReturned
        } else {
            channels.passive_safe.store(false, Ordering::Release);
            MonitorStop::Cancelled
        }
    } else {
        channels.passive_safe.store(false, Ordering::Release);
        MonitorStop::Deadline
    };
    if let Ok(mut output) = channels.reason.lock() {
        *output = Some(reason);
    }
}

struct WebAuthnForegroundMonitor {
    cancelled: Arc<AtomicBool>,
    api_returned: Arc<AtomicBool>,
    armed: Arc<AtomicBool>,
    accepted: Arc<Mutex<Option<AcceptedBroker>>>,
    worker: Option<JoinHandle<()>>,
    passive_safe: Arc<AtomicBool>,
    reason: Arc<Mutex<Option<MonitorStop>>>,
    operation: Operation,
    pid: u32,
}

impl WebAuthnForegroundMonitor {
    fn stop(&mut self) {
        self.cancelled.store(true, Ordering::Release);
        if let Some(worker) = self.worker.take() {
            if worker.join().is_err() {
                self.passive_safe.store(false, Ordering::Release);
                if let Ok(mut reason) = self.reason.lock() {
                    *reason = Some(MonitorStop::WorkerFailed);
                }
                if let Ok(mut accepted) = self.accepted.lock() {
                    *accepted = None;
                }
                log::warn!("[WebAuthN-handoff] reason=monitor-worker-failed");
            }
            if self.accepted.is_poisoned() {
                self.passive_safe.store(false, Ordering::Release);
                if let Ok(mut reason) = self.reason.lock() {
                    *reason = Some(MonitorStop::ChannelFailed);
                }
            }
            let reason = self
                .reason
                .lock()
                .map(|reason| *reason)
                .unwrap_or(Some(MonitorStop::ChannelFailed));
            log::info!(
                "[WebAuthN-monitor] {}",
                monitor_record(self.operation, self.pid, reason)
            );
        }
    }

    #[cfg(test)]
    fn finish(self) -> Option<AcceptedBroker> {
        self.finish_observation().broker
    }

    fn finish_observation(mut self) -> BrokerObservation {
        // Only this native-call-return path distinguishes normal worker shutdown.
        // Cancellation already observed before it remains permanently disqualified.
        let was_cancelled = self.cancelled.load(Ordering::Acquire);
        if !was_cancelled {
            self.api_returned.store(true, Ordering::Release);
        }
        self.stop();
        if was_cancelled {
            if let Ok(mut accepted) = self.accepted.lock() {
                *accepted = None;
            }
            return BrokerObservation::default();
        }
        let Ok(mut accepted) = self.accepted.lock() else {
            return BrokerObservation::default();
        };
        BrokerObservation {
            broker: accepted.take(),
            passive_safe: self.passive_safe.load(Ordering::Acquire),
        }
    }

    fn prepare(owner_hwnd: HWND, operation: Operation) -> Option<Self> {
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
            match operation { Operation::MakeCredential => "MakeCredential", Operation::GetAssertion => "GetAssertion" },
            current_session,
            baseline_windows.len(),
            baseline_broker_processes.len(),
        );

        let cancelled = Arc::new(AtomicBool::new(false));
        let armed = Arc::new(AtomicBool::new(false));
        let worker_cancelled = Arc::clone(&cancelled);
        let api_returned = Arc::new(AtomicBool::new(false));
        let worker_api_returned = Arc::clone(&api_returned);
        let worker_armed = Arc::clone(&armed);
        let accepted = Arc::new(Mutex::new(None));
        let worker_accepted = Arc::clone(&accepted);
        let passive_safe = Arc::new(AtomicBool::new(false));
        let worker_passive_safe = Arc::clone(&passive_safe);
        let reason = Arc::new(Mutex::new(None));
        let worker_reason = Arc::clone(&reason);
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
                run_monitor_worker(
                    &mut NativeForegroundSystem,
                    owner_hwnd_value,
                    baseline,
                    MonitorWorkerChannels {
                        cancelled: &worker_cancelled,
                        api_returned: &worker_api_returned,
                        armed: &worker_armed,
                        accepted: &worker_accepted,
                        passive_safe: &worker_passive_safe,
                        reason: &worker_reason,
                    },
                );
            }) {
            Ok(worker) => worker,
            Err(_) => {
                log::warn!("[WebAuthN-focus] reason=worker-start-failed");
                return None;
            }
        };

        Some(Self {
            cancelled,
            api_returned,
            armed,
            accepted,
            worker: Some(worker),
            passive_safe,
            reason,
            operation,
            pid: unsafe { GetCurrentProcessId() },
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
        let focus_monitor =
            WebAuthnForegroundMonitor::prepare(owner_for_prepare, Operation::MakeCredential);
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
        let accepted_broker = focus_monitor
            .map(WebAuthnForegroundMonitor::finish_observation)
            .unwrap_or_default();
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
        let mut continuation_diagnostic = ContinuationDiagnostics::default();
        let preparation = prepare_assertion_continuation(
            &mut continuation,
            self.hwnd,
            credential_ids,
            &mut system,
            &mut continuation_diagnostic,
        );
        log::info!(
            "[WebAuthN-continuation] {}",
            continuation_diagnostic.record(system.current_pid())
        );
        let creation_owner = match preparation {
            Ok((outcome, creation_owner)) => {
                log::info!(
                    "[WebAuthN-handoff] outcome={}",
                    match outcome {
                        HandoffOutcome::Ordinary => "ordinary",
                        HandoffOutcome::OwnerForeground => "owner-foreground",
                        HandoffOutcome::Recovered => "recovered",
                    }
                );
                creation_owner
            }
            Err(refusal) => {
                log::warn!("[WebAuthN-handoff] reason={}", refusal.reason());
                return Err(FidoError::Internal(format!(
                    "Windows WebAuthn continuation refused: {}",
                    refusal.reason()
                )));
            }
        };
        let owner_identity = assertion_owner_baseline(&mut system, self.hwnd, creation_owner)?;
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
        let focus_monitor =
            WebAuthnForegroundMonitor::prepare(owner_for_prepare, Operation::GetAssertion);
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
        let _ = focus_monitor.map(WebAuthnForegroundMonitor::finish_observation);
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
        owner_identity_uses_session: bool,
        owner_session_reads: usize,
        owner_drift_on_session: Option<(usize, u8)>,
        identity_hwnds: Vec<isize>,
        session_pids: Vec<u32>,
        broker_drift_on_path: bool,
        clock_base: Instant,
        time_ms: u64,
        native_delay_ms: u64,
        native_delays: std::collections::VecDeque<u64>,
        owner_query_delay_ms: u64,
        owner_foreground_on_metadata: bool,
        native_count: usize,
        mutation_on_native: Option<(usize, u8)>,
        native_sequence: std::collections::VecDeque<NativeSessionEvidence>,
        queried_sessions: Vec<u32>,
        test_pid: u32,
        cancel_on_wait: Option<Arc<AtomicBool>>,
        returned_on_wait: Option<Arc<AtomicBool>>,
        worker_wait_entered: Option<std::sync::mpsc::Sender<()>>,
        wait_until_stopped: Option<Arc<AtomicBool>>,
        native_evidence: NativeSessionEvidence,
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
        fn monotonic(&mut self) -> Instant {
            self.clock_base + Duration::from_millis(self.time_ms)
        }
        fn wait(&mut self, duration: Duration) {
            self.trace.push("wait");
            self.time_ms += duration.as_millis() as u64;
            if let Some(entered) = self.worker_wait_entered.take() {
                entered.send(()).unwrap();
            }
            if let Some(cancelled) = &self.wait_until_stopped {
                // Only the injected test clock waits for lifecycle shutdown.
                let deadline = Instant::now() + Duration::from_secs(5);
                while !cancelled.load(Ordering::Acquire) {
                    assert!(Instant::now() < deadline, "synthetic shutdown timed out");
                    thread::yield_now();
                }
            }
            if let Some(returned) = &self.returned_on_wait {
                returned.store(true, Ordering::Release);
            }
            if let Some(cancelled) = &self.cancel_on_wait {
                cancelled.store(true, Ordering::Release);
            }
        }
        fn native_session(&mut self, session: u32, _: Instant) -> NativeSessionEvidence {
            self.trace.push("native-session");
            self.time_ms += self
                .native_delays
                .pop_front()
                .unwrap_or(self.native_delay_ms);
            self.native_count += 1;
            self.queried_sessions.push(session);
            if let Some((count, fault)) = self.mutation_on_native {
                if count == self.native_count {
                    match fault {
                        0 => self.windows[0].identity.process_id = 99,
                        1 => self.windows[0].identity.thread_id = 99,
                        2 => self.windows[0].session = 3,
                        3 => self.windows[0].visible = false,
                        4 => self.windows[0].minimized = true,
                        5 => self.inaccessible_hwnd = Some(1),
                        6 => self.test_pid = 99,
                        7 => self.windows[0].identity.hwnd = 9,
                        _ => panic!("unknown fixture mutation"),
                    }
                }
            }
            self.native_sequence
                .pop_front()
                .unwrap_or(self.native_evidence)
        }
        fn identity(&mut self, hwnd: isize) -> Option<WindowIdentity> {
            self.trace.push("identity");
            self.identity_hwnds.push(hwnd);
            if self.inaccessible_hwnd == Some(hwnd) {
                return None;
            }
            let identity = self.window(hwnd).map(|w| w.identity)?;
            if self.owner_identity_uses_session && hwnd == 1 {
                // Mirror Native identity: capture PID/TID before session metadata.
                let session = self.session(identity.process_id)?;
                Some(WindowIdentity {
                    session,
                    ..identity
                })
            } else {
                Some(identity)
            }
        }
        fn foreground(&mut self) -> isize {
            self.trace.push("foreground");
            if let Some(hwnd) = self.foreground_sequence.pop_front() {
                self.foreground = hwnd;
            }
            self.foreground
        }
        fn owner_ids(&mut self, hwnd: isize) -> Option<(u32, u32)> {
            self.trace.push("owner-ids");
            if self.inaccessible_hwnd == Some(hwnd) {
                return None;
            }
            self.window(hwnd)
                .map(|w| (w.identity.process_id, w.identity.thread_id))
        }
        fn windows(&mut self) -> Result<Vec<isize>, ()> {
            if self.enumeration_failed {
                return Err(());
            }
            Ok(self.windows.iter().map(|w| w.identity.hwnd).collect())
        }
        fn visible(&mut self, hwnd: isize) -> bool {
            self.trace.push("visible");
            self.window(hwnd).is_some_and(|w| w.visible)
        }
        fn minimized(&mut self, hwnd: isize) -> bool {
            self.trace.push("minimized");
            self.window(hwnd).is_some_and(|w| w.minimized)
        }
        fn session(&mut self, pid: u32) -> Option<u32> {
            self.trace.push("session");
            self.session_pids.push(pid);
            self.owner_session_reads += usize::from(pid == 10);
            let captured_session = self
                .windows
                .iter()
                .find(|w| w.identity.process_id == pid)
                .map(|w| w.session);
            if let Some((read, drift)) = self.owner_drift_on_session {
                if pid == 10 && read == self.owner_session_reads {
                    self.owner_drift_on_session = None;
                    self.trace.push("metadata-drift");
                    match drift {
                        0..=4 => inject_owner_drift(self, drift),
                        5 => self.inaccessible_hwnd = Some(1),
                        6 => self.windows[0].identity.hwnd = 9,
                        _ => unreachable!("closed metadata drift fixture"),
                    }
                    return captured_session;
                }
            }
            if pid == 10 {
                self.time_ms += self.owner_query_delay_ms;
                if self.owner_foreground_on_metadata {
                    self.foreground = 1;
                }
            }
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
            self.test_pid
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
            session: 2,
        };
        let broker = WindowIdentity {
            hwnd: 2,
            process_id: 20,
            thread_id: 21,
            session: 2,
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
            owner_identity_uses_session: false,
            owner_session_reads: 0,
            owner_drift_on_session: None,
            identity_hwnds: Vec::new(),
            session_pids: Vec::new(),
            broker_drift_on_path: false,
            clock_base: Instant::now(),
            time_ms: 0,
            native_delay_ms: 0,
            native_delays: Default::default(),
            owner_query_delay_ms: 0,
            owner_foreground_on_metadata: false,
            native_count: 0,
            mutation_on_native: None,
            native_sequence: Default::default(),
            queried_sessions: Vec::new(),
            test_pid: 10,
            cancel_on_wait: None,
            returned_on_wait: None,
            worker_wait_entered: None,
            wait_until_stopped: None,
            native_evidence: session_evidence(Ok(2), Ok(WTSActive)),
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
                session: 2,
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
            session: 2,
        };
        system.windows.push(other);
        system.inaccessible_pid = Some(30);
        let observation = capture_broker(&mut system, baseline, broker);
        assert!(
            observation.is_none(),
            "incomplete competitor is not proof of uniqueness"
        );
        let mut pending = None;
        complete_registration(
            &mut pending,
            Ok((test_registration(), owner, (observation).into())),
        )
        .unwrap();
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

    #[test]
    fn passive_null_returns_to_owner_without_activation() {
        let (mut system, _, owner, _) = handoff_fixture();
        let mut pending = None;
        complete_registration(
            &mut pending,
            Ok((test_registration(), owner, (None).into())),
        )
        .unwrap();
        system.foreground_sequence = [0, owner.hwnd].into();
        assert_eq!(
            prepare_continuation(&mut pending, owner.hwnd, &[vec![7, 8]], &mut system),
            Ok(HandoffOutcome::OwnerForeground)
        );
        assert!(pending.is_none());
        assert!(!system.trace.contains(&"activate"));
        assert!(!system.trace.contains(&"restore"));
        assert!(system.windows[0].maximized);
        assert!(
            system.time_ms >= 20,
            "success must respect the minimum polling interval"
        );
    }

    #[test]
    fn passive_incomplete_monitor_cannot_become_authority() {
        let (mut system, baseline, owner, _) = handoff_fixture();
        system.enumeration_failed = true;
        let accepted = Mutex::new(None);
        let mut policy = MonitorPolicy::default();
        assert!(policy.observe(
            &mut system,
            owner.hwnd,
            baseline,
            &AtomicBool::new(false),
            &accepted
        ));
        let observation = BrokerObservation {
            broker: accepted.lock().unwrap().take(),
            passive_safe: policy.passive_safe,
        };
        let mut pending = None;
        complete_registration(
            &mut pending,
            Ok((test_registration(), owner, (observation).into())),
        )
        .unwrap();
        system.enumeration_failed = false;
        system.foreground_sequence = [0, owner.hwnd].into();
        assert_eq!(
            prepare_continuation(&mut pending, owner.hwnd, &[vec![7, 8]], &mut system),
            Err(HandoffRefusal::UnobservedBroker)
        );
        assert!(pending.is_none());
    }

    fn passive_pending(owner: WindowIdentity) -> Option<RegistrationContinuation> {
        let mut pending = None;
        complete_registration(&mut pending, Ok((test_registration(), owner, None.into()))).unwrap();
        pending
    }

    #[test]
    fn passive_timeout_and_slow_metadata_never_accept_late_owner() {
        for (native_delay, owner_delay, sequence, expected_time) in [
            (0, 0, vec![0], 1000),
            (1000, 0, vec![0, 1], 1000),
            (1001, 0, vec![0, 1], 1001),
            (0, 1000, vec![0, 1], 1000),
            (995, 0, vec![0, 0, 1], 995),
        ] {
            let (mut system, _, owner, _) = handoff_fixture();
            let mut pending = passive_pending(owner);
            system.native_delay_ms = native_delay;
            system.owner_query_delay_ms = owner_delay;
            system.foreground_sequence = sequence.into();
            assert_eq!(
                prepare_continuation(&mut pending, 1, &[vec![7, 8]], &mut system),
                Err(HandoffRefusal::PassiveDeadline)
            );
            assert_eq!(system.time_ms, expected_time);
            assert!(pending.is_none());
            assert!(!system.trace.contains(&"activate"));
            assert!(!system.trace.contains(&"restore"));
            assert!(system.windows[0].maximized);
        }
        let (mut system, _, owner, _) = handoff_fixture();
        system.native_delays = [0, 979].into();
        system.foreground_sequence = [0, 1].into();
        assert_eq!(
            prepare_continuation(&mut passive_pending(owner), 1, &[vec![7, 8]], &mut system),
            Ok(HandoffOutcome::OwnerForeground)
        );
        assert_eq!(system.time_ms, 999);
    }

    #[test]
    fn passive_only_null_samples_wait_and_initial_unrelated_is_immediate() {
        for (sequence, native_count, waits, refusal) in [
            (vec![3, 1], 0, 0, HandoffRefusal::UnobservedBroker),
            (vec![0, 3, 1], 2, 1, HandoffRefusal::Foreground),
            (vec![0, 0, 3, 1], 3, 2, HandoffRefusal::Foreground),
        ] {
            let (mut system, _, owner, _) = handoff_fixture();
            system.foreground_sequence = sequence.into();
            let mut pending = passive_pending(owner);
            assert_eq!(
                prepare_continuation(&mut pending, 1, &[vec![7, 8]], &mut system),
                Err(refusal)
            );
            assert_eq!(system.native_count, native_count);
            assert_eq!(system.trace.iter().filter(|v| **v == "wait").count(), waits);
            assert_eq!(system.time_ms, waits as u64 * 20);
            assert!(pending.is_none());
            assert!(!system.trace.contains(&"activate"));
            assert!(!system.trace.contains(&"restore"));
        }
    }

    #[test]
    fn passive_native_session_unknown_console_legacy_disconnected_and_failures_refuse() {
        let invalid = [
            session_evidence(Ok(0), Ok(0)),
            session_evidence(Ok(1), Ok(0)),
            session_evidence(Ok(3), Ok(0)),
            session_evidence(Ok(2), Ok(4)),
            session_evidence(Ok(2), Ok(10)),
            session_evidence(Err(QueryStatus::NativeFailure), Ok(0)),
            session_evidence(Err(QueryStatus::NullBuffer), Ok(0)),
            session_evidence(Err(QueryStatus::InvalidLength), Ok(0)),
            session_evidence(Ok(2), Err(QueryStatus::NativeFailure)),
            session_evidence(Ok(2), Err(QueryStatus::NullBuffer)),
            session_evidence(Ok(2), Err(QueryStatus::InvalidLength)),
            session_evidence(Ok(2), Err(QueryStatus::NotQueried)),
        ];
        for evidence in invalid {
            for change_during_wait in [false, true] {
                let (mut system, _, owner, _) = handoff_fixture();
                system.foreground_sequence = [0, 0, 1].into();
                system.native_sequence = if change_during_wait {
                    vec![session_evidence(Ok(2), Ok(0)), evidence]
                } else {
                    vec![evidence]
                }
                .into();
                let mut pending = passive_pending(owner);
                assert_eq!(
                    prepare_continuation(&mut pending, 1, &[vec![7, 8]], &mut system),
                    Err(HandoffRefusal::PassiveSession)
                );
                assert!(pending.is_none());
                assert!(!system.trace.contains(&"activate"));
                if !change_during_wait {
                    assert!(
                        !system.trace.contains(&"wait"),
                        "invalid native evidence cannot authorize waiting"
                    );
                }
                assert!(!system.trace.contains(&"restore"));
            }
        }
    }

    #[test]
    fn passive_owner_and_session_mutations_before_and_after_metadata_refuse() {
        for fault in 0..8 {
            for query in [1, 2] {
                let (mut system, _, owner, _) = handoff_fixture();
                system.foreground_sequence = [0, 0, 1].into();
                system.mutation_on_native = Some((query, fault));
                let mut pending = passive_pending(owner);
                assert_eq!(
                    prepare_continuation(&mut pending, 1, &[vec![7, 8]], &mut system),
                    Err(HandoffRefusal::Owner)
                );
                assert!(pending.is_none());
                assert!(!system.trace.contains(&"activate"));
                assert!(!system.trace.contains(&"restore"));
                assert!(system.queried_sessions.iter().all(|s| *s == 2));
            }
        }
        for fault in 0..4 {
            let (mut system, _, mut owner, _) = handoff_fixture();
            match fault {
                0 => {
                    owner.session = 0;
                    system.windows[0].identity.session = 0;
                    system.windows[0].session = 0;
                }
                1 => system.windows[0].visible = false,
                2 => system.windows[0].minimized = true,
                _ => system.inaccessible_session = Some(10),
            }
            let mut pending = passive_pending(owner);
            system.foreground_sequence = [0, 1].into();
            assert_eq!(
                prepare_continuation(&mut pending, 1, &[vec![7, 8]], &mut system),
                Err(HandoffRefusal::Owner)
            );
            assert_eq!(system.native_count, 0);
            assert!(pending.is_none());
        }
    }

    #[test]
    fn passive_single_created_credential_one_use_and_ordinary_login() {
        for ids in [
            vec![],
            vec![vec![9]],
            vec![vec![7, 8], vec![7, 8]],
            vec![vec![7, 8], vec![9]],
        ] {
            let (mut system, _, owner, _) = handoff_fixture();
            system.foreground_sequence = [0, 1].into();
            let mut pending = passive_pending(owner);
            assert_eq!(
                prepare_continuation(&mut pending, 1, &ids, &mut system),
                Err(HandoffRefusal::Credential)
            );
            assert!(pending.is_none());
            assert_eq!(system.native_count, 0);
        }
        let (mut system, _, owner, _) = handoff_fixture();
        let mut pending = passive_pending(owner);
        system.foreground_sequence = [0, 1].into();
        assert_eq!(
            prepare_continuation(&mut pending, 1, &[vec![7, 8]], &mut system),
            Ok(HandoffOutcome::OwnerForeground)
        );
        let calls = system.native_count;
        system.foreground = 3;
        assert_eq!(
            prepare_continuation(&mut pending, 1, &[vec![7, 8]], &mut system),
            Ok(HandoffOutcome::Ordinary)
        );
        assert_eq!(system.native_count, calls);
        assert!(validate_owner_foreground(1 as HWND, system.foreground as HWND).is_err());
        let mut pending = passive_pending(owner);
        system.foreground = 1;
        system.native_evidence = session_evidence(Ok(0), Ok(0));
        assert_eq!(
            prepare_continuation(&mut pending, 1, &[vec![7, 8]], &mut system),
            Ok(HandoffOutcome::OwnerForeground)
        );
        assert_eq!(system.native_count, calls);
        assert!(!system.trace.contains(&"activate"));
    }

    #[test]
    fn native_wts_parser_checks_bool_null_exact_typed_sizes_and_known_values() {
        let value = 2u16;
        let pointer = &value as *const u16;
        for success in [1, -1, 2] {
            assert_eq!(unsafe { parse_wts::<u16>(success, pointer, 2) }, Ok(2));
        }
        assert_eq!(
            unsafe { parse_wts::<u16>(0, pointer, 2) },
            Err(QueryStatus::NativeFailure)
        );
        assert_eq!(
            unsafe { parse_wts::<u16>(1, ptr::null(), 2) },
            Err(QueryStatus::NullBuffer)
        );
        for bytes in [0, 1, 3, 4, u32::MAX] {
            assert_eq!(
                unsafe { parse_wts::<u16>(1, pointer, bytes) },
                Err(QueryStatus::InvalidLength)
            );
        }
        let active = WTSActive;
        assert_eq!(
            unsafe { parse_wts::<i32>(1, (&active as *const i32).cast(), 4) },
            Ok(WTSActive)
        );
        for protocol in [0, 1, 2, 3, u16::MAX] {
            assert_eq!(
                session_evidence(Ok(protocol), Ok(0)).active_rdp(),
                protocol == 2
            );
        }
        for state in [-1, 0, 1, 4, 9, 10, i32::MAX] {
            assert_eq!(session_evidence(Ok(2), Ok(state)).active_rdp(), state == 0);
        }
    }

    #[test]
    fn monitor_precise_terminal_reasons_are_per_instance_and_permanent() {
        for (fault, expected) in [
            (0, MonitorStop::Incomplete),
            (1, MonitorStop::Ambiguous),
            (2, MonitorStop::ForegroundLost),
            (3, MonitorStop::Cancelled),
            (4, MonitorStop::Accepted),
            (5, MonitorStop::ActivationFailed),
        ] {
            let (mut system, baseline, owner, _) = handoff_fixture();
            let cancelled = AtomicBool::new(fault == 3);
            let accepted = Mutex::new(None);
            let mut policy = MonitorPolicy::default();
            match fault {
                0 => system.enumeration_failed = true,
                1 => {
                    let mut other = system.windows[1].clone();
                    other.identity.hwnd = 3;
                    other.identity.process_id = 30;
                    system.windows.push(other);
                }
                2 => {
                    system.windows.pop();
                    system.foreground = 0;
                }
                5 => {
                    system.foreground = 1;
                    system.activation_succeeds = false;
                }
                _ => (),
            }
            assert!(policy.observe(&mut system, 1, Arc::clone(&baseline), &cancelled, &accepted));
            assert_eq!(policy.reason, Some(expected));
            let safe = policy.passive_safe;
            system.enumeration_failed = false;
            system.windows.truncate(1);
            system.foreground = owner.hwnd;
            assert!(policy.observe(&mut system, 1, baseline, &cancelled, &accepted));
            assert_eq!(policy.reason, Some(expected));
            assert_eq!(policy.passive_safe, safe);
            assert_eq!(safe, fault == 2);
            let other = MonitorPolicy::default();
            assert!(other.reason.is_none());
            assert!(!other.passive_safe);
        }
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
            Ok((test_registration(), owner, (Some(accepted)).into())),
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
            Ok((test_registration(), owner, (Some(accepted)).into())),
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
                    session: 2,
                };
                system.windows.push(other);
            } else {
                system.windows.pop();
            }
            let observation = capture_broker(&mut system, baseline, broker);
            assert!(observation.is_none());
            let mut pending = None;
            complete_registration(
                &mut pending,
                Ok((test_registration(), owner, (observation).into())),
            )
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
                        session: 2,
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
            api_returned: Arc::new(AtomicBool::new(false)),
            armed: Arc::new(AtomicBool::new(true)),
            accepted: Arc::clone(&accepted),
            worker: Some(thread::spawn(move || {
                *worker_result.lock().unwrap() = Some(proof);
            })),
            passive_safe: Arc::new(AtomicBool::new(false)),
            reason: Arc::new(Mutex::new(None)),
            operation: Operation::MakeCredential,
            pid: 10,
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
            api_returned: Arc::new(AtomicBool::new(false)),
            armed: Arc::new(AtomicBool::new(true)),
            accepted: Arc::new(Mutex::new(Some(proof))),
            worker: Some(thread::spawn(|| panic!("synthetic monitor failure"))),
            passive_safe: Arc::new(AtomicBool::new(false)),
            reason: Arc::new(Mutex::new(None)),
            operation: Operation::MakeCredential,
            pid: 10,
        };
        let reason = Arc::clone(&monitor.reason);
        assert!(monitor.finish().is_none());
        assert_eq!(*reason.lock().unwrap(), Some(MonitorStop::WorkerFailed));
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

    #[test]
    fn fix_s1_session_metadata_drift_rejects_creation_owner() {
        for native_identity_metadata in [false, true] {
            for drift in [0, 1, 3, 4, 5, 6] {
                let (mut system, _, owner, _) = handoff_fixture();
                system.foreground = owner.hwnd;
                system.owner_identity_uses_session = native_identity_metadata;
                system.owner_drift_on_session =
                    Some((if native_identity_metadata { 2 } else { 1 }, drift));
                let result = checked_owner_snapshot(&mut system, owner);
                assert!(result.is_err(), "CONTRACT:S1_METADATA_DRIFT_REFUSED native_identity={native_identity_metadata} drift={drift}");
                assert!(system.trace.contains(&"metadata-drift"));
                assert!(!system.trace.contains(&"activate"));
                assert!(!system.trace.contains(&"restore"));
            }
        }
    }

    #[test]
    fn fix_s1_unchanged_owner_and_unknown_session() {
        for native_identity_metadata in [false, true] {
            let (mut system, _, owner, _) = handoff_fixture();
            system.owner_identity_uses_session = native_identity_metadata;
            assert_eq!(checked_owner_snapshot(&mut system, owner).unwrap(), owner);
            system.inaccessible_session = Some(owner.process_id);
            assert!(checked_owner_snapshot(&mut system, owner).is_err());
        }
    }

    #[test]
    fn fix_s1_final_lightweight_guard_follows_metadata() {
        for native_identity_metadata in [false, true] {
            let (mut system, _, owner, _) = handoff_fixture();
            system.owner_identity_uses_session = native_identity_metadata;
            system.foreground = owner.hwnd;
            assert_eq!(checked_owner_snapshot(&mut system, owner).unwrap(), owner);
            let metadata = system
                .trace
                .iter()
                .rposition(|event| *event == "session")
                .unwrap();
            assert_eq!(
                &system.trace[metadata + 1..],
                ["minimized", "visible", "minimized", "owner-ids"]
            );
            assert_eq!(system.foreground(), owner.hwnd);
            assert_eq!(
                &system.trace[system.trace.len() - 2..],
                ["owner-ids", "foreground"]
            );
        }
        for field in ["pid", "tid"] {
            let (mut system, _, owner, _) = handoff_fixture();
            if field == "pid" {
                system.windows[0].identity.process_id = 0;
            } else {
                system.windows[0].identity.thread_id = 0;
            }
            assert!(checked_owner_snapshot(&mut system, owner).is_err());
        }
    }

    fn inject_owner_drift(system: &mut TestSystem, drift: u8) {
        match drift {
            0 => system.windows[0].identity.thread_id += 1,
            1 => system.windows[0].identity.process_id += 1,
            2 => {
                system.windows[0].identity.session += 1;
                system.windows[0].session += 1;
            }
            3 => system.windows[0].visible = false,
            4 => system.windows[0].minimized = true,
            _ => unreachable!("closed synthetic drift cases"),
        }
    }

    #[test]
    fn fix_r1_owner_drift_after_successful_preparation_refuses() {
        for drift in 0..5 {
            for before_selection in [true, false] {
                let (mut system, _, owner, _) = handoff_fixture();
                system.foreground = owner.hwnd;
                let mut pending = passive_pending(owner);
                let (outcome, creation_owner) = prepare_assertion_continuation(
                    &mut pending,
                    owner.hwnd,
                    &[vec![7, 8]],
                    &mut system,
                    &mut ContinuationDiagnostics::default(),
                )
                .unwrap();
                assert_eq!(outcome, HandoffOutcome::OwnerForeground);
                assert_eq!(creation_owner, Some(owner));
                assert!(pending.is_none());
                if before_selection {
                    inject_owner_drift(&mut system, drift);
                }
                let selection = assertion_owner_baseline(&mut system, owner.hwnd, creation_owner);
                if !before_selection {
                    inject_owner_drift(&mut system, drift);
                }
                let result =
                    selection.and_then(|selected| checked_owner_snapshot(&mut system, selected));
                assert!(result.is_err(), "R1 creation owner must survive post-preparation drift={drift}, before_selection={before_selection}");
                let (outcome, replay_owner) = prepare_assertion_continuation(
                    &mut pending,
                    owner.hwnd,
                    &[vec![7, 8]],
                    &mut system,
                    &mut ContinuationDiagnostics::default(),
                )
                .unwrap();
                assert_eq!(outcome, HandoffOutcome::Ordinary);
                assert!(
                    replay_owner.is_none(),
                    "consumed creation authority cannot replay"
                );
                assert!(!system.trace.contains(&"activate"));
                assert!(!system.trace.contains(&"restore"));
            }
        }
    }

    #[test]
    fn fix_r1_zero_creation_session_is_not_authority() {
        let (mut system, _, mut owner, _) = handoff_fixture();
        owner.session = 0;
        system.windows[0].identity = owner;
        system.windows[0].session = 0;
        assert!(assertion_owner_baseline(&mut system, owner.hwnd, Some(owner)).is_err());
    }

    #[test]
    fn fix_r1_ordinary_login_can_establish_fresh_thread_baseline() {
        let (mut system, _, owner, _) = handoff_fixture();
        system.foreground = owner.hwnd;
        inject_owner_drift(&mut system, 0);
        let selected = assertion_owner_baseline(&mut system, owner.hwnd, None).unwrap();
        assert_ne!(selected, owner);
        assert_eq!(
            checked_owner_snapshot(&mut system, selected).unwrap(),
            selected
        );
        assert!(!system.trace.contains(&"activate"));
    }

    #[test]
    fn fix_r1_ordinary_and_unchanged_owner_remain_safe() {
        for continuation in [false, true] {
            let (mut system, _, owner, _) = handoff_fixture();
            system.foreground = owner.hwnd;
            let mut pending = if continuation {
                passive_pending(owner)
            } else {
                None
            };
            let (_, creation_owner) = prepare_assertion_continuation(
                &mut pending,
                owner.hwnd,
                &[vec![7, 8]],
                &mut system,
                &mut ContinuationDiagnostics::default(),
            )
            .unwrap();
            assert_eq!(creation_owner, continuation.then_some(owner));
            let selected =
                assertion_owner_baseline(&mut system, owner.hwnd, creation_owner).unwrap();
            assert_eq!(
                checked_owner_snapshot(&mut system, selected).unwrap(),
                owner
            );
            assert!(
                validate_owner_foreground(owner.hwnd as HWND, system.foreground as HWND).is_ok()
            );
            assert!(!system.trace.contains(&"activate"));
        }
    }

    #[test]
    fn fix_r1_drift_prevents_second_ffi_and_mock_vault_persistence() {
        let (mut vault, dir) = fixture_vault();
        let before = std::fs::read(&vault.path).unwrap();
        let slots = vault.keys_meta();
        let audit = vault.audit().len();
        for drift in 0..5 {
            let mut backend = ceremony_backend(None, false);
            backend.passive_registration = true;
            backend.owner_drift_after_preparation = Some(drift);
            assert!(
                vault
                    .register_key_with_label(&mut backend, None, "Synthetic")
                    .is_err(),
                "R1 drift={drift} must refuse before fake second FFI"
            );
            assert_eq!(backend.get_calls, 1);
            assert_eq!(backend.ffi_calls, 0);
            assert!(backend.pending.is_none());
            assert_eq!(vault.keys_meta(), slots);
            assert_eq!(vault.audit().len(), audit);
            assert_eq!(std::fs::read(&vault.path).unwrap(), before);
            assert!(!backend.system.trace.contains(&"activate"));
            assert!(!backend.system.trace.contains(&"restore"));
        }
        std::fs::remove_file(&vault.path).unwrap();
        std::fs::remove_dir(dir).unwrap();
    }

    struct CeremonyBackend {
        system: TestSystem,
        baseline: Arc<BrokerBaseline>,
        owner: WindowIdentity,
        broker: WindowIdentity,
        pending: Option<RegistrationContinuation>,
        first_error: Option<FidoError>,
        second_error: bool,
        passive_registration: bool,
        owner_drift_after_preparation: Option<u8>,
        ffi_calls: usize,
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
            } else if self.passive_registration {
                self.system.windows.truncate(1);
                self.system.foreground = 0;
                let accepted = Mutex::new(None);
                let mut policy = MonitorPolicy::default();
                assert!(policy.observe(
                    &mut self.system,
                    self.owner.hwnd,
                    Arc::clone(&self.baseline),
                    &AtomicBool::new(false),
                    &accepted
                ));
                self.system.foreground_sequence = [0, self.owner.hwnd].into();
                let broker = accepted.lock().unwrap().take();
                Ok((
                    test_registration(),
                    self.owner,
                    BrokerObservation {
                        broker,
                        passive_safe: policy.passive_safe,
                    },
                ))
            } else {
                // Synthetic native success/focus loss, followed by real capture policy.
                self.system.foreground = self.broker.hwnd;
                let observation =
                    capture_broker(&mut self.system, Arc::clone(&self.baseline), self.broker);
                Ok((test_registration(), self.owner, (observation).into()))
            };
            complete_registration(&mut self.pending, result)
        }
        fn get_prf_secret(&mut self, id: &[u8], _: Option<&str>) -> Result<[u8; 32], FidoError> {
            self.get_calls += 1;
            let (_, creation_owner) = prepare_assertion_continuation(
                &mut self.pending,
                self.owner.hwnd,
                &[id.to_vec()],
                &mut self.system,
                &mut ContinuationDiagnostics::default(),
            )
            .map_err(|refusal| FidoError::Internal(refusal.reason().into()))?;
            if let Some(drift) = self.owner_drift_after_preparation.take() {
                inject_owner_drift(&mut self.system, drift);
            }
            // Same owner selection and final identity policy as the native wrapper.
            let selected =
                assertion_owner_baseline(&mut self.system, self.owner.hwnd, creation_owner)?;
            checked_owner_snapshot(&mut self.system, selected)?;
            validate_owner_foreground(self.owner.hwnd as HWND, self.system.foreground as HWND)?;
            self.ffi_calls += 1;
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
            passive_registration: false,
            owner_drift_after_preparation: None,
            ffi_calls: 0,
            get_calls: 0,
        }
    }

    #[test]
    fn monitor_worker_lifecycle_reasons_and_private_channels() {
        for (armed, cancelled, expected) in [
            (false, true, MonitorStop::CancelledBeforeArm),
            (true, true, MonitorStop::Cancelled),
            (true, false, MonitorStop::Deadline),
        ] {
            let (mut system, baseline, owner, _) = handoff_fixture();
            system.windows.truncate(1);
            system.foreground = 1;
            let cancelled = AtomicBool::new(cancelled);
            let armed = AtomicBool::new(armed);
            let accepted = Mutex::new(None);
            let safe = AtomicBool::new(false);
            let reason = Mutex::new(None);
            run_monitor_worker(
                &mut system,
                owner.hwnd,
                baseline,
                MonitorWorkerChannels {
                    cancelled: &cancelled,
                    api_returned: &AtomicBool::new(false),
                    armed: &armed,
                    accepted: &accepted,
                    passive_safe: &safe,
                    reason: &reason,
                },
            );
            assert_eq!(*reason.lock().unwrap(), Some(expected));
            assert!(accepted.lock().unwrap().is_none());
            assert!(!safe.load(Ordering::Acquire));
            assert!(!system.trace.contains(&"activate"));
        }
        let (mut system, baseline, owner, broker) = handoff_fixture();
        let proof = capture_broker(&mut system, Arc::clone(&baseline), broker).unwrap();
        let accepted_a = Arc::new(Mutex::new(None));
        let accepted_b = Arc::new(Mutex::new(None));
        let reason_a = Arc::new(Mutex::new(None));
        let reason_b = Arc::new(Mutex::new(None));
        assert!(!Arc::ptr_eq(&accepted_a, &accepted_b));
        assert!(!Arc::ptr_eq(&reason_a, &reason_b));
        let output = Arc::clone(&accepted_a);
        let reason = Arc::clone(&reason_a);
        let a = WebAuthnForegroundMonitor {
            cancelled: Arc::new(AtomicBool::new(false)),
            api_returned: Arc::new(AtomicBool::new(false)),
            armed: Arc::new(AtomicBool::new(true)),
            accepted: Arc::clone(&accepted_a),
            passive_safe: Arc::new(AtomicBool::new(false)),
            reason: Arc::clone(&reason_a),
            operation: Operation::MakeCredential,
            pid: owner.process_id,
            worker: Some(thread::spawn(move || {
                *output.lock().unwrap() = Some(proof);
                *reason.lock().unwrap() = Some(MonitorStop::Accepted);
            })),
        };
        let reason = Arc::clone(&reason_b);
        let b = WebAuthnForegroundMonitor {
            cancelled: Arc::new(AtomicBool::new(false)),
            api_returned: Arc::new(AtomicBool::new(false)),
            armed: Arc::new(AtomicBool::new(true)),
            accepted: Arc::clone(&accepted_b),
            passive_safe: Arc::new(AtomicBool::new(false)),
            reason: Arc::clone(&reason_b),
            operation: Operation::GetAssertion,
            pid: 10,
            worker: Some(thread::spawn(move || {
                *reason.lock().unwrap() = Some(MonitorStop::Incomplete);
            })),
        };
        assert_eq!(a.finish_observation().broker.unwrap().identity, broker);
        let outcome = b.finish_observation();
        assert!(outcome.broker.is_none());
        assert!(!outcome.passive_safe);
        assert!(accepted_a.lock().unwrap().is_none());
        assert!(accepted_b.lock().unwrap().is_none());
        assert_eq!(*reason_a.lock().unwrap(), Some(MonitorStop::Accepted));
        assert_eq!(*reason_b.lock().unwrap(), Some(MonitorStop::Incomplete));
    }

    #[test]
    fn passive_vault_second_failure_preserves_bytes_audit_and_slots() {
        let (mut vault, dir) = fixture_vault();
        vault
            .register_key_with_label(&mut crate::fido2::MockBackend::new(), None, "Existing")
            .unwrap();
        let slots = vault.keys_meta();
        let audit = vault.audit().len();
        let before = std::fs::read(&vault.path).unwrap();
        for refusal in [false, true] {
            let mut backend = ceremony_backend(None, true);
            backend.passive_registration = true;
            if refusal {
                backend.system.native_evidence = session_evidence(Ok(0), Ok(0));
            }
            assert!(vault
                .register_key_with_label(&mut backend, None, "New")
                .is_err());
            assert_eq!(backend.get_calls, 1);
            assert!(backend.pending.is_none());
            assert_eq!(vault.keys_meta(), slots);
            assert_eq!(vault.audit().len(), audit);
            assert_eq!(std::fs::read(&vault.path).unwrap(), before);
            assert!(!backend.system.trace.contains(&"activate"));
            assert!(!backend.system.trace.contains(&"restore"));
            assert!(backend.system.windows[0].maximized);
            if refusal {
                assert!(!backend.system.trace.contains(&"wait"));
            } else {
                assert!(backend.system.time_ms >= 20);
            }
        }
        std::fs::remove_file(&vault.path).unwrap();
        std::fs::remove_dir(dir).unwrap();
    }

    #[test]
    fn fix_r2_production_wrappers_finish_native_return() {
        let source = include_str!("windows_webauthn.rs").replace("\r\n", "\n");
        for ffi in [
            "WebAuthNAuthenticatorMakeCredential(",
            "WebAuthNAuthenticatorGetAssertion(",
        ] {
            let after = source.split(ffi).nth(1).expect("native wrapper locator");
            let shutdown = after.split("log::info!(").next().unwrap();
            assert!(
                shutdown.contains(".map(WebAuthnForegroundMonitor::finish_observation)"),
                "R2_NATIVE_RETURN_WRAPPER: {ffi}"
            );
            assert!(
                !shutdown.contains("drop(focus_monitor)"),
                "R2_DROP_IS_CANCELLATION"
            );
        }
    }

    #[test]
    fn fix_r2_injected_native_return_stops_and_joins_actual_monitor() {
        for operation in [Operation::MakeCredential, Operation::GetAssertion] {
            for pre_cancelled in [false, true] {
                let (mut system, baseline, owner, _) = handoff_fixture();
                system.windows.truncate(1);
                system.foreground = owner.hwnd;
                let cancelled = Arc::new(AtomicBool::new(false));
                let returned = Arc::new(AtomicBool::new(false));
                let armed = Arc::new(AtomicBool::new(true));
                let accepted = Arc::new(Mutex::new(None));
                let safe = Arc::new(AtomicBool::new(false));
                let reason = Arc::new(Mutex::new(None));
                let (entered, waiting) = std::sync::mpsc::channel();
                system.worker_wait_entered = Some(entered);
                system.wait_until_stopped = Some(Arc::clone(&cancelled));
                let worker_cancelled = Arc::clone(&cancelled);
                let worker_returned = Arc::clone(&returned);
                let worker_armed = Arc::clone(&armed);
                let worker_accepted = Arc::clone(&accepted);
                let worker_safe = Arc::clone(&safe);
                let worker_reason = Arc::clone(&reason);
                let worker = thread::spawn(move || {
                    run_monitor_worker(
                        &mut system,
                        owner.hwnd,
                        baseline,
                        MonitorWorkerChannels {
                            cancelled: &worker_cancelled,
                            api_returned: &worker_returned,
                            armed: &worker_armed,
                            accepted: &worker_accepted,
                            passive_safe: &worker_safe,
                            reason: &worker_reason,
                        },
                    );
                });
                let mut monitor = WebAuthnForegroundMonitor {
                    cancelled,
                    api_returned: Arc::clone(&returned),
                    armed,
                    accepted,
                    passive_safe: safe,
                    reason: Arc::clone(&reason),
                    operation,
                    pid: owner.process_id,
                    worker: Some(worker),
                };
                waiting.recv_timeout(Duration::from_secs(5)).unwrap();
                if pre_cancelled {
                    monitor.stop();
                }
                // Exactly the production normal-return method; no test sets api_returned.
                let observation = monitor.finish_observation();
                assert_eq!(returned.load(Ordering::Acquire), !pre_cancelled);
                assert_eq!(
                    *reason.lock().unwrap(),
                    Some(if pre_cancelled {
                        MonitorStop::Cancelled
                    } else {
                        MonitorStop::ApiReturned
                    })
                );
                assert_eq!(observation.passive_safe, !pre_cancelled);
                assert!(observation.broker.is_none());
            }
        }
    }

    #[test]
    fn fix_r2_native_return_cannot_revive_terminal_worker_faults() {
        for (fault, expected) in [
            (0, MonitorStop::Incomplete),
            (1, MonitorStop::Ambiguous),
            (2, MonitorStop::ForegroundLost),
            (3, MonitorStop::Cancelled),
            (4, MonitorStop::WorkerFailed),
        ] {
            let (mut system, baseline, owner, _) = handoff_fixture();
            match fault {
                0 => system.enumeration_failed = true,
                1 => {
                    let mut other = system.windows[1].clone();
                    other.identity.hwnd = 3;
                    other.identity.process_id = 30;
                    system.windows.push(other);
                }
                2 => {
                    system.windows.truncate(1);
                    system.foreground = 3;
                }
                3 => (),
                4 => (),
                _ => unreachable!(),
            }
            let cancelled = Arc::new(AtomicBool::new(fault == 3));
            let returned = Arc::new(AtomicBool::new(false));
            let armed = Arc::new(AtomicBool::new(true));
            let accepted = Arc::new(Mutex::new(None));
            let safe = Arc::new(AtomicBool::new(false));
            let reason = Arc::new(Mutex::new(None));
            let worker_cancelled = Arc::clone(&cancelled);
            let worker_returned = Arc::clone(&returned);
            let worker_armed = Arc::clone(&armed);
            let worker_accepted = Arc::clone(&accepted);
            let worker_safe = Arc::clone(&safe);
            let worker_reason = Arc::clone(&reason);
            let (done, completed) = std::sync::mpsc::channel();
            let worker = thread::spawn(move || {
                if fault == 4 {
                    done.send(()).unwrap();
                    panic!("synthetic worker fault");
                }
                run_monitor_worker(
                    &mut system,
                    owner.hwnd,
                    baseline,
                    MonitorWorkerChannels {
                        cancelled: &worker_cancelled,
                        api_returned: &worker_returned,
                        armed: &worker_armed,
                        accepted: &worker_accepted,
                        passive_safe: &worker_safe,
                        reason: &worker_reason,
                    },
                );
                done.send(()).unwrap();
            });
            completed.recv_timeout(Duration::from_secs(5)).unwrap();
            let monitor = WebAuthnForegroundMonitor {
                cancelled,
                api_returned: returned,
                armed,
                accepted,
                passive_safe: safe,
                reason: Arc::clone(&reason),
                operation: Operation::GetAssertion,
                pid: owner.process_id,
                worker: Some(worker),
            };
            let observation = monitor.finish_observation();
            assert!(observation.broker.is_none());
            assert!(!observation.passive_safe);
            assert_eq!(*reason.lock().unwrap(), Some(expected));
        }
    }

    #[test]
    fn monitor_api_return_differs_from_cancellation_and_unrelated_loss() {
        for normal_return in [false, true] {
            let (mut system, baseline, owner, _) = handoff_fixture();
            system.windows.truncate(1);
            system.foreground = 1;
            let cancelled = Arc::new(AtomicBool::new(false));
            let returned = Arc::new(AtomicBool::new(false));
            system.cancel_on_wait = Some(Arc::clone(&cancelled));
            if normal_return {
                system.returned_on_wait = Some(Arc::clone(&returned));
            }
            let accepted = Mutex::new(None);
            let safe = AtomicBool::new(false);
            let reason = Mutex::new(None);
            run_monitor_worker(
                &mut system,
                1,
                baseline,
                MonitorWorkerChannels {
                    cancelled: &cancelled,
                    api_returned: &returned,
                    armed: &AtomicBool::new(true),
                    accepted: &accepted,
                    passive_safe: &safe,
                    reason: &reason,
                },
            );
            assert_eq!(
                *reason.lock().unwrap(),
                Some(if normal_return {
                    MonitorStop::ApiReturned
                } else {
                    MonitorStop::Cancelled
                })
            );
            assert_eq!(safe.load(Ordering::Acquire), normal_return);
            let observation = BrokerObservation {
                broker: accepted.lock().unwrap().take(),
                passive_safe: safe.load(Ordering::Acquire),
            };
            let mut pending = None;
            complete_registration(&mut pending, Ok((test_registration(), owner, observation)))
                .unwrap();
            system.cancel_on_wait = None;
            system.returned_on_wait = None;
            system.foreground_sequence = [0, 1].into();
            let result = prepare_continuation(&mut pending, 1, &[vec![7, 8]], &mut system);
            assert_eq!(
                result,
                if normal_return {
                    Ok(HandoffOutcome::OwnerForeground)
                } else {
                    Err(HandoffRefusal::UnobservedBroker)
                }
            );
            assert!(pending.is_none());
        }
        let (mut system, baseline, owner, _) = handoff_fixture();
        system.windows.truncate(1);
        system.foreground = 3;
        let accepted = Mutex::new(None);
        let mut policy = MonitorPolicy::default();
        assert!(policy.observe(&mut system, 1, baseline, &AtomicBool::new(false), &accepted));
        assert_eq!(policy.reason, Some(MonitorStop::ForegroundLost));
        assert!(!policy.passive_safe);
        let observation = BrokerObservation {
            broker: None,
            passive_safe: policy.passive_safe,
        };
        let mut pending = None;
        complete_registration(&mut pending, Ok((test_registration(), owner, observation))).unwrap();
        system.foreground_sequence = [0, 1].into();
        assert_eq!(
            prepare_continuation(&mut pending, 1, &[vec![7, 8]], &mut system),
            Err(HandoffRefusal::UnobservedBroker)
        );
        assert!(!system.trace.contains(&"wait"));
    }

    #[test]
    fn monitor_poisoned_authoritative_channel_cannot_authorize_passive_return() {
        let accepted = Arc::new(Mutex::new(None));
        let poisoned = Arc::clone(&accepted);
        let worker = thread::spawn(move || {
            let _guard = poisoned.lock().unwrap();
            panic!("synthetic channel poison");
        });
        let _ = worker.join();
        let reason = Arc::new(Mutex::new(None));
        let monitor = WebAuthnForegroundMonitor {
            cancelled: Arc::new(AtomicBool::new(false)),
            api_returned: Arc::new(AtomicBool::new(false)),
            armed: Arc::new(AtomicBool::new(true)),
            accepted,
            passive_safe: Arc::new(AtomicBool::new(true)),
            reason: Arc::clone(&reason),
            operation: Operation::MakeCredential,
            pid: 10,
            worker: Some(thread::spawn(|| {})),
        };
        let observation = monitor.finish_observation();
        assert!(observation.broker.is_none());
        assert!(!observation.passive_safe);
        assert_eq!(*reason.lock().unwrap(), Some(MonitorStop::ChannelFailed));
    }

    #[test]
    fn fix_d1_early_owner_refusal_keeps_foreground_identity_unknown() {
        for fault in 0..7 {
            let (mut system, _, owner, _) = handoff_fixture();
            let mut pending = passive_pending(owner);
            system.foreground = owner.hwnd;
            match fault {
                0..=2 => inject_owner_drift(&mut system, fault),
                3 => system.inaccessible_hwnd = Some(owner.hwnd),
                4 => system.inaccessible_session = Some(owner.process_id),
                5 => system.windows[0].session += 1,
                6 => {
                    system.owner_identity_uses_session = true;
                    system.owner_drift_on_session = Some((2, 0));
                }
                _ => unreachable!("closed diagnostic fixtures"),
            }
            let mut diagnostic = ContinuationDiagnostics::default();
            assert_eq!(
                prepare_continuation_recorded(
                    &mut pending,
                    owner.hwnd,
                    &[vec![7, 8]],
                    &mut system,
                    &mut diagnostic
                ),
                Err(HandoffRefusal::Owner)
            );
            let record = diagnostic.record(owner.process_id);
            assert_eq!(record["foreground"]["hwnd"], owner.hwnd);
            for field in ["pid", "tid", "session"] {
                assert!(
                    record["foreground"][field].is_null(),
                    "CONTRACT:D1_FOREGROUND_IDENTITY_UNKNOWN fault={fault} field={field}"
                );
            }
            assert!(pending.is_none());
            assert!(!system.trace.contains(&"wait"));
            assert!(!system.trace.contains(&"activate"));
            assert!(!system.trace.contains(&"restore"));
        }
    }

    #[test]
    fn fix_d1_current_valid_null_and_unrelated_samples() {
        for foreground in [1, 0, 3] {
            let (mut system, _, owner, _) = handoff_fixture();
            system.foreground = foreground;
            system.native_evidence = session_evidence(Ok(0), Ok(0));
            let mut pending = passive_pending(owner);
            // Poison only diagnostic input; it must not supply policy or observations.
            let mut diagnostic = ContinuationDiagnostics {
                foreground: WindowScalars {
                    hwnd: Some(1),
                    pid: Some(99),
                    tid: Some(99),
                    session: Some(99),
                },
                identity_match: Some(true),
                ..Default::default()
            };
            let result = prepare_continuation_recorded(
                &mut pending,
                owner.hwnd,
                &[vec![7, 8]],
                &mut system,
                &mut diagnostic,
            );
            let record = diagnostic.record(owner.process_id);
            assert_eq!(
                result,
                match foreground {
                    1 => Ok(HandoffOutcome::OwnerForeground),
                    0 => Err(HandoffRefusal::PassiveSession),
                    _ => Err(HandoffRefusal::UnobservedBroker),
                }
            );
            if foreground == owner.hwnd {
                assert_eq!(
                    record["foreground"],
                    serde_json::json!({"hwnd":1,"pid":10,"tid":11,"session":2})
                );
            } else {
                assert_eq!(
                    record["foreground"]["hwnd"],
                    if foreground == 0 {
                        Value::Null
                    } else {
                        Value::from(foreground)
                    }
                );
                for field in ["pid", "tid", "session"] {
                    assert!(record["foreground"][field].is_null());
                }
            }
            assert!(system.identity_hwnds.iter().all(|hwnd| *hwnd == owner.hwnd));
            assert!(system
                .session_pids
                .iter()
                .all(|pid| *pid == owner.process_id));
            assert!(pending.is_none());
            assert!(!system.trace.contains(&"wait"));
            assert!(!system.trace.contains(&"activate"));
            assert!(!system.trace.contains(&"restore"));
        }
    }

    #[test]
    fn fix_d1_final_identity_metadata_drift_is_not_observation() {
        let (mut system, _, owner, _) = handoff_fixture();
        system.foreground = owner.hwnd;
        system.owner_identity_uses_session = true;
        system.owner_drift_on_session = Some((3, 0));
        let mut pending = passive_pending(owner);
        let mut diagnostic = ContinuationDiagnostics::default();
        assert_eq!(
            prepare_continuation_recorded(
                &mut pending,
                owner.hwnd,
                &[vec![7, 8]],
                &mut system,
                &mut diagnostic
            ),
            Err(HandoffRefusal::Owner)
        );
        let record = diagnostic.record(owner.process_id);
        assert_eq!(record["foreground"]["hwnd"], owner.hwnd);
        for field in ["pid", "tid", "session"] {
            assert!(record["foreground"][field].is_null());
        }
        assert_eq!(record["identity_match"], false);
        assert!(system.trace.contains(&"metadata-drift"));
    }

    #[test]
    fn passive_diagnostic_fields_never_authorize_or_fabricate_foreign_session() {
        let (mut system, _, owner, _) = handoff_fixture();
        let mut pending = passive_pending(owner);
        system.foreground_sequence = [0, 1].into();
        system.native_evidence = session_evidence(Ok(0), Ok(0));
        let mut diagnostic = ContinuationDiagnostics {
            native: Some(session_evidence(Ok(2), Ok(0))),
            owner_visible: Some(true),
            identity_match: Some(true),
            status: Some(ContinuationStatus::PassiveReturn),
            ..Default::default()
        };
        assert_eq!(
            prepare_continuation_recorded(
                &mut pending,
                1,
                &[vec![7, 8]],
                &mut system,
                &mut diagnostic
            ),
            Err(HandoffRefusal::PassiveSession)
        );
        assert!(!system.trace.contains(&"wait"));
        assert!(pending.is_none());
        assert_eq!(diagnostic.record(10)["native_protocol"], "console");
        assert_eq!(diagnostic.record(10)["outcome"], "session-refused");
        let mut pending = passive_pending(owner);
        system.windows[0].identity.process_id = 99;
        system.windows[0].identity.session = 3;
        system.windows[0].session = 3;
        let mut diagnostic = ContinuationDiagnostics::default();
        assert_eq!(
            prepare_continuation_recorded(
                &mut pending,
                1,
                &[vec![7, 8]],
                &mut system,
                &mut diagnostic
            ),
            Err(HandoffRefusal::Owner)
        );
        assert_eq!(diagnostic.record(10)["owner"]["pid"], 99);
        assert_eq!(diagnostic.record(10)["owner"]["session"], 3);
        assert_eq!(diagnostic.record(10)["identity_match"], false);
    }

    #[test]
    fn native_session_failure_or_non_rdp_stops_before_state_query() {
        use std::cell::RefCell;
        let started = Instant::now();
        let deadline = started + Duration::from_millis(1000);
        for protocol in [
            Ok(0),
            Ok(1),
            Ok(3),
            Err(QueryStatus::NativeFailure),
            Err(QueryStatus::NullBuffer),
            Err(QueryStatus::InvalidLength),
        ] {
            let calls = RefCell::new(Vec::new());
            let evidence = query_native_session(
                2,
                deadline,
                |session| {
                    calls.borrow_mut().push(("protocol", session));
                    protocol
                },
                |session| {
                    calls.borrow_mut().push(("state", session));
                    Ok(WTSActive)
                },
                || started,
            );
            assert!(!evidence.active_rdp());
            assert_eq!(
                *calls.borrow(),
                vec![("protocol", 2)],
                "ineligible protocol must refuse without further blocking native query"
            );
            assert_eq!(evidence.state_query, QueryStatus::NotQueried);
        }
        for late in [false, true] {
            let calls = RefCell::new(Vec::new());
            let evidence = query_native_session(
                2,
                deadline,
                |session| {
                    calls.borrow_mut().push(("protocol", session));
                    Ok(2)
                },
                |session| {
                    calls.borrow_mut().push(("state", session));
                    Ok(WTSActive)
                },
                || if late { deadline } else { started },
            );
            assert_eq!(evidence.active_rdp(), !late);
            assert_eq!(
                *calls.borrow(),
                if late {
                    vec![("protocol", 2)]
                } else {
                    vec![("protocol", 2), ("state", 2)]
                }
            );
        }
    }

    #[test]
    fn passive_initial_null_before_slow_owner_metadata_cannot_become_late_ordinary_pass() {
        let (mut system, _, owner, _) = handoff_fixture();
        let mut pending = passive_pending(owner);
        system.foreground = 0;
        system.owner_query_delay_ms = 1000;
        system.owner_foreground_on_metadata = true;
        assert_eq!(
            prepare_continuation(&mut pending, 1, &[vec![7, 8]], &mut system),
            Err(HandoffRefusal::PassiveDeadline)
        );
        assert_eq!(system.time_ms, 1000);
        assert!(pending.is_none());
        assert_eq!(system.native_count, 0);
        assert!(!system.trace.contains(&"wait"));
        assert!(!system.trace.contains(&"activate"));
        assert!(!system.trace.contains(&"restore"));
    }

    #[test]
    fn passive_owner_initially_foreground_then_null_does_not_gain_wait_authority() {
        let (mut system, _, owner, _) = handoff_fixture();
        let mut pending = passive_pending(owner);
        system.foreground_sequence = [1, 0, 1].into();
        assert_eq!(
            prepare_continuation(&mut pending, 1, &[vec![7, 8]], &mut system),
            Err(HandoffRefusal::UnobservedBroker)
        );
        assert!(pending.is_none());
        assert_eq!(system.native_count, 0);
        assert!(!system.trace.contains(&"wait"));
        assert!(!system.trace.contains(&"activate"));
        assert!(!system.trace.contains(&"restore"));
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
            session: 2,
        };
        let baseline = HashSet::from([existing]);
        assert!(!is_new_window_identity(existing, &baseline));
        assert!(is_new_window_identity(
            WindowIdentity {
                hwnd: existing.hwnd,
                process_id: 2000,
                thread_id: 3000,
                session: 2,
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
            session: 2,
        };
        let second = WindowIdentity {
            hwnd: 0xf03fc,
            process_id: 11064,
            thread_id: 9552,
            session: 2,
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
