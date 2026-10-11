//! Windows GUI FIDO backend based on Microsoft's WebAuthn API.
//! The raw CTAP backend remains available for the CLI and diagnostics.

use crate::fido2::{
    BackendInitError, DetectedKey, FidoBackend, FidoError, KeyKind, RegisteredCredential,
};
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
        atomic::{AtomicBool, AtomicU8, Ordering},
        Arc, Mutex,
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};
use windows_sys::Win32::Foundation::{
    CloseHandle, GetLastError, SetLastError, HANDLE, HWND, LPARAM,
};
use windows_sys::Win32::Networking::WindowsWebServices::*;
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
    IsIconic, IsWindow, IsWindowVisible, SetForegroundWindow,
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
}

// A fresh identity is only temporal evidence; it does not prove that this broker
// window belongs to the current WebAuthn operation.
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

fn is_new_window_identity(
    identity: WindowIdentity,
    baseline: &HashSet<WindowIdentity>,
    unattributed: &HashSet<(isize, u32, u32)>,
) -> bool {
    !baseline.contains(&identity)
        && !unattributed.contains(&(identity.hwnd, identity.process_id, identity.thread_id))
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
    local_console: bool,
    windows: HashSet<WindowIdentity>,
    // (hwnd, pid, tid) of baseline windows whose session could not be read.
    unattributed_windows: HashSet<(isize, u32, u32)>,
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
        return Err(HandoffRefusal::Owner);
    }
    // The accepted broker proves prior association only. Continuation cannot
    // restore or activate the owner; it succeeds only if Windows/user action
    // naturally returns focus to the validated owner.
    // All potentially blocking identity queries precede this final passive
    // focus sample. No retry or focus bypass; the later API guard remains separate.
    if !current_broker(system, &broker) || !valid_owner(system, context.owner) {
        return Err(HandoffRefusal::Broker);
    }
    if system.identity(context.owner.hwnd) != Some(context.owner)
        || system.identity(broker.identity.hwnd) != Some(broker.identity)
    {
        return Err(HandoffRefusal::Broker);
    }
    if system.foreground() != owner {
        return Err(HandoffRefusal::Foreground);
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

fn is_local_console_session(evidence: NativeSessionEvidence) -> bool {
    evidence.protocol_query == QueryStatus::Valid && evidence.protocol == SessionProtocol::Console
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

const PHASE_WATCHING: u8 = 0;
const PHASE_ACTIVATION_CLAIMED: u8 = 1;
const PHASE_ACTIVATED: u8 = 2;
const PHASE_PUBLICATION_CLAIMED: u8 = 3;
const PHASE_PUBLISHED: u8 = 4;
const PHASE_API_RETURNED: u8 = 5;
const PHASE_CANCELLED: u8 = 6;
const PHASE_FAILED: u8 = 7;
const PHASE_ACTIVATION_COMMITTED: u8 = 8;

#[derive(Default)]
struct MonitorTerminal {
    gate: Mutex<()>,
    phase: AtomicU8,
}

impl MonitorTerminal {
    fn lock(&self) -> std::sync::LockResult<std::sync::MutexGuard<'_, ()>> {
        self.gate.lock()
    }

    fn try_lock(&self) -> std::sync::TryLockResult<std::sync::MutexGuard<'_, ()>> {
        self.gate.try_lock()
    }

    fn mark_api_returned(&self) {
        loop {
            let phase = self.phase.load(Ordering::Acquire);
            let next = match phase {
                PHASE_WATCHING | PHASE_ACTIVATION_CLAIMED | PHASE_ACTIVATED => {
                    PHASE_API_RETURNED
                }
                _ => return,
            };
            if self
                .phase
                .compare_exchange(phase, next, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                return;
            }
        }
    }

    fn mark_cancelled(&self) {
        loop {
            let phase = self.phase.load(Ordering::Acquire);
            let next = match phase {
                PHASE_WATCHING | PHASE_ACTIVATION_CLAIMED | PHASE_ACTIVATED => PHASE_CANCELLED,
                _ => return,
            };
            if self
                .phase
                .compare_exchange(phase, next, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                return;
            }
        }
    }

    fn claim_activation(&self) -> Result<(), MonitorStop> {
        self.phase
            .compare_exchange(
                PHASE_WATCHING,
                PHASE_ACTIVATION_CLAIMED,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .map(|_| ())
            .map_err(|phase| Self::phase_reason(phase, MonitorStop::ActivationFailed))
    }

    fn commit_activation(&self) -> Result<(), MonitorStop> {
        self.phase
            .compare_exchange(
                PHASE_ACTIVATION_CLAIMED,
                PHASE_ACTIVATION_COMMITTED,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .map(|_| ())
            .map_err(|phase| Self::phase_reason(phase, MonitorStop::ActivationFailed))
    }

    fn finish_activation(&self, succeeded: bool) {
        let next = if succeeded {
            PHASE_ACTIVATED
        } else {
            PHASE_FAILED
        };
        let _ = self.phase.compare_exchange(
            PHASE_ACTIVATION_COMMITTED,
            next,
            Ordering::AcqRel,
            Ordering::Acquire,
        );
    }

    fn abort_activation(&self, reason: MonitorStop) {
        let next = match reason {
            MonitorStop::ApiReturned => PHASE_API_RETURNED,
            MonitorStop::Cancelled => PHASE_CANCELLED,
            _ => PHASE_FAILED,
        };
        let _ = self.phase.compare_exchange(
            PHASE_ACTIVATION_CLAIMED,
            next,
            Ordering::AcqRel,
            Ordering::Acquire,
        );
    }

    fn claim_publication(&self, activated: bool) -> Result<(), MonitorStop> {
        let expected = if activated {
            PHASE_ACTIVATED
        } else {
            PHASE_WATCHING
        };
        self.phase
            .compare_exchange(
                expected,
                PHASE_PUBLICATION_CLAIMED,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .map(|_| ())
            .map_err(|phase| Self::phase_reason(phase, MonitorStop::ChannelFailed))
    }

    fn finish_publication(&self) {
        let _ = self.phase.compare_exchange(
            PHASE_PUBLICATION_CLAIMED,
            PHASE_PUBLISHED,
            Ordering::AcqRel,
            Ordering::Acquire,
        );
    }

    fn abort_publication(&self, reason: MonitorStop) {
        let next = match reason {
            MonitorStop::ApiReturned => PHASE_API_RETURNED,
            MonitorStop::Cancelled => PHASE_CANCELLED,
            _ => PHASE_FAILED,
        };
        let _ = self.phase.compare_exchange(
            PHASE_PUBLICATION_CLAIMED,
            next,
            Ordering::AcqRel,
            Ordering::Acquire,
        );
    }

    fn phase_reason(phase: u8, fallback: MonitorStop) -> MonitorStop {
        match phase {
            PHASE_API_RETURNED => MonitorStop::ApiReturned,
            PHASE_CANCELLED => MonitorStop::Cancelled,
            _ => fallback,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ActivationResult {
    Activated,
    FocusLost,
    CandidateChanged,
    Ambiguous,
    Incomplete,
    NonConsoleSession,
    ApiReturned,
    Cancelled,
    Failed,
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
    fn activate(&mut self, hwnd: isize) -> bool;
    fn after_monitor_publish_check(&mut self) {}
    fn after_broker_candidate_scan(&mut self) {}
    fn before_activation_guard(&mut self) {}
    fn after_activation_claim(&mut self) {}
    #[cfg(test)]
    fn before_final_activation_call(
        &mut self,
        _: &MonitorTerminal,
        _: &AtomicBool,
        _: &AtomicBool,
    ) {}
    fn activate_if_foreground(
        &mut self,
        baseline: &BrokerBaseline,
        owner: isize,
        candidate: WindowIdentity,
        terminal: &MonitorTerminal,
        cancelled: &AtomicBool,
        api_returned: &AtomicBool,
    ) -> ActivationResult
    where
        Self: Sized,
    {
        if !baseline.local_console {
            return ActivationResult::NonConsoleSession;
        }
        self.before_activation_guard();
        if api_returned.load(Ordering::Acquire) {
            return ActivationResult::ApiReturned;
        }
        if cancelled.load(Ordering::Acquire) {
            return ActivationResult::Cancelled;
        }
        let candidates = match broker_candidates(self, baseline) {
            Ok(candidates) => candidates,
            Err(ScanError::Pending) => return ActivationResult::Ambiguous,
            Err(ScanError::Failed) => return ActivationResult::Incomplete,
        };
        match candidates.as_slice() {
            [current] if *current == candidate => {}
            [] => return ActivationResult::CandidateChanged,
            [_] => return ActivationResult::CandidateChanged,
            _ => return ActivationResult::Ambiguous,
        }
        if self.identity(candidate.hwnd) != Some(candidate) || !self.visible(candidate.hwnd) {
            return ActivationResult::CandidateChanged;
        }
        if self.foreground() != owner {
            return ActivationResult::FocusLost;
        }
        if api_returned.load(Ordering::Acquire) {
            return ActivationResult::ApiReturned;
        }
        if cancelled.load(Ordering::Acquire) {
            return ActivationResult::Cancelled;
        }
        if let Err(reason) = terminal.claim_activation() {
            return match reason {
                MonitorStop::ApiReturned => ActivationResult::ApiReturned,
                MonitorStop::Cancelled => ActivationResult::Cancelled,
                _ => ActivationResult::Failed,
            };
        }

        self.after_activation_claim();
        if api_returned.load(Ordering::Acquire) {
            terminal.abort_activation(MonitorStop::ApiReturned);
            return ActivationResult::ApiReturned;
        }
        if cancelled.load(Ordering::Acquire) {
            terminal.abort_activation(MonitorStop::Cancelled);
            return ActivationResult::Cancelled;
        }
        let candidates = match broker_candidates(self, baseline) {
            Ok(candidates) => candidates,
            Err(ScanError::Pending) => {
                terminal.abort_activation(MonitorStop::Ambiguous);
                return ActivationResult::Ambiguous;
            }
            Err(ScanError::Failed) => {
                terminal.abort_activation(MonitorStop::Incomplete);
                return ActivationResult::Incomplete;
            }
        };
        match candidates.as_slice() {
            [current] if *current == candidate => {}
            [] | [_] => {
                terminal.abort_activation(MonitorStop::CandidateChanged);
                return ActivationResult::CandidateChanged;
            }
            _ => {
                terminal.abort_activation(MonitorStop::Ambiguous);
                return ActivationResult::Ambiguous;
            }
        }
        if self.identity(candidate.hwnd) != Some(candidate) || !self.visible(candidate.hwnd) {
            terminal.abort_activation(MonitorStop::CandidateChanged);
            return ActivationResult::CandidateChanged;
        }
        if self.foreground() != owner {
            terminal.abort_activation(MonitorStop::ForegroundLost);
            return ActivationResult::FocusLost;
        }
        if api_returned.load(Ordering::Acquire) {
            terminal.abort_activation(MonitorStop::ApiReturned);
            return ActivationResult::ApiReturned;
        }
        if cancelled.load(Ordering::Acquire) {
            terminal.abort_activation(MonitorStop::Cancelled);
            return ActivationResult::Cancelled;
        }

        #[cfg(test)]
        self.before_final_activation_call(terminal, cancelled, api_returned);
        if let Err(reason) = terminal.commit_activation() {
            return match reason {
                MonitorStop::ApiReturned => ActivationResult::ApiReturned,
                MonitorStop::Cancelled => ActivationResult::Cancelled,
                _ => ActivationResult::Failed,
            };
        }
        let succeeded = self.activate(candidate.hwnd);
        terminal.finish_activation(succeeded);
        if succeeded {
            ActivationResult::Activated
        } else {
            ActivationResult::Failed
        }
    }
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
        is_new_window: is_new_window_identity(
            identity,
            &baseline.windows,
            &baseline.unattributed_windows,
        ),
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ScanError {
    Failed,
    // A visible broker host whose caption is not assigned yet: neither a
    // candidate nor evidence that no broker-like window exists.
    Pending,
}

fn broker_candidates(
    system: &mut impl ForegroundSystem,
    baseline: &BrokerBaseline,
) -> Result<Vec<WindowIdentity>, ScanError> {
    let mut candidates = Vec::new();
    let mut pending = false;
    for hwnd in system.windows().map_err(|()| ScanError::Failed)? {
        if !system.visible(hwnd) {
            continue;
        }
        // Positive ordinary class evidence avoids slow process queries. Unknown
        // class/title is conservative: it cannot prove an unrelated window.
        let class = system.class(hwnd).ok_or(ScanError::Failed)?;
        if !class.eq_ignore_ascii_case("Credential Dialog Xaml Host") {
            continue;
        }
        let title = system.title(hwnd).ok_or(ScanError::Failed)?;
        if title.is_empty() {
            pending = true;
            continue;
        }
        if !title.trim().eq_ignore_ascii_case("Windows Security")
            && !title
                .trim()
                .eq_ignore_ascii_case("Windows \u{5b89}\u{5168}\u{6027}")
        {
            continue;
        }
        let identity = system.identity(hwnd).ok_or(ScanError::Failed)?;
        if observe_broker(system, baseline, identity).map_err(|()| ScanError::Failed)? {
            candidates.push(identity);
        }
    }
    system.after_broker_candidate_scan();
    if pending {
        return Err(ScanError::Pending);
    }
    Ok(candidates)
}

#[cfg(test)]
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

#[derive(Default)]
struct MonitorPolicy {
    stopped: bool,
    reason: Option<MonitorStop>,
    passive_safe: bool,
}
impl MonitorPolicy {
    #[cfg(test)]
    fn observe(
        &mut self,
        system: &mut impl ForegroundSystem,
        owner: isize,
        baseline: Arc<BrokerBaseline>,
        cancelled: &AtomicBool,
        accepted: &Mutex<Option<AcceptedBroker>>,
    ) -> bool {
        let api_returned = AtomicBool::new(false);
        let terminal_gate = MonitorTerminal::default();
        self.observe_with_api_return(
            system,
            owner,
            baseline,
            cancelled,
            &api_returned,
            &terminal_gate,
            accepted,
        )
    }

    fn observe_with_api_return(
        &mut self,
        system: &mut impl ForegroundSystem,
        owner: isize,
        baseline: Arc<BrokerBaseline>,
        cancelled: &AtomicBool,
        api_returned: &AtomicBool,
        terminal_gate: &MonitorTerminal,
        accepted: &Mutex<Option<AcceptedBroker>>,
    ) -> bool {
        if !self.stopped {
            self.reason = monitor_observe_reason(
                system,
                owner,
                baseline,
                cancelled,
                api_returned,
                terminal_gate,
                &mut self.passive_safe,
                accepted,
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
    monitor_observe_reason(
        system,
        owner,
        baseline,
        cancelled,
        &AtomicBool::new(false),
        &MonitorTerminal::default(),
        &mut false,
        accepted,
    )
    .is_some()
}

fn monitor_observe_reason(
    system: &mut impl ForegroundSystem,
    owner: isize,
    baseline: Arc<BrokerBaseline>,
    cancelled: &AtomicBool,
    api_returned: &AtomicBool,
    terminal_gate: &MonitorTerminal,
    passive_safe: &mut bool,
    accepted: &Mutex<Option<AcceptedBroker>>,
) -> Option<MonitorStop> {
    if api_returned.load(Ordering::Acquire) {
        return Some(MonitorStop::ApiReturned);
    }
    if cancelled.load(Ordering::Acquire) {
        *passive_safe = false;
        return Some(MonitorStop::Cancelled);
    }
    let candidates = match broker_candidates(system, &baseline) {
        Ok(candidates) => candidates,
        // An untitled broker host is still being created: keep polling, but
        // this round proves neither a candidate nor broker absence.
        Err(ScanError::Pending) => {
            *passive_safe = false;
            return None;
        }
        Err(ScanError::Failed) => {
            *passive_safe = false;
            return Some(MonitorStop::Incomplete);
        }
    };
    if api_returned.load(Ordering::Acquire) {
        return Some(MonitorStop::ApiReturned);
    }
    if cancelled.load(Ordering::Acquire) {
        *passive_safe = false;
        return Some(MonitorStop::Cancelled);
    }
    if candidates.len() > 1 {
        *passive_safe = false;
        return Some(MonitorStop::Ambiguous);
    }
    if candidates.is_empty() {
        // Complete absence is policy evidence; terminal disqualification cannot
        // be undone by a later disappearing competitor or diagnostic label.
        let Ok(_terminal_guard) = terminal_gate.lock() else {
            *passive_safe = false;
            return Some(MonitorStop::ChannelFailed);
        };
        if api_returned.load(Ordering::Acquire) {
            return Some(MonitorStop::ApiReturned);
        }
        if cancelled.load(Ordering::Acquire) {
            *passive_safe = false;
            return Some(MonitorStop::Cancelled);
        }
        let foreground = system.foreground();
        if api_returned.load(Ordering::Acquire) {
            return Some(MonitorStop::ApiReturned);
        }
        if cancelled.load(Ordering::Acquire) {
            *passive_safe = false;
            return Some(MonitorStop::Cancelled);
        }
        *passive_safe = foreground == owner || foreground == 0;
        return (foreground != owner).then_some(MonitorStop::ForegroundLost);
    }
    *passive_safe = false;
    if api_returned.load(Ordering::Acquire) {
        return Some(MonitorStop::ApiReturned);
    }
    if cancelled.load(Ordering::Acquire) {
        return Some(MonitorStop::Cancelled);
    }
    let candidate = candidates[0];
    let initial_foreground = system.foreground();
    if api_returned.load(Ordering::Acquire) {
        return Some(MonitorStop::ApiReturned);
    }
    if initial_foreground != owner && initial_foreground != candidate.hwnd {
        return Some(MonitorStop::ForegroundLost);
    }

    // Re-scan after the initial focus sample so the final identity/visibility
    // checks and foreground guard sit directly before the one allowed attempt.
    let revalidated = match broker_candidates(system, &baseline) {
        Ok(candidates) => candidates,
        Err(ScanError::Pending) => return Some(MonitorStop::Ambiguous),
        Err(ScanError::Failed) => return Some(MonitorStop::Incomplete),
    };
    if api_returned.load(Ordering::Acquire) {
        return Some(MonitorStop::ApiReturned);
    }
    if revalidated.len() > 1 {
        return Some(MonitorStop::Ambiguous);
    }
    if select_unique_candidate(&revalidated) != Some(candidate)
        || system.identity(candidate.hwnd) != Some(candidate)
        || !system.visible(candidate.hwnd)
    {
        return Some(MonitorStop::CandidateChanged);
    }
    if api_returned.load(Ordering::Acquire) {
        return Some(MonitorStop::ApiReturned);
    }
    if cancelled.load(Ordering::Acquire) {
        return Some(MonitorStop::Cancelled);
    }

    let mut activated = false;
    if initial_foreground != candidate.hwnd {
        if !baseline.local_console {
            return Some(MonitorStop::NonConsoleSession);
        }
        // The final phase CAS decides whether this one-shot application-level
        // activation may be attempted; it cannot make the Windows call atomic.
        let Ok(_terminal_guard) = terminal_gate.lock() else {
            return Some(MonitorStop::ChannelFailed);
        };
        if api_returned.load(Ordering::Acquire) {
            return Some(MonitorStop::ApiReturned);
        }
        if cancelled.load(Ordering::Acquire) {
            return Some(MonitorStop::Cancelled);
        }
        if system.foreground() != owner {
            return Some(MonitorStop::ForegroundLost);
        }
        match system.activate_if_foreground(
            &baseline,
            owner,
            candidate,
            terminal_gate,
            cancelled,
            api_returned,
        ) {
            ActivationResult::Activated => activated = true,
            ActivationResult::FocusLost => return Some(MonitorStop::ForegroundLost),
            ActivationResult::CandidateChanged => return Some(MonitorStop::CandidateChanged),
            ActivationResult::Ambiguous => return Some(MonitorStop::Ambiguous),
            ActivationResult::Incomplete => return Some(MonitorStop::Incomplete),
            ActivationResult::NonConsoleSession => return Some(MonitorStop::NonConsoleSession),
            ActivationResult::ApiReturned => return Some(MonitorStop::ApiReturned),
            ActivationResult::Cancelled => return Some(MonitorStop::Cancelled),
            ActivationResult::Failed => return Some(MonitorStop::ActivationFailed),
        }
        if api_returned.load(Ordering::Acquire) {
            return Some(MonitorStop::ApiReturned);
        }
        if cancelled.load(Ordering::Acquire) {
            return Some(MonitorStop::Cancelled);
        }
    }

    if api_returned.load(Ordering::Acquire) {
        return Some(MonitorStop::ApiReturned);
    }
    if cancelled.load(Ordering::Acquire) {
        return Some(MonitorStop::Cancelled);
    }
    let Ok(_terminal_guard) = terminal_gate.lock() else {
        return Some(MonitorStop::ChannelFailed);
    };
    let Ok(mut accepted) = accepted.lock() else {
        return Some(MonitorStop::ChannelFailed);
    };
    system.after_monitor_publish_check();
    if api_returned.load(Ordering::Acquire) {
        return Some(MonitorStop::ApiReturned);
    }
    if cancelled.load(Ordering::Acquire) {
        return Some(MonitorStop::Cancelled);
    }
    let final_candidates = match broker_candidates(system, &baseline) {
        Ok(candidates) => candidates,
        Err(ScanError::Pending) => return Some(MonitorStop::Ambiguous),
        Err(ScanError::Failed) => return Some(MonitorStop::Incomplete),
    };
    if api_returned.load(Ordering::Acquire) {
        return Some(MonitorStop::ApiReturned);
    }
    if cancelled.load(Ordering::Acquire) {
        return Some(MonitorStop::Cancelled);
    }
    if final_candidates.len() > 1 {
        return Some(MonitorStop::Ambiguous);
    }
    if select_unique_candidate(&final_candidates) != Some(candidate)
        || system.identity(candidate.hwnd) != Some(candidate)
        || !system.visible(candidate.hwnd)
    {
        return Some(MonitorStop::CandidateChanged);
    }
    let final_foreground = system.foreground();
    if api_returned.load(Ordering::Acquire) {
        return Some(MonitorStop::ApiReturned);
    }
    if cancelled.load(Ordering::Acquire) {
        return Some(MonitorStop::Cancelled);
    }
    if final_foreground != candidate.hwnd {
        return Some(MonitorStop::ForegroundLost);
    }
    if let Err(reason) = terminal_gate.claim_publication(activated) {
        return Some(reason);
    }
    if api_returned.load(Ordering::Acquire) {
        terminal_gate.abort_publication(MonitorStop::ApiReturned);
        return Some(MonitorStop::ApiReturned);
    }
    if cancelled.load(Ordering::Acquire) {
        terminal_gate.abort_publication(MonitorStop::Cancelled);
        return Some(MonitorStop::Cancelled);
    }
    *accepted = Some(AcceptedBroker {
        identity: candidate,
        baseline,
    });
    terminal_gate.finish_publication();
    Some(MonitorStop::CandidateForeground)
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

const BASELINE_CAPTURE_MAX_ATTEMPTS: usize = 3;
const BASELINE_CAPTURE_RETRY_DELAY: Duration = Duration::from_millis(10);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BaselineCaptureStage {
    WindowEnumeration,
    WindowIdentity,
}

impl BaselineCaptureStage {
    fn label(self) -> &'static str {
        match self {
            Self::WindowEnumeration => "window-enumeration",
            Self::WindowIdentity => "window-identity",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct BaselineCaptureError {
    stage: BaselineCaptureStage,
    attempts: usize,
}

struct BaselineWindowSnapshot {
    identities: HashSet<WindowIdentity>,
    unattributed: HashSet<(isize, u32, u32)>,
    attempts: usize,
}

fn baseline_window_identities(
    system: &mut impl ForegroundSystem,
) -> Result<BaselineWindowSnapshot, BaselineCaptureError> {
    let mut last_failure = BaselineCaptureStage::WindowEnumeration;

    for attempt in 1..=BASELINE_CAPTURE_MAX_ATTEMPTS {
        let windows = match system.windows() {
            Ok(windows) => windows,
            Err(()) => {
                last_failure = BaselineCaptureStage::WindowEnumeration;
                if attempt < BASELINE_CAPTURE_MAX_ATTEMPTS {
                    system.wait(BASELINE_CAPTURE_RETRY_DELAY);
                }
                continue;
            }
        };

        let mut identities = HashSet::with_capacity(windows.len());
        let mut unattributed = HashSet::new();
        let mut identity_failed = false;
        for hwnd in windows {
            match system.identity(hwnd) {
                Some(identity) => {
                    identities.insert(identity);
                }
                None => {
                    // Owner ids exist but the session is unreadable (e.g. dwm.exe):
                    // keep the window in the baseline so it can never become new.
                    if let Some((pid, tid)) = system
                        .owner_ids(hwnd)
                        .filter(|&(pid, tid)| pid != 0 && tid != 0)
                    {
                        unattributed.insert((hwnd, pid, tid));
                        continue;
                    }
                    identity_failed = true;
                    last_failure = BaselineCaptureStage::WindowIdentity;
                    break;
                }
            }
        }
        if !identity_failed {
            return Ok(BaselineWindowSnapshot {
                identities,
                unattributed,
                attempts: attempt,
            });
        }
        if attempt < BASELINE_CAPTURE_MAX_ATTEMPTS {
            system.wait(BASELINE_CAPTURE_RETRY_DELAY);
        }
    }

    Err(BaselineCaptureError {
        stage: last_failure,
        attempts: BASELINE_CAPTURE_MAX_ATTEMPTS,
    })
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
    unsafe { SetLastError(0) };
    let length = unsafe { GetWindowTextW(hwnd, buffer.as_mut_ptr(), buffer.len() as i32) };
    if length == 0 {
        // A zero length is an empty caption only when no error was reported
        // and the window still exists; otherwise the query failed.
        let error = unsafe { GetLastError() };
        return (error == 0 && unsafe { IsWindow(hwnd) } != 0).then(String::new);
    }
    if length < 0 || length as usize >= buffer.len() - 1 {
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
    terminal_gate: &'a MonitorTerminal,
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
        if channels.api_returned.load(Ordering::Acquire) {
            channels.passive_safe.store(false, Ordering::Release);
            if let Ok(mut reason) = channels.reason.lock() {
                *reason = Some(MonitorStop::ApiReturnedBeforeArm);
            }
            return;
        }
        if channels.cancelled.load(Ordering::Acquire) {
            channels.passive_safe.store(false, Ordering::Release);
            if let Ok(mut reason) = channels.reason.lock() {
                *reason = Some(MonitorStop::CancelledBeforeArm);
            }
            return;
        }
        system.wait(Duration::from_millis(5));
    }
    let deadline = system.monotonic() + focus_monitor_timeout();
    let mut policy = MonitorPolicy::default();
    while !channels.cancelled.load(Ordering::Acquire)
        && !channels.api_returned.load(Ordering::Acquire)
        && system.monotonic() < deadline
    {
        let terminal = policy.observe_with_api_return(
            system,
            owner,
            Arc::clone(&baseline),
            channels.cancelled,
            channels.api_returned,
            channels.terminal_gate,
            channels.accepted,
        );
        if !policy.passive_safe {
            channels.passive_safe.store(false, Ordering::Release);
        } else if !terminal {
            let Ok(_terminal_guard) = channels.terminal_gate.lock() else {
                channels.passive_safe.store(false, Ordering::Release);
                if let Ok(mut reason) = channels.reason.lock() {
                    *reason = Some(MonitorStop::ChannelFailed);
                }
                return;
            };
            if !channels.api_returned.load(Ordering::Acquire)
                && !channels.cancelled.load(Ordering::Acquire)
            {
                channels.passive_safe.store(true, Ordering::Release);
            }
        }
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
    let reason = if channels.api_returned.load(Ordering::Acquire) {
        MonitorStop::ApiReturned
    } else if channels.cancelled.load(Ordering::Acquire) {
        channels.passive_safe.store(false, Ordering::Release);
        MonitorStop::Cancelled
    } else {
        channels.passive_safe.store(false, Ordering::Release);
        MonitorStop::Deadline
    };
    if let Ok(mut output) = channels.reason.lock() {
        *output = Some(reason);
    }
}

fn request_monitor_cancellation(terminal_gate: &MonitorTerminal, cancelled: &AtomicBool) {
    cancelled.store(true, Ordering::Release);
    terminal_gate.mark_cancelled();
    drop(terminal_gate.lock());
}

fn mark_monitor_api_returned(
    terminal_gate: &MonitorTerminal,
    cancelled: &AtomicBool,
    api_returned: &AtomicBool,
) -> bool {
    if !cancelled.load(Ordering::Acquire) {
        api_returned.store(true, Ordering::Release);
        terminal_gate.mark_api_returned();
    }
    match terminal_gate.lock() {
        Ok(_guard) => cancelled.load(Ordering::Acquire),
        Err(_) => {
            cancelled.store(true, Ordering::Release);
            terminal_gate.mark_cancelled();
            api_returned.store(true, Ordering::Release);
            true
        }
    }
}

struct WebAuthnForegroundMonitor {
    cancelled: Arc<AtomicBool>,
    api_returned: Arc<AtomicBool>,
    terminal_gate: Arc<MonitorTerminal>,
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
        request_monitor_cancellation(&self.terminal_gate, &self.cancelled);
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
        let was_cancelled =
            mark_monitor_api_returned(&self.terminal_gate, &self.cancelled, &self.api_returned);
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
        let session_evidence = NativeForegroundSystem
            .native_session(current_session, Instant::now() + Duration::from_secs(2));
        let local_console = is_local_console_session(session_evidence);
        let baseline_snapshot = match baseline_window_identities(&mut NativeForegroundSystem) {
            Ok(snapshot) => snapshot,
            Err(error) => {
                let operation = match operation {
                    Operation::MakeCredential => "MakeCredential",
                    Operation::GetAssertion => "GetAssertion",
                };
                log::warn!(
                    "[WebAuthN-focus] reason=baseline-window-snapshot-failed operation={} stage={} attempts={}",
                    operation,
                    error.stage.label(),
                    error.attempts,
                );
                return None;
            }
        };
        let baseline_attempts = baseline_snapshot.attempts;
        let baseline_windows = baseline_snapshot.identities;
        log::info!(
            "[WebAuthN-focus] prepared operation={} session={} local_console={} baseline_windows={} baseline_unattributed={} baseline_attempts={}",
            match operation { Operation::MakeCredential => "MakeCredential", Operation::GetAssertion => "GetAssertion" },
            current_session,
            local_console,
            baseline_windows.len(),
            baseline_snapshot.unattributed.len(),
            baseline_attempts,
        );

        let cancelled = Arc::new(AtomicBool::new(false));
        let terminal_gate = Arc::new(MonitorTerminal::default());
        let armed = Arc::new(AtomicBool::new(false));
        let worker_cancelled = Arc::clone(&cancelled);
        let worker_terminal_gate = Arc::clone(&terminal_gate);
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
            local_console,
            windows: baseline_windows.clone(),
            unattributed_windows: baseline_snapshot.unattributed,
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
                        terminal_gate: &worker_terminal_gate,
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
            terminal_gate,
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
    pub fn new(hwnd: isize) -> Result<Self, BackendInitError> {
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
            return Err(BackendInitError::WebAuthnApiBelowV4 { api_version });
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
        exclude: &[Vec<u8>],
    ) -> Result<RegisteredCredential, FidoError> {
        self.continuation = None;
        let result = diagnose(
            Operation::MakeCredential,
            |diagnostic| self.make_credential_with_diagnostics(detected, exclude, diagnostic),
            |record| log::info!("[WebAuthN-operation] {}", record),
        );
        complete_registration(&mut self.continuation, result)
    }

    fn make_credential_with_diagnostics(
        &self,
        detected: &DetectedKey,
        exclude: &[Vec<u8>],
        diagnostic: &mut OperationDiagnostics,
    ) -> CreationResult {
        diagnostic.failure_stage = Some(FailureStage::Preflight);
        validate_exclude_credential_ids(exclude)?;
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
        // excludeCredentials（v1 CredentialList 欄位）：`exclude` 與 entries 須存活到 API 返回。
        let mut exclude_entries = exclude_credential_entries(exclude);
        let exclude_list = exclude_credential_list(&mut exclude_entries);
        let options = WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS {
            dwVersion: WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS_VERSION_5,
            dwTimeoutMilliseconds: OP_TIMEOUT_MS,
            CredentialList: exclude_list,
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
            return Err(make_credential_error(hr, !exclude.is_empty()));
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
        self.make_credential(detected, &[])
    }

    fn register_credential_excluding(
        &mut self,
        detected: &DetectedKey,
        _pin: Option<&str>,
        exclude: &[Vec<u8>],
    ) -> Result<RegisteredCredential, FidoError> {
        self.make_credential(detected, exclude)
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

/// makeCredential 失敗 HRESULT → FidoError。有送 excludeCredentials 時，`NTE_EXISTS`
/// （WebAuthNGetErrorName = "InvalidStateError"）代表命中：此金鑰已持有本金庫的 credential。
/// 未送排除清單（單人版）時維持通用錯誤，不顯示雙人版專用訊息。
fn make_credential_error(hr: windows_sys::core::HRESULT, exclude_requested: bool) -> FidoError {
    if exclude_requested && hr == windows_sys::Win32::Foundation::NTE_EXISTS {
        return FidoError::CredentialExcluded;
    }
    api_error("makeCredential", hr)
}

/// excludeCredentials 清單（指標借用 `credential_ids`，呼叫端須讓其存活至 API 返回）。
fn exclude_credential_entries(credential_ids: &[Vec<u8>]) -> Vec<WEBAUTHN_CREDENTIAL> {
    credential_ids
        .iter()
        .map(|credential_id| WEBAUTHN_CREDENTIAL {
            dwVersion: WEBAUTHN_CREDENTIAL_CURRENT_VERSION,
            cbId: credential_id.len() as u32,
            pbId: credential_id.as_ptr() as *mut u8,
            pwszCredentialType: WEBAUTHN_CREDENTIAL_TYPE_PUBLIC_KEY,
        })
        .collect()
}

/// v1 `CredentialList`（makeCredential 的 exclude 欄位）：空清單 → null 指標、count 0（與未設定相同）。
fn exclude_credential_list(entries: &mut [WEBAUTHN_CREDENTIAL]) -> WEBAUTHN_CREDENTIALS {
    WEBAUTHN_CREDENTIALS {
        cCredentials: entries.len() as u32,
        pCredentials: if entries.is_empty() {
            ptr::null_mut()
        } else {
            entries.as_mut_ptr()
        },
    }
}

/// 排除清單驗證：可為空；每筆不可空白或超過 API buffer 上限（與 allow-list 驗證同一組防禦式檢查）。
fn validate_exclude_credential_ids(credential_ids: &[Vec<u8>]) -> Result<(), FidoError> {
    if credential_ids.len() > u32::MAX as usize
        || credential_ids
            .iter()
            .any(|id| id.is_empty() || id.len() > MAX_API_BUFFER || id.len() > u32::MAX as usize)
    {
        return Err(FidoError::Internal(
            "credential exclude-list contains an invalid ID or count".into(),
        ));
    }
    Ok(())
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

    // ── D6：excludeCredentials ──

    #[test]
    fn make_credential_nte_exists_is_credential_excluded() {
        assert!(matches!(
            make_credential_error(windows_sys::Win32::Foundation::NTE_EXISTS, true),
            FidoError::CredentialExcluded
        ));
        let other = make_credential_error(0x8009_0030_u32 as i32, true);
        assert!(
            matches!(&other, FidoError::Internal(m) if m.contains("0x80090030")),
            "{other:?}"
        );
    }

    /// 未要求排除（單人版）時 NTE_EXISTS 不可顯示雙人版專用「已註冊」訊息。
    #[test]
    fn make_credential_nte_exists_without_exclude_keeps_generic_error() {
        let e = make_credential_error(windows_sys::Win32::Foundation::NTE_EXISTS, false);
        assert!(
            matches!(&e, FidoError::Internal(m) if m.contains("0x8009000F")),
            "{e:?}"
        );
    }

    #[test]
    fn exclude_list_points_at_entries_and_is_null_when_empty() {
        let ids = vec![vec![1u8, 2, 3], vec![4u8; 8]];
        let mut entries = exclude_credential_entries(&ids);
        let list = exclude_credential_list(&mut entries);
        assert_eq!(list.cCredentials, 2);
        assert_eq!(list.pCredentials, entries.as_mut_ptr());
        let mut none: Vec<WEBAUTHN_CREDENTIAL> = Vec::new();
        let empty = exclude_credential_list(&mut none);
        assert_eq!(empty.cCredentials, 0);
        assert!(empty.pCredentials.is_null());
    }

    #[test]
    fn exclude_ids_are_validated() {
        assert!(validate_exclude_credential_ids(&[]).is_ok());
        assert!(validate_exclude_credential_ids(&[vec![1u8; 16]]).is_ok());
        assert!(validate_exclude_credential_ids(&[vec![1u8; 16], Vec::new()]).is_err());
        assert!(validate_exclude_credential_ids(&[vec![0u8; MAX_API_BUFFER + 1]]).is_err());
    }

    /// 原始碼 contract：makeCredential options 確實帶入排除清單，且不使用 v3 pExcludeCredentialList。
    #[test]
    fn make_credential_options_wire_exclude_list() {
        // 定位字串以 format! 組出：既有 source-wiring oracle 要求原始 `fn …(` 標記在檔案中唯一，
        // 測試本身不得再以字面量重複這些標記。
        let source = include_str!("windows_webauthn.rs").replace("\r\n", "\n");
        let start_marker = format!("    fn {}(", "make_credential_with_diagnostics");
        let end_marker = format!("    fn {}(", "get_hmac_secret");
        assert_eq!(source.matches(&start_marker).count(), 1);
        let start = source.find(&start_marker).unwrap();
        let end = start
            + source[start..]
                .find(&end_marker)
                .expect("get_hmac_secret follows");
        let body = &source[start..end];
        assert!(body.contains("validate_exclude_credential_ids(exclude)?;"));
        assert!(body.contains("let exclude_list = exclude_credential_list(&mut exclude_entries);"));
        assert!(body.contains("CredentialList: exclude_list,"));
        assert!(body.contains("make_credential_error(hr, !exclude.is_empty())"));
        assert!(!body.contains("pExcludeCredentialList"));
    }

    #[test]
    fn exclude_entries_reference_each_credential_id() {
        let ids = vec![vec![1u8, 2, 3], vec![9u8; 64]];
        let entries = exclude_credential_entries(&ids);
        assert_eq!(entries.len(), 2);
        for (entry, id) in entries.iter().zip(ids.iter()) {
            assert_eq!(entry.dwVersion, WEBAUTHN_CREDENTIAL_CURRENT_VERSION);
            assert_eq!(entry.cbId as usize, id.len());
            assert_eq!(entry.pbId as *const u8, id.as_ptr());
            // `w!` 常數每次使用位址可能不同 → 比較字串內容而非指標。
            assert_eq!(
                unsafe { api_wide_string(entry.pwszCredentialType) }.as_deref(),
                Some("public-key")
            );
        }
        assert!(exclude_credential_entries(&[]).is_empty());
    }

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
        activation_pause: Option<GatePause>,
        final_activation_transition: Option<TerminalTransition>,
        publish_pause: Option<GatePause>,
        focus_change_before_activation: Option<isize>,
        focus_change_after_activation_claim: Option<isize>,
        focus_change_before_publish: Option<isize>,
        candidate_reuse_before_activation: Option<WindowIdentity>,
        candidate_reuse_after_activation_claim: Option<WindowIdentity>,
        competing_window_after_activation_claim: Option<TestWindow>,
        api_returned_before_activation: Option<Arc<AtomicBool>>,
        cancelled_before_activation: Option<Arc<AtomicBool>>,
        api_returned_after_activation_claim: Option<Arc<AtomicBool>>,
        cancelled_after_activation_claim: Option<Arc<AtomicBool>>,
        remove_window_after_broker_scan: Option<isize>,
        window_after_broker_scan: Option<(usize, TestWindow)>,
        // The broker host is visible before Windows assigns its caption.
        empty_title_reads: Option<(isize, usize)>,
        title_unavailable_hwnd: Option<isize>,
        broker_candidate_scans: usize,
        foreground_sequence: std::collections::VecDeque<isize>,
        foreground_reads: usize,
        api_returned_on_foreground: Option<(usize, Arc<AtomicBool>)>,
        broker_path_reads: usize,
        owner_change_on_broker_path: Option<(usize, WindowIdentity)>,
        enumeration_failed: bool,
        transient_enumeration_failures: usize,
        transient_identity_failures: std::collections::VecDeque<isize>,
        window_on_transient_identity_failure: Option<TestWindow>,
        transient_owner_ids_failure: Option<isize>,
        inaccessible_hwnd: Option<isize>,
        // Owner ids are readable but the session query fails (e.g. dwm.exe).
        session_unavailable_hwnd: Option<isize>,
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

    struct GatePause {
        entered: std::sync::mpsc::Sender<()>,
        release: std::sync::mpsc::Receiver<()>,
        terminal_flag: Arc<AtomicBool>,
        observed_terminal: Arc<AtomicBool>,
    }

    impl GatePause {
        fn wait_and_sample(self) {
            self.entered.send(()).unwrap();
            self.release
                .recv_timeout(Duration::from_secs(5))
                .expect("test synchronization timed out");
            self.observed_terminal.store(
                self.terminal_flag.load(Ordering::Acquire),
                Ordering::Release,
            );
        }
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
            if self.inaccessible_hwnd == Some(hwnd)
                || self.session_unavailable_hwnd == Some(hwnd)
            {
                return None;
            }
            if self.transient_identity_failures.front() == Some(&hwnd) {
                self.transient_identity_failures.pop_front();
                // A transient identity failure also hides the owner ids for this read.
                self.transient_owner_ids_failure = Some(hwnd);
                if let Some(window) = self.window_on_transient_identity_failure.take() {
                    self.windows.push(window);
                }
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
            self.foreground_reads += 1;
            if let Some((read, returned)) = &self.api_returned_on_foreground {
                if *read == self.foreground_reads {
                    returned.store(true, Ordering::Release);
                }
            }
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
            if self.transient_owner_ids_failure == Some(hwnd) {
                self.transient_owner_ids_failure = None;
                return None;
            }
            self.window(hwnd)
                .map(|w| (w.identity.process_id, w.identity.thread_id))
        }
        fn windows(&mut self) -> Result<Vec<isize>, ()> {
            self.trace.push("windows");
            if self.transient_enumeration_failures > 0 {
                self.transient_enumeration_failures -= 1;
                return Err(());
            }
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
            if self.unknown_metadata && hwnd == 3 || self.title_unavailable_hwnd == Some(hwnd) {
                return None;
            }
            if let Some((pending, reads)) = &mut self.empty_title_reads {
                if *pending == hwnd && *reads > 0 {
                    *reads -= 1;
                    return self.window(hwnd).map(|_| String::new());
                }
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
        fn activate(&mut self, hwnd: isize) -> bool {
            self.trace.push("activate");
            if self.activation_succeeds {
                self.foreground = hwnd;
            }
            if let Some(pause) = self.activation_pause.take() {
                pause.wait_and_sample();
            }
            self.activation_succeeds
        }
        fn after_broker_candidate_scan(&mut self) {
            self.broker_candidate_scans += 1;
            if self.broker_candidate_scans == 1 {
                if let Some(hwnd) = self.remove_window_after_broker_scan.take() {
                    self.windows.retain(|window| window.identity.hwnd != hwnd);
                }
            }
            if self
                .window_after_broker_scan
                .as_ref()
                .is_some_and(|(scan, _)| *scan == self.broker_candidate_scans)
            {
                let (_, window) = self.window_after_broker_scan.take().unwrap();
                self.windows.push(window);
            }
        }
        fn before_activation_guard(&mut self) {
            if let Some(hwnd) = self.focus_change_before_activation.take() {
                self.foreground = hwnd;
            }
            if let Some(identity) = self.candidate_reuse_before_activation.take() {
                if let Some(window) = self
                    .windows
                    .iter_mut()
                    .find(|window| window.identity.hwnd == identity.hwnd)
                {
                    window.identity = identity;
                }
            }
            if let Some(api_returned) = self.api_returned_before_activation.take() {
                api_returned.store(true, Ordering::Release);
            }
            if let Some(cancelled) = self.cancelled_before_activation.take() {
                cancelled.store(true, Ordering::Release);
            }
        }
        fn after_activation_claim(&mut self) {
            if let Some(hwnd) = self.focus_change_after_activation_claim.take() {
                self.foreground = hwnd;
            }
            if let Some(identity) = self.candidate_reuse_after_activation_claim.take() {
                if let Some(window) = self
                    .windows
                    .iter_mut()
                    .find(|window| window.identity.hwnd == identity.hwnd)
                {
                    window.identity = identity;
                }
            }
            if let Some(window) = self.competing_window_after_activation_claim.take() {
                self.windows.push(window);
            }
            if let Some(api_returned) = self.api_returned_after_activation_claim.take() {
                api_returned.store(true, Ordering::Release);
            }
            if let Some(cancelled) = self.cancelled_after_activation_claim.take() {
                cancelled.store(true, Ordering::Release);
            }
        }
        fn before_final_activation_call(
            &mut self,
            terminal: &MonitorTerminal,
            cancelled: &AtomicBool,
            api_returned: &AtomicBool,
        ) {
            if let Some(transition) = self.final_activation_transition.take() {
                match transition {
                    TerminalTransition::ApiReturned => {
                        api_returned.store(true, Ordering::Release);
                        terminal.mark_api_returned();
                    }
                    TerminalTransition::Cancelled => {
                        cancelled.store(true, Ordering::Release);
                        terminal.mark_cancelled();
                    }
                }
            }
        }
        fn after_monitor_publish_check(&mut self) {
            if let Some(hwnd) = self.focus_change_before_publish.take() {
                self.foreground = hwnd;
            }
            if let Some(pause) = self.publish_pause.take() {
                pause.wait_and_sample();
            }
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
            activation_pause: None,
            final_activation_transition: None,
            publish_pause: None,
            focus_change_before_activation: None,
            focus_change_after_activation_claim: None,
            focus_change_before_publish: None,
            candidate_reuse_before_activation: None,
            candidate_reuse_after_activation_claim: None,
            competing_window_after_activation_claim: None,
            api_returned_before_activation: None,
            cancelled_before_activation: None,
            api_returned_after_activation_claim: None,
            cancelled_after_activation_claim: None,
            remove_window_after_broker_scan: None,
            window_after_broker_scan: None,
            empty_title_reads: None,
            title_unavailable_hwnd: None,
            broker_candidate_scans: 0,
            foreground_sequence: Default::default(),
            foreground_reads: 0,
            api_returned_on_foreground: None,
            broker_path_reads: 0,
            owner_change_on_broker_path: None,
            enumeration_failed: false,
            transient_enumeration_failures: 0,
            transient_identity_failures: Default::default(),
            window_on_transient_identity_failure: None,
            transient_owner_ids_failure: None,
            inaccessible_hwnd: None,
            session_unavailable_hwnd: None,
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
            // Monitor-policy tests model the specifically authorized local Console path.
            local_console: true,
            windows: HashSet::from([owner]),
            unattributed_windows: HashSet::new(),
        });
        (system, baseline, owner, broker)
    }

    #[derive(Clone, Copy)]
    enum TerminalTransition {
        ApiReturned,
        Cancelled,
    }

    fn apply_terminal_transition(
        transition: TerminalTransition,
        terminal_gate: &MonitorTerminal,
        cancelled: &AtomicBool,
        api_returned: &AtomicBool,
    ) {
        match transition {
            TerminalTransition::ApiReturned => {
                assert!(!mark_monitor_api_returned(
                    terminal_gate,
                    cancelled,
                    api_returned
                ));
            }
            TerminalTransition::Cancelled => {
                request_monitor_cancellation(terminal_gate, cancelled);
            }
        }
    }

    fn spawn_terminal_transition(
        transition: TerminalTransition,
        terminal_gate: Arc<MonitorTerminal>,
        cancelled: Arc<AtomicBool>,
        api_returned: Arc<AtomicBool>,
    ) -> (
        std::sync::mpsc::Receiver<()>,
        std::sync::mpsc::Receiver<()>,
        thread::JoinHandle<()>,
    ) {
        let (started_tx, started_rx) = std::sync::mpsc::channel();
        let (complete_tx, complete_rx) = std::sync::mpsc::channel();
        let worker = thread::spawn(move || {
            started_tx.send(()).unwrap();
            apply_terminal_transition(transition, &terminal_gate, &cancelled, &api_returned);
            complete_tx.send(()).unwrap();
        });
        (started_rx, complete_rx, worker)
    }

    #[test]
    fn terminal_transition_is_serialized_with_activation_attempt() {
        for transition in [
            TerminalTransition::ApiReturned,
            TerminalTransition::Cancelled,
        ] {
            let (mut system, baseline, owner, _) = handoff_fixture();
            system.foreground = owner.hwnd;
            let cancelled = Arc::new(AtomicBool::new(false));
            let api_returned = Arc::new(AtomicBool::new(false));
            let terminal_flag = match transition {
                TerminalTransition::ApiReturned => Arc::clone(&api_returned),
                TerminalTransition::Cancelled => Arc::clone(&cancelled),
            };
            let observed_terminal = Arc::new(AtomicBool::new(false));
            let (entered_tx, entered_rx) = std::sync::mpsc::channel();
            let (release_tx, release_rx) = std::sync::mpsc::channel();
            system.activation_pause = Some(GatePause {
                entered: entered_tx,
                release: release_rx,
                terminal_flag: Arc::clone(&terminal_flag),
                observed_terminal: Arc::clone(&observed_terminal),
            });

            let terminal_gate = Arc::new(MonitorTerminal::default());
            let accepted = Arc::new(Mutex::new(None));
            let worker_gate = Arc::clone(&terminal_gate);
            let worker_cancelled = Arc::clone(&cancelled);
            let worker_returned = Arc::clone(&api_returned);
            let worker_accepted = Arc::clone(&accepted);
            let worker = thread::spawn(move || {
                let mut policy = MonitorPolicy::default();
                policy.observe_with_api_return(
                    &mut system,
                    owner.hwnd,
                    baseline,
                    &worker_cancelled,
                    &worker_returned,
                    &worker_gate,
                    &worker_accepted,
                );
                system
            });

            entered_rx
                .recv_timeout(Duration::from_secs(5))
                .expect("monitor did not reach the one-shot activation attempt");
            assert_eq!(
                terminal_gate.phase.load(Ordering::Acquire),
                PHASE_ACTIVATION_COMMITTED,
                "the fake activation is paused after its one-shot attempt is committed"
            );

            let gate_held = match terminal_gate.try_lock() {
                Err(std::sync::TryLockError::WouldBlock) => true,
                Ok(guard) => {
                    drop(guard);
                    false
                }
                Err(std::sync::TryLockError::Poisoned(_)) => {
                    panic!("terminal gate unexpectedly poisoned")
                }
            };
            // Mirror the wrappers' nonblocking marker stores and phase helper
            // while activation is paused. The wrappers themselves acquire the
            // gate after marking, so calling one here would deadlock the test.
            match transition {
                TerminalTransition::ApiReturned => {
                    api_returned.store(true, Ordering::Release);
                    terminal_gate.mark_api_returned();
                }
                TerminalTransition::Cancelled => {
                    cancelled.store(true, Ordering::Release);
                    terminal_gate.mark_cancelled();
                }
            }
            assert!(terminal_flag.load(Ordering::Acquire));
            assert_eq!(
                terminal_gate.phase.load(Ordering::Acquire),
                PHASE_ACTIVATION_COMMITTED,
                "the committed activation phase remains stable until activation returns"
            );

            release_tx.send(()).unwrap();
            let system = worker.join().unwrap();
            assert_eq!(terminal_gate.phase.load(Ordering::Acquire), PHASE_ACTIVATED);

            // Run the real wrapper after activation has joined. It completes
            // the terminal transition without racing finish_activation's
            // committed-to-activated phase update.
            let (started_rx, complete_rx, transition_worker) = spawn_terminal_transition(
                transition,
                Arc::clone(&terminal_gate),
                Arc::clone(&cancelled),
                Arc::clone(&api_returned),
            );
            started_rx
                .recv_timeout(Duration::from_secs(5))
                .expect("terminal transition worker did not start");
            complete_rx
                .recv_timeout(Duration::from_secs(5))
                .expect("terminal transition wrapper did not complete");
            transition_worker.join().unwrap();

            assert!(gate_held, "terminal state must synchronize with activation");
            assert!(system.trace.contains(&"activate"));
            assert_eq!(
                system.trace.iter().filter(|event| **event == "activate").count(),
                1,
                "a committed activation is attempted at most once"
            );
            let expected_phase = match transition {
                TerminalTransition::ApiReturned => PHASE_API_RETURNED,
                TerminalTransition::Cancelled => PHASE_CANCELLED,
            };
            assert_eq!(terminal_gate.phase.load(Ordering::Acquire), expected_phase);
            assert!(
                observed_terminal.load(Ordering::Acquire),
                "terminal transition is recorded during the already-claimed activation"
            );
            assert!(accepted.lock().unwrap().is_none());
            assert!(cancelled.load(Ordering::Acquire) || api_returned.load(Ordering::Acquire));
        }
    }

    #[test]
    fn terminal_transition_is_serialized_with_accepted_publication() {
        let (mut system, baseline, owner, broker) = handoff_fixture();
        system.foreground = broker.hwnd;
        let cancelled = Arc::new(AtomicBool::new(false));
        let api_returned = Arc::new(AtomicBool::new(false));
        let observed_terminal = Arc::new(AtomicBool::new(false));
        let (entered_tx, entered_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        system.publish_pause = Some(GatePause {
            entered: entered_tx,
            release: release_rx,
            terminal_flag: Arc::clone(&api_returned),
            observed_terminal: Arc::clone(&observed_terminal),
        });
        let terminal_gate = Arc::new(MonitorTerminal::default());
        let accepted = Arc::new(Mutex::new(None));
        let worker_gate = Arc::clone(&terminal_gate);
        let worker_cancelled = Arc::clone(&cancelled);
        let worker_returned = Arc::clone(&api_returned);
        let worker_accepted = Arc::clone(&accepted);
        let worker = thread::spawn(move || {
            let mut policy = MonitorPolicy::default();
            policy.observe_with_api_return(
                &mut system,
                owner.hwnd,
                baseline,
                &worker_cancelled,
                &worker_returned,
                &worker_gate,
                &worker_accepted,
            );
            system
        });

        entered_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("monitor did not reach accepted-result publication");
        let (started_rx, complete_rx, transition_worker) = spawn_terminal_transition(
            TerminalTransition::ApiReturned,
            Arc::clone(&terminal_gate),
            Arc::clone(&cancelled),
            Arc::clone(&api_returned),
        );
        started_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("API-return transition worker did not start");
        // `started` is signalled before the wrapper stores its marker. Wait for
        // the wrapper's nonblocking marker store (it precedes the gate lock) so
        // the paused publication samples a deterministic terminal state.
        let marker_deadline = Instant::now() + Duration::from_secs(5);
        while !api_returned.load(Ordering::Acquire) {
            assert!(
                Instant::now() < marker_deadline,
                "API-return wrapper did not publish its marker"
            );
            thread::yield_now();
        }

        let gate_held = match terminal_gate.try_lock() {
            Err(std::sync::TryLockError::WouldBlock) => true,
            Ok(guard) => {
                drop(guard);
                false
            }
            Err(std::sync::TryLockError::Poisoned(_)) => {
                panic!("terminal gate unexpectedly poisoned")
            }
        };
        if !gate_held {
            complete_rx
                .recv_timeout(Duration::from_secs(5))
                .expect("unsynchronized API-return transition did not complete");
        }
        release_tx.send(()).unwrap();
        let system = worker.join().unwrap();
        transition_worker.join().unwrap();

        assert!(
            gate_held,
            "terminal state must synchronize with publication"
        );
        assert!(
            observed_terminal.load(Ordering::Acquire),
            "API return is visible before the publication claim"
        );
        assert!(accepted.lock().unwrap().is_none());
        assert!(api_returned.load(Ordering::Acquire));
        assert_eq!(system.foreground, broker.hwnd);
    }

    #[test]
    fn baseline_snapshot_retries_a_transient_identity_failure_without_dropping_hidden_windows() {
        let (mut system, _, owner, broker) = handoff_fixture();
        system.windows[1].visible = false;
        system.transient_identity_failures.push_back(broker.hwnd);

        let baseline = baseline_window_identities(&mut system);
        assert!(
            baseline.is_ok(),
            "a transient identity-read failure should retry a complete baseline snapshot"
        );
        let baseline = baseline.unwrap();
        assert_eq!(baseline.identities, HashSet::from([owner, broker]));
        assert_eq!(baseline.attempts, 2);
        assert_eq!(
            system
                .trace
                .iter()
                .filter(|step| **step == "windows")
                .count(),
            2
        );
        assert_eq!(
            system.trace.iter().filter(|step| **step == "wait").count(),
            1
        );
        assert_eq!(system.time_ms, 10);
    }

    #[test]
    fn baseline_retry_uses_fresh_snapshot_including_new_window() {
        let (mut system, _, owner, broker) = handoff_fixture();
        let mut added_window = system.window(broker.hwnd).unwrap().clone();
        let added_identity = WindowIdentity {
            hwnd: 3,
            process_id: 30,
            thread_id: 31,
            session: 2,
        };
        added_window.identity = added_identity;
        system.transient_identity_failures.push_back(broker.hwnd);
        system.window_on_transient_identity_failure = Some(added_window);

        let baseline = baseline_window_identities(&mut system)
            .expect("the second complete enumeration should include the new window");
        assert_eq!(
            baseline.identities,
            HashSet::from([owner, broker, added_identity])
        );
        assert_eq!(baseline.attempts, 2);
    }

    #[test]
    fn baseline_enumeration_retries_a_transient_failure() {
        let (mut system, _, owner, broker) = handoff_fixture();
        system.transient_enumeration_failures = 1;

        let baseline = baseline_window_identities(&mut system)
            .expect("a transient enumeration failure should retry the full snapshot");
        assert_eq!(baseline.identities, HashSet::from([owner, broker]));
        assert_eq!(baseline.attempts, 2);
        assert_eq!(
            system
                .trace
                .iter()
                .filter(|step| **step == "windows")
                .count(),
            2
        );
        assert_eq!(
            system.trace.iter().filter(|step| **step == "wait").count(),
            1
        );
        assert_eq!(system.time_ms, 10);
    }

    #[test]
    fn baseline_enumeration_failure_retries_are_bounded() {
        let (mut system, _, _, _) = handoff_fixture();
        system.enumeration_failed = true;

        let error = baseline_window_identities(&mut system)
            .err()
            .expect("persistent enumeration failure must not return a partial snapshot");
        assert_eq!(error.stage, BaselineCaptureStage::WindowEnumeration);
        assert_eq!(error.attempts, BASELINE_CAPTURE_MAX_ATTEMPTS);
        assert_eq!(
            system
                .trace
                .iter()
                .filter(|step| **step == "windows")
                .count(),
            3
        );
        assert_eq!(
            system.trace.iter().filter(|step| **step == "wait").count(),
            2
        );
        assert_eq!(system.time_ms, 20);
    }

    #[test]
    fn baseline_identity_failure_retries_are_bounded_without_partial_snapshot() {
        let (mut system, _, _, broker) = handoff_fixture();
        system.inaccessible_hwnd = Some(broker.hwnd);

        let error = baseline_window_identities(&mut system)
            .err()
            .expect("persistent identity failure must not return a partial snapshot");
        assert_eq!(error.stage, BaselineCaptureStage::WindowIdentity);
        assert_eq!(error.attempts, BASELINE_CAPTURE_MAX_ATTEMPTS);
        assert_eq!(
            system
                .trace
                .iter()
                .filter(|step| **step == "windows")
                .count(),
            3
        );
        assert_eq!(
            system.trace.iter().filter(|step| **step == "wait").count(),
            2
        );
        assert_eq!(system.time_ms, 20);
    }

    fn session_unavailable_dwm_window(system: &mut TestSystem) -> (isize, u32, u32) {
        let identity = WindowIdentity {
            hwnd: 4,
            process_id: 40,
            thread_id: 41,
            session: 1,
        };
        system.windows.push(TestWindow {
            identity,
            visible: false,
            minimized: false,
            maximized: false,
            session: 1,
            path: r"C:\Windows\System32\dwm.exe".into(),
            title: String::new(),
            class: "Dwm".into(),
        });
        system.session_unavailable_hwnd = Some(identity.hwnd);
        (identity.hwnd, identity.process_id, identity.thread_id)
    }

    #[test]
    fn baseline_records_session_unattributed_window_without_failing() {
        let (mut system, _, owner, broker) = handoff_fixture();
        let dwm = session_unavailable_dwm_window(&mut system);

        let baseline = baseline_window_identities(&mut system)
            .expect("a window with readable owner ids but no session must not fail the baseline");
        assert_eq!(baseline.attempts, 1);
        assert_eq!(baseline.identities, HashSet::from([owner, broker]));
        assert_eq!(baseline.unattributed, HashSet::from([dwm]));
        assert!(!system.trace.contains(&"wait"));
    }

    #[test]
    fn monitor_activates_new_broker_with_session_unattributed_baseline_window() {
        let (mut system, _, owner, broker) = handoff_fixture();
        let broker_window = system.windows.remove(1);
        session_unavailable_dwm_window(&mut system);
        let snapshot = baseline_window_identities(&mut system)
            .expect("baseline with a session-unattributed window should be prepared");
        let baseline = Arc::new(BrokerBaseline {
            system_directory: r"C:\Windows\System32".into(),
            session: 2,
            local_console: true,
            windows: snapshot.identities,
            unattributed_windows: snapshot.unattributed,
        });
        system.windows.push(broker_window);
        system.foreground = owner.hwnd;
        let cancelled = AtomicBool::new(false);
        let accepted = Mutex::new(None);
        let mut policy = MonitorPolicy::default();

        assert!(policy.observe(&mut system, owner.hwnd, baseline, &cancelled, &accepted));

        assert_eq!(policy.reason, Some(MonitorStop::CandidateForeground));
        assert_eq!(
            accepted
                .lock()
                .unwrap()
                .as_ref()
                .map(|proof| proof.identity),
            Some(broker)
        );
        assert_eq!(
            system
                .trace
                .iter()
                .filter(|event| **event == "activate")
                .count(),
            1
        );
    }

    #[test]
    fn session_unattributed_baseline_window_is_never_a_new_broker() {
        let (mut system, mut baseline, owner, broker) = handoff_fixture();
        Arc::get_mut(&mut baseline)
            .unwrap()
            .unattributed_windows
            .insert((broker.hwnd, broker.process_id, broker.thread_id));
        assert!(!is_new_window_identity(
            broker,
            &baseline.windows,
            &baseline.unattributed_windows
        ));
        assert!(is_new_window_identity(
            WindowIdentity {
                thread_id: 99,
                ..broker
            },
            &baseline.windows,
            &baseline.unattributed_windows
        ));
        assert!(capture_broker(&mut system, Arc::clone(&baseline), broker).is_none());

        system.trace.clear();
        system.foreground = owner.hwnd;
        let cancelled = AtomicBool::new(false);
        let accepted = Mutex::new(None);
        let mut policy = MonitorPolicy::default();
        policy.observe(&mut system, owner.hwnd, baseline, &cancelled, &accepted);
        assert!(accepted.lock().unwrap().is_none());
        assert!(!system.trace.contains(&"activate"));
        assert_eq!(system.foreground, owner.hwnd);
    }

    #[test]
    fn baseline_owner_ids_failure_stays_bounded_with_unattributed_window_present() {
        let (mut system, _, _, broker) = handoff_fixture();
        session_unavailable_dwm_window(&mut system);
        system.inaccessible_hwnd = Some(broker.hwnd);

        let error = baseline_window_identities(&mut system)
            .err()
            .expect("a window without owner ids must still fail the baseline");
        assert_eq!(error.stage, BaselineCaptureStage::WindowIdentity);
        assert_eq!(error.attempts, BASELINE_CAPTURE_MAX_ATTEMPTS);
        assert_eq!(
            system.trace.iter().filter(|step| **step == "wait").count(),
            2
        );
    }

    #[test]
    fn handoff_review_worker_branches_fail_closed_on_incomplete_or_ambiguous_metadata() {
        for fault in [0, 1, 2, 3, 5, 6] {
            let (mut system, baseline, owner, _) = handoff_fixture();
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
                5 => (),
                6 => system.inaccessible_session = Some(30),
                _ => unreachable!(),
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
            assert!(accepted.lock().unwrap().is_none());
            assert!(!system.trace.contains(&"activate"));

            // A failed, incomplete or ambiguous observation is terminal; a later
            // clean sample cannot revive the same monitor instance.
            system.windows.pop();
            system.enumeration_failed = false;
            system.inaccessible_hwnd = None;
            system.inaccessible_pid = None;
            system.inaccessible_session = None;
            system.unknown_metadata = false;
            assert!(policy.observe(&mut system, owner.hwnd, baseline, &cancelled, &accepted));
            assert!(accepted.lock().unwrap().is_none());
            assert!(!system.trace.contains(&"activate"));
        }
    }

    #[test]
    fn monitor_activates_unique_candidate_despite_unrelated_cross_session_window() {
        let (mut system, baseline, owner, broker) = handoff_fixture();
        let mut other = system.windows[1].clone();
        other.identity = WindowIdentity {
            hwnd: 3,
            process_id: 30,
            thread_id: 31,
            session: 3,
        };
        other.session = 3;
        other.class = "ordinary".into();
        system.windows.push(other);
        system.foreground = owner.hwnd;
        let cancelled = AtomicBool::new(false);
        let accepted = Mutex::new(None);
        let mut policy = MonitorPolicy::default();

        assert!(policy.observe(&mut system, owner.hwnd, baseline, &cancelled, &accepted));

        assert_eq!(policy.reason, Some(MonitorStop::CandidateForeground));
        assert_eq!(
            accepted
                .lock()
                .unwrap()
                .as_ref()
                .map(|proof| proof.identity),
            Some(broker)
        );
        assert_eq!(
            system
                .trace
                .iter()
                .filter(|event| **event == "activate")
                .count(),
            1
        );
        assert!(!policy.passive_safe);
    }

    #[test]
    fn monitor_accepts_unique_candidate_already_foreground_without_activation() {
        let (mut system, baseline, owner, broker) = handoff_fixture();
        system.foreground = broker.hwnd;
        let accepted = Mutex::new(None);

        assert!(monitor_observe(
            &mut system,
            owner.hwnd,
            baseline,
            &AtomicBool::new(false),
            &accepted,
        ));

        assert_eq!(
            accepted
                .lock()
                .unwrap()
                .as_ref()
                .map(|proof| proof.identity),
            Some(broker)
        );
        assert!(!system.trace.contains(&"activate"));
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
        assert!(is_local_console_session(session_evidence(
            Ok(0),
            Err(QueryStatus::NotQueried)
        )));
        assert!(!is_local_console_session(session_evidence(
            Ok(2),
            Ok(WTSActive)
        )));
        assert!(!is_local_console_session(session_evidence(
            Err(QueryStatus::NativeFailure),
            Err(QueryStatus::NotQueried)
        )));
        for state in [-1, 0, 1, 4, 9, 10, i32::MAX] {
            assert_eq!(session_evidence(Ok(2), Ok(state)).active_rdp(), state == 0);
        }
    }

    #[test]
    fn monitor_raises_unique_new_dialog_in_existing_broker_process_once() {
        let (mut system, mut baseline, owner, broker) = handoff_fixture();
        let existing_broker_window = WindowIdentity {
            hwnd: 3,
            process_id: broker.process_id,
            thread_id: broker.thread_id + 1,
            session: broker.session,
        };
        Arc::get_mut(&mut baseline)
            .unwrap()
            .windows
            .insert(existing_broker_window);
        system.windows.push(TestWindow {
            identity: existing_broker_window,
            visible: false,
            minimized: false,
            maximized: false,
            session: broker.session,
            path: r"C:\Windows\System32\CredentialUIBroker.exe".into(),
            title: String::new(),
            class: "IME".into(),
        });
        system.foreground = owner.hwnd;
        let accepted = Mutex::new(None);
        let mut policy = MonitorPolicy::default();

        assert!(policy.observe(
            &mut system,
            owner.hwnd,
            baseline,
            &AtomicBool::new(false),
            &accepted,
        ));

        assert_eq!(
            system
                .trace
                .iter()
                .filter(|event| **event == "activate")
                .count(),
            1,
            "a unique new dialog should receive exactly one activation attempt"
        );
        let activation = system
            .trace
            .iter()
            .position(|event| *event == "activate")
            .unwrap();
        assert_eq!(system.trace[activation - 1], "foreground");
        assert_eq!(system.trace[activation - 2], "visible");
        assert_eq!(system.foreground, broker.hwnd);
        assert_eq!(
            accepted
                .lock()
                .unwrap()
                .as_ref()
                .map(|proof| proof.identity),
            Some(broker),
            "a newly created dialog remains detectable in an already-running broker process"
        );
        assert!(!policy.passive_safe);
    }

    #[test]
    fn monitor_does_not_raise_candidate_after_user_focus_changes() {
        let (mut system, baseline, owner, _) = handoff_fixture();
        system.foreground = owner.hwnd;
        system.foreground_sequence = [owner.hwnd, 3].into();
        let cancelled = AtomicBool::new(false);
        let mut passive_safe = true;
        let accepted = Mutex::new(None);

        let reason = monitor_observe_reason(
            &mut system,
            owner.hwnd,
            baseline,
            &cancelled,
            &AtomicBool::new(false),
            &MonitorTerminal::default(),
            &mut passive_safe,
            &accepted,
        );

        assert_eq!(reason, Some(MonitorStop::ForegroundLost));
        assert!(
            !system.trace.contains(&"activate"),
            "the monitor must not override focus after the user leaves FidoVault"
        );
        assert!(accepted.lock().unwrap().is_none());
        assert!(!passive_safe);
    }

    #[test]
    fn monitor_stops_when_initial_ambiguity_disappears_before_revalidation() {
        let (mut system, baseline, owner, _) = handoff_fixture();
        let mut competing = system.windows[1].clone();
        competing.identity.hwnd = 3;
        competing.identity.process_id = 30;
        competing.identity.thread_id = 31;
        system.windows.push(competing);
        system.remove_window_after_broker_scan = Some(3);
        system.foreground = owner.hwnd;
        let accepted = Mutex::new(None);
        let mut passive_safe = false;

        let reason = monitor_observe_reason(
            &mut system,
            owner.hwnd,
            baseline,
            &AtomicBool::new(false),
            &AtomicBool::new(false),
            &MonitorTerminal::default(),
            &mut passive_safe,
            &accepted,
        );

        assert_eq!(reason, Some(MonitorStop::Ambiguous));
        assert_eq!(system.broker_candidate_scans, 1);
        assert!(!system.trace.contains(&"activate"));
        assert!(accepted.lock().unwrap().is_none());
    }

    #[test]
    fn monitor_refuses_activation_if_focus_changes_at_activation_boundary() {
        let (mut system, baseline, owner, _) = handoff_fixture();
        system.foreground = owner.hwnd;
        system.focus_change_before_activation = Some(3);
        let accepted = Mutex::new(None);
        let mut passive_safe = false;

        let reason = monitor_observe_reason(
            &mut system,
            owner.hwnd,
            baseline,
            &AtomicBool::new(false),
            &AtomicBool::new(false),
            &MonitorTerminal::default(),
            &mut passive_safe,
            &accepted,
        );

        assert_eq!(reason, Some(MonitorStop::ForegroundLost));
        assert_eq!(system.foreground, 3);
        assert!(!system.trace.contains(&"activate"));
        assert!(accepted.lock().unwrap().is_none());
    }

    #[test]
    fn monitor_refuses_recycled_candidate_at_activation_boundary() {
        let (mut system, baseline, owner, broker) = handoff_fixture();
        system.foreground = owner.hwnd;
        system.candidate_reuse_before_activation = Some(WindowIdentity {
            process_id: broker.process_id + 100,
            thread_id: broker.thread_id + 100,
            ..broker
        });
        let accepted = Mutex::new(None);
        let mut passive_safe = false;

        let reason = monitor_observe_reason(
            &mut system,
            owner.hwnd,
            baseline,
            &AtomicBool::new(false),
            &AtomicBool::new(false),
            &MonitorTerminal::default(),
            &mut passive_safe,
            &accepted,
        );

        assert_eq!(reason, Some(MonitorStop::CandidateChanged));
        assert_eq!(system.foreground, owner.hwnd);
        assert!(!system.trace.contains(&"activate"));
        assert!(accepted.lock().unwrap().is_none());
    }

    #[test]
    fn monitor_does_not_publish_after_focus_changes_before_acceptance() {
        let (mut system, baseline, _, broker) = handoff_fixture();
        system.foreground = broker.hwnd;
        system.focus_change_before_publish = Some(3);
        let accepted = Mutex::new(None);
        let mut passive_safe = false;

        let reason = monitor_observe_reason(
            &mut system,
            1,
            baseline,
            &AtomicBool::new(false),
            &AtomicBool::new(false),
            &MonitorTerminal::default(),
            &mut passive_safe,
            &accepted,
        );

        assert_eq!(reason, Some(MonitorStop::ForegroundLost));
        assert_eq!(system.foreground, 3);
        assert!(!system.trace.contains(&"activate"));
        assert!(accepted.lock().unwrap().is_none());
    }

    #[test]
    fn monitor_api_return_or_cancellation_before_native_activation_prevents_attempt() {
        for terminal in [
            TerminalTransition::ApiReturned,
            TerminalTransition::Cancelled,
        ] {
            for after_claim in [false, true] {
                let (mut system, baseline, owner, _) = handoff_fixture();
                system.foreground = owner.hwnd;
                let cancelled = Arc::new(AtomicBool::new(false));
                let api_returned = Arc::new(AtomicBool::new(false));
                match (terminal, after_claim) {
                    (TerminalTransition::ApiReturned, false) => {
                        system.api_returned_before_activation = Some(Arc::clone(&api_returned));
                    }
                    (TerminalTransition::Cancelled, false) => {
                        system.cancelled_before_activation = Some(Arc::clone(&cancelled));
                    }
                    (TerminalTransition::ApiReturned, true) => {
                        system.api_returned_after_activation_claim =
                            Some(Arc::clone(&api_returned));
                    }
                    (TerminalTransition::Cancelled, true) => {
                        system.cancelled_after_activation_claim = Some(Arc::clone(&cancelled));
                    }
                }
                let accepted = Mutex::new(None);
                let mut passive_safe = false;
                let reason = monitor_observe_reason(
                    &mut system,
                    owner.hwnd,
                    baseline,
                    &cancelled,
                    &api_returned,
                    &MonitorTerminal::default(),
                    &mut passive_safe,
                    &accepted,
                );
                let expected = match terminal {
                    TerminalTransition::ApiReturned => MonitorStop::ApiReturned,
                    TerminalTransition::Cancelled => MonitorStop::Cancelled,
                };
                assert_eq!(reason, Some(expected));
                assert!(!system.trace.contains(&"activate"));
                assert!(accepted.lock().unwrap().is_none());
            }
        }
    }

    #[test]
    fn terminal_transition_wins_at_final_activation_commit_boundary() {
        for transition in [
            TerminalTransition::ApiReturned,
            TerminalTransition::Cancelled,
        ] {
            let (mut system, baseline, owner, _) = handoff_fixture();
            system.foreground = owner.hwnd;
            system.final_activation_transition = Some(transition);
            let cancelled = AtomicBool::new(false);
            let api_returned = AtomicBool::new(false);
            let terminal_flag = match transition {
                TerminalTransition::ApiReturned => &api_returned,
                TerminalTransition::Cancelled => &cancelled,
            };
            let terminal_gate = MonitorTerminal::default();
            let accepted = Mutex::new(None);
            let mut passive_safe = false;
            let reason = monitor_observe_reason(
                &mut system,
                owner.hwnd,
                baseline,
                &cancelled,
                &api_returned,
                &terminal_gate,
                &mut passive_safe,
                &accepted,
            );
            let expected = match transition {
                TerminalTransition::ApiReturned => MonitorStop::ApiReturned,
                TerminalTransition::Cancelled => MonitorStop::Cancelled,
            };
            assert!(terminal_flag.load(Ordering::Acquire));
            assert_eq!(reason, Some(expected));
            assert!(accepted.lock().unwrap().is_none());
            assert_eq!(
                system.trace.iter().filter(|event| **event == "activate").count(),
                0,
                "terminal transition at the final activation boundary must prevent activation"
            );
        }
    }

    #[test]
    fn monitor_rechecks_focus_after_activation_claim_before_native_call() {
        let (mut system, baseline, owner, _) = handoff_fixture();
        system.foreground = owner.hwnd;
        system.focus_change_after_activation_claim = Some(3);
        let accepted = Mutex::new(None);
        let mut passive_safe = false;

        let reason = monitor_observe_reason(
            &mut system,
            owner.hwnd,
            baseline,
            &AtomicBool::new(false),
            &AtomicBool::new(false),
            &MonitorTerminal::default(),
            &mut passive_safe,
            &accepted,
        );

        assert_eq!(reason, Some(MonitorStop::ForegroundLost));
        assert_eq!(system.foreground, 3);
        assert!(!system.trace.contains(&"activate"));
        assert!(accepted.lock().unwrap().is_none());
    }

    #[test]
    fn monitor_refuses_candidate_when_activation_claim_revalidation_is_ambiguous() {
        let (mut system, baseline, owner, _) = handoff_fixture();
        system.foreground = owner.hwnd;
        system.competing_window_after_activation_claim = Some(TestWindow {
            identity: WindowIdentity {
                hwnd: 3,
                process_id: 21,
                thread_id: 31,
                session: 2,
            },
            visible: true,
            minimized: false,
            maximized: false,
            session: 2,
            path: r"C:\Windows\System32\CredentialUIBroker.exe".into(),
            title: "Windows Security".into(),
            class: "Credential Dialog Xaml Host".into(),
        });
        let accepted = Mutex::new(None);
        let mut passive_safe = false;

        let reason = monitor_observe_reason(
            &mut system,
            owner.hwnd,
            baseline,
            &AtomicBool::new(false),
            &AtomicBool::new(false),
            &MonitorTerminal::default(),
            &mut passive_safe,
            &accepted,
        );

        assert_eq!(reason, Some(MonitorStop::Ambiguous));
        assert_eq!(system.foreground, owner.hwnd);
        assert!(!system.trace.contains(&"activate"));
        assert!(accepted.lock().unwrap().is_none());
    }

    fn untitled_broker_host(hwnd: isize) -> TestWindow {
        TestWindow {
            identity: WindowIdentity {
                hwnd,
                process_id: 30,
                thread_id: 31,
                session: 2,
            },
            visible: true,
            minimized: false,
            maximized: false,
            session: 2,
            path: r"C:\Windows\System32\CredentialUIBroker.exe".into(),
            title: String::new(),
            class: "Credential Dialog Xaml Host".into(),
        }
    }

    fn activation_count(system: &TestSystem) -> usize {
        system
            .trace
            .iter()
            .filter(|event| **event == "activate")
            .count()
    }

    #[test]
    fn monitor_waits_for_untitled_broker_host_then_activates_once() {
        let (mut system, baseline, owner, broker) = handoff_fixture();
        system.windows[1].title = "Windows \u{5b89}\u{5168}\u{6027}".into();
        system.foreground = owner.hwnd;
        system.empty_title_reads = Some((broker.hwnd, 2));
        let cancelled = AtomicBool::new(false);
        let accepted = Mutex::new(None);
        let mut policy = MonitorPolicy::default();

        for _ in 0..2 {
            assert!(!policy.observe(
                &mut system,
                owner.hwnd,
                Arc::clone(&baseline),
                &cancelled,
                &accepted
            ));
            assert_eq!(policy.reason, None);
            assert!(
                !policy.passive_safe,
                "an untitled broker host is not evidence of broker absence"
            );
            assert_eq!(activation_count(&system), 0);
            assert!(accepted.lock().unwrap().is_none());
        }

        assert!(policy.observe(
            &mut system,
            owner.hwnd,
            Arc::clone(&baseline),
            &cancelled,
            &accepted
        ));
        assert_eq!(policy.reason, Some(MonitorStop::CandidateForeground));
        assert_eq!(
            accepted
                .lock()
                .unwrap()
                .as_ref()
                .map(|proof| proof.identity),
            Some(broker)
        );
        assert_eq!(activation_count(&system), 1);

        // One-shot: the stopped monitor never activates again.
        system.foreground = owner.hwnd;
        assert!(policy.observe(&mut system, owner.hwnd, baseline, &cancelled, &accepted));
        assert_eq!(activation_count(&system), 1);
    }

    #[test]
    fn monitor_broker_host_title_query_failure_stays_incomplete() {
        let (mut system, baseline, owner, broker) = handoff_fixture();
        system.foreground = owner.hwnd;
        system.title_unavailable_hwnd = Some(broker.hwnd);
        let cancelled = AtomicBool::new(false);
        let accepted = Mutex::new(None);
        let mut policy = MonitorPolicy::default();

        assert!(policy.observe(&mut system, owner.hwnd, baseline, &cancelled, &accepted));

        assert_eq!(policy.reason, Some(MonitorStop::Incomplete));
        assert!(!policy.passive_safe);
        assert_eq!(activation_count(&system), 0);
        assert!(accepted.lock().unwrap().is_none());
    }

    #[test]
    fn monitor_treats_untitled_broker_host_during_rescan_as_ambiguous() {
        // Scan 2 is the revalidation, scans 3 and 4 run inside activation (before
        // and after the claim), scan 5 is the final publication check.
        for (after_scan, activations, phase) in [
            (1, 0, PHASE_WATCHING),
            (2, 0, PHASE_WATCHING),
            (3, 0, PHASE_FAILED),
            (4, 1, PHASE_ACTIVATED),
        ] {
            let (mut system, baseline, owner, _) = handoff_fixture();
            system.foreground = owner.hwnd;
            system.window_after_broker_scan = Some((after_scan, untitled_broker_host(3)));
            let terminal = MonitorTerminal::default();
            let accepted = Mutex::new(None);
            let mut passive_safe = false;

            let reason = monitor_observe_reason(
                &mut system,
                owner.hwnd,
                baseline,
                &AtomicBool::new(false),
                &AtomicBool::new(false),
                &terminal,
                &mut passive_safe,
                &accepted,
            );

            assert_eq!(reason, Some(MonitorStop::Ambiguous), "after scan {after_scan}");
            assert_eq!(activation_count(&system), activations, "after scan {after_scan}");
            assert_eq!(terminal.phase.load(Ordering::Acquire), phase, "after scan {after_scan}");
            assert!(!passive_safe);
            assert!(accepted.lock().unwrap().is_none());
        }
    }

    #[test]
    fn untitled_broker_host_is_never_a_candidate() {
        let (mut system, baseline, owner, broker) = handoff_fixture();
        system.windows[1].title = String::new();
        system.foreground = owner.hwnd;

        assert!(broker_candidates(&mut system, &baseline).is_err());
        assert!(capture_broker(&mut system, Arc::clone(&baseline), broker).is_none());

        let cancelled = AtomicBool::new(false);
        let accepted = Mutex::new(None);
        let mut policy = MonitorPolicy::default();
        for _ in 0..5 {
            assert!(!policy.observe(
                &mut system,
                owner.hwnd,
                Arc::clone(&baseline),
                &cancelled,
                &accepted
            ));
            assert!(!policy.passive_safe);
        }
        assert_eq!(policy.reason, None);
        assert_eq!(activation_count(&system), 0);
        assert!(accepted.lock().unwrap().is_none());
        assert_eq!(system.foreground, owner.hwnd);

        // A hidden untitled host is not broker-like evidence at all.
        system.windows[1].visible = false;
        assert_eq!(broker_candidates(&mut system, &baseline), Ok(Vec::new()));
    }

    #[test]
    fn scan_failure_outranks_untitled_broker_host() {
        for failing_first in [false, true] {
            let (mut system, baseline, owner, _) = handoff_fixture();
            system.windows[1].title = String::new();
            let mut failing = untitled_broker_host(3);
            failing.title = "Windows Security".into();
            if failing_first {
                system.windows.insert(1, failing);
            } else {
                system.windows.push(failing);
            }
            system.title_unavailable_hwnd = Some(3);
            system.foreground = owner.hwnd;
            let cancelled = AtomicBool::new(false);
            let accepted = Mutex::new(None);
            let mut policy = MonitorPolicy::default();

            assert!(policy.observe(&mut system, owner.hwnd, baseline, &cancelled, &accepted));

            assert_eq!(policy.reason, Some(MonitorStop::Incomplete));
            assert_eq!(activation_count(&system), 0);
            assert!(accepted.lock().unwrap().is_none());
        }
    }

    #[test]
    fn monitor_never_activates_candidate_from_rdp_session() {
        let (mut system, mut baseline, owner, _) = handoff_fixture();
        Arc::get_mut(&mut baseline).unwrap().local_console = false;
        system.foreground = owner.hwnd;
        let accepted = Mutex::new(None);
        let mut passive_safe = false;

        let reason = monitor_observe_reason(
            &mut system,
            owner.hwnd,
            baseline,
            &AtomicBool::new(false),
            &AtomicBool::new(false),
            &MonitorTerminal::default(),
            &mut passive_safe,
            &accepted,
        );

        assert_eq!(reason, Some(MonitorStop::NonConsoleSession));
        assert_eq!(system.foreground, owner.hwnd);
        assert!(!system.trace.contains(&"activate"));
        assert!(accepted.lock().unwrap().is_none());
    }

    #[test]
    fn monitor_precise_terminal_reasons_are_per_instance_and_permanent() {
        for (fault, expected) in [
            (0, MonitorStop::Incomplete),
            (1, MonitorStop::Ambiguous),
            (2, MonitorStop::ForegroundLost),
            (3, MonitorStop::Cancelled),
            (4, MonitorStop::CandidateForeground),
            (5, MonitorStop::CandidateForeground),
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
                5 => system.foreground = 1,
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

    #[test]
    fn monitor_activation_failure_is_terminal_and_not_retried() {
        let (mut system, baseline, owner, _) = handoff_fixture();
        system.foreground = owner.hwnd;
        system.activation_succeeds = false;
        let accepted = Mutex::new(None);
        let cancelled = AtomicBool::new(false);
        let mut policy = MonitorPolicy::default();

        assert!(policy.observe(
            &mut system,
            owner.hwnd,
            Arc::clone(&baseline),
            &cancelled,
            &accepted,
        ));
        assert_eq!(policy.reason, Some(MonitorStop::ActivationFailed));
        assert_eq!(
            system
                .trace
                .iter()
                .filter(|event| **event == "activate")
                .count(),
            1
        );
        assert!(accepted.lock().unwrap().is_none());

        assert!(policy.observe(&mut system, owner.hwnd, baseline, &cancelled, &accepted,));
        assert_eq!(
            system
                .trace
                .iter()
                .filter(|event| **event == "activate")
                .count(),
            1
        );
    }

    #[test]
    fn monitor_worker_activates_and_publishes_unique_dialog() {
        let (mut system, baseline, owner, broker) = handoff_fixture();
        system.foreground = owner.hwnd;
        let cancelled = AtomicBool::new(false);
        let api_returned = AtomicBool::new(false);
        let armed = AtomicBool::new(true);
        let accepted = Mutex::new(None);
        let passive_safe = AtomicBool::new(false);
        let reason = Mutex::new(None);

        run_monitor_worker(
            &mut system,
            owner.hwnd,
            baseline,
            MonitorWorkerChannels {
                cancelled: &cancelled,
                api_returned: &api_returned,
                terminal_gate: &MonitorTerminal::default(),
                armed: &armed,
                accepted: &accepted,
                passive_safe: &passive_safe,
                reason: &reason,
            },
        );

        assert_eq!(
            *reason.lock().unwrap(),
            Some(MonitorStop::CandidateForeground)
        );
        assert_eq!(
            accepted
                .lock()
                .unwrap()
                .as_ref()
                .map(|proof| proof.identity),
            Some(broker)
        );
        assert_eq!(system.foreground, broker.hwnd);
        assert_eq!(
            system
                .trace
                .iter()
                .filter(|event| **event == "activate")
                .count(),
            1
        );
        assert!(!passive_safe.load(Ordering::Acquire));
    }

    #[test]
    fn monitor_does_not_activate_candidate_after_api_return_marker() {
        let (mut system, baseline, owner, _) = handoff_fixture();
        system.foreground = owner.hwnd;
        let cancelled = AtomicBool::new(false);
        let api_returned = AtomicBool::new(true);
        let armed = AtomicBool::new(true);
        let accepted = Mutex::new(None);
        let passive_safe = AtomicBool::new(false);
        let reason = Mutex::new(None);

        run_monitor_worker(
            &mut system,
            owner.hwnd,
            baseline,
            MonitorWorkerChannels {
                cancelled: &cancelled,
                api_returned: &api_returned,
                terminal_gate: &MonitorTerminal::default(),
                armed: &armed,
                accepted: &accepted,
                passive_safe: &passive_safe,
                reason: &reason,
            },
        );

        assert_eq!(*reason.lock().unwrap(), Some(MonitorStop::ApiReturned));
        assert!(!system.trace.contains(&"activate"));
        assert!(accepted.lock().unwrap().is_none());
    }

    #[test]
    fn monitor_stops_if_api_returns_during_final_focus_sample() {
        let (mut system, baseline, owner, _) = handoff_fixture();
        system.foreground = owner.hwnd;
        let cancelled = AtomicBool::new(false);
        let api_returned = Arc::new(AtomicBool::new(false));
        system.api_returned_on_foreground = Some((2, Arc::clone(&api_returned)));
        let armed = AtomicBool::new(true);
        let accepted = Mutex::new(None);
        let passive_safe = AtomicBool::new(false);
        let reason = Mutex::new(None);

        run_monitor_worker(
            &mut system,
            owner.hwnd,
            baseline,
            MonitorWorkerChannels {
                cancelled: &cancelled,
                api_returned: &api_returned,
                terminal_gate: &MonitorTerminal::default(),
                armed: &armed,
                accepted: &accepted,
                passive_safe: &passive_safe,
                reason: &reason,
            },
        );

        assert_eq!(*reason.lock().unwrap(), Some(MonitorStop::ApiReturned));
        assert!(!system.trace.contains(&"activate"));
        assert!(accepted.lock().unwrap().is_none());
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
        system.foreground_sequence = [broker.hwnd, owner.hwnd].into();
        system.trace.clear();
        assert_eq!(
            prepare_continuation(&mut pending, owner.hwnd, &[vec![7, 8]], &mut system),
            Ok(HandoffOutcome::Recovered)
        );
        assert!(pending.is_none());
        assert!(validate_owner_foreground(owner.hwnd as HWND, system.foreground as HWND).is_ok());
        assert!(!system.trace.contains(&"activate"));
        assert!(
            !system.trace.contains(&"restore"),
            "continuation must not restore or foreground any HWND"
        );
        assert!(system.windows[0].maximized);
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
    fn handoff_minimized_owner_is_refused_without_restore() {
        let (mut system, baseline, owner, broker) = handoff_fixture();
        let mut pending = test_pending(&mut system, baseline, owner, broker);
        system.windows[0].minimized = true;
        system.trace.clear();
        assert_eq!(
            prepare_continuation(&mut pending, owner.hwnd, &[vec![7, 8]], &mut system),
            Err(HandoffRefusal::Owner)
        );
        assert!(!system.trace.contains(&"activate"));
        assert!(!system.trace.contains(&"restore"));
        assert!(system.windows[0].minimized);
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
    fn handoff_broker_still_foreground_refuses_and_cannot_replay() {
        let (mut system, baseline, owner, broker) = handoff_fixture();
        let mut pending = test_pending(&mut system, baseline, owner, broker);
        system.trace.clear();
        assert_eq!(
            prepare_continuation(&mut pending, owner.hwnd, &[vec![7, 8]], &mut system),
            Err(HandoffRefusal::Foreground)
        );
        assert!(pending.is_none());
        assert!(!system.trace.contains(&"activate"));
        assert!(!system.trace.contains(&"restore"));
        system.trace.clear();
        assert_eq!(
            prepare_continuation(&mut pending, owner.hwnd, &[vec![7, 8]], &mut system),
            Ok(HandoffOutcome::Ordinary)
        );
        assert!(!system.trace.contains(&"activate"));
        assert!(!system.trace.contains(&"restore"));
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
            terminal_gate: Arc::new(MonitorTerminal::default()),
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
            terminal_gate: Arc::new(MonitorTerminal::default()),
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
    fn handoff_capture_refuses_preexisting_hidden_or_changed_candidates() {
        for change in 0..4 {
            let (mut system, mut baseline, _, broker) = handoff_fixture();
            match change {
                0 => {
                    Arc::get_mut(&mut baseline).unwrap().windows.insert(broker);
                }
                1 => system.windows[1].visible = false,
                2 => system.windows[1].identity.thread_id = 99,
                _ => system.foreground = 3,
            }
            assert!(capture_broker(&mut system, baseline, broker).is_none());
        }
    }

    #[test]
    fn baseline_known_window_is_not_accepted_as_a_new_dialog() {
        let (mut system, mut baseline, owner, broker) = handoff_fixture();
        Arc::get_mut(&mut baseline).unwrap().windows.insert(broker);

        assert!(!is_new_window_identity(
            broker,
            &baseline.windows,
            &baseline.unattributed_windows
        ));
        let initial_foreground = system.foreground;
        let cancelled = AtomicBool::new(false);
        let mut passive_safe = true;
        let accepted = Mutex::new(None);
        let reason = monitor_observe_reason(
            &mut system,
            owner.hwnd,
            baseline,
            &cancelled,
            &AtomicBool::new(false),
            &MonitorTerminal::default(),
            &mut passive_safe,
            &accepted,
        );

        assert_eq!(
            reason,
            Some(MonitorStop::ForegroundLost),
            "a window already present in the complete baseline is not a new candidate"
        );
        assert_eq!(
            system.foreground, initial_foreground,
            "the monitor must leave focus unchanged"
        );
        assert!(!system.trace.contains(&"activate"));
        assert!(!passive_safe);

        let observation = BrokerObservation {
            broker: None,
            passive_safe,
        };
        let mut pending = None;
        complete_registration(&mut pending, Ok((test_registration(), owner, observation))).unwrap();
        assert_eq!(
            prepare_continuation(&mut pending, owner.hwnd, &[vec![7, 8]], &mut system),
            Err(HandoffRefusal::UnobservedBroker)
        );
        assert_eq!(
            system.foreground, initial_foreground,
            "unbound prompt must not trigger owner activation"
        );
        assert!(!system.trace.contains(&"activate"));
    }

    #[test]
    fn handoff_minimized_owner_never_restores_or_activates() {
        let (mut system, baseline, owner, broker) = handoff_fixture();
        let mut pending = test_pending(&mut system, baseline, owner, broker);
        system.windows[0].minimized = true;
        system.trace.clear();
        assert_eq!(
            prepare_continuation(&mut pending, owner.hwnd, &[vec![7, 8]], &mut system),
            Err(HandoffRefusal::Owner)
        );
        assert!(pending.is_none());
        assert!(!system.trace.contains(&"activate"));
        assert!(!system.trace.contains(&"restore"));
        assert!(system.windows[0].minimized);
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
                let accepted = Mutex::new(None);
                let mut policy = MonitorPolicy::default();
                assert!(policy.observe(
                    &mut self.system,
                    self.owner.hwnd,
                    Arc::clone(&self.baseline),
                    &AtomicBool::new(false),
                    &accepted
                ));
                let observation = BrokerObservation {
                    broker: accepted.lock().unwrap().take(),
                    passive_safe: policy.passive_safe,
                };
                self.system.foreground_sequence = [self.broker.hwnd, self.owner.hwnd].into();
                Ok((test_registration(), self.owner, observation))
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
                    terminal_gate: &MonitorTerminal::default(),
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
        let accepted_a: Arc<Mutex<Option<AcceptedBroker>>> = Arc::new(Mutex::new(None));
        let accepted_b: Arc<Mutex<Option<AcceptedBroker>>> = Arc::new(Mutex::new(None));
        let reason_a = Arc::new(Mutex::new(None));
        let reason_b = Arc::new(Mutex::new(None));
        assert!(!Arc::ptr_eq(&accepted_a, &accepted_b));
        assert!(!Arc::ptr_eq(&reason_a, &reason_b));
        let reason = Arc::clone(&reason_a);
        let a = WebAuthnForegroundMonitor {
            cancelled: Arc::new(AtomicBool::new(false)),
            api_returned: Arc::new(AtomicBool::new(false)),
            terminal_gate: Arc::new(MonitorTerminal::default()),
            armed: Arc::new(AtomicBool::new(true)),
            accepted: Arc::clone(&accepted_a),
            passive_safe: Arc::new(AtomicBool::new(false)),
            reason: Arc::clone(&reason_a),
            operation: Operation::MakeCredential,
            pid: 10,
            worker: Some(thread::spawn(move || {
                *reason.lock().unwrap() = Some(MonitorStop::ActivationFailed);
            })),
        };
        let reason = Arc::clone(&reason_b);
        let b = WebAuthnForegroundMonitor {
            cancelled: Arc::new(AtomicBool::new(false)),
            api_returned: Arc::new(AtomicBool::new(false)),
            terminal_gate: Arc::new(MonitorTerminal::default()),
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
        let outcome_a = a.finish_observation();
        let outcome_b = b.finish_observation();
        assert!(outcome_a.broker.is_none());
        assert!(outcome_b.broker.is_none());
        assert!(!outcome_a.passive_safe);
        assert!(!outcome_b.passive_safe);
        assert!(accepted_a.lock().unwrap().is_none());
        assert!(accepted_b.lock().unwrap().is_none());
        assert_eq!(
            *reason_a.lock().unwrap(),
            Some(MonitorStop::ActivationFailed)
        );
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
            assert_eq!(backend.ffi_calls, if refusal { 0 } else { 1 });
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
                let terminal_gate = Arc::new(MonitorTerminal::default());
                let (entered, waiting) = std::sync::mpsc::channel();
                system.worker_wait_entered = Some(entered);
                system.wait_until_stopped = Some(Arc::clone(&cancelled));
                let worker_cancelled = Arc::clone(&cancelled);
                let worker_returned = Arc::clone(&returned);
                let worker_terminal_gate = Arc::clone(&terminal_gate);
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
                            terminal_gate: &worker_terminal_gate,
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
                    terminal_gate,
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
            let terminal_gate = Arc::new(MonitorTerminal::default());
            let worker_cancelled = Arc::clone(&cancelled);
            let worker_returned = Arc::clone(&returned);
            let worker_terminal_gate = Arc::clone(&terminal_gate);
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
                        terminal_gate: &worker_terminal_gate,
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
                terminal_gate,
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
                    terminal_gate: &MonitorTerminal::default(),
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
            terminal_gate: Arc::new(MonitorTerminal::default()),
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
            assert_eq!(backend.ffi_calls, if activation_fails { 0 } else { 1 });
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
        assert_eq!(backend.ffi_calls, 1);
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
                }
            ));
        }
    }

    #[test]
    fn new_security_dialog_window_in_existing_trusted_broker_process_is_detected() {
        let candidate = WindowsSecurityDialogCandidate {
            title: "Windows 安全性",
            class_name: "Credential Dialog Xaml Host",
            process_path: r"C:\Windows\System32\CredentialUIBroker.exe",
            system_directory: r"C:\Windows\System32",
            visible: true,
            current_session: 2,
            window_session: 2,
            is_new_window: true,
        };
        let existing_broker_window = WindowIdentity {
            hwnd: 0x1203ce,
            process_id: 1492,
            thread_id: 2844,
            session: 2,
        };
        let newly_created_dialog = WindowIdentity {
            hwnd: 0xf03fc,
            process_id: existing_broker_window.process_id,
            thread_id: 9552,
            session: 2,
        };
        assert!(is_new_window_identity(
            newly_created_dialog,
            &HashSet::from([existing_broker_window]),
            &HashSet::new()
        ));
        assert!(is_new_windows_security_dialog(candidate));
    }

    #[test]
    fn broker_dialog_requires_new_window_identity() {
        let trusted = WindowsSecurityDialogCandidate {
            title: "Windows 安全性",
            class_name: "Credential Dialog Xaml Host",
            process_path: r"C:\Windows\System32\CredentialUIBroker.exe",
            system_directory: r"C:\Windows\System32",
            visible: true,
            current_session: 2,
            window_session: 2,
            is_new_window: true,
        };
        assert!(is_new_windows_security_dialog(trusted));
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
        assert!(!is_new_window_identity(existing, &baseline, &HashSet::new()));
        assert!(is_new_window_identity(
            WindowIdentity {
                hwnd: existing.hwnd,
                process_id: 2000,
                thread_id: 3000,
                session: 2,
            },
            &baseline,
            &HashSet::new(),
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
    fn api_below_v4_is_classified_as_webauthn_unavailable_not_generic_failure() {
        // The constructor calls FFI, so pin its guard outcome at source level (same style as the
        // webauthn_diagnostics wiring contracts): only the closed category may leave the guard.
        // Patterns are split with concat! so this test does not add extra matches for the
        // unique-locator source contracts in webauthn_diagnostics.
        let source = include_str!("windows_webauthn.rs").replace("\r\n", "\n");
        let start = source
            .find(concat!("pub fn ", "new(hwnd:"))
            .expect("constructor");
        let end = start
            + source[start..]
                .find(concat!("fn ", "hwnd("))
                .expect("constructor end");
        let constructor = &source[start..end];
        let guard = constructor
            .find(concat!("if !hmac_secret_api_", "supported(api_version) {"))
            .expect("API guard");
        let guard_end = constructor[guard..].find("\n        }").expect("guard end");
        let guard_body = &constructor[guard..guard + guard_end];
        assert!(
            guard_body.contains(concat!(
                "return Err(BackendInitError::",
                "WebAuthnApiBelowV4 { api_version });"
            )),
            "API < v4 must return WebAuthnApiBelowV4: {guard_body}"
        );
        assert!(
            !constructor.contains("NotSupported"),
            "constructor must not report API < v4 as a generic NotSupported error"
        );
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
