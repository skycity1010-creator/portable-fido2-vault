//! Allowlisted diagnostics. This module never accepts WebAuthn response bytes.
use crate::fido2::FidoError;
use serde_json::{json, Value};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum QueryStatus {
    Valid,
    NativeFailure,
    NullBuffer,
    InvalidLength,
    NotQueried,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SessionProtocol {
    Console,
    Legacy,
    Rdp,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SessionState {
    Active,
    Inactive,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct NativeSessionEvidence {
    pub(crate) protocol: SessionProtocol,
    pub(crate) state: SessionState,
    pub(crate) protocol_query: QueryStatus,
    pub(crate) state_query: QueryStatus,
}

impl NativeSessionEvidence {
    pub(crate) fn active_rdp(self) -> bool {
        self.protocol_query == QueryStatus::Valid
            && self.state_query == QueryStatus::Valid
            && self.protocol == SessionProtocol::Rdp
            && self.state == SessionState::Active
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MonitorStop {
    CancelledBeforeArm,
    Cancelled,
    ApiReturned,
    ApiReturnedBeforeArm,
    Deadline,
    Incomplete,
    Ambiguous,
    ForegroundLost,
    CandidateForeground,
    CandidateChanged,
    ActivationFailed,
    NonConsoleSession,
    WorkerFailed,
    ChannelFailed,
}

impl MonitorStop {
    fn label(self) -> &'static str {
        match self {
            Self::CancelledBeforeArm => "cancelled-before-arm",
            Self::Cancelled => "cancelled",
            Self::ApiReturned => "api-returned",
            Self::ApiReturnedBeforeArm => "api-returned-before-arm",
            Self::Deadline => "deadline",
            Self::Incomplete => "incomplete",
            Self::Ambiguous => "ambiguous",
            Self::ForegroundLost => "foreground-lost",
            Self::CandidateForeground => "candidate-foreground",
            Self::CandidateChanged => "candidate-changed",
            Self::ActivationFailed => "activation-failed",
            Self::NonConsoleSession => "non-console-session",
            Self::WorkerFailed => "worker-failed",
            Self::ChannelFailed => "channel-failed",
        }
    }
}

pub(crate) fn monitor_record(operation: Operation, pid: u32, reason: Option<MonitorStop>) -> Value {
    json!({"operation": operation.label(), "pid": pid, "stop_reason": reason.map(MonitorStop::label)})
}

#[derive(Default, Clone, Copy)]
pub(crate) struct WindowScalars {
    pub(crate) hwnd: Option<isize>,
    pub(crate) pid: Option<u32>,
    pub(crate) tid: Option<u32>,
    pub(crate) session: Option<u32>,
}

impl WindowScalars {
    fn record(self) -> Value {
        json!({"hwnd": self.hwnd.filter(|v| *v != 0), "pid": self.pid.filter(|v| *v != 0),
            "tid": self.tid.filter(|v| *v != 0), "session": self.session})
    }
}

#[derive(Clone, Copy)]
pub(crate) enum ContinuationStatus {
    Ordinary,
    OwnerForeground,
    Recovered,
    PassiveReturn,
    Credential,
    Owner,
    UnobservedBroker,
    Foreground,
    Broker,
    Session,
    Deadline,
}

impl ContinuationStatus {
    fn label(self) -> &'static str {
        match self {
            Self::Ordinary => "ordinary",
            Self::OwnerForeground => "owner-foreground",
            Self::Recovered => "broker-recovered",
            Self::PassiveReturn => "passive-return",
            Self::Credential => "credential-refused",
            Self::Owner => "owner-refused",
            Self::UnobservedBroker => "unobserved-broker",
            Self::Foreground => "foreground-refused",
            Self::Broker => "broker-refused",
            Self::Session => "session-refused",
            Self::Deadline => "deadline",
        }
    }
}

#[derive(Default)]
pub(crate) struct ContinuationDiagnostics {
    pub(crate) owner: WindowScalars,
    pub(crate) foreground: WindowScalars,
    pub(crate) owner_visible: Option<bool>,
    pub(crate) owner_minimized: Option<bool>,
    pub(crate) identity_match: Option<bool>,
    pub(crate) native: Option<NativeSessionEvidence>,
    pub(crate) elapsed_ms: u64,
    pub(crate) status: Option<ContinuationStatus>,
}

impl ContinuationDiagnostics {
    pub(crate) fn record(&self, pid: u32) -> Value {
        let query_label = |query| match query {
            QueryStatus::Valid => "valid",
            QueryStatus::NativeFailure => "native-failure",
            QueryStatus::NullBuffer => "null-buffer",
            QueryStatus::InvalidLength => "invalid-length",
            QueryStatus::NotQueried => "not-queried",
        };
        json!({
            "operation": Operation::GetAssertion.label(), "pid": pid,
            "owner": self.owner.record(), "foreground": self.foreground.record(),
            "owner_visible": self.owner_visible, "owner_minimized": self.owner_minimized,
            "identity_match": self.identity_match,
            "native_protocol": self.native.map(|v| match v.protocol {
                SessionProtocol::Console => "console", SessionProtocol::Legacy => "legacy",
                SessionProtocol::Rdp => "rdp", SessionProtocol::Unknown => "unknown"}),
            "native_state": self.native.map(|v| match v.state {
                SessionState::Active => "active", SessionState::Inactive => "inactive",
                SessionState::Unknown => "unknown"}),
            "protocol_query": self.native.map(|v| query_label(v.protocol_query)),
            "state_query": self.native.map(|v| query_label(v.state_query)),
            "elapsed_ms": self.elapsed_ms, "outcome": self.status.map(ContinuationStatus::label),
        })
    }
}

pub(crate) fn capability_record(
    api_version: Option<u32>,
    process_id: Option<u32>,
    session_id: Option<u32>,
) -> Value {
    json!({
        "api_version": api_version,
        "hmac_secret_api_supported": api_version.map(|api| api >= 4),
        "pid": process_id.filter(|pid| *pid != 0),
        "session_id": session_id,
        "session_kind": if session_id == Some(0) { "noninteractive" } else { "unknown" },
        "measured_in": "gui-process",
    })
}

fn error_category(error: &FidoError) -> &'static str {
    match error {
        FidoError::NoDevice => "no-device",
        FidoError::PinRequired(_) => "pin-required",
        FidoError::PinRejected => "pin-rejected",
        FidoError::PrfNotSupported => "prf-unsupported",
        FidoError::PrfNotConfirmed => "hmac-creation-unconfirmed",
        FidoError::CredentialExcluded => "credential-excluded",
        FidoError::NotSupported(_) => "capability-unsupported",
        FidoError::Internal(_) => "internal",
        FidoError::DeviceOpenDenied { .. } => "device-open-denied",
    }
}

// Closed enums prevent an operation name or failure stage carrying arbitrary text.
#[derive(Clone, Copy)]
pub(crate) enum Operation {
    MakeCredential,
    GetAssertion,
}

impl Operation {
    fn label(self) -> &'static str {
        match self {
            Self::MakeCredential => "MakeCredential",
            Self::GetAssertion => "GetAssertion",
        }
    }
}

#[derive(Clone, Copy)]
pub(crate) enum FailureStage {
    Preflight,
    Api,
    Response,
}

pub(crate) struct OperationDiagnostics {
    operation: Operation,
    pub(crate) hmac_creation_confirmed: Option<bool>,
    pub(crate) output_present: Option<bool>,
    pub(crate) output_length: Option<u32>,
    pub(crate) credential_match: Option<bool>,
    pub(crate) failure_stage: Option<FailureStage>,
}

impl OperationDiagnostics {
    pub(crate) fn new(operation: Operation) -> Self {
        Self {
            operation,
            hmac_creation_confirmed: None,
            output_present: None,
            output_length: None,
            credential_match: None,
            failure_stage: None,
        }
    }

    fn failure_category(&self, error: &FidoError) -> &'static str {
        // Describe observations only; never parse or serialize the error's message.
        if matches!(error, FidoError::Internal(_)) {
            if self.credential_match == Some(false) {
                return "credential-mismatch";
            }
            if self
                .output_length
                .is_some_and(|length| length != 32 || self.output_present != Some(true))
            {
                return "invalid-output";
            }
            if self.output_present == Some(false) {
                return "unsupported-output";
            }
            if let Some(stage) = self.failure_stage {
                return match stage {
                    FailureStage::Preflight => "preflight",
                    FailureStage::Api => "api-error",
                    FailureStage::Response => "invalid-response",
                };
            }
        }
        error_category(error)
    }

    pub(crate) fn record(&self, error: Option<&FidoError>) -> Value {
        let operation = match self.operation {
            Operation::MakeCredential => "MakeCredential",
            Operation::GetAssertion => "GetAssertion",
        };
        json!({
            "operation": operation,
            "error_category": error.map(|error| self.failure_category(error)),
            "hmac_creation_confirmed": self.hmac_creation_confirmed,
            "output_present": self.output_present,
            "output_length": self.output_length,
            "credential_match": self.credential_match,
        })
    }
}

// Emit after run returns, including every error/early return. No secret enters emit.
pub(crate) fn diagnose<T>(
    operation: Operation,
    run: impl FnOnce(&mut OperationDiagnostics) -> Result<T, FidoError>,
    emit: impl FnOnce(Value),
) -> Result<T, FidoError> {
    let mut diagnostic = OperationDiagnostics::new(operation);
    let result = run(&mut diagnostic);
    emit(diagnostic.record(result.as_ref().err()));
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn continuation_serializer_exact_null_allowlist() {
        let record = ContinuationDiagnostics::default().record(10);
        assert_eq!(
            record,
            json!({
                "operation": "GetAssertion", "pid": 10,
                "owner": {"hwnd": null, "pid": null, "tid": null, "session": null},
                "foreground": {"hwnd": null, "pid": null, "tid": null, "session": null},
                "owner_visible": null, "owner_minimized": null, "identity_match": null,
                "native_protocol": null, "native_state": null, "protocol_query": null,
                "state_query": null, "elapsed_ms": 0, "outcome": null,
            })
        );
        let zero = WindowScalars {
            hwnd: Some(0),
            pid: Some(0),
            tid: Some(0),
            session: Some(0),
        };
        assert_eq!(
            zero.record(),
            json!({"hwnd": null, "pid": null, "tid": null, "session": 0})
        );
    }

    #[test]
    fn continuation_serializer_closed_enums_and_scalars_only() {
        let scalars = WindowScalars {
            hwnd: Some(1),
            pid: Some(10),
            tid: Some(11),
            session: Some(2),
        };
        for (protocol, label) in [
            (SessionProtocol::Console, "console"),
            (SessionProtocol::Legacy, "legacy"),
            (SessionProtocol::Rdp, "rdp"),
            (SessionProtocol::Unknown, "unknown"),
        ] {
            for (state, state_label) in [
                (SessionState::Active, "active"),
                (SessionState::Inactive, "inactive"),
                (SessionState::Unknown, "unknown"),
            ] {
                for (query, query_label) in [
                    (QueryStatus::Valid, "valid"),
                    (QueryStatus::NativeFailure, "native-failure"),
                    (QueryStatus::NullBuffer, "null-buffer"),
                    (QueryStatus::InvalidLength, "invalid-length"),
                    (QueryStatus::NotQueried, "not-queried"),
                ] {
                    let native = NativeSessionEvidence {
                        protocol,
                        state,
                        protocol_query: query,
                        state_query: query,
                    };
                    let diagnostic = ContinuationDiagnostics {
                        owner: scalars,
                        foreground: scalars,
                        owner_visible: Some(true),
                        owner_minimized: Some(false),
                        identity_match: Some(true),
                        native: Some(native),
                        elapsed_ms: 999,
                        status: Some(ContinuationStatus::PassiveReturn),
                    };
                    assert_eq!(
                        diagnostic.record(10),
                        json!({
                            "operation":"GetAssertion", "pid":10,
                            "owner":{"hwnd":1,"pid":10,"tid":11,"session":2},
                            "foreground":{"hwnd":1,"pid":10,"tid":11,"session":2},
                            "owner_visible":true,"owner_minimized":false,"identity_match":true,
                            "native_protocol":label,"native_state":state_label,
                            "protocol_query":query_label,"state_query":query_label,
                            "elapsed_ms":999,"outcome":"passive-return",
                        })
                    );
                    assert_eq!(
                        native.active_rdp(),
                        protocol == SessionProtocol::Rdp
                            && state == SessionState::Active
                            && query == QueryStatus::Valid
                    );
                }
            }
        }
    }

    #[test]
    fn monitor_serializer_exact_operation_pid_and_closed_reason() {
        for (reason, label) in [
            (MonitorStop::CancelledBeforeArm, "cancelled-before-arm"),
            (MonitorStop::Cancelled, "cancelled"),
            (MonitorStop::ApiReturned, "api-returned"),
            (MonitorStop::ApiReturnedBeforeArm, "api-returned-before-arm"),
            (MonitorStop::Deadline, "deadline"),
            (MonitorStop::Incomplete, "incomplete"),
            (MonitorStop::Ambiguous, "ambiguous"),
            (MonitorStop::ForegroundLost, "foreground-lost"),
            (MonitorStop::CandidateForeground, "candidate-foreground"),
            (MonitorStop::CandidateChanged, "candidate-changed"),
            (MonitorStop::ActivationFailed, "activation-failed"),
            (MonitorStop::NonConsoleSession, "non-console-session"),
            (MonitorStop::WorkerFailed, "worker-failed"),
            (MonitorStop::ChannelFailed, "channel-failed"),
        ] {
            assert_eq!(
                monitor_record(Operation::MakeCredential, 10, Some(reason)),
                json!({"operation":"MakeCredential","pid":10,"stop_reason":label})
            );
        }
        assert_eq!(
            monitor_record(Operation::GetAssertion, 20, None),
            json!({"operation":"GetAssertion","pid":20,"stop_reason":null})
        );
    }

    fn contract(condition: bool, tag: &str) {
        assert!(condition, "CONTRACT:{tag}");
    }

    fn contract_position(source: &str, pattern: &str, tag: &str) -> usize {
        contract(source.contains(pattern), tag);
        source
            .find(pattern)
            .expect("LOCATOR:position-after-contract")
    }

    fn assert_passive_contract(source: &str) {
        let source = source.replace("\r\n", "\n");
        let passive = contract_section(&source, "fn passive_owner_return(", "fn session_evidence(");
        for forbidden in [
            ".activate(",
            ".restore(",
            "SetForegroundWindow",
            "ShowWindow",
            "AttachThreadInput",
            "ASFW_ANY",
        ] {
            contract(!passive.contains(forbidden), "PASSIVE_NO_ACTIVATION");
        }
        let eligibility = contract_position(
            passive,
            "passive_eligibility(system, owner, deadline, diagnostic)?;",
            "PASSIVE_ELIGIBILITY",
        );
        let wait = contract_position(passive, "system.wait(poll);", "PASSIVE_WAIT");
        contract(eligibility < wait, "PASSIVE_ELIGIBILITY_ORDER");
        contract(passive.contains("if foreground != 0"), "PASSIVE_NULL_ONLY");
        contract(
            passive.contains("Duration::from_millis(1000)"),
            "PASSIVE_DEADLINE",
        );
        contract(
            passive.contains("Duration::from_millis(20)"),
            "PASSIVE_POLL",
        );
        let continuation = contract_section(
            &source,
            "fn prepare_continuation_inner(",
            "fn passive_owner_return(",
        );
        contract(
            continuation.contains("if foreground != 0 || !context.passive_safe"),
            "CONTINUATION_NULL_ONLY",
        );
        contract(
            continuation.contains("initial_foreground != Some(0)"),
            "INITIAL_NULL_REQUIRED",
        );
        let initial = contract_position(
            continuation,
            "let initial_foreground =",
            "INITIAL_SAMPLE_PRESENT",
        );
        let owner_query = contract_position(
            continuation,
            "valid_owner_recorded(system, context.owner",
            "INITIAL_OWNER_QUERY",
        );
        contract(initial < owner_query, "INITIAL_SAMPLE_ORDER");
        let native_query =
            contract_section(&source, "fn query_native_session(", "fn session_evidence(");
        let gate = contract_position(
            native_query,
            "protocol == Ok(2) && now() < deadline",
            "NATIVE_PROTOCOL_DEADLINE",
        );
        let protocol = contract_position(
            native_query,
            "query_protocol(session)",
            "NATIVE_PROTOCOL_QUERY",
        );
        let state = contract_position(native_query, "query_state(session)", "NATIVE_STATE_QUERY");
        contract(protocol < gate && gate < state, "NATIVE_QUERY_ORDER");
        let allocation = contract_section(&source, "fn query_wts<T: Copy>(", "fn valid_owner(");
        let allocated = contract_position(
            allocation,
            "let allocation = WtsAllocation(buffer);",
            "WTS_ALLOCATION",
        );
        let parsed = contract_position(allocation, "parse_wts(", "WTS_PARSE");
        contract(allocated < parsed, "WTS_CLEANUP_ORDER");
        let cleanup = contract_section(
            &source,
            "impl Drop for WtsAllocation",
            "fn query_wts<T: Copy>(",
        );
        contract(
            cleanup.contains("WTSFreeMemory(self.0.cast());"),
            "WTS_FREEBUFFER",
        );
        let wrapper = contract_section(
            &source,
            "fn prepare_continuation_recorded(",
            "fn prepare_assertion_continuation(",
        );
        let clock = contract_position(wrapper, "let started = system.monotonic();", "CLOCK_SOURCE");
        let inner = contract_position(wrapper, "prepare_continuation_inner(", "CLOCK_INNER");
        contract(clock < inner, "CLOCK_ORDER");
        assert_creation_owner_and_native_return_wiring(&source);
        assert_backend_wiring(&source);
    }

    fn assert_creation_owner_and_native_return_wiring(source: &str) {
        let preparation = contract_section(
            source,
            "fn prepare_assertion_continuation(",
            "fn assertion_owner_baseline(",
        );
        let captured = contract_position(
            preparation,
            "let creation_owner = pending.as_ref().map(|context| context.owner);",
            "CREATION_OWNER_CAPTURE",
        );
        let consumed = contract_position(
            preparation,
            "prepare_continuation_recorded(",
            "CREATION_OWNER_PREPARATION",
        );
        contract(captured < consumed, "CREATION_OWNER_CAPTURE_ORDER");
        contract(
            preparation.contains(".map(|outcome| (outcome, creation_owner))"),
            "CREATION_OWNER_SUCCESS_CHANNEL",
        );
        let selection = contract_section(
            source,
            "fn assertion_owner_baseline(",
            "fn identity_scalars(",
        );
        contract(
            selection.contains("if let Some(expected) = creation_owner"),
            "CREATION_OWNER_SELECTION",
        );
        contract(
            selection.contains("expected.hwnd != hwnd || expected.session == 0"),
            "CREATION_OWNER_NONZERO_SESSION",
        );
        contract(
            selection.contains("return checked_owner_snapshot(system, expected);"),
            "CREATION_OWNER_GUARD",
        );
        let assertion = contract_section(
            source,
            "fn get_hmac_secret_for_any_with_diagnostics(",
            "impl FidoBackend for WindowsWebAuthnBackend",
        );
        contract(
            assertion.contains("let preparation = prepare_assertion_continuation("),
            "CREATION_OWNER_WRAPPER_PREPARATION",
        );
        contract(
            assertion.contains("Ok((outcome, creation_owner))"),
            "CREATION_OWNER_WRAPPER_CHANNEL",
        );
        contract(
            assertion.contains("assertion_owner_baseline(&mut system, self.hwnd, creation_owner)?"),
            "CREATION_OWNER_WRAPPER_SELECTION",
        );
        contract(
            assertion.contains("self.foreground_owner_hwnd(owner_identity)?"),
            "CREATION_OWNER_FINAL_GUARD",
        );
        for (start, end, ffi) in [
            (
                "fn make_credential_with_diagnostics(",
                "fn get_hmac_secret(",
                "WebAuthNAuthenticatorMakeCredential(",
            ),
            (
                "fn get_hmac_secret_for_any_with_diagnostics(",
                "impl FidoBackend for WindowsWebAuthnBackend",
                "WebAuthNAuthenticatorGetAssertion(",
            ),
        ] {
            let wrapper = contract_section(source, start, end);
            let after = wrapper.split_once(ffi).expect("LOCATOR:native-wrapper").1;
            let shutdown = after
                .split_once("log::info!(")
                .expect("LOCATOR:native-return-log")
                .0;
            contract(
                shutdown.contains(".map(WebAuthnForegroundMonitor::finish_observation)"),
                "NATIVE_RETURN_SHUTDOWN",
            );
            contract(
                !shutdown.contains("drop(focus_monitor)"),
                "NATIVE_RETURN_NO_DROP",
            );
        }
    }

    fn assert_cycle2_owner_contract(source: &str) {
        let source = source.replace("\r\n", "\n");
        let guard = contract_section(&source, "fn checked_owner_snapshot(", "fn current_broker(");
        let metadata = contract_position(
            guard,
            "let current = checked_owner(system, expected.hwnd)?;",
            "S1_METADATA_GUARD",
        );
        contract(
            guard.contains("if current != expected"),
            "S1_CREATION_BOUND_COMPARISON",
        );
        let visible =
            contract_position(guard, "!system.visible(expected.hwnd)", "S1_FINAL_VISIBLE");
        let minimized = contract_position(
            guard,
            "system.minimized(expected.hwnd)",
            "S1_FINAL_NOT_MINIMIZED",
        );
        let ids = contract_position(
            guard,
            "system.owner_ids(expected.hwnd) != Some((expected.process_id, expected.thread_id))",
            "S1_LIGHTWEIGHT_IDENTITY",
        );
        contract(
            metadata < visible && visible < minimized && minimized < ids,
            "S1_METADATA_THEN_LIGHTWEIGHT",
        );
        for forbidden in [
            "system.identity(",
            "system.session(",
            "checked_owner(",
            "process_session(",
        ] {
            contract(!guard[ids..].contains(forbidden), "S1_FINAL_NO_METADATA");
        }
        let native = contract_section(
            &source,
            "impl ForegroundSystem for NativeForegroundSystem",
            "fn observe_broker(",
        );
        let native_ids = contract_section(native, "fn owner_ids(", "fn windows(");
        contract(
            native_ids.contains("hwnd == 0 || unsafe { IsWindow(hwnd as HWND) } == 0"),
            "S1_NATIVE_VALID_WINDOW",
        );
        contract(
            native_ids.contains("GetWindowThreadProcessId(hwnd as HWND, &mut process_id)"),
            "S1_NATIVE_THREAD_PROCESS_QUERY",
        );
        contract(
            native_ids
                .contains("(process_id != 0 && thread_id != 0).then_some((process_id, thread_id))"),
            "S1_NATIVE_NONZERO_IDS",
        );
        for forbidden in [
            "session(",
            "identity(",
            "path(",
            "title(",
            "class(",
            "wait(",
            "log::",
        ] {
            contract(
                !native_ids.contains(forbidden),
                "S1_NATIVE_LIGHTWEIGHT_ONLY",
            );
        }
        let final_owner =
            contract_section(&source, "fn foreground_owner_hwnd(", "fn make_credential(");
        let checked = contract_position(
            final_owner,
            "checked_owner_snapshot(&mut NativeForegroundSystem, owner_identity)?;",
            "S1_PRODUCTION_GUARD",
        );
        let sample = contract_position(
            final_owner,
            "let foreground = unsafe { GetForegroundWindow() };",
            "S1_PRODUCTION_SAMPLE",
        );
        contract(checked < sample, "S1_PRODUCTION_GUARD_ORDER");
        assert_backend_wiring(&source);
    }

    fn assert_cycle2_diagnostic_contract(source: &str) {
        let source = source.replace("\r\n", "\n");
        let serializer = contract_section(
            &source,
            "fn diagnostic_foreground(",
            "fn valid_owner_recorded(",
        );
        contract(
            serializer.contains("observed_owner: Option<WindowScalars>"),
            "D1_OBSERVED_OPTION_ONLY",
        );
        contract(
            serializer.contains(".filter(|observed| observed.hwnd == Some(hwnd))"),
            "D1_MATCHED_OBSERVATION",
        );
        contract(
            serializer.contains(".unwrap_or_else(|| identity_scalars(None, hwnd))"),
            "D1_UNKNOWN_IDENTITY_NULL",
        );
        for forbidden in ["system.", "context.owner", "WindowIdentity", "log::"] {
            contract(
                !serializer.contains(forbidden),
                "D1_NO_METADATA_OR_SAVED_IDENTITY",
            );
        }
        let continuation = contract_section(
            &source,
            "fn prepare_continuation_inner(",
            "fn passive_owner_return(",
        );
        let initial = contract_position(
            continuation,
            "diagnostic_foreground(diagnostic, foreground, None);",
            "D1_INITIAL_HWND_ONLY",
        );
        let verified = contract_position(
            continuation,
            "if !valid_owner_recorded(system, context.owner, diagnostic)",
            "D1_CURRENT_OWNER_VALIDATION",
        );
        let observed = contract_position(
            continuation,
            "let observed_owner = diagnostic.owner;",
            "D1_CURRENT_OBSERVATION",
        );
        contract(
            initial < verified && verified < observed,
            "D1_OBSERVATION_AFTER_VALIDATION",
        );
        contract(
            continuation
                .contains("diagnostic_foreground(diagnostic, foreground, Some(observed_owner));"),
            "D1_VERIFIED_FOREGROUND_FIELDS",
        );
        let validation = contract_section(
            &source,
            "fn valid_owner_recorded(",
            "fn prepare_continuation_inner(",
        );
        let metadata = contract_position(
            validation,
            "let final_identity = system.identity(owner.hwnd);",
            "D1_FINAL_IDENTITY_METADATA",
        );
        let ids = contract_position(
            validation,
            "system.owner_ids(owner.hwnd) == Some((owner.process_id, owner.thread_id))",
            "D1_LIGHTWEIGHT_OBSERVATION",
        );
        contract(metadata < ids, "D1_METADATA_BEFORE_OBSERVATION");
        contract(
            validation.contains("&& session == Some(owner.session)\n        && system.owner_ids"),
            "D1_MATCHING_SESSION",
        );
        for forbidden in ["system.identity(", "system.session("] {
            contract(
                !validation[ids..].contains(forbidden),
                "D1_NO_METADATA_AFTER_OBSERVATION",
            );
        }
        let passive = contract_section(
            &source,
            "fn passive_owner_return(",
            "fn passive_eligibility(",
        );
        contract(
            passive.contains("let observed_owner = diagnostic.owner;"),
            "D1_PASSIVE_CURRENT_OBSERVATION",
        );
        contract(
            passive
                .contains("diagnostic_foreground(diagnostic, foreground, Some(observed_owner));"),
            "D1_PASSIVE_VERIFIED_FIELDS",
        );
        assert_backend_wiring(&source);
    }

    #[test]
    fn fix_s1_source_wiring_and_exact_mutations() {
        let source = include_str!("windows_webauthn.rs").replace("\r\n", "\n");
        for original in [source.clone(), source.replace('\n', "\r\n")] {
            assert_cycle2_owner_contract(&original);
        }
        for (start, end, from, to, tag) in [
            ("fn checked_owner_snapshot(", "fn current_broker(", "if current != expected", "if current.hwnd != expected.hwnd", "S1_CREATION_BOUND_COMPARISON"),
            ("fn checked_owner_snapshot(", "fn current_broker(", "!system.visible(expected.hwnd)", "false", "S1_FINAL_VISIBLE"),
            ("fn checked_owner_snapshot(", "fn current_broker(", "system.minimized(expected.hwnd)", "false", "S1_FINAL_NOT_MINIMIZED"),
            ("fn checked_owner_snapshot(", "fn current_broker(", "Some((expected.process_id, expected.thread_id))", "Some((expected.process_id, expected.process_id))", "S1_LIGHTWEIGHT_IDENTITY"),
            ("fn checked_owner_snapshot(", "fn current_broker(", "Ok(current)", "system.session(expected.process_id); Ok(current)", "S1_FINAL_NO_METADATA"),
            ("impl ForegroundSystem for NativeForegroundSystem", "fn observe_broker(", "GetWindowThreadProcessId(hwnd as HWND, &mut process_id)", "removed_thread_process_query(hwnd)", "S1_NATIVE_THREAD_PROCESS_QUERY"),
            ("impl ForegroundSystem for NativeForegroundSystem", "fn observe_broker(", "(process_id != 0 && thread_id != 0).then_some((process_id, thread_id))", "Some((process_id, thread_id))", "S1_NATIVE_NONZERO_IDS"),
            ("impl ForegroundSystem for NativeForegroundSystem", "fn observe_broker(", "(process_id != 0 && thread_id != 0).then_some((process_id, thread_id))", "self.session(process_id); (process_id != 0 && thread_id != 0).then_some((process_id, thread_id))", "S1_NATIVE_LIGHTWEIGHT_ONLY"),
            ("fn foreground_owner_hwnd(", "fn make_credential(", "checked_owner_snapshot(&mut NativeForegroundSystem, owner_identity)?;", "checked_owner(&mut NativeForegroundSystem, owner_identity.hwnd)?;", "S1_PRODUCTION_GUARD"),
        ] {
            let mutant = mutate_unique(&source, start, end, from, to);
            for (ending, fixture) in [("LF", mutant.clone()), ("CRLF", mutant.replace('\n', "\r\n"))] {
                let observed = panic_tag(std::panic::catch_unwind(|| assert_cycle2_owner_contract(&fixture)));
                assert_eq!(observed, format!("CONTRACT:{tag}"));
                eprintln!("MUTATION_VALIDATED {ending} {tag}");
            }
        }
    }

    #[test]
    fn fix_d1_source_wiring_and_exact_mutations() {
        let source = include_str!("windows_webauthn.rs").replace("\r\n", "\n");
        for original in [source.clone(), source.replace('\n', "\r\n")] {
            assert_cycle2_diagnostic_contract(&original);
        }
        for (start, end, from, to, tag) in [
            (
                "fn diagnostic_foreground(",
                "fn valid_owner_recorded(",
                "observed_owner: Option<WindowScalars>",
                "observed_owner: WindowIdentity",
                "D1_OBSERVED_OPTION_ONLY",
            ),
            (
                "fn diagnostic_foreground(",
                "fn valid_owner_recorded(",
                ".filter(|observed| observed.hwnd == Some(hwnd))",
                ".filter(|_| true)",
                "D1_MATCHED_OBSERVATION",
            ),
            (
                "fn diagnostic_foreground(",
                "fn valid_owner_recorded(",
                "identity_scalars(None, hwnd)",
                "identity_scalars(Some(owner), hwnd)",
                "D1_UNKNOWN_IDENTITY_NULL",
            ),
            (
                "fn prepare_continuation_inner(",
                "fn passive_owner_return(",
                "diagnostic_foreground(diagnostic, foreground, None);",
                "diagnostic_foreground(diagnostic, foreground, Some(diagnostic.owner));",
                "D1_INITIAL_HWND_ONLY",
            ),
            (
                "fn prepare_continuation_inner(",
                "fn passive_owner_return(",
                "let observed_owner = diagnostic.owner;",
                "let observed_owner = identity_scalars(Some(context.owner), owner);",
                "D1_CURRENT_OBSERVATION",
            ),
            (
                "fn valid_owner_recorded(",
                "fn prepare_continuation_inner(",
                "system.owner_ids(owner.hwnd) == Some((owner.process_id, owner.thread_id))",
                "true",
                "D1_LIGHTWEIGHT_OBSERVATION",
            ),
            (
                "fn valid_owner_recorded(",
                "fn prepare_continuation_inner(",
                "&& session == Some(owner.session)\n        && system.owner_ids",
                "&& session.is_some()\n        && system.owner_ids",
                "D1_MATCHING_SESSION",
            ),
            (
                "fn passive_owner_return(",
                "fn passive_eligibility(",
                "let observed_owner = diagnostic.owner;",
                "let observed_owner = identity_scalars(Some(owner), owner.hwnd);",
                "D1_PASSIVE_CURRENT_OBSERVATION",
            ),
        ] {
            let mutant = mutate_unique(&source, start, end, from, to);
            for (ending, fixture) in [
                ("LF", mutant.clone()),
                ("CRLF", mutant.replace('\n', "\r\n")),
            ] {
                let observed = panic_tag(std::panic::catch_unwind(|| {
                    assert_cycle2_diagnostic_contract(&fixture)
                }));
                assert_eq!(observed, format!("CONTRACT:{tag}"));
                eprintln!("MUTATION_VALIDATED {ending} {tag}");
            }
        }
    }

    fn panic_tag(result: std::thread::Result<()>) -> String {
        let error = result.expect_err("negative mutation must fail a contract");
        if let Some(text) = error.downcast_ref::<String>() {
            text.clone()
        } else if let Some(text) = error.downcast_ref::<&str>() {
            (*text).to_owned()
        } else {
            panic!("LOCATOR:non-text-panic");
        }
    }

    fn contract_section<'a>(source: &'a str, start: &str, end: &str) -> &'a str {
        assert_eq!(source.matches(start).count(), 1, "LOCATOR:section-start");
        let section = source.split_once(start).expect("LOCATOR:section-start").1;
        assert_eq!(section.matches(end).count(), 1, "LOCATOR:section-end");
        section.split_once(end).expect("LOCATOR:section-end").0
    }

    fn mutate_unique(source: &str, start: &str, end: &str, from: &str, to: &str) -> String {
        assert_ne!(from, to, "LOCATOR:unchanged-mutation");
        let section = contract_section(source, start, end);
        assert_eq!(
            section.matches(from).count(),
            1,
            "LOCATOR:mutation-location"
        );
        let changed = section.replacen(from, to, 1);
        assert_eq!(changed.matches(to).count(), 1, "LOCATOR:changed-location");
        let prefix_len = source.find(start).expect("LOCATOR:mutation-prefix") + start.len();
        format!(
            "{}{}{}",
            &source[..prefix_len],
            changed,
            &source[prefix_len + section.len()..]
        )
    }

    #[test]
    fn passive_source_wiring_and_negative_mutation_oracle() {
        let source = include_str!("windows_webauthn.rs").replace("\r\n", "\n");
        let check = assert_passive_contract;
        for original in [source.clone(), source.replace('\n', "\r\n")] {
            check(&original);
        }
        let mutations = [
            ("fn prepare_continuation_recorded(", "fn prepare_assertion_continuation(", "let started = system.monotonic();", "let started = Instant::now();", "CLOCK_SOURCE"),
            ("fn passive_owner_return(", "fn passive_eligibility(", "system.wait(poll);", "system.activate(owner.hwnd);", "PASSIVE_NO_ACTIVATION"),
            ("fn passive_owner_return(", "fn passive_eligibility(", "system.wait(poll);", "system.restore(owner.hwnd);", "PASSIVE_NO_ACTIVATION"),
            ("fn passive_owner_return(", "fn passive_eligibility(", "if foreground != 0", "if foreground == -1", "PASSIVE_NULL_ONLY"),
            ("fn passive_owner_return(", "fn passive_eligibility(", "Duration::from_millis(1000)", "Duration::from_millis(1001)", "PASSIVE_DEADLINE"),
            ("fn passive_owner_return(", "fn passive_eligibility(", "Duration::from_millis(20)", "Duration::from_millis(19)", "PASSIVE_POLL"),
            ("fn prepare_continuation_inner(", "fn passive_owner_return(", "if foreground != 0 || !context.passive_safe", "if foreground == -1 || !context.passive_safe", "CONTINUATION_NULL_ONLY"),
            ("fn prepare_continuation_inner(", "fn passive_owner_return(", "initial_foreground != Some(0)", "initial_foreground == Some(0)", "INITIAL_NULL_REQUIRED"),
            ("fn prepare_continuation_inner(", "fn passive_owner_return(", "let initial_foreground =", "let removed_initial_foreground =", "INITIAL_SAMPLE_PRESENT"),
            ("fn prepare_continuation_inner(", "fn passive_owner_return(", "let initial_foreground =", "valid_owner_recorded(system, context.owner, diagnostic); let initial_foreground =", "INITIAL_SAMPLE_ORDER"),
            ("fn prepare_continuation_recorded(", "fn prepare_assertion_continuation(", "let started = system.monotonic();", "prepare_continuation_inner(pending, owner, credential_ids, system, started, diagnostic); let started = system.monotonic();", "CLOCK_ORDER"),
            ("fn query_native_session(", "fn session_evidence(", "protocol == Ok(2) && now() < deadline", "now() < deadline", "NATIVE_PROTOCOL_DEADLINE"),
            ("fn query_native_session(", "fn session_evidence(", "let protocol = query_protocol(session);", "query_state(session); let protocol = query_protocol(session);", "NATIVE_QUERY_ORDER"),
            ("fn query_wts<T: Copy>(", "fn valid_owner(", "let allocation = WtsAllocation(buffer);", "let allocation = removed_allocation(buffer);", "WTS_ALLOCATION"),
            ("impl Drop for WtsAllocation", "fn query_wts<T: Copy>(", "WTSFreeMemory(self.0.cast());", "removed_cleanup();", "WTS_FREEBUFFER"),
            ("fn query_wts<T: Copy>(", "fn valid_owner(", "let allocation = WtsAllocation(buffer);", "parse_wts(success, buffer, bytes); let allocation = WtsAllocation(buffer);", "WTS_CLEANUP_ORDER"),
        ];
        for (start, end, from, to, tag) in mutations {
            let mutant = mutate_unique(&source, start, end, from, to);
            for (ending, fixture) in [
                ("LF", mutant.clone()),
                ("CRLF", mutant.replace('\n', "\r\n")),
            ] {
                let observed = panic_tag(std::panic::catch_unwind(|| check(&fixture)));
                assert_eq!(observed, format!("CONTRACT:{tag}"), "mutation must fail its intended contract, never a parser/locator or unrelated assertion");
                eprintln!("MUTATION_VALIDATED {ending} {tag}");
            }
        }
    }

    #[test]
    fn fix_r3_locators_fail_separately_from_contracts() {
        let source = include_str!("windows_webauthn.rs").replace("\r\n", "\n");
        let missing_section = source.replacen(
            "fn passive_owner_return(",
            "fn missing_passive_owner_return(",
            1,
        );
        for fixture in [
            missing_section.clone(),
            missing_section.replace('\n', "\r\n"),
        ] {
            let observed = panic_tag(std::panic::catch_unwind(|| {
                assert_passive_contract(&fixture)
            }));
            assert!(observed.contains("LOCATOR:section-start"));
            assert!(!observed.starts_with("CONTRACT:"));
        }
        let observed = panic_tag(std::panic::catch_unwind(|| {
            let _ = mutate_unique(
                &source,
                "fn query_native_session(",
                "fn session_evidence(",
                "missing unique location",
                "changed",
            );
        }));
        assert!(observed.contains("LOCATOR:mutation-location"));
    }

    #[test]
    fn fix_r3_owner_and_return_wiring_mutations_have_exact_tags() {
        let source = include_str!("windows_webauthn.rs").replace("\r\n", "\n");
        for original in [source.clone(), source.replace('\n', "\r\n")] {
            assert_passive_contract(&original);
        }
        for (start, end, from, to, tag) in [
            (
                "fn prepare_assertion_continuation(",
                "fn assertion_owner_baseline(",
                ".map(|outcome| (outcome, creation_owner))",
                ".map(|outcome| (outcome, None))",
                "CREATION_OWNER_SUCCESS_CHANNEL",
            ),
            (
                "fn assertion_owner_baseline(",
                "fn identity_scalars(",
                "return checked_owner_snapshot(system, expected);",
                "return checked_owner(system, hwnd);",
                "CREATION_OWNER_GUARD",
            ),
            (
                "fn get_hmac_secret_for_any_with_diagnostics(",
                "impl FidoBackend for WindowsWebAuthnBackend",
                "assertion_owner_baseline(&mut system, self.hwnd, creation_owner)?",
                "assertion_owner_baseline(&mut system, self.hwnd, None)?",
                "CREATION_OWNER_WRAPPER_SELECTION",
            ),
            (
                "fn make_credential_with_diagnostics(",
                "fn get_hmac_secret(",
                ".map(WebAuthnForegroundMonitor::finish_observation)",
                ".map(drop)",
                "NATIVE_RETURN_SHUTDOWN",
            ),
            (
                "fn get_hmac_secret_for_any_with_diagnostics(",
                "impl FidoBackend for WindowsWebAuthnBackend",
                ".map(WebAuthnForegroundMonitor::finish_observation)",
                ".map(drop)",
                "NATIVE_RETURN_SHUTDOWN",
            ),
        ] {
            let mutant = mutate_unique(&source, start, end, from, to);
            for (ending, fixture) in [
                ("LF", mutant.clone()),
                ("CRLF", mutant.replace('\n', "\r\n")),
            ] {
                let observed = panic_tag(std::panic::catch_unwind(|| {
                    assert_passive_contract(&fixture)
                }));
                assert_eq!(observed, format!("CONTRACT:{tag}"));
                eprintln!("MUTATION_VALIDATED {ending} {tag}");
            }
        }
    }

    #[test]
    fn capability_api_boundaries() {
        for api in [0, 1, 3, 4, 9] {
            let record = capability_record(Some(api), Some(123), Some(2));
            assert_eq!(record["api_version"], api);
            assert_eq!(record["hmac_secret_api_supported"], api >= 4);
        }
    }

    #[test]
    fn capability_unknown_session_and_allowlist() {
        let unknown = capability_record(None, None, None);
        assert_eq!(
            unknown,
            json!({
                "api_version": null,
                "hmac_secret_api_supported": null,
                "pid": null,
                "session_id": null,
                "session_kind": "unknown",
                "measured_in": "gui-process",
            })
        );
        let zero = capability_record(Some(4), Some(123), Some(0));
        assert_eq!(zero["session_kind"], "noninteractive");
        assert_eq!(zero["pid"], 123);
        assert_eq!(zero["session_id"], 0);
        let interactive_unknown = capability_record(Some(4), Some(123), Some(2));
        assert_eq!(interactive_unknown["session_kind"], "unknown");
        assert_eq!(interactive_unknown.as_object().unwrap().len(), 6);
        assert!(capability_record(Some(4), Some(0), None)["pid"].is_null());
    }

    #[test]
    fn error_categories_never_use_raw_text() {
        let cases = [
            (FidoError::NoDevice, "no-device"),
            (FidoError::PinRequired("SENTINEL".into()), "pin-required"),
            (FidoError::PinRejected, "pin-rejected"),
            (FidoError::PrfNotSupported, "prf-unsupported"),
            (FidoError::PrfNotConfirmed, "hmac-creation-unconfirmed"),
            (FidoError::CredentialExcluded, "credential-excluded"),
            (
                FidoError::NotSupported("SENTINEL".into()),
                "capability-unsupported",
            ),
            (FidoError::Internal("SENTINEL".into()), "internal"),
            (
                FidoError::DeviceOpenDenied {
                    what: "SENTINEL".into(),
                    last_err: "SENTINEL".into(),
                    attempts: 3,
                },
                "device-open-denied",
            ),
        ];
        for (error, expected) in cases {
            assert_eq!(error_category(&error), expected);
            let record = OperationDiagnostics::new(Operation::GetAssertion).record(Some(&error));
            assert_eq!(record["error_category"], expected);
            assert!(!record.to_string().contains("SENTINEL"));
        }
    }

    #[test]
    fn operation_names_and_keys_are_closed_allowlists() {
        for (operation, name) in [
            (Operation::MakeCredential, "MakeCredential"),
            (Operation::GetAssertion, "GetAssertion"),
        ] {
            let record = OperationDiagnostics::new(operation).record(None);
            assert_eq!(
                record,
                json!({
                    "operation": name,
                    "error_category": null,
                    "hmac_creation_confirmed": null,
                    "output_present": null,
                    "output_length": null,
                    "credential_match": null,
                })
            );
        }
        let record = OperationDiagnostics::new(Operation::GetAssertion)
            .record(Some(&FidoError::Internal("SENTINEL".into())));
        assert_eq!(record["error_category"], "internal");
        assert!(!record.to_string().contains("SENTINEL"));
    }

    #[test]
    fn hmac_creation_reports_positive_and_unconfirmed_only() {
        let mut diagnostic = OperationDiagnostics::new(Operation::MakeCredential);
        diagnostic.hmac_creation_confirmed = Some(true);
        let success = diagnostic.record(None);
        assert_eq!(success["hmac_creation_confirmed"], true);
        assert!(success["error_category"].is_null());
        diagnostic.hmac_creation_confirmed = Some(false);
        let failure = diagnostic.record(Some(&FidoError::PrfNotConfirmed));
        assert_eq!(failure["hmac_creation_confirmed"], false);
        assert_eq!(failure["error_category"], "hmac-creation-unconfirmed");
    }

    #[test]
    fn valid_output_metadata_is_32_bytes_and_matched() {
        let mut diagnostic = OperationDiagnostics::new(Operation::GetAssertion);
        diagnostic.output_present = Some(true);
        diagnostic.output_length = Some(32);
        diagnostic.credential_match = Some(true);
        let record = diagnostic.record(None);
        assert_eq!(record["output_present"], true);
        assert_eq!(record["output_length"], 32);
        assert_eq!(record["credential_match"], true);
        assert!(record["error_category"].is_null());
    }

    #[test]
    fn missing_and_invalid_output_and_mismatch_are_distinct() {
        let error = FidoError::Internal("SENTINEL".into());
        let mut diagnostic = OperationDiagnostics::new(Operation::GetAssertion);
        diagnostic.output_present = Some(false);
        assert_eq!(
            diagnostic.record(Some(&error))["error_category"],
            "unsupported-output"
        );
        for (present, length) in [(true, 0), (true, 31), (true, 33), (false, 32)] {
            diagnostic.output_present = Some(present);
            diagnostic.output_length = Some(length);
            let record = diagnostic.record(Some(&error));
            assert_eq!(record["error_category"], "invalid-output");
            assert_eq!(record["output_length"], length);
            assert_eq!(record["output_present"], present);
            assert!(!record.to_string().contains("SENTINEL"));
        }
        diagnostic.credential_match = Some(false);
        assert_eq!(
            diagnostic.record(Some(&error))["error_category"],
            "credential-mismatch"
        );
        assert_eq!(diagnostic.record(Some(&error))["credential_match"], false);
        assert!(diagnostic.record(None)["error_category"].is_null());
        assert_eq!(
            diagnostic.record(Some(&FidoError::NoDevice))["error_category"],
            "no-device"
        );
    }

    #[test]
    fn api_preflight_and_response_failures_do_not_guess_cause() {
        let mut diagnostic = OperationDiagnostics::new(Operation::GetAssertion);
        for (stage, category) in [
            (FailureStage::Preflight, "preflight"),
            (FailureStage::Api, "api-error"),
            (FailureStage::Response, "invalid-response"),
        ] {
            diagnostic.failure_stage = Some(stage);
            let record = diagnostic.record(Some(&FidoError::Internal("SENTINEL".into())));
            assert_eq!(record["error_category"], category);
            assert!(!record.to_string().contains("SENTINEL"));
            assert!(diagnostic.record(None)["error_category"].is_null());
        }
    }

    #[test]
    fn observer_runs_after_operation_and_keeps_result_unchanged() {
        use std::cell::RefCell;
        let trace = RefCell::new(Vec::new());
        let result = diagnose(
            Operation::GetAssertion,
            |diagnostic| {
                trace.borrow_mut().push("operation-return");
                diagnostic.credential_match = Some(true);
                Ok(123)
            },
            |record| {
                trace.borrow_mut().push("emit");
                assert_eq!(record["credential_match"], true);
            },
        );
        assert_eq!(result.unwrap(), 123);
        assert_eq!(*trace.borrow(), ["operation-return", "emit"]);
        let mut calls = 0;
        let result: Result<(), FidoError> = diagnose(
            Operation::MakeCredential,
            |_| Err(FidoError::PrfNotConfirmed),
            |record| {
                calls += 1;
                assert_eq!(record["error_category"], "hmac-creation-unconfirmed");
            },
        );
        assert!(matches!(result, Err(FidoError::PrfNotConfirmed)));
        assert_eq!(calls, 1);
    }

    // Wiring regression supplements runtime metadata/observer tests; never calls FFI.
    #[test]
    fn backend_wiring_preserves_guard_and_foreground_ffi_gap() {
        assert_backend_wiring(include_str!("windows_webauthn.rs"));
    }

    #[test]
    fn backend_wiring_accepts_lf_and_crlf() {
        let lf = include_str!("windows_webauthn.rs").replace("\r\n", "\n");
        assert_backend_wiring(&lf);
        assert_backend_wiring(&lf.replace('\n', "\r\n"));
    }

    fn assert_wiring_rejected_for_both_line_endings(source: &str, expected_tag: &str) {
        let lf = source.replace("\r\n", "\n");
        for (ending, fixture) in [("LF", lf.clone()), ("CRLF", lf.replace('\n', "\r\n"))] {
            let observed = panic_tag(std::panic::catch_unwind(|| assert_backend_wiring(&fixture)));
            assert_eq!(observed, format!("CONTRACT:{expected_tag}"));
            eprintln!("MUTATION_VALIDATED {ending} {expected_tag}");
        }
    }

    #[test]
    fn backend_wiring_rejects_missing_operation_wrappers() {
        let source = include_str!("windows_webauthn.rs").replace("\r\n", "\n");
        assert_backend_wiring(&source);
        assert_backend_wiring(&source.replace('\n', "\r\n"));
        for (operation, tag) in [
            ("MakeCredential", "MAKE_OPERATION_WRAPPER"),
            ("GetAssertion", "GET_OPERATION_WRAPPER"),
        ] {
            let wrapper = format!("diagnose(\n            Operation::{operation}");
            let mutant = mutate_unique(
                &source,
                "impl WindowsWebAuthnBackend",
                "impl FidoBackend for WindowsWebAuthnBackend",
                &wrapper,
                "removed_wrapper(",
            );
            assert_wiring_rejected_for_both_line_endings(&mutant, tag);
        }
    }

    #[test]
    fn backend_wiring_rejects_capability_after_guard() {
        let source = include_str!("windows_webauthn.rs").replace("\r\n", "\n");
        assert_backend_wiring(&source);
        assert_backend_wiring(&source.replace('\n', "\r\n"));
        let guard = "if !hmac_secret_api_supported(api_version) {";
        let removed = mutate_unique(
            &source,
            "pub fn new(hwnd:",
            "fn hwnd(",
            "capability_record(",
            "removed_capability(",
        );
        let mutant = mutate_unique(
            &removed,
            "pub fn new(hwnd:",
            "fn hwnd(",
            guard,
            &format!("{guard}\ncapability_record();"),
        );
        assert_wiring_rejected_for_both_line_endings(&mutant, "CAPABILITY_ORDER");
    }

    #[test]
    fn backend_wiring_rejects_observers_in_foreground_ffi_gap() {
        let source = include_str!("windows_webauthn.rs").replace("\r\n", "\n");
        assert_backend_wiring(&source);
        assert_backend_wiring(&source.replace('\n', "\r\n"));
        for (start, end, ffi) in [
            (
                "fn make_credential_with_diagnostics(",
                "fn get_hmac_secret(",
                "WebAuthNAuthenticatorMakeCredential(",
            ),
            (
                "fn get_hmac_secret_for_any_with_diagnostics(",
                "impl FidoBackend for WindowsWebAuthnBackend",
                "WebAuthNAuthenticatorGetAssertion(",
            ),
        ] {
            for (observer, tag) in [
                ("log::info!(\"synthetic\");", "FFI_GAP_LOG"),
                ("diagnose(synthetic);", "FFI_GAP_DIAGNOSTIC"),
            ] {
                let mutant = mutate_unique(&source, start, end, ffi, &format!("{observer}\n{ffi}"));
                assert_wiring_rejected_for_both_line_endings(&mutant, tag);
            }
        }
    }

    #[test]
    fn backend_wiring_rejects_blocking_or_policy_calls_in_final_gap() {
        let source = include_str!("windows_webauthn.rs").replace("\r\n", "\n");
        assert_backend_wiring(&source);
        assert_backend_wiring(&source.replace('\n', "\r\n"));
        for (start, end, ffi) in [
            (
                "fn make_credential_with_diagnostics(",
                "fn get_hmac_secret(",
                "WebAuthNAuthenticatorMakeCredential(",
            ),
            (
                "fn get_hmac_secret_for_any_with_diagnostics(",
                "impl FidoBackend for WindowsWebAuthnBackend",
                "WebAuthNAuthenticatorGetAssertion(",
            ),
        ] {
            for observer in ["std::thread::sleep(delay);", "capture_broker(system);"] {
                let mutant = mutate_unique(&source, start, end, ffi, &format!("{observer}\n{ffi}"));
                assert_wiring_rejected_for_both_line_endings(&mutant, "FFI_GAP_EXACT");
            }
        }
    }

    fn assert_backend_wiring(source: &str) {
        // Normalize checkout line endings only; preserve every statement and space.
        let source = source.replace("\r\n", "\n");
        let constructor = contract_section(&source, "pub fn new(hwnd:", "fn hwnd(");
        let capability = contract_position(constructor, "capability_record(", "CAPABILITY_PRESENT");
        let guard = contract_position(
            constructor,
            "if !hmac_secret_api_supported(api_version)",
            "API_GUARD_PRESENT",
        );
        assert!(capability < guard, "CONTRACT:CAPABILITY_ORDER");
        assert!(
            constructor.contains("process_session(process_id)"),
            "CONTRACT:CAPABILITY_SESSION"
        );
        for (start, end, ffi) in [
            (
                "fn make_credential_with_diagnostics(",
                "fn get_hmac_secret(",
                "WebAuthNAuthenticatorMakeCredential(",
            ),
            (
                "fn get_hmac_secret_for_any_with_diagnostics(",
                "impl FidoBackend for WindowsWebAuthnBackend",
                "WebAuthNAuthenticatorGetAssertion(",
            ),
        ] {
            let wrapper = contract_section(&source, start, end);
            let before_ffi = wrapper.split_once(ffi).expect("LOCATOR:final-ffi").0;
            let gap = before_ffi
                .rsplit_once("self.foreground_owner_hwnd(owner_identity)?")
                .expect("LOCATOR:final-owner-sample")
                .1;
            assert!(!gap.contains("log::"), "CONTRACT:FFI_GAP_LOG");
            assert!(!gap.contains("diagnose("), "CONTRACT:FFI_GAP_DIAGNOSTIC");
            contract(gap.trim() == ";\n        if let Some(monitor) = focus_monitor.as_ref() {\n            monitor.arm();\n        }\n        let hr = unsafe {", "FFI_GAP_EXACT");
            assert_eq!(gap.trim(), ";\n        if let Some(monitor) = focus_monitor.as_ref() {\n            monitor.arm();\n        }\n        let hr = unsafe {");
        }
        assert!(
            source.contains("diagnose(\n            Operation::MakeCredential"),
            "CONTRACT:MAKE_OPERATION_WRAPPER"
        );
        assert!(
            source.contains("diagnose(\n            Operation::GetAssertion"),
            "CONTRACT:GET_OPERATION_WRAPPER"
        );
    }
}
