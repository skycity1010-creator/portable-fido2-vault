//! Allowlisted diagnostics. This module never accepts WebAuthn response bytes.
use crate::fido2::FidoError;
use serde_json::{json, Value};

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
        let source = include_str!("windows_webauthn.rs");
        let constructor = source
            .split("pub fn new(hwnd:")
            .nth(1)
            .unwrap()
            .split("fn hwnd(")
            .next()
            .unwrap();
        let capability = constructor
            .find("capability_record(")
            .expect("capability must be logged before API guard");
        let guard = constructor
            .find("if !hmac_secret_api_supported(api_version)")
            .unwrap();
        assert!(capability < guard);
        assert!(constructor.contains("process_session(process_id)"));
        for ffi in [
            "WebAuthNAuthenticatorMakeCredential(",
            "WebAuthNAuthenticatorGetAssertion(",
        ] {
            let before_ffi = source.split(ffi).next().unwrap();
            let gap = before_ffi
                .rsplit("self.foreground_owner_hwnd()?")
                .next()
                .unwrap();
            assert!(!gap.contains("log::"));
            assert!(!gap.contains("diagnose("));
        }
        assert!(source.contains("diagnose(\n            Operation::MakeCredential"));
        assert!(source.contains("diagnose(\n            Operation::GetAssertion"));
    }
}
