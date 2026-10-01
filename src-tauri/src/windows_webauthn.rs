//! Windows GUI FIDO backend based on Microsoft's WebAuthn API.
//! The raw CTAP backend remains available for the CLI and diagnostics.

use crate::fido2::{DetectedKey, FidoBackend, FidoError, KeyKind, RegisteredCredential};
use std::{
    collections::HashSet,
    ffi::c_void,
    ptr, slice,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
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
    IsWindowVisible, SetForegroundWindow,
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

fn is_new_windows_security_dialog(
    title: &str,
    class_name: &str,
    process_path: &str,
    system_directory: &str,
    visible: bool,
    current_session: u32,
    window_session: u32,
    is_new_window: bool,
    is_new_process: bool,
) -> bool {
    let title_matches = title.trim().eq_ignore_ascii_case("Windows Security")
        || title.trim().eq_ignore_ascii_case("Windows 安全性");
    let normalize_path = |path: &str| path.replace('/', "\\").trim_end_matches('\\').to_owned();
    let expected_path = format!(
        "{}\\CredentialUIBroker.exe",
        normalize_path(system_directory)
    );

    visible
        && current_session == window_session
        && is_new_window
        && is_new_process
        && title_matches
        && class_name.eq_ignore_ascii_case("Credential Dialog Xaml Host")
        && normalize_path(process_path).eq_ignore_ascii_case(&expected_path)
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

fn top_level_windows() -> Vec<HWND> {
    let mut windows = Vec::new();
    unsafe {
        EnumWindows(
            Some(collect_top_level_window),
            (&mut windows as *mut Vec<HWND>) as LPARAM,
        );
    }
    windows
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

fn top_level_window_identities() -> HashSet<WindowIdentity> {
    top_level_windows()
        .into_iter()
        .filter_map(window_identity)
        .collect()
}

fn credential_broker_process_ids() -> Option<HashSet<u32>> {
    let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
    if snapshot.is_null() || snapshot as isize == -1 {
        return None;
    }
    let _snapshot = ProcessHandle(snapshot);
    let mut entry = PROCESSENTRY32W::default();
    entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;
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

fn window_text(hwnd: HWND) -> String {
    let mut buffer = [0u16; 256];
    let length = unsafe { GetWindowTextW(hwnd, buffer.as_mut_ptr(), buffer.len() as i32) };
    if length <= 0 {
        String::new()
    } else {
        String::from_utf16_lossy(&buffer[..length as usize])
    }
}

fn window_class(hwnd: HWND) -> String {
    let mut buffer = [0u16; 256];
    let length = unsafe { GetClassNameW(hwnd, buffer.as_mut_ptr(), buffer.len() as i32) };
    if length <= 0 {
        String::new()
    } else {
        String::from_utf16_lossy(&buffer[..length as usize])
    }
}

fn visible_windows_security_dialogs(
    system_directory: &str,
    current_session: u32,
    baseline_windows: &HashSet<WindowIdentity>,
    baseline_broker_processes: &HashSet<u32>,
) -> Vec<WindowIdentity> {
    top_level_windows()
        .into_iter()
        .filter(|hwnd| unsafe { IsWindowVisible(*hwnd) } != 0)
        .filter_map(|hwnd| {
            let identity = window_identity(hwnd)?;
            let is_new_window = is_new_window_identity(identity, baseline_windows);
            let is_new_process = !baseline_broker_processes.contains(&identity.process_id);
            if !is_new_window || !is_new_process {
                return None;
            }

            let title = window_text(hwnd);
            let class_name = window_class(hwnd);
            let window_session = process_session(identity.process_id)?;
            let process_path = process_image_path(identity.process_id)?;
            is_new_windows_security_dialog(
                &title,
                &class_name,
                &process_path,
                system_directory,
                true,
                current_session,
                window_session,
                is_new_window,
                is_new_process,
            )
            .then_some(identity)
        })
        .collect()
}

struct WebAuthnForegroundMonitor {
    cancelled: Arc<AtomicBool>,
    armed: Arc<AtomicBool>,
    worker: Option<JoinHandle<()>>,
}

impl WebAuthnForegroundMonitor {
    fn prepare(owner_hwnd: HWND, operation: &'static str) -> Option<Self> {
        let system_directory = system_directory().or_else(|| {
            log::warn!("[WebAuthN-focus] could not determine the Windows system directory");
            None
        })?;
        let current_session = process_session(unsafe { GetCurrentProcessId() }).or_else(|| {
            log::warn!("[WebAuthN-focus] could not determine the current Windows session");
            None
        })?;
        let baseline_windows = top_level_window_identities();
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
                while !worker_cancelled.load(Ordering::Acquire) && Instant::now() < deadline {
                    let candidates = visible_windows_security_dialogs(
                        &system_directory,
                        current_session,
                        &baseline_windows,
                        &baseline_broker_processes,
                    );
                    if candidates.len() > 1 {
                        log::warn!(
                            "[WebAuthN-focus] operation={} found multiple new broker dialogs; leaving them untouched",
                            operation,
                        );
                        return;
                    }
                    if let Some(candidate) = select_unique_candidate(&candidates) {
                        if worker_cancelled.load(Ordering::Acquire) {
                            return;
                        }
                        let hwnd = candidate.hwnd as HWND;
                        let foreground = unsafe { GetForegroundWindow() } as isize;
                        if foreground == candidate.hwnd {
                            log::info!(
                                "[WebAuthN-focus] operation={} new broker dialog already foreground: hwnd={:#x}",
                                operation,
                                candidate.hwnd,
                            );
                            return;
                        }
                        if !should_attempt_dialog_activation(
                            owner_hwnd_value,
                            candidate.hwnd,
                            foreground,
                            worker_cancelled.load(Ordering::Acquire),
                        ) {
                            log::info!(
                                "[WebAuthN-focus] operation={} left broker dialog untouched after focus changed: hwnd={:#x} foreground={:#x}",
                                operation,
                                candidate.hwnd,
                                foreground,
                            );
                            return;
                        }
                        let current_candidates = visible_windows_security_dialogs(
                            &system_directory,
                            current_session,
                            &baseline_windows,
                            &baseline_broker_processes,
                        );
                        if select_unique_candidate(&current_candidates) != Some(candidate)
                            || window_identity(hwnd) != Some(candidate)
                            || unsafe { IsWindowVisible(hwnd) } == 0
                            || worker_cancelled.load(Ordering::Acquire)
                        {
                            log::debug!(
                                "[WebAuthN-focus] operation={} skipped a broker window that changed during validation",
                                operation,
                            );
                            return;
                        }
                        let foreground_before = unsafe { GetForegroundWindow() } as isize;
                        if !should_attempt_dialog_activation(
                            owner_hwnd_value,
                            candidate.hwnd,
                            foreground_before,
                            worker_cancelled.load(Ordering::Acquire),
                        ) {
                            log::info!(
                                "[WebAuthN-focus] operation={} canceled broker activation because foreground changed: hwnd={:#x} foreground={:#x}",
                                operation,
                                candidate.hwnd,
                                foreground_before,
                            );
                            return;
                        }

                        // Best-effort only: Windows can still change focus after this sample.
                        let activated = unsafe { SetForegroundWindow(hwnd) } != 0;
                        let foreground_after = unsafe { GetForegroundWindow() } as isize;
                        log::info!(
                            "[WebAuthN-focus] operation={} broker dialog activation attempt: hwnd={:#x} set_foreground={} foreground_after={:#x}",
                            operation,
                            candidate.hwnd,
                            activated,
                            foreground_after,
                        );
                        return;
                    }

                    if unsafe { GetForegroundWindow() } as isize != owner_hwnd_value {
                        log::debug!(
                            "[WebAuthN-focus] operation={} stopped monitoring after FidoVault lost foreground",
                            operation,
                        );
                        return;
                    }
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
            worker: Some(worker),
        })
    }

    fn arm(&self) {
        self.armed.store(true, Ordering::Release);
    }
}

impl Drop for WebAuthnForegroundMonitor {
    fn drop(&mut self) {
        self.cancelled.store(true, Ordering::Release);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
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
}

impl WindowsWebAuthnBackend {
    pub fn new(hwnd: isize) -> Result<Self, FidoError> {
        let api_version = unsafe { WebAuthNGetApiVersionNumber() };
        if !hmac_secret_api_supported(api_version) {
            return Err(FidoError::NotSupported(format!(
                "Windows WebAuthn API v{api_version} lacks HMAC-secret assertion support (requires v4+)"
            )));
        }
        Ok(Self { hwnd, api_version })
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

    fn foreground_owner_hwnd(&self) -> Result<(HWND, HWND), FidoError> {
        let owner = self.hwnd()?;
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

    fn make_credential(&self, detected: &DetectedKey) -> Result<RegisteredCredential, FidoError> {
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
        let focus_monitor = WebAuthnForegroundMonitor::prepare(owner_for_prepare, "MakeCredential");
        let (owner_hwnd, foreground_before_api) = self.foreground_owner_hwnd()?;
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
        drop(focus_monitor);
        log::info!(
            "Windows WebAuthn MakeCredential owner snapshot captured immediately before API: owner={:p} foreground={:p}",
            owner_hwnd,
            foreground_before_api,
        );
        if hr < 0 {
            if !attestation.is_null() {
                unsafe { WebAuthNFreeCredentialAttestation(attestation) };
            }
            return Err(api_error("makeCredential", hr));
        }
        if attestation.is_null() {
            return Err(FidoError::Internal(
                "Windows WebAuthn API returned no credential attestation".into(),
            ));
        }
        let attestation = AttestationGuard(attestation);
        let att = unsafe { &*attestation.0 };
        if !hmac_secret_enabled(&att.Extensions) {
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

        Ok(RegisteredCredential {
            credential_id,
            aaguid,
            label: detected.label.clone(),
            kind: detected.kind,
        })
    }

    fn get_hmac_secret(&self, credential_id: &[u8]) -> Result<[u8; 32], FidoError> {
        self.get_hmac_secret_for_any(&[credential_id.to_vec()])
            .map(|(_, secret)| secret)
    }

    fn get_hmac_secret_for_any(
        &self,
        credential_ids: &[Vec<u8>],
    ) -> Result<(Vec<u8>, [u8; 32]), FidoError> {
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
        let (owner_hwnd, foreground_before_api) = self.foreground_owner_hwnd()?;
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
        if hr < 0 {
            if !assertion.is_null() {
                unsafe { WebAuthNFreeAssertion(assertion) };
            }
            return Err(api_error("getAssertion", hr));
        }
        if assertion.is_null() {
            return Err(FidoError::Internal(
                "Windows WebAuthn API returned no assertion".into(),
            ));
        }
        let assertion = AssertionGuard(assertion);
        let result = unsafe { &*assertion.0 };
        if result.pHmacSecret.is_null() {
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
        let selected_id = validate_selected_credential_id(credential_ids, &selected_id)?;
        let output = unsafe { &*result.pHmacSecret };
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
        self.hwnd = handle;
    }

    fn detect(&mut self) -> Result<DetectedKey, FidoError> {
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

    #[test]
    fn windows_backend_advertises_brokered_key_selection_ui() {
        let backend = WindowsWebAuthnBackend {
            hwnd: 0,
            api_version: 4,
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
            "Windows 安全性",
            "Credential Dialog Xaml Host",
            r"C:\Windows\System32\CredentialUIBroker.exe",
            r"C:\Windows\System32",
            true,
            2,
            2,
            true,
            true,
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
                title,
                class_name,
                path,
                r"C:\Windows\System32",
                visible,
                current_session,
                window_session,
                is_new,
                true,
            ));
        }
    }

    #[test]
    fn broker_dialog_requires_new_process_and_new_window_identity() {
        let trusted = (
            "Windows 安全性",
            "Credential Dialog Xaml Host",
            r"C:\Windows\System32\CredentialUIBroker.exe",
            r"C:\Windows\System32",
            true,
            2,
            2,
        );
        assert!(is_new_windows_security_dialog(
            trusted.0, trusted.1, trusted.2, trusted.3, trusted.4, trusted.5, trusted.6, true,
            true,
        ));
        assert!(!is_new_windows_security_dialog(
            trusted.0, trusted.1, trusted.2, trusted.3, trusted.4, trusted.5, trusted.6, true,
            false,
        ));
        assert!(!is_new_windows_security_dialog(
            trusted.0, trusted.1, trusted.2, trusted.3, trusted.4, trusted.5, trusted.6, false,
            true,
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
