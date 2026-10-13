//! Isolated mock-only Windows Hello gate; never use with a production vault.
use base64::{engine::general_purpose::STANDARD, Engine as _};
use portable_fido_vault::edition::Edition;
use portable_fido_vault::fido2::{
    DetectedKey, FidoBackend, FidoError, MockBackend, MockPlatformMode, PlatformRegistration,
    PlatformStatus, RegisteredCredential,
};
use portable_fido_vault::vault::{PlatformCleanupOutcome, SlotAuthenticator, Vault, VaultError};
use std::cell::Cell;
use std::io::{self, Read};
use std::path::{Path, PathBuf};

fn fixture_path(raw: &str) -> Result<PathBuf, &'static str> {
    let path = PathBuf::from(raw);
    let root = if std::env::var("GITHUB_ACTIONS").as_deref() == Ok("true") {
        PathBuf::from(std::env::var("RUNNER_TEMP").map_err(|_| "CI runner temp root missing")?)
    } else {
        PathBuf::from("D:/scratch")
    };
    if !root.is_absolute() {
        return Err("invalid scratch root");
    }
    let parent = path.parent().ok_or("invalid fixture path")?;
    let parent = parent
        .canonicalize()
        .map_err(|_| "missing fixture parent")?;
    let scratch = root.canonicalize().map_err(|_| "missing scratch root")?;
    if !parent.starts_with(&scratch) || path.file_name() != Some(std::ffi::OsStr::new("vault.db")) {
        return Err("fixture must be beneath allowed scratch root");
    }
    if !parent.join(".windows-hello-gate").is_file() {
        return Err("unclaimed mock gate fixture");
    }
    // The vault writer uses a sibling .tmp and may write a failure sidecar.
    // Never follow caller-planted links/reparse points outside this fixture.
    for name in [
        ".windows-hello-gate",
        "vault.db",
        "vault.db.tmp",
        "vault.db.failures",
    ] {
        let candidate = parent.join(name);
        if candidate
            .symlink_metadata()
            .is_ok_and(|m| m.file_type().is_symlink())
        {
            return Err("fixture contains a linked gate file");
        }
    }
    if parent.join("vault.db.tmp").exists() {
        return Err("fixture contains a pre-existing temp file");
    }
    Ok(parent.join("vault.db"))
}

fn local_backend(path: &Path, host: &str) -> Result<MockBackend, &'static str> {
    let ids = if host == "home" {
        Vault::read_header(path, Edition::Single)
            .map_err(|_| "header failed")?
            .key_slots
            .into_iter()
            .filter(|s| s.authenticator == Some(SlotAuthenticator::Platform))
            .map(|s| {
                STANDARD
                    .decode(s.credential_id)
                    .map_err(|_| "bad credential")
            })
            .collect::<Result<Vec<_>, _>>()?
    } else {
        Vec::new()
    };
    Ok(MockBackend::new().with_platform_credentials(ids))
}

/// Records actual platform calls, rather than trusting a rejected return value.
struct TracedPlatform {
    inner: MockBackend,
    other_calls: Cell<usize>,
    status: Cell<usize>,
    lists: usize,
    created: Vec<Vec<u8>>,
    assertions: Vec<Vec<Vec<u8>>>,
    deleted: Vec<Vec<u8>>,
}

impl TracedPlatform {
    fn new(inner: MockBackend) -> Self {
        Self {
            inner,
            other_calls: Cell::new(0),
            status: Cell::new(0),
            lists: 0,
            created: vec![],
            assertions: vec![],
            deleted: vec![],
        }
    }
    fn untouched(&self) -> bool {
        self.other_calls.get() == 0
            && self.status.get() == 0
            && self.lists == 0
            && self.created.is_empty()
            && self.assertions.is_empty()
            && self.deleted.is_empty()
    }
}

impl FidoBackend for TracedPlatform {
    fn detect(&mut self) -> Result<DetectedKey, FidoError> {
        self.other_calls.set(self.other_calls.get() + 1);
        Err(FidoError::NoDevice)
    }
    fn register_credential(
        &mut self,
        _: &DetectedKey,
        _: Option<&str>,
    ) -> Result<RegisteredCredential, FidoError> {
        self.other_calls.set(self.other_calls.get() + 1);
        Err(FidoError::NoDevice)
    }
    fn get_prf_secret(&mut self, _: &[u8], _: Option<&str>) -> Result<[u8; 32], FidoError> {
        self.other_calls.set(self.other_calls.get() + 1);
        Err(FidoError::NoDevice)
    }
    fn platform_status(&self) -> PlatformStatus {
        self.status.set(self.status.get() + 1);
        self.inner.platform_status()
    }
    fn list_platform_credentials(&mut self) -> Result<Vec<Vec<u8>>, FidoError> {
        self.lists += 1;
        self.inner.list_platform_credentials()
    }
    fn register_platform_credential(
        &mut self,
        label: &str,
        exclude: &[Vec<u8>],
    ) -> Result<PlatformRegistration, FidoError> {
        let registration = self.inner.register_platform_credential(label, exclude)?;
        self.created
            .push(registration.credential.credential_id.clone());
        Ok(registration)
    }
    fn get_platform_prf_secret(
        &mut self,
        ids: &[Vec<u8>],
    ) -> Result<(Vec<u8>, [u8; 32]), FidoError> {
        self.assertions.push(ids.to_vec());
        self.inner.get_platform_prf_secret(ids)
    }
    fn delete_platform_credential(&mut self, id: &[u8]) -> Result<(), FidoError> {
        self.deleted.push(id.to_vec());
        self.inner.delete_platform_credential(id)
    }
}

fn run() -> Result<&'static str, &'static str> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.len() != 3 {
        return Err("usage: <create|register> <fixture-vault-path> <home|away>");
    }
    let path = fixture_path(&args[1])?;
    if args[2] != "home" && args[2] != "away" {
        return Err("invalid host");
    }
    let mut password = String::new();
    io::stdin()
        .read_to_string(&mut password)
        .map_err(|_| "password input failed")?;
    if password.is_empty() {
        return Err("empty password");
    }
    match args[0].as_str() {
        "dual-guard" => {
            if path.exists() {
                return Err("vault already exists");
            }
            let mut vault = Vault::create_for(&path, &password, Edition::Dual)
                .map_err(|_| "dual create failed")?;
            let mut backend = TracedPlatform::new(MockBackend::new());
            let rejected = matches!(
                vault.register_windows_hello(&mut backend, "gate-host", Edition::Dual),
                Err(VaultError::Format(_))
            );
            let header =
                Vault::read_header(&path, Edition::Dual).map_err(|_| "dual header failed")?;
            if !rejected || !header.key_slots.is_empty() || !backend.untouched() {
                return Err("dual platform guard failed");
            }
            Ok("dual-rejected")
        }
        "create" => {
            if path.exists() {
                return Err("vault already exists");
            }
            Vault::create_for(&path, &password, Edition::Single).map_err(|_| "create failed")?;
            Ok("created")
        }
        "register" => {
            let mut vault = Vault::open_password_for(&path, &password, Edition::Single)
                .map_err(|_| "unlock failed")?;
            let mut backend = TracedPlatform::new(local_backend(&path, &args[2])?);
            let registered = vault
                .register_windows_hello(&mut backend, "gate-host", Edition::Single)
                .map_err(|_| "registration rejected")?;
            let header = Vault::read_header(&path, Edition::Single).map_err(|_| "header failed")?;
            if header.key_slots.len() != 1
                || header.key_slots[0].authenticator != Some(SlotAuthenticator::Platform)
                || backend.created.len() != 1
                || STANDARD
                    .decode(&header.key_slots[0].credential_id)
                    .ok()
                    .as_ref()
                    != backend.created.first()
                || registered.credential_id != backend.created[0]
                || backend.assertions.as_slice() != [vec![backend.created[0].clone()]]
                || backend.inner.platform_credential_ids() != backend.created.as_slice()
            {
                return Err("platform registration postcondition failed");
            }
            Ok("registered")
        }
        "register-roaming" => {
            let mut vault = Vault::open_password_for(&path, &password, Edition::Single)
                .map_err(|_| "unlock failed")?;
            let mut backend = MockBackend::new();
            vault
                .register_key_with_label(&mut backend, None, "gate-roaming")
                .map_err(|_| "roaming registration failed")?;
            let header = Vault::read_header(&path, Edition::Single).map_err(|_| "header failed")?;
            if header.key_slots.len() != 2
                || header
                    .key_slots
                    .iter()
                    .filter(|s| s.authenticator.is_none())
                    .count()
                    != 1
            {
                return Err("roaming slot missing");
            }
            Ok("roaming-registered")
        }
        "remove" => {
            let mut vault = Vault::open_password_for(&path, &password, Edition::Single)
                .map_err(|_| "unlock failed")?;
            let header = Vault::read_header(&path, Edition::Single).map_err(|_| "header failed")?;
            if header.key_slots.len() != 1 {
                return Err("unexpected slot count");
            }
            let id = &header.key_slots[0].credential_id;
            let mut backend = local_backend(&path, &args[2])?;
            let outcome = vault
                .remove_key_with_platform(id, &mut backend, Edition::Single)
                .map_err(|_| "remove failed")?;
            let after = Vault::read_header(&path, Edition::Single).map_err(|_| "header failed")?;
            if outcome != PlatformCleanupOutcome::Removed
                || !after.key_slots.is_empty()
                || !backend.platform_credential_ids().is_empty()
            {
                return Err("remove incomplete");
            }
            Ok("removed-clean")
        }
        "duplicate" => {
            let mut vault = Vault::open_password_for(&path, &password, Edition::Single)
                .map_err(|_| "unlock failed")?;
            let before = std::fs::read(&path).map_err(|_| "vault read failed")?;
            let mut backend = local_backend(&path, &args[2])?;
            let local_before = backend.platform_credential_ids().to_vec();
            let rejected = matches!(
                vault.register_windows_hello(&mut backend, "gate-host", Edition::Single),
                Err(VaultError::Fido(FidoError::PlatformCredentialExists))
            );
            if !rejected
                || std::fs::read(&path).map_err(|_| "vault read failed")? != before
                || backend.platform_credential_ids() != local_before
            {
                return Err("duplicate was not rejected atomically");
            }
            Ok("duplicate-rejected")
        }
        "register-fail" => {
            let mut vault = Vault::open_password_for(&path, &password, Edition::Single)
                .map_err(|_| "unlock failed")?;
            let file_before = std::fs::read(&path).map_err(|_| "vault read failed")?;
            let before = Vault::read_header(&path, Edition::Single)
                .map_err(|_| "header failed")?
                .key_slots
                .len();
            let mut backend = TracedPlatform::new(
                local_backend(&path, &args[2])?
                    .with_platform_mode(MockPlatformMode::AssertionPrfFails),
            );
            let rejected = matches!(
                vault.register_windows_hello(&mut backend, "gate-host", Edition::Single),
                Err(VaultError::Fido(FidoError::PlatformPrfUnsupported))
            );
            let after = Vault::read_header(&path, Edition::Single)
                .map_err(|_| "header failed")?
                .key_slots
                .len();
            if !rejected
                || before != after
                || backend.created.len() != 1
                || backend.assertions.as_slice() != [vec![backend.created[0].clone()]]
                || backend.deleted.as_slice() != [backend.created[0].clone()]
                || !backend.inner.platform_credential_ids().is_empty()
                || std::fs::read(&path).map_err(|_| "vault read failed")? != file_before
            {
                return Err("PRF failure not atomic");
            }
            Ok("rejected-clean")
        }
        "login-pw" => {
            Vault::open_password_for(&path, &password, Edition::Single)
                .map_err(|_| "password login rejected")?;
            Ok("password")
        }
        "login-roaming" => {
            let mut backend = local_backend(&path, &args[2])?;
            Vault::open_any_key(&path, None, &mut backend).map_err(|_| "roaming login rejected")?;
            Ok("roaming-login")
        }
        "login" => {
            let mut backend = local_backend(&path, &args[2])?;
            Vault::open_windows_hello(&path, &mut backend, Edition::Single)
                .map_err(|_| "platform login rejected")?;
            Ok("login")
        }
        _ => Err("unknown command"),
    }
}

fn main() {
    match run() {
        Ok(status) => println!("OK {status}"),
        Err(category) => {
            eprintln!("FAIL {category}");
            std::process::exit(1);
        }
    }
}
