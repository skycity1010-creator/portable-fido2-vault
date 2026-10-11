//! dual_vault_cli：雙群組控管版（v2）mock 端到端驗證 CLI。
//!
//! 只供 `scripts/gate_e2e_dual.py` 以**模擬金鑰**跨行程驗證 vault 層行為；不支援實體金鑰、
//! 不建置進產品執行檔（`vault_cli` 本期仍不支援 v2，見 docs/plans/dual-control.md §5）。
//! `--device NAME` 代表「哪一支實體金鑰」：同名即同一支（excludeCredentials 會拒絕重複註冊），
//! 金鑰只認得自己簽發的 credential（模擬 broker：不在允許清單 → 無法完成該步）。
//!
//! 用法（於 src-tauri/ 下，需 `--features dual-control`）：
//!   dual_vault_cli create      --path P --pw PASS
//!   dual_vault_cli login-pw    --path P --pw PASS
//!   dual_vault_cli register-key --path P --pw PASS --device D --group A|B --label L
//!   dual_vault_cli login-dual  --path P --first D1 [--second D2] [--advance-secs N] [--cancel]
//!   dual_vault_cli remove-key  --path P --pw PASS --label L
//!   dual_vault_cli set-timeout --path P --pw PASS --secs N
//!   dual_vault_cli settings    --path P --pw PASS
//!   dual_vault_cli keys        --path P
//!   dual_vault_cli audit       --path P --pw PASS

use portable_fido_vault::crypto::KeyGroup;
use portable_fido_vault::edition::Edition;
use portable_fido_vault::fido2::{
    DetectedKey, FidoBackend, FidoError, KeyKind, MockBackend, RegisteredCredential,
};
use portable_fido_vault::vault::Vault;
use sha2::{Digest, Sha256};
use std::path::PathBuf;
use std::time::{Duration, Instant};

/// 模擬一支有名字的實體金鑰。credential_id 版面：`[kind, device_tag(8), random(23)]`。
struct SimKey {
    device: String,
}

impl SimKey {
    fn new(device: &str) -> Self {
        Self {
            device: device.to_owned(),
        }
    }

    fn tag(&self) -> [u8; 8] {
        let digest = Sha256::digest(format!("f2vlt-e2e-sim-device|{}", self.device).as_bytes());
        let mut tag = [0u8; 8];
        tag.copy_from_slice(&digest[..8]);
        tag
    }

    fn owns(&self, credential_id: &[u8]) -> bool {
        credential_id.len() >= 9 && credential_id[1..9] == self.tag()[..]
    }
}

impl FidoBackend for SimKey {
    fn detect(&mut self) -> Result<DetectedKey, FidoError> {
        let mut aaguid = [0u8; 16];
        aaguid[..8].copy_from_slice(b"f2vle2e!");
        aaguid[8..].copy_from_slice(&self.tag());
        Ok(DetectedKey {
            kind: KeyKind::Fingerprint,
            label: format!("Sim {}", self.device),
            aaguid,
        })
    }

    fn register_credential(
        &mut self,
        detected: &DetectedKey,
        _pin: Option<&str>,
    ) -> Result<RegisteredCredential, FidoError> {
        use rand::RngCore;
        let mut id = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut id);
        id[0] = detected.kind.to_u8();
        id[1..9].copy_from_slice(&self.tag());
        Ok(RegisteredCredential {
            credential_id: id.to_vec(),
            aaguid: detected.aaguid,
            label: detected.label.clone(),
            kind: detected.kind,
        })
    }

    fn register_credential_excluding(
        &mut self,
        detected: &DetectedKey,
        pin: Option<&str>,
        exclude: &[Vec<u8>],
    ) -> Result<RegisteredCredential, FidoError> {
        if exclude.iter().any(|id| self.owns(id)) {
            return Err(FidoError::CredentialExcluded);
        }
        self.register_credential(detected, pin)
    }

    fn get_prf_secret(
        &mut self,
        credential_id: &[u8],
        _pin: Option<&str>,
    ) -> Result<[u8; 32], FidoError> {
        if !self.owns(credential_id) {
            return Err(FidoError::Internal(
                "模擬金鑰：此金鑰沒有該 credential".into(),
            ));
        }
        Ok(MockBackend::prf_for_credential(credential_id))
    }

    fn get_prf_secret_for_any(
        &mut self,
        credential_ids: &[Vec<u8>],
        pin: Option<&str>,
    ) -> Result<(Vec<u8>, [u8; 32]), FidoError> {
        // 模擬 broker：只有允許清單中屬於這支金鑰的 credential 能完成。
        let id = credential_ids
            .iter()
            .find(|id| self.owns(id))
            .ok_or_else(|| FidoError::Internal("模擬金鑰：此金鑰不在本步驟的允許清單中".into()))?
            .clone();
        let secret = self.get_prf_secret(&id, pin)?;
        Ok((id, secret))
    }

    fn peek_kind(&self) -> KeyKind {
        KeyKind::Fingerprint
    }

    fn prf_supported(&self) -> bool {
        true
    }
}

#[derive(Default)]
struct Opts {
    path: Option<PathBuf>,
    pw: Option<String>,
    device: Option<String>,
    group: Option<String>,
    label: Option<String>,
    first: Option<String>,
    second: Option<String>,
    advance_secs: u64,
    secs: Option<u32>,
    cancel: bool,
}

fn parse(args: &[String]) -> Result<(String, Opts), String> {
    let mut o = Opts::default();
    let mut cmd = None;
    let mut i = 0;
    while i < args.len() {
        let a = args[i].as_str();
        let mut value = || -> Result<String, String> {
            i += 1;
            args.get(i)
                .cloned()
                .ok_or_else(|| format!("{a} 缺少參數值"))
        };
        match a {
            "--path" => o.path = Some(PathBuf::from(value()?)),
            "--pw" => o.pw = Some(value()?),
            "--device" => o.device = Some(value()?),
            "--group" => o.group = Some(value()?),
            "--label" => o.label = Some(value()?),
            "--first" => o.first = Some(value()?),
            "--second" => o.second = Some(value()?),
            "--advance-secs" => {
                o.advance_secs = value()?.parse().map_err(|_| "--advance-secs 需為整數")?
            }
            "--secs" => o.secs = Some(value()?.parse().map_err(|_| "--secs 需為整數")?),
            "--cancel" => o.cancel = true,
            other if !other.starts_with("--") && cmd.is_none() => cmd = Some(other.to_owned()),
            other => return Err(format!("未知參數：{other}")),
        }
        i += 1;
    }
    Ok((cmd.unwrap_or_else(|| "help".into()), o))
}

fn need<'a, T>(v: &'a Option<T>, name: &str) -> Result<&'a T, String> {
    v.as_ref().ok_or_else(|| format!("缺少 {name}"))
}

fn group_of(s: &str) -> Result<KeyGroup, String> {
    match s {
        "A" => Ok(KeyGroup::A),
        "B" => Ok(KeyGroup::B),
        _ => Err("--group 只接受 A 或 B".into()),
    }
}

fn unlock_pw(o: &Opts) -> Result<Vault, String> {
    Vault::open_password_for(
        need(&o.path, "--path")?,
        need(&o.pw, "--pw")?,
        Edition::Dual,
    )
    .map_err(|e| e.to_string())
}

fn last_login_method(v: &Vault) -> String {
    v.audit()
        .iter()
        .rev()
        .find(|a| a.event == "login_success")
        .map(|a| a.method.clone())
        .unwrap_or_default()
}

fn run(cmd: &str, o: &Opts) -> Result<(), String> {
    match cmd {
        "create" => {
            let p = need(&o.path, "--path")?;
            Vault::create_for(p, need(&o.pw, "--pw")?, Edition::Dual).map_err(|e| e.to_string())?;
            println!("OK created edition=dual");
        }
        "login-pw" => {
            let v = unlock_pw(o)?;
            println!("OK login_success method={}", last_login_method(&v));
        }
        "register-key" => {
            let mut v = unlock_pw(o)?;
            let group = group_of(need(&o.group, "--group")?)?;
            let mut key = SimKey::new(need(&o.device, "--device")?);
            let reg = v
                .register_key_for(&mut key, None, need(&o.label, "--label")?, Some(group))
                .map_err(|e| e.to_string())?;
            println!("OK registered label={} group={}", reg.label, group.as_str());
        }
        "login-dual" => {
            let p = need(&o.path, "--path")?;
            let start = Instant::now();
            let mut first = SimKey::new(need(&o.first, "--first")?);
            let pending = Vault::dual_login_begin(p, None, &mut first, &mut || start)
                .map_err(|e| format!("step1: {e}"))?;
            println!(
                "STEP1 first_group={} first_label={} timeout_secs={}",
                pending.first_group().as_str(),
                pending.first_label(),
                pending.timeout_secs()
            );
            if o.cancel {
                pending.cancel().map_err(|e| e.to_string())?;
                println!("OK cancelled");
                return Ok(());
            }
            let later = start
                .checked_add(Duration::from_secs(o.advance_secs))
                .ok_or("--advance-secs 超出可模擬的時間範圍")?;
            let mut second = SimKey::new(need(&o.second, "--second")?);
            let v = Vault::dual_login_complete(pending, None, &mut second, &mut || later)
                .map_err(|e| format!("step2: {e}"))?;
            println!("OK login_success method={}", last_login_method(&v));
        }
        "remove-key" => {
            let mut v = unlock_pw(o)?;
            let label = need(&o.label, "--label")?;
            let header = Vault::read_header(need(&o.path, "--path")?, Edition::Dual)
                .map_err(|e| e.to_string())?;
            let slot = header
                .key_slots
                .iter()
                .find(|s| &s.label == label)
                .ok_or_else(|| format!("找不到金鑰：{label}"))?;
            v.remove_key(&slot.credential_id)
                .map_err(|e| e.to_string())?;
            println!("OK removed label={label}");
        }
        "set-timeout" => {
            let mut v = unlock_pw(o)?;
            let secs = *need(&o.secs, "--secs")?;
            v.set_dual_step_timeout(secs).map_err(|e| e.to_string())?;
            println!("OK timeout_secs={secs}");
        }
        "settings" => {
            let v = unlock_pw(o)?;
            println!(
                "OK authority_timeout_secs={}",
                v.settings()
                    .dual_step_timeout_secs
                    .map(|s| s.to_string())
                    .unwrap_or_else(|| "none".into())
            );
        }
        "keys" => {
            let h = Vault::read_header(need(&o.path, "--path")?, Edition::Dual)
                .map_err(|e| e.to_string())?;
            for s in &h.key_slots {
                println!(
                    "key label={} group={}",
                    s.label,
                    s.group.map(|g| g.as_str()).unwrap_or("-")
                );
            }
            println!("OK keys={}", h.key_slots.len());
        }
        "audit" => {
            let v = unlock_pw(o)?;
            for a in v.audit() {
                println!("[{}] method={} detail={}", a.event, a.method, a.detail);
            }
            println!("OK audit={}", v.audit().len());
        }
        _ => {
            println!("見原始碼頂端說明（僅供 scripts/gate_e2e_dual.py 使用）");
            return Err("未知指令".into());
        }
    }
    Ok(())
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let code = match parse(&args).and_then(|(cmd, o)| run(&cmd, &o)) {
        Ok(()) => 0,
        Err(e) => {
            println!("FAIL {e}");
            1
        }
    };
    std::process::exit(code);
}
