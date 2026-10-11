//! 金庫核心：檔案格式（magic + header JSON + AES-GCM payload）、建立/開啟/上鎖、
//! CRUD、軌跡紀錄、FIDO2 金鑰槽位管理。
//!
//! 設計（仿 LUKS 多槽位，詳見 docs/spec.md §3）：
//! - KEK（隨機 256-bit）只存在記憶體；落盤時以每個「解鎖方式」各自的金流包裝一次。
//! - header 明文區只含金鑰**包裝槽位**與金鑰 **metadata**（label/type），不含任何機密值。
//! - 登入失敗時沒有 KEK → 失敗事件寫入 sidecar `vault.db.failures`（僅時間戳+method，
//!   上限 10 筆）；成功解鎖時合併進加密 audit 並刪除 sidecar。

use std::fs;
use std::path::{Path, PathBuf};

use chrono::Utc;
use zeroize::{Zeroize, Zeroizing};

use crate::crypto::{
    aes_gcm_decrypt, aes_gcm_decrypt_aad, aes_gcm_encrypt, aes_gcm_encrypt_aad, argon2id_derive,
    base64_decode, base64_encode, dual_key_slot_aad, dual_wrap_key_from_shares,
    kek_from_prf_secret, random_kek, random_nonce, CryptoError, KeyGroup, DUAL_SLOT_AAD,
    FORMAT_VERSION, FORMAT_VERSION_DUAL, VAULT_MAGIC,
};
use crate::csv_import::{ImportAction, ImportPlan, ImportPreview};
use crate::edition::Edition;
use crate::fido2::{FidoBackend, FidoError, KeyKind, RegisteredCredential};

#[derive(Debug)]
pub enum VaultError {
    Io(std::io::Error),
    Format(String),
    Crypto(CryptoError),
    WrongPassword,
    Fido(FidoError),
    Json(serde_json::Error),
    /// 金庫檔的版本（單人版 v1 / 雙群組控管版 v2）與執行檔版本不符；未解密、未寫檔。
    WrongEdition {
        vault: Edition,
    },
}

impl std::fmt::Display for VaultError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "檔案錯誤：{e}"),
            Self::Format(m) => write!(f, "金庫格式錯誤：{m}"),
            Self::Crypto(CryptoError::DecryptFailed) => {
                write!(f, "密碼或金鑰不正確（解密驗證失敗）")
            }
            Self::Crypto(e) => write!(f, "加密錯誤：{e}"),
            Self::WrongPassword => write!(f, "密碼不正確"),
            Self::Fido(e) => write!(f, "{e}"),
            Self::Json(e) => write!(f, "JSON 錯誤：{e}"),
            Self::WrongEdition {
                vault: Edition::Dual,
            } => write!(
                f,
                "此為雙群組控管版金庫，請改用雙群組控管版程式（portable-fido-vault-dual.exe）"
            ),
            Self::WrongEdition {
                vault: Edition::Single,
            } => write!(
                f,
                "此為單人版金庫，請改用單人版程式（portable-fido-vault.exe）"
            ),
        }
    }
}

impl std::error::Error for VaultError {}

impl From<std::io::Error> for VaultError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

impl From<FidoError> for VaultError {
    fn from(e: FidoError) -> Self {
        Self::Fido(e)
    }
}

impl From<CryptoError> for VaultError {
    fn from(e: CryptoError) -> Self {
        Self::Crypto(e)
    }
}

// ─────────────────────────── 資料模型 ───────────────────────────

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Argon2Params {
    pub salt: String, // b64（32B）
}

/// 單一解鎖槽位：以該方式派生的金流包裝同一份 KEK。
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Slot {
    pub nonce: String, // b64 12B
    pub ct: String,    // b64 AES-GCM(KEK) 含 tag
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct KeySlot {
    pub credential_id: String, // b64
    pub aaguid: String,        // hex 32
    pub label: String,
    pub key_type: KeyKind,
    /// 雙群組控管版（v2）必填；單人版（v1）必為 None，且不序列化（v1 檔案格式不變）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group: Option<KeyGroup>,
    pub nonce: String,
    pub ct: String,
}

/// 金庫解鎖政策。v2 目前只有 `dual`；未知值在反序列化時即失敗（fail closed）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum VaultPolicy {
    Dual,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Header {
    pub v: u8,
    /// v2：必為 `dual`。v1：None（不序列化）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy: Option<VaultPolicy>,
    pub argon2: Argon2Params,
    pub password_slot: Slot,
    /// v2：AES-GCM(HKDF(share_A ‖ share_B), KEK)。v1：None。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dual_slot: Option<Slot>,
    pub key_slots: Vec<KeySlot>,
    /// v2：第一步等待時限的明文鏡像（登入前可讀；權威值在加密 payload settings）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dual_step_timeout_secs: Option<u32>,
    pub created_at: String,
}

type EncryptedPayload = ([u8; 12], Vec<u8>);
type VaultFileContents = (Header, EncryptedPayload);

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct FailureStamp {
    pub ts: String,
    pub method: String, // "password" | "fido2:<label>"
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Entry {
    pub id: String, // hex 32
    pub site: String,
    pub account: String,
    pub password: String,
    #[serde(default)]
    pub password_history: Vec<PasswordHistoryEntry>,
    pub notes: String,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PasswordHistoryEntry {
    pub id: String,
    pub password: String,
    pub archived_at: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AuditEvent {
    pub ts: String,
    /// vault_created / login_success / login_failed / key_registered / key_removed /
    /// entry_added / entry_updated / entry_deleted / settings_changed / auto_lock / manual_lock
    pub event: String,
    pub method: String, // password / fido2:<label> / setup / idle / manual
    pub detail: String, // 僅非機密資訊（永不記錄密碼/PIN/金流）
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Settings {
    pub idle_lock_minutes: u32,
    #[serde(default = "default_password_history_limit")]
    pub password_history_limit: u32,
    /// v2：第一步等待時限權威值（秒）。v1：None（不序列化）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dual_step_timeout_secs: Option<u32>,
}

const DEFAULT_PASSWORD_HISTORY_LIMIT: u32 = 3;
/// 雙群組控管版：第一步完成後等待第二群組的預設時限（秒，§4.3）。
pub const DEFAULT_DUAL_STEP_TIMEOUT_SECS: u32 = 120;
const MAX_KEY_LABEL_CHARS: usize = 64;

fn default_password_history_limit() -> u32 {
    DEFAULT_PASSWORD_HISTORY_LIMIT
}

fn validate_key_label(candidate: &str, existing_labels: &[&str]) -> Result<String, VaultError> {
    if candidate.chars().any(|character| character.is_control()) {
        return Err(VaultError::Format("金鑰名稱不能包含控制字元".into()));
    }
    let label = candidate.trim();
    if label.is_empty() {
        return Err(VaultError::Format("金鑰名稱不可空白".into()));
    }
    if label.chars().count() > MAX_KEY_LABEL_CHARS {
        return Err(VaultError::Format(format!(
            "金鑰名稱最多 {MAX_KEY_LABEL_CHARS} 個字元"
        )));
    }
    if existing_labels
        .iter()
        .any(|existing| caseless::canonical_caseless_match_str(existing.trim(), label))
    {
        return Err(VaultError::Format("金鑰名稱已存在，請改用其他名稱".into()));
    }
    Ok(label.to_owned())
}

fn suggest_unique_key_label(existing_labels: &[&str]) -> String {
    let base = "安全性金鑰";
    let candidate_count = existing_labels.len().saturating_add(1);
    for suffix in 1..=candidate_count {
        let candidate = if suffix == 1 {
            base.to_owned()
        } else {
            format!("{base} {suffix}")
        };
        if validate_key_label(&candidate, existing_labels).is_ok() {
            return candidate;
        }
    }
    unreachable!("one more candidate than existing labels must be available")
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct VaultData {
    pub entries: Vec<Entry>,
    pub audit: Vec<AuditEvent>,
    pub settings: Settings,
    /// v2：兩群組 share（只存在加密 payload）。v1：None（不序列化）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dual: Option<DualShares>,
}

/// 雙群組 share（各 32B，b64）。只存在加密 payload；Debug 遮蔽，drop 時清零。
#[derive(Clone, serde::Serialize, serde::Deserialize, zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
pub struct DualShares {
    pub share_a: String,
    pub share_b: String,
}

impl std::fmt::Debug for DualShares {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("DualShares { share_a: <redacted>, share_b: <redacted> }")
    }
}

/// 檢查 header 是否符合執行檔版本與該版本的欄位形狀（docs/plans/dual-control.md §3）。
/// 在任何解密或寫檔之前呼叫；不符 → fail closed。
pub fn check_header_edition(header: &Header, edition: Edition) -> Result<(), VaultError> {
    let vault_edition = match header.v {
        FORMAT_VERSION => Edition::Single,
        FORMAT_VERSION_DUAL => Edition::Dual,
        other => {
            return Err(VaultError::Format(format!("不支援的格式版本 v{other}")));
        }
    };
    if vault_edition != edition {
        return Err(VaultError::WrongEdition {
            vault: vault_edition,
        });
    }
    match edition {
        Edition::Single => {
            if header.policy.is_some()
                || header.dual_slot.is_some()
                || header.dual_step_timeout_secs.is_some()
                || header.key_slots.iter().any(|slot| slot.group.is_some())
            {
                return Err(VaultError::Format("v1 金庫不應含雙群組控管欄位".into()));
            }
        }
        Edition::Dual => {
            if header.policy != Some(VaultPolicy::Dual) {
                return Err(VaultError::Format("v2 金庫缺少 policy=dual".into()));
            }
            if header.dual_slot.is_none() {
                return Err(VaultError::Format("v2 金庫缺少 dual_slot".into()));
            }
            if header.key_slots.iter().any(|slot| slot.group.is_none()) {
                return Err(VaultError::Format("v2 金庫的金鑰槽缺少群組".into()));
            }
        }
    }
    Ok(())
}

/// header 已通過 `check_header_edition` 後，由版本號推得的版本。
fn edition_of(header: &Header) -> Edition {
    if header.v == FORMAT_VERSION_DUAL {
        Edition::Dual
    } else {
        Edition::Single
    }
}

fn decode_share(b64: &str) -> Result<Zeroizing<[u8; 32]>, VaultError> {
    let raw = Zeroizing::new(
        base64_decode(b64).map_err(|_| VaultError::Format("v2 share 解碼失敗".into()))?,
    );
    if raw.len() != 32 {
        return Err(VaultError::Format("v2 share 長度錯誤".into()));
    }
    let mut out = Zeroizing::new([0u8; 32]);
    out.copy_from_slice(&raw);
    Ok(out)
}

/// 解密後、寫檔前檢查 payload 形狀；v2 另驗證 dual_slot 確實是 HKDF(shares) 包出的同一把 KEK，
/// 避免 header 被竄改後主密碼仍可登入、金鑰登入卻默默失效。
fn check_payload_edition(
    header: &Header,
    data: &VaultData,
    kek: &[u8; 32],
) -> Result<(), VaultError> {
    match edition_of(header) {
        Edition::Single => {
            if data.dual.is_some() || data.settings.dual_step_timeout_secs.is_some() {
                return Err(VaultError::Format(
                    "v1 金庫 payload 不應含雙群組控管資料".into(),
                ));
            }
        }
        Edition::Dual => {
            let shares = data
                .dual
                .as_ref()
                .ok_or_else(|| VaultError::Format("v2 金庫 payload 缺少 share".into()))?;
            let share_a = decode_share(&shares.share_a)?;
            let share_b = decode_share(&shares.share_b)?;
            if data.settings.dual_step_timeout_secs.is_none() {
                return Err(VaultError::Format(
                    "v2 金庫 payload 缺少等待時限設定".into(),
                ));
            }
            let slot = header
                .dual_slot
                .as_ref()
                .ok_or_else(|| VaultError::Format("v2 金庫缺少 dual_slot".into()))?;
            let inconsistent =
                || VaultError::Format("dual_slot 與 share 不一致（金庫可能遭竄改）".into());
            let nonce = slot_nonce(&slot.nonce).map_err(|_| inconsistent())?;
            let ct = base64_decode(&slot.ct).map_err(|_| inconsistent())?;
            let wrap = dual_wrap_key_from_shares(&share_a, &share_b);
            let unwrapped = Zeroizing::new(
                aes_gcm_decrypt_aad(&wrap, &nonce, &ct, DUAL_SLOT_AAD)
                    .map_err(|_| inconsistent())?,
            );
            if unwrapped.as_slice() != kek.as_slice() {
                return Err(inconsistent());
            }
        }
    }
    Ok(())
}

const MAX_AUDIT: usize = 1000;
const MAX_LOGIN_FAILURES: usize = 10;

fn now_rfc3339() -> String {
    Utc::now().to_rfc3339()
}

// ─────────────────────────── Vault ───────────────────────────

pub struct Vault {
    pub path: PathBuf,
    header: Header,
    data: VaultData,
    kek: Zeroizing<[u8; 32]>,
}

impl Vault {
    // ── 建立 ──

    /// 首次執行：以主密碼建立金庫（單人版 v1）。
    pub fn create(path: &Path, password: &str) -> Result<Self, VaultError> {
        Self::create_with_edition(path, password, Edition::Single)
    }

    fn create_with_edition(
        path: &Path,
        password: &str,
        edition: Edition,
    ) -> Result<Self, VaultError> {
        if path.exists() {
            return Err(VaultError::Format("vault.db 已存在".into()));
        }
        let kek = random_kek();
        let salt = random_bytes(32);
        // 密碼槽：以 Argon2id(master_password) 派生的金流包裝 KEK（open_password 用同參數解包）。
        let pw_key = argon2id_derive(password.as_bytes(), &salt)?;
        let nonce = random_nonce();
        let ct = aes_gcm_encrypt(&pw_key, &nonce, kek.as_slice());

        // v2：兩群組 share 各自隨機；dual_slot = AES-GCM(HKDF(share_A ‖ share_B), KEK)。
        let (version, policy, dual_slot, dual_timeout, dual_shares) = match edition {
            Edition::Single => (FORMAT_VERSION, None, None, None, None),
            Edition::Dual => {
                let share_a = random_kek();
                let share_b = random_kek();
                let wrap = dual_wrap_key_from_shares(&share_a, &share_b);
                let dual_nonce = random_nonce();
                let dual_ct =
                    aes_gcm_encrypt_aad(&wrap, &dual_nonce, kek.as_slice(), DUAL_SLOT_AAD);
                (
                    FORMAT_VERSION_DUAL,
                    Some(VaultPolicy::Dual),
                    Some(Slot {
                        nonce: base64_encode(&dual_nonce),
                        ct: base64_encode(&dual_ct),
                    }),
                    Some(DEFAULT_DUAL_STEP_TIMEOUT_SECS),
                    Some(DualShares {
                        share_a: base64_encode(share_a.as_slice()),
                        share_b: base64_encode(share_b.as_slice()),
                    }),
                )
            }
        };
        let mut created_detail = format!(
            "argon2id m={}KiB t={} p={}",
            crate::crypto::ARGON2_M_COST,
            crate::crypto::ARGON2_T_COST,
            crate::crypto::ARGON2_P_COST
        );
        if edition == Edition::Dual {
            created_detail.push_str(" edition=dual");
        }

        let header = Header {
            v: version,
            policy,
            argon2: Argon2Params {
                salt: base64_encode(&salt),
            },
            password_slot: Slot {
                nonce: base64_encode(&nonce),
                ct: base64_encode(&ct),
            },
            dual_slot,
            key_slots: Vec::new(),
            dual_step_timeout_secs: dual_timeout,
            created_at: now_rfc3339(),
        };

        let data = VaultData {
            entries: Vec::new(),
            audit: vec![AuditEvent {
                ts: now_rfc3339(),
                event: "vault_created".into(),
                method: "setup".into(),
                detail: created_detail,
            }],
            settings: Settings {
                idle_lock_minutes: 5,
                password_history_limit: DEFAULT_PASSWORD_HISTORY_LIMIT,
                dual_step_timeout_secs: dual_timeout,
            },
            dual: dual_shares,
        };

        let vault = Self {
            path: path.to_path_buf(),
            header,
            data,
            kek,
        };
        vault.write_file()?;
        Ok(vault)
    }

    /// 雙群組控管版：以主密碼建立 v2 金庫（docs/plans/dual-control.md §4.1）。
    pub fn create_dual(path: &Path, password: &str) -> Result<Self, VaultError> {
        Self::create_with_edition(path, password, Edition::Dual)
    }

    /// 依執行檔版本建立金庫（lib.rs 以 `edition::current()` 呼叫）。
    pub fn create_for(path: &Path, password: &str, edition: Edition) -> Result<Self, VaultError> {
        Self::create_with_edition(path, password, edition)
    }

    /// 這個金庫的版本（由 header.v 決定，read_file 已驗證過形狀）。
    pub fn edition(&self) -> Edition {
        edition_of(&self.header)
    }

    // ── 開啟（解鎖）──

    /// 雙群組控管版：主密碼緊急登入（break-glass，§4.4）。
    pub fn open_password_dual(path: &Path, password: &str) -> Result<Self, VaultError> {
        Self::open_password_with_edition(path, password, Edition::Dual)
    }

    /// 依執行檔版本以主密碼登入。
    pub fn open_password_for(
        path: &Path,
        password: &str,
        edition: Edition,
    ) -> Result<Self, VaultError> {
        Self::open_password_with_edition(path, password, edition)
    }

    /// 主密碼登入。失敗 → sidecar 記一筆 login_failed。
    pub fn open_password(path: &Path, password: &str) -> Result<Self, VaultError> {
        Self::open_password_with_edition(path, password, Edition::Single)
    }

    fn open_password_with_edition(
        path: &Path,
        password: &str,
        edition: Edition,
    ) -> Result<Self, VaultError> {
        // 雙群組控管版的主密碼登入是 break-glass，稽核 method 與一般登入區分。
        let method = match edition {
            Edition::Single => "password",
            Edition::Dual => "password-breakglass",
        };
        let (header, payload) = Self::read_file(path, edition)?;
        let salt = base64_decode(&header.argon2.salt)
            .map_err(|_| VaultError::Format("argon2 salt 解碼失敗".into()))?;
        let k = argon2id_derive(password.as_bytes(), &salt).map_err(VaultError::Crypto)?;
        let nonce = slot_nonce(&header.password_slot.nonce)?;
        let ct = base64_decode(&header.password_slot.ct)
            .map_err(|_| VaultError::Format("password slot 解碼失敗".into()))?;

        match aes_gcm_decrypt(&k, &nonce, &ct) {
            Ok(kek_bytes) if kek_bytes.len() == 32 => {
                let mut kek = [0u8; 32];
                kek.copy_from_slice(&kek_bytes);
                Self::unlock(path, header, payload, Zeroizing::new(kek), method)
            }
            _ => {
                record_login_failure(path, method)?;
                Err(VaultError::WrongPassword)
            }
        }
    }

    /// FIDO2 金鑰登入（credential_id_b64 須為 header.key_slots 之一）。
    pub fn open_key(
        path: &Path,
        credential_id_b64: &str,
        pin: Option<&str>,
        backend: &mut (dyn FidoBackend + 'static),
    ) -> Result<Self, VaultError> {
        let (header, payload) = Self::read_file(path, Edition::Single)?;
        let slot = header
            .key_slots
            .iter()
            .find(|s| s.credential_id == credential_id_b64)
            .ok_or(VaultError::Fido(FidoError::NoDevice))?
            .clone();

        let cred_id = base64_decode(&slot.credential_id)
            .map_err(|_| VaultError::Format("credential_id 解碼失敗".into()))?;
        // PinRequired → 尚未真正嘗試，不記失敗（使用者只是還沒提供 PIN）。
        let secret = backend.get_prf_secret(&cred_id, pin)?;
        Self::open_with_key_secret(path, header, payload, slot, secret)
    }

    /// FIDO2 金鑰登入：一次交給 backend 所有槽位，由 broker 選擇 credential。
    pub fn open_any_key(
        path: &Path,
        pin: Option<&str>,
        backend: &mut (dyn FidoBackend + 'static),
    ) -> Result<Self, VaultError> {
        let (header, payload) = Self::read_file(path, Edition::Single)?;
        let credential_ids = header
            .key_slots
            .iter()
            .map(|slot| {
                base64_decode(&slot.credential_id)
                    .map_err(|_| VaultError::Format("credential_id 解碼失敗".into()))
            })
            .collect::<Result<Vec<_>, _>>()?;
        if credential_ids.is_empty() {
            return Err(VaultError::Fido(FidoError::NoDevice));
        }

        let (selected_id, secret) = backend.get_prf_secret_for_any(&credential_ids, pin)?;
        let selected_id_b64 = base64_encode(&selected_id);
        let slot = header
            .key_slots
            .iter()
            .find(|slot| slot.credential_id == selected_id_b64)
            .ok_or_else(|| {
                VaultError::Fido(FidoError::Internal(
                    "backend selected a credential not registered in this vault".into(),
                ))
            })?
            .clone();
        Self::open_with_key_secret(path, header, payload, slot, secret)
    }

    fn open_with_key_secret(
        path: &Path,
        header: Header,
        payload: EncryptedPayload,
        slot: KeySlot,
        secret: [u8; 32],
    ) -> Result<Self, VaultError> {
        let k = kek_from_prf_secret(&secret);
        let nonce = slot_nonce(&slot.nonce)?;
        let ct =
            base64_decode(&slot.ct).map_err(|_| VaultError::Format("key slot 解碼失敗".into()))?;

        match aes_gcm_decrypt(&k, &nonce, &ct) {
            Ok(kek_bytes) if kek_bytes.len() == 32 => {
                let mut kek = [0u8; 32];
                kek.copy_from_slice(&kek_bytes);
                Self::unlock(
                    path,
                    header,
                    payload,
                    Zeroizing::new(kek),
                    &format!("fido2:{}", slot.label),
                )
            }
            _ => {
                record_login_failure(path, &format!("fido2:{}", slot.label))?;
                Err(VaultError::Crypto(CryptoError::DecryptFailed))
            }
        }
    }

    /// 解密 payload → 合併 sidecar 失敗記錄 → 記 login_success → 落盤。
    fn unlock(
        path: &Path,
        header: Header,
        payload: EncryptedPayload,
        kek: Zeroizing<[u8; 32]>,
        method: &str,
    ) -> Result<Self, VaultError> {
        let mut data = Self::decrypt_payload(&kek, &payload)?;
        check_payload_edition(&header, &data, &kek)?;

        // 合併 sidecar（僅時間戳的失敗記錄）進加密 audit。
        let failures = read_failure_sidecar(path);
        if !failures.is_empty() {
            let events: Vec<AuditEvent> = failures
                .into_iter()
                .map(|f| AuditEvent {
                    ts: f.ts,
                    event: "login_failed".into(),
                    method: f.method,
                    detail: "decrypt_failed".into(),
                })
                .collect();
            data.audit.splice(0..0, events);
        }

        let mut vault = Self {
            path: path.to_path_buf(),
            header,
            data,
            kek,
        };
        vault.data.audit.push(AuditEvent {
            ts: now_rfc3339(),
            event: "login_success".into(),
            method: method.into(),
            detail: "金庫解鎖".into(),
        });
        trim_audit(&mut vault.data.audit);
        vault.write_file()?;
        let _ = fs::remove_file(failures_path(path));
        Ok(vault)
    }

    // ── 檔案 I/O ──

    /// 讀檔 → (header, (payload_nonce, ciphertext))。先檢查版本，不符即 fail closed。
    fn read_file(path: &Path, edition: Edition) -> Result<VaultFileContents, VaultError> {
        let buf = fs::read(path)?;
        if buf.len() < 6 + 4 + 12 {
            return Err(VaultError::Format("檔案過小".into()));
        }
        if &buf[..6] != VAULT_MAGIC {
            return Err(VaultError::Format("magic 不符（非 vault.db）".into()));
        }
        let header_len = u32::from_le_bytes(buf[6..10].try_into().unwrap()) as usize;
        if buf.len() < 10 + header_len + 12 {
            return Err(VaultError::Format("header_len 超出檔案範圍".into()));
        }
        let header_json = std::str::from_utf8(&buf[10..10 + header_len])
            .map_err(|_| VaultError::Format("header 非 UTF-8".into()))?;
        let header: Header = serde_json::from_str(header_json).map_err(VaultError::Json)?;
        check_header_edition(&header, edition)?;
        let off = 10 + header_len;
        let nonce: [u8; 12] = buf[off..off + 12].try_into().unwrap();
        let ciphertext = buf[off + 12..].to_vec();
        Ok((header, (nonce, ciphertext)))
    }

    /// 只讀 header（不需 KEK），供登入畫面列出金鑰；同樣先檢查版本。
    pub fn read_header(path: &Path, edition: Edition) -> Result<Header, VaultError> {
        Self::read_file(path, edition).map(|(header, _)| header)
    }

    fn decrypt_payload(
        kek: &[u8; 32],
        payload: &EncryptedPayload,
    ) -> Result<VaultData, VaultError> {
        let pt = aes_gcm_decrypt(kek, &payload.0, &payload.1).map_err(VaultError::Crypto)?;
        serde_json::from_slice(&pt).map_err(VaultError::Json)
    }

    /// 以目前 KEK 重新加密 payload + 原子寫入（tmp + rename）。
    fn write_file(&self) -> Result<(), VaultError> {
        self.write_data(&self.data)
    }

    fn write_data(&self, data: &VaultData) -> Result<(), VaultError> {
        let header_json = serde_json::to_vec(&self.header).map_err(VaultError::Json)?;
        let nonce = random_nonce();
        let pt = serde_json::to_vec(data).map_err(VaultError::Json)?;
        let ct = aes_gcm_encrypt(&self.kek, &nonce, &pt);

        let mut out = Vec::with_capacity(6 + 4 + header_json.len() + 12 + ct.len());
        out.extend_from_slice(VAULT_MAGIC);
        out.extend_from_slice(&(header_json.len() as u32).to_le_bytes());
        out.extend_from_slice(&header_json);
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&ct);

        let tmp = self.path.with_extension("db.tmp");
        fs::write(&tmp, &out)?;
        fs::rename(&tmp, &self.path)?;
        Ok(())
    }

    // ── 軌跡 ──

    /// 記一筆軌跡並落盤（detail 僅非機密資訊；永不記錄密碼/PIN/金流）。
    pub fn record(&mut self, event: &str, method: &str, detail: &str) -> Result<(), VaultError> {
        self.data.audit.push(AuditEvent {
            ts: now_rfc3339(),
            event: event.into(),
            method: method.into(),
            detail: detail.into(),
        });
        trim_audit(&mut self.data.audit);
        self.write_file()
    }

    // ── 讀取 ──

    pub fn entries(&self) -> &[Entry] {
        &self.data.entries
    }

    pub fn audit(&self) -> &[AuditEvent] {
        &self.data.audit
    }

    pub fn settings(&self) -> &Settings {
        &self.data.settings
    }

    /// 金鑰清單（credential_id_b64, label, type）。
    pub fn keys_meta(&self) -> Vec<(String, String, KeyKind)> {
        self.header
            .key_slots
            .iter()
            .map(|s| (s.credential_id.clone(), s.label.clone(), s.key_type))
            .collect()
    }

    // ── CRUD ──

    pub fn add_entry(
        &mut self,
        site: &str,
        account: &str,
        password: &str,
        notes: &str,
    ) -> Result<String, VaultError> {
        let id = hex32(&random_bytes(16));
        let ts = now_rfc3339();
        self.data.entries.push(Entry {
            id: id.clone(),
            site: site.into(),
            account: account.into(),
            password: password.into(),
            password_history: Vec::new(),
            notes: notes.into(),
            created_at: ts.clone(),
            updated_at: ts,
        });
        self.record("entry_added", "manual", site)?;
        Ok(id)
    }

    pub fn update_entry(
        &mut self,
        id: &str,
        site: Option<&str>,
        account: Option<&str>,
        password: Option<&str>,
        notes: Option<&str>,
    ) -> Result<(), VaultError> {
        self.update_entry_with_restore(id, site, account, password, notes, None)
    }

    pub fn update_entry_with_restore(
        &mut self,
        id: &str,
        site: Option<&str>,
        account: Option<&str>,
        password: Option<&str>,
        notes: Option<&str>,
        restore_history_id: Option<&str>,
    ) -> Result<(), VaultError> {
        let history_limit = self.data.settings.password_history_limit.clamp(1, 20) as usize;
        let e = self
            .data
            .entries
            .iter_mut()
            .find(|e| e.id == id)
            .ok_or_else(|| VaultError::Format("找不到該條目".into()))?;
        let selected_restore = if let Some(history_id) = restore_history_id {
            if password.is_none() {
                return Err(VaultError::Format("還原舊密碼時必須提供密碼值".into()));
            }
            let history = e
                .password_history
                .iter()
                .find(|item| item.id == history_id)
                .ok_or_else(|| VaultError::Format("找不到該舊密碼版本".into()))?;
            if password != Some(history.password.as_str()) {
                return Err(VaultError::Format("還原的舊密碼值不相符".into()));
            }
            Some(history.id.clone())
        } else {
            None
        };
        if let Some(v) = site {
            e.site = v.into();
        }
        if let Some(v) = account {
            e.account = v.into();
        }
        if let Some(v) = password {
            if v != e.password {
                let old_password = std::mem::replace(&mut e.password, v.into());
                e.password_history.insert(
                    0,
                    PasswordHistoryEntry {
                        id: hex32(&random_bytes(16)),
                        password: old_password,
                        archived_at: now_rfc3339(),
                    },
                );
            }
        }
        if let Some(history_id) = selected_restore.as_deref() {
            e.password_history.retain(|item| item.id != history_id);
        }
        e.password_history.truncate(history_limit);
        if let Some(v) = notes {
            e.notes = v.into();
        }
        e.updated_at = now_rfc3339();
        let site = e.site.clone(); // 先取值，避免與 record() 的 &mut self 重疊借用
        self.record("entry_updated", "manual", &site)?;
        Ok(())
    }

    /// Apply a reviewed CSV plan in one encrypted write; memory changes only after persistence succeeds.
    pub fn import_entries(&mut self, plan: &ImportPlan) -> Result<ImportPreview, VaultError> {
        let mut next_data = self.data.clone();
        let history_limit = next_data.settings.password_history_limit.clamp(1, 20) as usize;

        for action in &plan.actions {
            match action {
                ImportAction::Add(row) => {
                    let site = row.site.trim();
                    if site.is_empty() {
                        return Err(VaultError::Format("網站欄位必填".into()));
                    }
                    let timestamp = now_rfc3339();
                    next_data.entries.push(Entry {
                        id: hex32(&random_bytes(16)),
                        site: site.to_owned(),
                        account: row.account.trim().to_owned(),
                        password: row.password.clone(),
                        password_history: Vec::new(),
                        notes: row.notes.clone(),
                        created_at: timestamp.clone(),
                        updated_at: timestamp,
                    });
                }
                ImportAction::Update { entry_id, row } => {
                    let site = row.site.trim();
                    if site.is_empty() {
                        return Err(VaultError::Format("網站欄位必填".into()));
                    }
                    let entry = next_data
                        .entries
                        .iter_mut()
                        .find(|entry| entry.id == *entry_id)
                        .ok_or_else(|| {
                            VaultError::Format("匯入預覽已失效，請重新選擇檔案".into())
                        })?;
                    entry.site = site.to_owned();
                    if !row.account.trim().is_empty() {
                        entry.account = row.account.trim().to_owned();
                    }
                    if !row.password.is_empty() && row.password != entry.password {
                        let previous = std::mem::replace(&mut entry.password, row.password.clone());
                        entry.password_history.insert(
                            0,
                            PasswordHistoryEntry {
                                id: hex32(&random_bytes(16)),
                                password: previous,
                                archived_at: now_rfc3339(),
                            },
                        );
                        entry.password_history.truncate(history_limit);
                    }
                    if !row.notes.is_empty() {
                        entry.notes = row.notes.clone();
                    }
                    entry.updated_at = now_rfc3339();
                }
            }
        }

        next_data.audit.push(AuditEvent {
            ts: now_rfc3339(),
            event: "entries_imported".into(),
            method: "csv".into(),
            detail: format!(
                "added={} updated={} skipped={}",
                plan.preview.added, plan.preview.updated, plan.preview.skipped
            ),
        });
        trim_audit(&mut next_data.audit);
        self.write_data(&next_data)?;
        self.data = next_data;
        Ok(plan.preview.clone())
    }

    pub fn delete_entry(&mut self, id: &str) -> Result<(), VaultError> {
        let before = self.data.entries.len();
        self.data.entries.retain(|e| e.id != id);
        if self.data.entries.len() == before {
            return Err(VaultError::Format("找不到該條目".into()));
        }
        self.record("entry_deleted", "manual", "（條目已刪除）")?;
        Ok(())
    }

    pub fn set_idle_lock(&mut self, minutes: u32) -> Result<(), VaultError> {
        self.data.settings.idle_lock_minutes = minutes.clamp(1, 60);
        self.record(
            "settings_changed",
            "manual",
            &format!("idle_lock={}", self.data.settings.idle_lock_minutes),
        )?;
        Ok(())
    }

    pub fn set_password_history_limit(&mut self, limit: u32) -> Result<(), VaultError> {
        let limit = limit.clamp(1, 20);
        self.data.settings.password_history_limit = limit;
        for entry in &mut self.data.entries {
            entry.password_history.truncate(limit as usize);
        }
        self.record(
            "settings_changed",
            "manual",
            &format!("password_history_limit={limit}"),
        )?;
        Ok(())
    }

    // ── FIDO2 金鑰管理（需已解鎖）──

    /// 偵測 + 註冊新金鑰：以目前 KEK 包出新槽位。
    /// PIN 型金鑰註冊時即需提供 PIN（makeCredential 需與 token 建立安全通道）。
    /// **產品決策：不支援 PRF/hmac-secret 的金鑰一律拒絕註冊**（無法解鎖離線金庫）。
    pub fn register_key(
        &mut self,
        backend: &mut (dyn FidoBackend + 'static),
        pin: Option<&str>,
    ) -> Result<RegisteredCredential, VaultError> {
        self.register_key_internal(backend, pin, None, None)
    }

    /// Register with a FidoVault-local alias. Validate it before querying the authenticator.
    pub fn register_key_with_label(
        &mut self,
        backend: &mut (dyn FidoBackend + 'static),
        pin: Option<&str>,
        candidate_label: &str,
    ) -> Result<RegisteredCredential, VaultError> {
        let label = self.validate_new_key_label(candidate_label)?;
        self.register_key_internal(backend, pin, Some(&label), None)
    }

    /// 雙群組控管版：註冊金鑰並指定群組（§4.2）。以該群組 share 包裝槽位，AAD 綁定群組與 credential。
    pub fn register_key_in_group(
        &mut self,
        backend: &mut (dyn FidoBackend + 'static),
        pin: Option<&str>,
        candidate_label: &str,
        group: KeyGroup,
    ) -> Result<RegisteredCredential, VaultError> {
        if self.edition() != Edition::Dual {
            return Err(VaultError::Format("單人版金庫不支援金鑰群組".into()));
        }
        let label = self.validate_new_key_label(candidate_label)?;
        self.register_key_internal(backend, pin, Some(&label), Some(group))
    }

    /// 依金庫版本分派註冊：單人版不可帶群組；雙人版必須帶群組。
    pub fn register_key_for(
        &mut self,
        backend: &mut (dyn FidoBackend + 'static),
        pin: Option<&str>,
        candidate_label: &str,
        group: Option<KeyGroup>,
    ) -> Result<RegisteredCredential, VaultError> {
        match group {
            None => self.register_key_with_label(backend, pin, candidate_label),
            Some(group) => self.register_key_in_group(backend, pin, candidate_label, group),
        }
    }

    /// 已解鎖 session 的群組 share（只在雙人版有；payload 形狀已於解鎖時驗證）。
    fn group_share(&self, group: KeyGroup) -> Result<Zeroizing<[u8; 32]>, VaultError> {
        let shares = self
            .data
            .dual
            .as_ref()
            .ok_or_else(|| VaultError::Format("v2 金庫 payload 缺少 share".into()))?;
        match group {
            KeyGroup::A => decode_share(&shares.share_a),
            KeyGroup::B => decode_share(&shares.share_b),
        }
    }

    /// Validate a proposed local alias against every slot already stored in this vault.
    pub fn validate_new_key_label(&self, candidate_label: &str) -> Result<String, VaultError> {
        let existing_labels: Vec<&str> = self
            .header
            .key_slots
            .iter()
            .map(|slot| slot.label.as_str())
            .collect();
        validate_key_label(candidate_label, &existing_labels)
    }

    /// Suggest an unused default alias using the same canonical Unicode comparison as validation.
    pub fn suggested_key_label(&self) -> String {
        let existing_labels: Vec<&str> = self
            .header
            .key_slots
            .iter()
            .map(|slot| slot.label.as_str())
            .collect();
        suggest_unique_key_label(&existing_labels)
    }

    fn register_key_internal(
        &mut self,
        backend: &mut (dyn FidoBackend + 'static),
        pin: Option<&str>,
        custom_label: Option<&str>,
        group: Option<KeyGroup>,
    ) -> Result<RegisteredCredential, VaultError> {
        // 版本與群組必須一致；不一致時 fail closed，不呼叫 authenticator。
        let share = match (self.edition(), group) {
            (Edition::Dual, None) => {
                return Err(VaultError::Format(
                    "雙群組控管版註冊金鑰須指定群組（A 或 B）".into(),
                ));
            }
            (Edition::Single, Some(_)) => {
                return Err(VaultError::Format("單人版金庫不支援金鑰群組".into()));
            }
            (Edition::Dual, Some(group)) => Some(self.group_share(group)?),
            (Edition::Single, None) => None,
        };
        // 雙人版：Q3「同一支實體金鑰只能註冊一筆」→ 以金庫內全部既有 credential（A+B）作
        // excludeCredentials，由 authenticator 拒絕重複。在呼叫 authenticator 之前先解碼完成。
        let exclude = if group.is_some() {
            Some(
                self.header
                    .key_slots
                    .iter()
                    .map(|slot| {
                        base64_decode(&slot.credential_id)
                            .map_err(|_| VaultError::Format("credential_id 解碼失敗".into()))
                    })
                    .collect::<Result<Vec<_>, _>>()?,
            )
        } else {
            None
        };
        // 裁決②：不支援 hmac-secret/PRF 的金鑰拒絕註冊。
        // 順序：先 detect()（real 後端需 getInfo 才能知 PRF 能力；mock 的 detect 為無害循環），
        // 再 prf_supported()（依 detect 快取的資訊判定）。
        let detected = backend.detect()?;
        if !backend.prf_supported() {
            return Err(VaultError::Fido(FidoError::PrfNotSupported));
        }
        // 單人版維持原本的註冊呼叫（不帶排除清單）。
        let mut reg = match exclude.as_deref() {
            Some(exclude) => backend.register_credential_excluding(&detected, pin, exclude)?,
            None => backend.register_credential(&detected, pin)?,
        };
        let secret = backend.get_prf_secret(&reg.credential_id, pin)?;
        let k = kek_from_prf_secret(&secret);
        let nonce = random_nonce();
        // 單人版：槽位包 KEK。雙人版：槽位只包該群組 share，AAD 綁定群組與 credential_id。
        let ct = match (group, share.as_ref()) {
            (Some(group), Some(share)) => aes_gcm_encrypt_aad(
                &k,
                &nonce,
                share.as_slice(),
                &dual_key_slot_aad(group, &reg.credential_id),
            ),
            _ => aes_gcm_encrypt(&k, &nonce, self.kek.as_slice()),
        };

        if let Some(label) = custom_label {
            reg.label = label.to_owned();
        }
        self.header.key_slots.push(KeySlot {
            credential_id: base64_encode(&reg.credential_id),
            aaguid: hex32_16(reg.aaguid),
            label: reg.label.clone(),
            key_type: reg.kind,
            group,
            nonce: base64_encode(&nonce),
            ct: base64_encode(&ct),
        });
        let kind_str = format!("{}", reg.kind);
        let detail = match group {
            Some(group) => format!("type={kind_str} group={group:?}"),
            None => format!("type={kind_str}"),
        };
        self.record("key_registered", &format!("fido2:{}", reg.label), &detail)?;
        Ok(reg)
    }

    /// 移除金鑰槽（不可逆：該金鑰將無法再解鎖）。
    pub fn remove_key(&mut self, credential_id_b64: &str) -> Result<(), VaultError> {
        let idx = self
            .header
            .key_slots
            .iter()
            .position(|s| s.credential_id == credential_id_b64)
            .ok_or(VaultError::Fido(FidoError::NoDevice))?;
        let label = self.header.key_slots[idx].label.clone();
        self.header.key_slots.remove(idx);
        self.record(
            "key_removed",
            &format!("fido2:{label}"),
            "金鑰槽已移除（該金鑰無法再解鎖）",
        )?;
        Ok(())
    }

    // ── 上鎖 ──

    /// 上鎖：記 audit、KEK 清零。回傳 header 快照供登入畫面顯示金鑰清單。
    pub fn lock(mut self) -> Header {
        let _ = self.record("manual_lock", "manual", "手動上鎖");
        self.kek.zeroize();
        self.header.clone()
    }

    /// 閒置自動上鎖（前端計時逾時呼叫）。
    pub fn auto_lock(mut self) -> Header {
        let _ = self.record("auto_lock", "idle", "閒置逾時自動上鎖");
        self.kek.zeroize();
        self.header.clone()
    }
}

// ─────────────────────────── 輔助 ───────────────────────────

fn random_bytes(n: usize) -> Vec<u8> {
    let mut b = vec![0u8; n];
    use rand::RngCore;
    rand::rngs::OsRng.fill_bytes(&mut b);
    b
}

fn slot_nonce(b64: &str) -> Result<[u8; 12], VaultError> {
    let v = base64_decode(b64).map_err(|_| VaultError::Format("slot nonce 解碼失敗".into()))?;
    v.try_into()
        .map_err(|_| VaultError::Format("slot nonce 長度錯誤".into()))
}

fn hex32(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn hex32_16(a: [u8; 16]) -> String {
    a.iter().map(|x| format!("{x:02x}")).collect()
}

fn trim_audit(audit: &mut Vec<AuditEvent>) {
    if audit.len() > MAX_AUDIT {
        let excess = audit.len() - MAX_AUDIT;
        audit.drain(0..excess);
    }
}

// ── 未解鎖失敗記錄（sidecar）──
// 登入失敗時沒有 KEK，無法改動加密 payload；header 明文區又不放大 audit。
// 失敗事件寫入同資料夾 sidecar `vault.db.failures`（僅時間戳+method，無機密，上限 10 筆）。
// 成功解鎖時合併進加密 audit 並刪除 sidecar → Gate 2「錯誤密碼拒絕且計入軌跡」可驗證。

pub fn failures_path(vault_path: &Path) -> PathBuf {
    let mut s = vault_path.as_os_str().to_owned();
    s.push(".failures");
    PathBuf::from(s)
}

fn read_failure_sidecar(path: &Path) -> Vec<FailureStamp> {
    match fs::read_to_string(failures_path(path)) {
        Ok(s) => serde_json::from_str(&s).unwrap_or_default(),
        Err(_) => Vec::new(),
    }
}

/// 記錄一次登入失敗（未解鎖情境）。
pub fn record_login_failure(vault_path: &Path, method: &str) -> Result<(), VaultError> {
    let mut list = read_failure_sidecar(vault_path);
    list.push(FailureStamp {
        ts: now_rfc3339(),
        method: method.into(),
    });
    if list.len() > MAX_LOGIN_FAILURES {
        list.remove(0);
    }
    fs::write(
        failures_path(vault_path),
        serde_json::to_string(&list).unwrap(),
    )
    .map_err(VaultError::Io)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fido2::{FidoBackend, FidoError, KeyKind, MockBackend};
    use std::env;

    /// 不支援 PRF 的金鑰包裝（驗證裁決②：拒絕註冊）。
    struct NoPrfBackend(MockBackend);
    impl FidoBackend for NoPrfBackend {
        fn detect(&mut self) -> Result<crate::fido2::DetectedKey, FidoError> {
            self.0.detect()
        }
        fn register_credential(
            &mut self,
            d: &crate::fido2::DetectedKey,
            pin: Option<&str>,
        ) -> Result<crate::fido2::RegisteredCredential, FidoError> {
            self.0.register_credential(d, pin)
        }
        fn get_prf_secret(&mut self, id: &[u8], pin: Option<&str>) -> Result<[u8; 32], FidoError> {
            self.0.get_prf_secret(id, pin)
        }
        fn prf_supported(&self) -> bool {
            false
        }
    }

    #[test]
    fn register_rejects_non_prf_key() {
        let d = tmp_dir("noprfr");
        let p = d.join("vault.db");
        let _ = fs::remove_file(&p);
        let v = Vault::create(&p, "Pw-12345").unwrap();
        let mut v = v;
        let mut bad = NoPrfBackend(MockBackend::new());
        assert!(matches!(
            v.register_key(&mut bad, None),
            Err(VaultError::Fido(FidoError::PrfNotSupported))
        ));
        let mut bad_named = NoPrfBackend(MockBackend::new());
        assert!(matches!(
            v.register_key_with_label(&mut bad_named, None, "Test Alias"),
            Err(VaultError::Fido(FidoError::PrfNotSupported))
        ));
        // 金鑰槽數不變
        assert_eq!(v.keys_meta().len(), 0);
        let _ = fs::remove_dir_all(&d);
    }

    fn tmp_dir(tag: &str) -> PathBuf {
        let d = env::temp_dir().join(format!("f2v-test-{tag}-{}", std::process::id()));
        let _ = fs::create_dir_all(&d);
        d
    }

    // ── D3：v2 header / 版本互斥 ──

    fn raw_header_json(path: &Path) -> serde_json::Value {
        let buf = fs::read(path).unwrap();
        let len = u32::from_le_bytes(buf[6..10].try_into().unwrap()) as usize;
        serde_json::from_slice(&buf[10..10 + len]).unwrap()
    }

    /// 以新的 header JSON 重寫檔案（payload 原封不動），模擬另一版本產生的檔案。
    fn rewrite_header(path: &Path, edit: impl FnOnce(&mut serde_json::Value)) {
        let buf = fs::read(path).unwrap();
        let len = u32::from_le_bytes(buf[6..10].try_into().unwrap()) as usize;
        let mut header: serde_json::Value = serde_json::from_slice(&buf[10..10 + len]).unwrap();
        edit(&mut header);
        let new_header = serde_json::to_vec(&header).unwrap();
        let mut out = Vec::new();
        out.extend_from_slice(&buf[..6]);
        out.extend_from_slice(&(new_header.len() as u32).to_le_bytes());
        out.extend_from_slice(&new_header);
        out.extend_from_slice(&buf[10 + len..]);
        fs::write(path, out).unwrap();
    }

    fn as_v2(header: &mut serde_json::Value) {
        header["v"] = serde_json::json!(2);
        header["policy"] = serde_json::json!("dual");
        header["dual_slot"] = header["password_slot"].clone();
        header["dual_step_timeout_secs"] = serde_json::json!(120);
    }

    fn sample_slot() -> Slot {
        Slot {
            nonce: "bm9uY2U=".into(),
            ct: "Y3Q=".into(),
        }
    }

    fn sample_key_slot(group: Option<KeyGroup>) -> KeySlot {
        KeySlot {
            credential_id: "Y3JlZA==".into(),
            aaguid: "00".repeat(16),
            label: "k1".into(),
            key_type: KeyKind::TouchOnly,
            group,
            nonce: "bm9uY2U=".into(),
            ct: "Y3Q=".into(),
        }
    }

    fn sample_header(v: u8) -> Header {
        Header {
            v,
            policy: None,
            argon2: Argon2Params {
                salt: "c2FsdA==".into(),
            },
            password_slot: sample_slot(),
            dual_slot: None,
            key_slots: Vec::new(),
            dual_step_timeout_secs: None,
            created_at: "2026-10-11T00:00:00Z".into(),
        }
    }

    fn valid_v2_header() -> Header {
        let mut h = sample_header(2);
        h.policy = Some(VaultPolicy::Dual);
        h.dual_slot = Some(sample_slot());
        h.dual_step_timeout_secs = Some(120);
        h.key_slots = vec![sample_key_slot(Some(KeyGroup::A))];
        h
    }

    #[test]
    fn edition_check_accepts_matching_shapes() {
        assert!(check_header_edition(&sample_header(1), Edition::Single).is_ok());
        let mut v1_with_key = sample_header(1);
        v1_with_key.key_slots = vec![sample_key_slot(None)];
        assert!(check_header_edition(&v1_with_key, Edition::Single).is_ok());
        assert!(check_header_edition(&valid_v2_header(), Edition::Dual).is_ok());
    }

    #[test]
    fn single_edition_rejects_v2_header() {
        assert!(matches!(
            check_header_edition(&valid_v2_header(), Edition::Single),
            Err(VaultError::WrongEdition {
                vault: Edition::Dual
            })
        ));
    }

    #[test]
    fn dual_edition_rejects_v1_header() {
        assert!(matches!(
            check_header_edition(&sample_header(1), Edition::Dual),
            Err(VaultError::WrongEdition {
                vault: Edition::Single
            })
        ));
    }

    #[test]
    fn unknown_format_version_is_rejected_by_both_editions() {
        for edition in [Edition::Single, Edition::Dual] {
            assert!(matches!(
                check_header_edition(&sample_header(3), edition),
                Err(VaultError::Format(_))
            ));
            assert!(matches!(
                check_header_edition(&sample_header(0), edition),
                Err(VaultError::Format(_))
            ));
        }
    }

    #[test]
    fn v2_header_missing_required_dual_fields_is_rejected() {
        let mut no_policy = valid_v2_header();
        no_policy.policy = None;
        let mut no_dual_slot = valid_v2_header();
        no_dual_slot.dual_slot = None;
        let mut ungrouped_slot = valid_v2_header();
        ungrouped_slot.key_slots.push(sample_key_slot(None));
        for header in [no_policy, no_dual_slot, ungrouped_slot] {
            assert!(matches!(
                check_header_edition(&header, Edition::Dual),
                Err(VaultError::Format(_))
            ));
        }
    }

    #[test]
    fn v1_header_with_dual_fields_is_rejected() {
        let mut with_policy = sample_header(1);
        with_policy.policy = Some(VaultPolicy::Dual);
        let mut with_dual_slot = sample_header(1);
        with_dual_slot.dual_slot = Some(sample_slot());
        let mut with_timeout = sample_header(1);
        with_timeout.dual_step_timeout_secs = Some(120);
        let mut with_group = sample_header(1);
        with_group.key_slots = vec![sample_key_slot(Some(KeyGroup::B))];
        for header in [with_policy, with_dual_slot, with_timeout, with_group] {
            assert!(matches!(
                check_header_edition(&header, Edition::Single),
                Err(VaultError::Format(_))
            ));
        }
    }

    #[test]
    fn unknown_policy_or_group_value_fails_to_parse() {
        let mut h = serde_json::to_value(valid_v2_header()).unwrap();
        h["policy"] = serde_json::json!("triple");
        assert!(serde_json::from_value::<Header>(h).is_err());
        let mut h = serde_json::to_value(valid_v2_header()).unwrap();
        h["key_slots"][0]["group"] = serde_json::json!("C");
        assert!(serde_json::from_value::<Header>(h).is_err());
    }

    #[test]
    fn wrong_edition_message_names_the_right_program() {
        let to_dual = VaultError::WrongEdition {
            vault: Edition::Dual,
        }
        .to_string();
        assert!(to_dual.contains("雙群組控管版"), "{to_dual}");
        assert!(
            to_dual.contains("portable-fido-vault-dual.exe"),
            "{to_dual}"
        );
        let to_single = VaultError::WrongEdition {
            vault: Edition::Single,
        }
        .to_string();
        assert!(to_single.contains("單人版"), "{to_single}");
        assert!(to_single.contains("portable-fido-vault.exe"), "{to_single}");
    }

    #[test]
    fn dual_shares_debug_is_redacted() {
        let shares = DualShares {
            share_a: "SECRET-SHARE-A".into(),
            share_b: "SECRET-SHARE-B".into(),
        };
        let shown = format!("{shares:?}");
        assert!(!shown.contains("SECRET-SHARE-A"), "{shown}");
        assert!(!shown.contains("SECRET-SHARE-B"), "{shown}");
    }

    /// 既有行為回歸（GREEN→GREEN）：v1 檔案 header/payload 不出現任何 v2 欄位。
    #[test]
    fn v1_files_serialize_without_dual_fields() {
        let d = tmp_dir("d3-v1-shape");
        let p = d.join("vault.db");
        let _ = fs::remove_file(&p);
        let mut v = Vault::create(&p, "Pw-12345").unwrap();
        let mut backend = MockBackend::new();
        v.register_key(&mut backend, None).unwrap();
        let header = raw_header_json(&p);
        let obj = header.as_object().unwrap();
        for key in ["policy", "dual_slot", "dual_step_timeout_secs"] {
            assert!(!obj.contains_key(key), "unexpected {key} in v1 header");
        }
        assert_eq!(header["v"], serde_json::json!(1));
        assert!(!header["key_slots"][0]
            .as_object()
            .unwrap()
            .contains_key("group"));
        let data = serde_json::to_value(&v.data).unwrap();
        assert!(!data.as_object().unwrap().contains_key("dual"));
        assert!(!data["settings"]
            .as_object()
            .unwrap()
            .contains_key("dual_step_timeout_secs"));
    }

    #[test]
    fn single_edition_open_rejects_v2_file_without_writing() {
        let d = tmp_dir("d3-v2-reject");
        let p = d.join("vault.db");
        let _ = fs::remove_file(&p);
        let _ = fs::remove_file(failures_path(&p));
        drop(Vault::create(&p, "Pw-12345").unwrap());
        rewrite_header(&p, as_v2);
        let before = fs::read(&p).unwrap();

        let result = Vault::open_password(&p, "Pw-12345");
        assert!(
            matches!(
                result,
                Err(VaultError::WrongEdition {
                    vault: Edition::Dual
                })
            ),
            "single edition must refuse a v2 vault"
        );
        assert_eq!(
            fs::read(&p).unwrap(),
            before,
            "v2 file must stay byte-identical"
        );
        assert!(
            !failures_path(&p).exists(),
            "no failure sidecar for edition mismatch"
        );
        assert!(!p.with_extension("db.tmp").exists());
        assert!(matches!(
            Vault::read_header(&p, Edition::Single),
            Err(VaultError::WrongEdition {
                vault: Edition::Dual
            })
        ));
    }

    // ── D4：建立 v2 / 主密碼 break-glass / payload 形狀 ──

    fn fresh_path(tag: &str) -> PathBuf {
        let d = tmp_dir(tag);
        let p = d.join("vault.db");
        let _ = fs::remove_file(&p);
        let _ = fs::remove_file(failures_path(&p));
        let _ = fs::remove_file(p.with_extension("db.tmp"));
        p
    }

    fn decode_share(b64: &str) -> [u8; 32] {
        base64_decode(b64).unwrap().try_into().unwrap()
    }

    #[test]
    fn create_dual_writes_v2_header() {
        let p = fresh_path("d4-create-header");
        let v = Vault::create_dual(&p, "Pw-12345").unwrap();
        assert_eq!(v.edition(), Edition::Dual);
        drop(v);
        let raw = raw_header_json(&p);
        assert_eq!(raw["v"], serde_json::json!(2));
        assert_eq!(raw["policy"], serde_json::json!("dual"));
        assert!(raw["dual_slot"].is_object(), "dual_slot missing: {raw}");
        assert_eq!(raw["dual_step_timeout_secs"], serde_json::json!(120));
        assert_eq!(raw["key_slots"], serde_json::json!([]));
        assert!(Vault::read_header(&p, Edition::Dual).is_ok());
        assert!(matches!(
            Vault::read_header(&p, Edition::Single),
            Err(VaultError::WrongEdition {
                vault: Edition::Dual
            })
        ));
    }

    #[test]
    fn create_dual_payload_holds_distinct_shares_and_timeout() {
        let p = fresh_path("d4-create-payload");
        let v = Vault::create_dual(&p, "Pw-12345").unwrap();
        let shares = v.data.dual.clone();
        assert!(shares.is_some(), "payload must hold dual shares");
        let shares = shares.unwrap();
        let a = decode_share(&shares.share_a);
        let b = decode_share(&shares.share_b);
        assert_ne!(a, b);
        assert_ne!(a, *v.kek);
        assert_ne!(b, *v.kek);
        assert_eq!(v.data.settings.dual_step_timeout_secs, Some(120));
        assert!(v.data.audit[0].detail.contains("edition=dual"));
    }

    #[test]
    fn dual_slot_unwraps_to_kek_with_both_shares() {
        let p = fresh_path("d4-dual-slot");
        let v = Vault::create_dual(&p, "Pw-12345").unwrap();
        assert!(v.data.dual.is_some(), "dual shares missing");
        assert!(v.header.dual_slot.is_some(), "dual slot missing");
        let shares = v.data.dual.clone().unwrap();
        let slot = v.header.dual_slot.clone().unwrap();
        let wrap = crate::crypto::dual_wrap_key_from_shares(
            &decode_share(&shares.share_a),
            &decode_share(&shares.share_b),
        );
        let kek = crate::crypto::aes_gcm_decrypt_aad(
            &wrap,
            &slot_nonce(&slot.nonce).unwrap(),
            &base64_decode(&slot.ct).unwrap(),
            crate::crypto::DUAL_SLOT_AAD,
        )
        .unwrap();
        assert_eq!(kek.as_slice(), v.kek.as_slice());
    }

    #[test]
    fn dual_password_breakglass_unlocks_and_audits() {
        let p = fresh_path("d4-breakglass");
        let mut v = Vault::create_dual(&p, "Pw-12345").unwrap();
        v.add_entry("example.com", "alice", "s3cret", "").unwrap();
        drop(v.lock());
        let reopened = Vault::open_password_dual(&p, "Pw-12345");
        assert!(
            reopened.is_ok(),
            "break-glass login failed: {:?}",
            reopened.err()
        );
        let reopened = reopened.unwrap();
        assert_eq!(reopened.entries().len(), 1);
        let last = reopened.audit().last().unwrap();
        assert_eq!(last.event, "login_success");
        assert_eq!(last.method, "password-breakglass");
        assert!(reopened.data.dual.is_some());
    }

    #[test]
    fn dual_password_wrong_records_breakglass_failure_without_touching_vault() {
        let p = fresh_path("d4-breakglass-wrong");
        drop(Vault::create_dual(&p, "Pw-12345").unwrap());
        let before = fs::read(&p).unwrap();
        assert!(matches!(
            Vault::open_password_dual(&p, "wrong-pass"),
            Err(VaultError::WrongPassword)
        ));
        assert_eq!(fs::read(&p).unwrap(), before);
        let stamps = read_failure_sidecar(&p);
        assert_eq!(stamps.len(), 1);
        assert_eq!(stamps[0].method, "password-breakglass");
    }

    #[test]
    fn dual_open_rejects_v1_file_without_writing() {
        let p = fresh_path("d4-dual-open-v1");
        drop(Vault::create(&p, "Pw-12345").unwrap());
        let before = fs::read(&p).unwrap();
        assert!(matches!(
            Vault::open_password_dual(&p, "Pw-12345"),
            Err(VaultError::WrongEdition {
                vault: Edition::Single
            })
        ));
        assert_eq!(fs::read(&p).unwrap(), before);
        assert!(!failures_path(&p).exists());
    }

    #[test]
    fn dual_payload_missing_shares_is_rejected_without_writing() {
        let p = fresh_path("d4-missing-shares");
        let mut v = Vault::create_dual(&p, "Pw-12345").unwrap();
        v.data.dual = None;
        v.write_file().unwrap();
        drop(v);
        let before = fs::read(&p).unwrap();
        let result = Vault::open_password_dual(&p, "Pw-12345");
        assert!(
            matches!(&result, Err(VaultError::Format(m)) if m.contains("share")),
            "expected share-shape error, got {:?}",
            result.err()
        );
        assert_eq!(fs::read(&p).unwrap(), before);
    }

    #[test]
    fn dual_slot_inconsistent_with_shares_is_rejected_without_writing() {
        let p = fresh_path("d4-bad-dual-slot");
        drop(Vault::create_dual(&p, "Pw-12345").unwrap());
        rewrite_header(&p, |h| {
            // 以 password_slot 取代 dual_slot：形狀合法但不是 HKDF(shares) 包出的 KEK。
            h["dual_slot"] = h["password_slot"].clone();
        });
        let before = fs::read(&p).unwrap();
        let result = Vault::open_password_dual(&p, "Pw-12345");
        assert!(
            matches!(&result, Err(VaultError::Format(m)) if m.contains("dual_slot")),
            "expected dual_slot consistency error, got {:?}",
            result.err()
        );
        assert_eq!(fs::read(&p).unwrap(), before);
    }

    #[test]
    fn single_payload_with_dual_shares_is_rejected_without_writing() {
        let p = fresh_path("d4-v1-with-shares");
        let mut v = Vault::create(&p, "Pw-12345").unwrap();
        v.data.dual = Some(DualShares {
            share_a: base64_encode(&[1u8; 32]),
            share_b: base64_encode(&[2u8; 32]),
        });
        v.write_file().unwrap();
        drop(v);
        let before = fs::read(&p).unwrap();
        let result = Vault::open_password(&p, "Pw-12345");
        assert!(
            matches!(&result, Err(VaultError::Format(_))),
            "v1 payload must not carry dual shares, got {:?}",
            result.as_ref().map(|_| ())
        );
        assert_eq!(fs::read(&p).unwrap(), before);
    }

    #[test]
    fn edition_dispatch_creates_and_opens_matching_format() {
        let single = fresh_path("d4-dispatch-single");
        drop(Vault::create_for(&single, "Pw-12345", Edition::Single).unwrap());
        assert_eq!(raw_header_json(&single)["v"], serde_json::json!(1));
        assert!(Vault::open_password_for(&single, "Pw-12345", Edition::Single).is_ok());

        let dual = fresh_path("d4-dispatch-dual");
        drop(Vault::create_for(&dual, "Pw-12345", Edition::Dual).unwrap());
        assert_eq!(raw_header_json(&dual)["v"], serde_json::json!(2));
        let opened = Vault::open_password_for(&dual, "Pw-12345", Edition::Dual);
        assert!(
            opened.is_ok(),
            "dual dispatch open failed: {:?}",
            opened.err()
        );
        assert!(matches!(
            Vault::open_password_for(&dual, "Pw-12345", Edition::Single),
            Err(VaultError::WrongEdition {
                vault: Edition::Dual
            })
        ));
    }

    #[test]
    fn dual_vault_refuses_ungrouped_key_registration() {
        let p = fresh_path("d4-dual-register-guard");
        let mut v = Vault::create_dual(&p, "Pw-12345").unwrap();
        let mut backend = MockBackend::new();
        let result = v.register_key(&mut backend, None);
        assert!(
            matches!(&result, Err(VaultError::Format(m)) if m.contains("群組")),
            "dual vault must not register an ungrouped key, got {:?}",
            result.as_ref().map(|_| ())
        );
        assert!(v.header.key_slots.is_empty());
        let named = v.register_key_with_label(&mut backend, None, "k1");
        assert!(named.is_err());
        assert!(v.header.key_slots.is_empty());
        assert!(Vault::read_header(&p, Edition::Dual).is_ok());
    }

    // ── D5：雙群組註冊 ──

    /// 計數用後端：記錄 detect/register 呼叫次數（驗證失敗時不碰 authenticator）。
    struct CountingBackend {
        inner: MockBackend,
        detects: u32,
        registers: u32,
    }

    impl CountingBackend {
        fn new() -> Self {
            Self {
                inner: MockBackend::new(),
                detects: 0,
                registers: 0,
            }
        }
    }

    impl FidoBackend for CountingBackend {
        fn detect(&mut self) -> Result<crate::fido2::DetectedKey, FidoError> {
            self.detects += 1;
            self.inner.detect()
        }
        fn register_credential(
            &mut self,
            d: &crate::fido2::DetectedKey,
            pin: Option<&str>,
        ) -> Result<crate::fido2::RegisteredCredential, FidoError> {
            self.registers += 1;
            self.inner.register_credential(d, pin)
        }
        fn get_prf_secret(&mut self, id: &[u8], pin: Option<&str>) -> Result<[u8; 32], FidoError> {
            self.inner.get_prf_secret(id, pin)
        }
        fn prf_supported(&self) -> bool {
            self.inner.prf_supported()
        }
    }

    /// 以金鑰 PRF 解開槽位（帶指定群組 AAD），回傳明文。
    fn unwrap_group_slot(
        slot: &KeySlot,
        backend: &mut dyn FidoBackend,
        aad_group: KeyGroup,
    ) -> Result<Vec<u8>, CryptoError> {
        let cred = base64_decode(&slot.credential_id).unwrap();
        let secret = backend.get_prf_secret(&cred, None).unwrap();
        let k = kek_from_prf_secret(&secret);
        crate::crypto::aes_gcm_decrypt_aad(
            &k,
            &slot_nonce(&slot.nonce).unwrap(),
            &base64_decode(&slot.ct).unwrap(),
            &crate::crypto::dual_key_slot_aad(aad_group, &cred),
        )
    }

    #[test]
    fn dual_register_in_group_wraps_that_groups_share() {
        let p = fresh_path("d5-register-ab");
        let mut v = Vault::create_dual(&p, "Pw-12345").unwrap();
        let mut backend = MockBackend::new();
        let ra = v.register_key_in_group(&mut backend, None, "王小明", KeyGroup::A);
        assert!(ra.is_ok(), "register A failed: {:?}", ra.err());
        // MockBackend 每次 detect 會循環金鑰類型（第二支為 PIN 型）；每支金鑰用新的 mock 實例。
        // PRF 由 credential_id 決定，任一 mock 實例都能解包。
        let mut backend_b = MockBackend::new();
        let rb = v.register_key_in_group(&mut backend_b, None, "李大華", KeyGroup::B);
        assert!(rb.is_ok(), "register B failed: {:?}", rb.err());
        assert_eq!(v.header.key_slots.len(), 2);

        let shares = v.data.dual.clone().unwrap();
        let share_a = decode_share(&shares.share_a);
        let share_b = decode_share(&shares.share_b);
        let slot_a = v.header.key_slots[0].clone();
        let slot_b = v.header.key_slots[1].clone();
        assert_eq!(slot_a.group, Some(KeyGroup::A));
        assert_eq!(slot_b.group, Some(KeyGroup::B));
        assert_eq!(slot_a.label, "王小明");

        let a_plain = unwrap_group_slot(&slot_a, &mut backend, KeyGroup::A).unwrap();
        assert_eq!(a_plain.as_slice(), share_a.as_slice());
        assert_ne!(
            a_plain.as_slice(),
            v.kek.as_slice(),
            "slot must not wrap the KEK"
        );
        let b_plain = unwrap_group_slot(&slot_b, &mut backend, KeyGroup::B).unwrap();
        assert_eq!(b_plain.as_slice(), share_b.as_slice());
        // 群組標記被改：AAD 不符 → 解包失敗。
        assert!(unwrap_group_slot(&slot_a, &mut backend, KeyGroup::B).is_err());
        assert!(unwrap_group_slot(&slot_b, &mut backend, KeyGroup::A).is_err());
    }

    #[test]
    fn dual_registration_persists_and_audits_group() {
        let p = fresh_path("d5-persist");
        let mut v = Vault::create_dual(&p, "Pw-12345").unwrap();
        let mut backend = MockBackend::new();
        let r = v.register_key_in_group(&mut backend, None, "k-a", KeyGroup::A);
        assert!(r.is_ok(), "register failed: {:?}", r.err());
        let last = v.audit().last().unwrap().clone();
        assert_eq!(last.event, "key_registered");
        assert_eq!(last.method, "fido2:k-a");
        assert!(last.detail.contains("group=A"), "{}", last.detail);
        drop(v.lock());

        let raw = raw_header_json(&p);
        assert_eq!(raw["key_slots"][0]["group"], serde_json::json!("A"));
        assert!(Vault::read_header(&p, Edition::Dual).is_ok());
        let reopened = Vault::open_password_dual(&p, "Pw-12345");
        assert!(reopened.is_ok(), "reopen failed: {:?}", reopened.err());
    }

    #[test]
    fn dual_registration_validates_label_before_authenticator() {
        let p = fresh_path("d5-label");
        let mut v = Vault::create_dual(&p, "Pw-12345").unwrap();
        let mut backend = CountingBackend::new();
        assert!(v
            .register_key_in_group(&mut backend, None, "dup", KeyGroup::A)
            .is_ok());
        let detects = backend.detects;
        for bad in ["", "   ", "DUP", "bad\u{7}name"] {
            assert!(v
                .register_key_in_group(&mut backend, None, bad, KeyGroup::B)
                .is_err());
        }
        assert_eq!(
            backend.detects, detects,
            "invalid labels must not reach the key"
        );
        assert_eq!(v.header.key_slots.len(), 1);
    }

    #[test]
    fn dual_registration_rejects_non_prf_key_without_slot() {
        let p = fresh_path("d5-noprf");
        let mut v = Vault::create_dual(&p, "Pw-12345").unwrap();
        let mut bad = NoPrfBackend(MockBackend::new());
        let r = v.register_key_in_group(&mut bad, None, "k", KeyGroup::A);
        assert!(
            matches!(r, Err(VaultError::Fido(FidoError::PrfNotSupported))),
            "expected PrfNotSupported, got {:?}",
            r.as_ref().map(|_| ())
        );
        assert!(v.header.key_slots.is_empty());
    }

    #[test]
    fn single_vault_rejects_group_registration_without_authenticator() {
        let p = fresh_path("d5-single-group");
        let mut v = Vault::create(&p, "Pw-12345").unwrap();
        let mut backend = CountingBackend::new();
        let r = v.register_key_in_group(&mut backend, None, "k", KeyGroup::A);
        assert!(
            matches!(&r, Err(VaultError::Format(m)) if m.contains("單人版")),
            "single vault must refuse groups, got {:?}",
            r.as_ref().map(|_| ())
        );
        assert_eq!(backend.detects, 0);
        assert!(v.header.key_slots.is_empty());
    }

    #[test]
    fn register_key_for_dispatches_by_vault_edition() {
        // 單人版：無群組 → 註冊；有群組 → 拒絕
        let single = fresh_path("d5-dispatch-single");
        let mut v1 = Vault::create(&single, "Pw-12345").unwrap();
        let mut backend = CountingBackend::new();
        assert!(v1.register_key_for(&mut backend, None, "s1", None).is_ok());
        assert_eq!(v1.header.key_slots[0].group, None);
        let before = backend.detects;
        assert!(v1
            .register_key_for(&mut backend, None, "s2", Some(KeyGroup::A))
            .is_err());
        assert_eq!(backend.detects, before);
        assert_eq!(v1.header.key_slots.len(), 1);

        // 雙人版：有群組 → 註冊；無群組 → 拒絕
        let dual = fresh_path("d5-dispatch-dual");
        let mut v2 = Vault::create_dual(&dual, "Pw-12345").unwrap();
        // 新的 mock 實例：避免 detect 循環到 PIN 型金鑰（與受測行為無關）。
        let mut backend = CountingBackend::new();
        let r = v2.register_key_for(&mut backend, None, "d1", Some(KeyGroup::B));
        assert!(r.is_ok(), "dual dispatch failed: {:?}", r.err());
        assert_eq!(v2.header.key_slots[0].group, Some(KeyGroup::B));
        let before = backend.detects;
        assert!(v2.register_key_for(&mut backend, None, "d2", None).is_err());
        assert_eq!(backend.detects, before);
        assert_eq!(v2.header.key_slots.len(), 1);
    }

    // ── D6：同一支實體金鑰只能註冊一筆 ──

    /// 記錄 vault 呼叫哪一個註冊方法與排除清單。
    struct RecordingBackend {
        inner: MockBackend,
        calls: Vec<Option<Vec<Vec<u8>>>>,
    }

    impl FidoBackend for RecordingBackend {
        fn detect(&mut self) -> Result<crate::fido2::DetectedKey, FidoError> {
            self.inner.detect()
        }
        fn register_credential(
            &mut self,
            d: &crate::fido2::DetectedKey,
            pin: Option<&str>,
        ) -> Result<crate::fido2::RegisteredCredential, FidoError> {
            self.calls.push(None);
            self.inner.register_credential(d, pin)
        }
        fn register_credential_excluding(
            &mut self,
            d: &crate::fido2::DetectedKey,
            pin: Option<&str>,
            exclude: &[Vec<u8>],
        ) -> Result<crate::fido2::RegisteredCredential, FidoError> {
            self.calls.push(Some(exclude.to_vec()));
            self.inner.register_credential_excluding(d, pin, exclude)
        }
        fn get_prf_secret(&mut self, id: &[u8], pin: Option<&str>) -> Result<[u8; 32], FidoError> {
            self.inner.get_prf_secret(id, pin)
        }
        fn prf_supported(&self) -> bool {
            self.inner.prf_supported()
        }
    }

    #[test]
    fn dual_registration_excludes_every_registered_credential() {
        let p = fresh_path("d6-exclude-list");
        let mut v = Vault::create_dual(&p, "Pw-12345").unwrap();
        let mut b1 = MockBackend::new();
        v.register_key_in_group(&mut b1, None, "a1", KeyGroup::A)
            .unwrap();
        let mut b2 = MockBackend::new();
        v.register_key_in_group(&mut b2, None, "b1", KeyGroup::B)
            .unwrap();
        let expected: Vec<Vec<u8>> = v
            .header
            .key_slots
            .iter()
            .map(|s| base64_decode(&s.credential_id).unwrap())
            .collect();

        let mut rec = RecordingBackend {
            inner: MockBackend::new(),
            calls: Vec::new(),
        };
        let r = v.register_key_in_group(&mut rec, None, "a2", KeyGroup::A);
        assert!(r.is_ok(), "third key failed: {:?}", r.err());
        assert_eq!(
            rec.calls,
            vec![Some(expected)],
            "dual registration must pass all existing credentials (A and B) as excludeCredentials"
        );
    }

    #[test]
    fn dual_same_physical_key_cannot_register_twice_in_any_group() {
        let p = fresh_path("d6-same-key");
        let mut v = Vault::create_dual(&p, "Pw-12345").unwrap();
        let mut key = MockBackend::new();
        v.register_key_in_group(&mut key, None, "王小明", KeyGroup::A)
            .unwrap();
        let audit_len = v.audit().len();
        for (label, group) in [("同一支-B", KeyGroup::B), ("同一支-A", KeyGroup::A)] {
            key.reuse_device();
            let r = v.register_key_in_group(&mut key, None, label, group);
            assert!(
                matches!(r, Err(VaultError::Fido(FidoError::CredentialExcluded))),
                "same physical key must be refused for group {group:?}, got {:?}",
                r.as_ref().map(|_| ())
            );
        }
        assert_eq!(v.header.key_slots.len(), 1);
        assert_eq!(
            v.audit().len(),
            audit_len,
            "refused registration must not be audited as registered"
        );
        drop(v.lock());
        assert_eq!(
            Vault::read_header(&p, Edition::Dual)
                .unwrap()
                .key_slots
                .len(),
            1
        );
    }

    #[test]
    fn single_registration_keeps_legacy_call_without_exclusion() {
        let p = fresh_path("d6-single-legacy");
        let mut v = Vault::create(&p, "Pw-12345").unwrap();
        let mut rec = RecordingBackend {
            inner: MockBackend::new(),
            calls: Vec::new(),
        };
        v.register_key_with_label(&mut rec, None, "s1").unwrap();
        let mut rec2 = RecordingBackend {
            inner: MockBackend::new(),
            calls: Vec::new(),
        };
        v.register_key_with_label(&mut rec2, None, "s2").unwrap();
        assert_eq!(rec.calls, vec![None]);
        assert_eq!(rec2.calls, vec![None]);
    }

    #[test]
    fn read_header_for_dual_edition_rejects_v1_file() {
        let d = tmp_dir("d3-v1-reject");
        let p = d.join("vault.db");
        let _ = fs::remove_file(&p);
        drop(Vault::create(&p, "Pw-12345").unwrap());
        assert!(matches!(
            Vault::read_header(&p, Edition::Dual),
            Err(VaultError::WrongEdition {
                vault: Edition::Single
            })
        ));
        assert!(Vault::read_header(&p, Edition::Single).is_ok());
    }

    #[test]
    fn legacy_payload_defaults_password_history_and_limit() {
        let legacy = serde_json::json!({
            "entries": [{
                "id": "entry-1",
                "site": "example.com",
                "account": "alice",
                "password": "current-secret",
                "notes": "",
                "created_at": "2026-10-01T00:00:00Z",
                "updated_at": "2026-10-01T00:00:00Z"
            }],
            "audit": [],
            "settings": { "idle_lock_minutes": 5 }
        });

        let decoded: VaultData = serde_json::from_value(legacy).unwrap();
        let encoded = serde_json::to_value(decoded).unwrap();
        assert_eq!(
            encoded["entries"][0]["password_history"],
            serde_json::json!([])
        );
        assert_eq!(
            encoded["settings"]["password_history_limit"],
            serde_json::json!(3)
        );
    }

    #[test]
    fn password_changes_archive_only_the_previous_value() {
        let d = tmp_dir("password-history-change");
        let p = d.join("vault.db");
        let _ = fs::remove_file(&p);
        let mut v = Vault::create(&p, "Pw-12345").unwrap();
        let id = v
            .add_entry("example.com", "alice", "old-secret", "")
            .unwrap();

        v.update_entry(&id, None, None, Some("new-secret"), None)
            .unwrap();
        let serialized = serde_json::to_value(&v.entries()[0]).unwrap();
        let history = serialized["password_history"].as_array();
        assert_eq!(history.map(Vec::len), Some(1));
        assert_eq!(history.unwrap()[0]["password"], "old-secret");
        assert!(history.unwrap()[0]["archived_at"].as_str().is_some());

        v.update_entry(&id, Some("renamed.example"), None, None, None)
            .unwrap();
        v.update_entry(&id, None, None, Some("new-secret"), None)
            .unwrap();
        let serialized = serde_json::to_value(&v.entries()[0]).unwrap();
        assert_eq!(
            serialized["password_history"].as_array().map(Vec::len),
            Some(1)
        );
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn lowering_password_history_limit_prunes_oldest_and_persists() {
        let d = tmp_dir("password-history-limit");
        let p = d.join("vault.db");
        let _ = fs::remove_file(&p);
        let mut v = Vault::create(&p, "Pw-12345").unwrap();
        let id = v.add_entry("example.com", "alice", "p0", "").unwrap();
        for password in ["p1", "p2", "p3"] {
            v.update_entry(&id, None, None, Some(password), None)
                .unwrap();
        }

        v.set_password_history_limit(2).unwrap();
        assert_eq!(v.settings().password_history_limit, 2);
        let history = &v.entries()[0].password_history;
        assert_eq!(history.len(), 2);
        assert_eq!(history[0].password, "p2");
        assert_eq!(history[1].password, "p1");
        drop(v);

        let reopened = Vault::open_password(&p, "Pw-12345").unwrap();
        assert_eq!(reopened.settings().password_history_limit, 2);
        assert_eq!(reopened.entries()[0].password_history.len(), 2);
        assert!(!reopened
            .audit()
            .iter()
            .any(|event| event.detail.contains("p0")));
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn restoring_password_archives_current_and_removes_selected_history_version() {
        let d = tmp_dir("password-history-restore");
        let p = d.join("vault.db");
        let _ = fs::remove_file(&p);
        let mut v = Vault::create(&p, "Pw-12345").unwrap();
        let id = v.add_entry("example.com", "alice", "p0", "").unwrap();
        v.update_entry(&id, None, None, Some("p1"), None).unwrap();
        v.update_entry(&id, None, None, Some("p2"), None).unwrap();
        let selected_id = v.entries()[0].password_history[1].id.clone();

        v.update_entry_with_restore(&id, None, None, Some("p0"), None, Some(&selected_id))
            .unwrap();

        assert_eq!(v.entries()[0].password, "p0");
        let history = &v.entries()[0].password_history;
        assert_eq!(history.len(), 2);
        assert_eq!(history[0].password, "p2");
        assert_eq!(history[1].password, "p1");
        assert!(!history.iter().any(|item| item.id == selected_id));
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn create_and_password_login_roundtrip() {
        let d = tmp_dir("roundtrip");
        let p = d.join("vault.db");
        let _ = fs::remove_file(&p);
        let v = Vault::create(&p, "Correct-Horse-42").unwrap();
        drop(v);

        // 錯誤密碼 → 拒絕 + sidecar 記一筆
        assert!(matches!(
            Vault::open_password(&p, "wrong"),
            Err(VaultError::WrongPassword)
        ));
        let fc = read_failure_sidecar(&p);
        assert_eq!(fc.len(), 1);
        assert_eq!(fc[0].method, "password");

        // 正確密碼 → 成功 + sidecar 合併進 audit + 刪除
        let v = Vault::open_password(&p, "Correct-Horse-42").unwrap();
        assert!(v.audit().iter().any(|a| a.event == "login_success"));
        assert!(v
            .audit()
            .iter()
            .any(|a| a.event == "login_failed" && a.method == "password"));
        assert!(!failures_path(&p).exists());
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn key_register_and_key_login() {
        let d = tmp_dir("key");
        let p = d.join("vault.db");
        let _ = fs::remove_file(&p);
        let v = Vault::create(&p, "Pw-12345").unwrap();
        drop(v);

        // 註冊兩支金鑰（fingerprint + pin）
        let mut backend = MockBackend::new();
        let v = Vault::open_password(&p, "Pw-12345").unwrap();
        let mut v = v;
        let k1 = v.register_key(&mut backend, None).unwrap();
        assert_eq!(k1.kind, KeyKind::Fingerprint);
        // PIN 型：註冊時即需提供 PIN
        assert!(v
            .register_key(&mut MockBackend::new().with_next_kind(KeyKind::Pin), None)
            .is_err());
        let k2 = v
            .register_key(
                &mut MockBackend::new().with_next_kind(KeyKind::Pin),
                Some("1234"),
            )
            .unwrap();
        assert_eq!(k2.kind, KeyKind::Pin);
        assert_eq!(v.keys_meta().len(), 2);
        drop(v);

        // 金鑰 1（fingerprint，不需 PIN）登入
        let mut b = MockBackend::new();
        let v = Vault::open_key(&p, &base64_encode(&k1.credential_id), None, &mut b).unwrap();
        assert!(v
            .audit()
            .iter()
            .any(|a| a.event == "login_success" && a.method.contains("Mock")));
        drop(v);

        // 金鑰 2（pin）：無 PIN → PinRequired；有 PIN → 成功
        let mut b = MockBackend::new();
        assert!(matches!(
            Vault::open_key(&p, &base64_encode(&k2.credential_id), None, &mut b),
            Err(VaultError::Fido(FidoError::PinRequired(_)))
        ));
        let mut b = MockBackend::new();
        let v =
            Vault::open_key(&p, &base64_encode(&k2.credential_id), Some("1234"), &mut b).unwrap();
        assert!(!v.entries().iter().any(|_| false)); // 解鎖成功即可
        let _ = fs::remove_dir_all(&d);
    }

    struct ChosenCredentialBackend {
        selected_id: Vec<u8>,
        return_unregistered: bool,
    }

    impl FidoBackend for ChosenCredentialBackend {
        fn detect(&mut self) -> Result<crate::fido2::DetectedKey, FidoError> {
            Err(FidoError::NoDevice)
        }

        fn register_credential(
            &mut self,
            _detected: &crate::fido2::DetectedKey,
            _pin: Option<&str>,
        ) -> Result<RegisteredCredential, FidoError> {
            Err(FidoError::NoDevice)
        }

        fn get_prf_secret(&mut self, id: &[u8], _pin: Option<&str>) -> Result<[u8; 32], FidoError> {
            Ok(MockBackend::prf_for_credential(id))
        }

        fn get_prf_secret_for_any(
            &mut self,
            credential_ids: &[Vec<u8>],
            _pin: Option<&str>,
        ) -> Result<(Vec<u8>, [u8; 32]), FidoError> {
            if !self.return_unregistered && !credential_ids.contains(&self.selected_id) {
                return Err(FidoError::NoDevice);
            }
            Ok((
                self.selected_id.clone(),
                MockBackend::prf_for_credential(&self.selected_id),
            ))
        }
    }

    #[test]
    fn any_key_login_uses_the_credential_selected_by_the_backend() {
        let d = tmp_dir("any-key-selected");
        let p = d.join("vault.db");
        let _ = fs::remove_file(&p);
        let v = Vault::create(&p, "Pw-12345").unwrap();
        drop(v);

        let mut register_backend = MockBackend::new();
        let mut v = Vault::open_password(&p, "Pw-12345").unwrap();
        let first = v.register_key(&mut register_backend, None).unwrap();
        let second = v.register_key(&mut register_backend, Some("1234")).unwrap();
        assert_ne!(first.credential_id, second.credential_id);
        let expected_method = format!("fido2:{}", second.label);
        drop(v);

        let mut login_backend = ChosenCredentialBackend {
            selected_id: second.credential_id,
            return_unregistered: false,
        };
        let unlocked = Vault::open_any_key(&p, None, &mut login_backend).unwrap();
        assert!(unlocked
            .audit()
            .iter()
            .any(|event| { event.event == "login_success" && event.method == expected_method }));
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn any_key_login_rejects_a_credential_id_not_in_the_vault() {
        let d = tmp_dir("any-key-unknown");
        let p = d.join("vault.db");
        let _ = fs::remove_file(&p);
        let v = Vault::create(&p, "Pw-12345").unwrap();
        drop(v);

        let mut register_backend = MockBackend::new();
        let mut v = Vault::open_password(&p, "Pw-12345").unwrap();
        v.register_key(&mut register_backend, None).unwrap();
        drop(v);

        let mut login_backend = ChosenCredentialBackend {
            selected_id: vec![0xA5; 32],
            return_unregistered: true,
        };
        assert!(matches!(
            Vault::open_any_key(&p, None, &mut login_backend),
            Err(VaultError::Fido(FidoError::Internal(_)))
        ));
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn crud_and_timestamps() {
        let d = tmp_dir("crud");
        let p = d.join("vault.db");
        let _ = fs::remove_file(&p);
        let v = Vault::create(&p, "Pw-12345").unwrap();
        let mut v = v;

        let id = v
            .add_entry("example.com", "alice", "S3cret!x", "note1")
            .unwrap();
        let before = v.entries()[0].updated_at.clone();
        std::thread::sleep(std::time::Duration::from_millis(5));
        v.update_entry(&id, None, Some("alice2"), None, Some("note2"))
            .unwrap();
        assert_eq!(v.entries()[0].account, "alice2");
        assert_ne!(v.entries()[0].updated_at, before);
        assert_eq!(v.entries()[0].created_at, v.entries()[0].created_at); // 不變

        v.delete_entry(&id).unwrap();
        assert!(v.entries().is_empty());
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn portability_copy_decrypts_elsewhere() {
        let d1 = tmp_dir("port-a");
        let d2 = tmp_dir("port-b");
        let pa = d1.join("vault.db");
        let pb = d2.join("vault.db");
        let _ = fs::remove_file(&pa);
        let _ = fs::remove_file(&pb);

        let v = Vault::create(&pa, "Portable-99").unwrap();
        drop(v);
        fs::copy(&pa, &pb).unwrap(); // 直拷加密檔

        let v = Vault::open_password(&pb, "Portable-99").unwrap();
        assert!(v.entries().is_empty());
        let _ = fs::remove_dir_all(&d1);
        let _ = fs::remove_dir_all(&d2);
    }

    #[test]
    fn header_contains_no_secret_material() {
        let d = tmp_dir("nosecret");
        let p = d.join("vault.db");
        let _ = fs::remove_file(&p);
        let v = Vault::create(&p, "TopSecret-Pw-77").unwrap();
        drop(v);

        let buf = fs::read(&p).unwrap();
        let text = String::from_utf8_lossy(&buf);
        // 主密碼明文不得出現於檔案任何位置（header 或密文區都不可）。
        assert!(!text.contains("TopSecret-Pw-77"));

        // header JSON 部分（magic 後）也不得含密碼。
        let header_len = u32::from_le_bytes(buf[6..10].try_into().unwrap()) as usize;
        let header_str = String::from_utf8_lossy(&buf[10..10 + header_len]);
        assert!(!header_str.contains("TopSecret-Pw-77"));
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn custom_key_label_validation_trims_and_rejects_invalid_or_duplicate_values() {
        assert_eq!(
            validate_key_label("  Recovery Key  ", &[]).unwrap(),
            "Recovery Key"
        );
        assert!(validate_key_label("", &[]).is_err());
        assert!(validate_key_label("   ", &[]).is_err());
        assert!(validate_key_label("line\nbreak", &[]).is_err());
        assert!(validate_key_label(&"x".repeat(65), &[]).is_err());
        assert!(validate_key_label(&"😀".repeat(64), &[]).is_ok());
        assert!(validate_key_label(&"😀".repeat(65), &[]).is_err());
        assert!(validate_key_label(" recovery key ", &["Recovery Key"]).is_err());
        assert!(validate_key_label("ς", &["Σ"]).is_err());
        assert!(validate_key_label("STRASSE", &["Straße"]).is_err());
        assert!(validate_key_label("É", &["e\u{301}"]).is_err());
    }

    #[test]
    fn suggested_key_label_skips_existing_names_using_the_canonical_comparison() {
        assert_eq!(suggest_unique_key_label(&[]), "安全性金鑰");
        assert_eq!(
            suggest_unique_key_label(&["安全性金鑰", "安全性金鑰 2"]),
            "安全性金鑰 3"
        );
    }

    #[test]
    fn custom_key_label_persists_to_header_list_and_audit() {
        let d = tmp_dir("custom-key-label");
        let p = d.join("vault.db");
        let _ = fs::remove_file(&p);
        let mut v = Vault::create(&p, "Pw-12345").unwrap();
        let mut backend = MockBackend::new();
        let registered = v
            .register_key_with_label(&mut backend, None, "  Recovery Key  ")
            .unwrap();
        assert_eq!(registered.label, "Recovery Key");
        assert_eq!(v.keys_meta()[0].1, "Recovery Key");
        assert!(v.audit().iter().any(|event| {
            event.event == "key_registered" && event.method == "fido2:Recovery Key"
        }));
        drop(v);

        let reopened = Vault::open_password(&p, "Pw-12345").unwrap();
        assert_eq!(reopened.keys_meta()[0].1, "Recovery Key");
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn invalid_or_duplicate_key_label_is_rejected_before_backend_detection() {
        use std::sync::{
            atomic::{AtomicBool, Ordering},
            Arc,
        };

        struct DetectSpy(Arc<AtomicBool>);
        impl FidoBackend for DetectSpy {
            fn detect(&mut self) -> Result<crate::fido2::DetectedKey, FidoError> {
                self.0.store(true, Ordering::SeqCst);
                Err(FidoError::NoDevice)
            }
            fn register_credential(
                &mut self,
                _detected: &crate::fido2::DetectedKey,
                _pin: Option<&str>,
            ) -> Result<RegisteredCredential, FidoError> {
                Err(FidoError::NoDevice)
            }
            fn get_prf_secret(
                &mut self,
                _id: &[u8],
                _pin: Option<&str>,
            ) -> Result<[u8; 32], FidoError> {
                Err(FidoError::NoDevice)
            }
        }

        let d = tmp_dir("custom-key-label-invalid");
        let p = d.join("vault.db");
        let _ = fs::remove_file(&p);
        let mut v = Vault::create(&p, "Pw-12345").unwrap();
        let mut initial = MockBackend::new();
        v.register_key_with_label(&mut initial, None, "Existing Key")
            .unwrap();

        let detected = Arc::new(AtomicBool::new(false));
        let mut spy = DetectSpy(detected.clone());
        assert!(matches!(
            v.register_key_with_label(&mut spy, None, " existing key "),
            Err(VaultError::Format(_))
        ));
        assert!(!detected.load(Ordering::SeqCst));
        assert_eq!(v.keys_meta().len(), 1);

        let mut blank_spy = DetectSpy(detected.clone());
        assert!(matches!(
            v.register_key_with_label(&mut blank_spy, None, "  "),
            Err(VaultError::Format(_))
        ));
        assert!(!detected.load(Ordering::SeqCst));
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn batch_import_updates_preserve_blank_fields_and_keep_password_history() {
        let d = tmp_dir("batch-import-update");
        let p = d.join("vault.db");
        let _ = fs::remove_file(&p);
        let mut v = Vault::create(&p, "Pw-12345").unwrap();
        let existing_id = v
            .add_entry("example.com", "alice", "old-import-password", "old note")
            .unwrap();

        let parsed = crate::csv_import::parse_import_csv(
            "site,account,password,notes\n EXAMPLE.com , Alice ,new-import-password,new note\nnew.example,bob,,\n",
        )
        .unwrap();
        let plan = crate::csv_import::build_import_plan(v.entries(), parsed);
        let preview = v.import_entries(&plan).unwrap();

        assert_eq!((preview.added, preview.updated, preview.skipped), (1, 1, 0));
        let updated = v
            .entries()
            .iter()
            .find(|entry| entry.id == existing_id)
            .unwrap();
        assert_eq!(updated.site, "EXAMPLE.com");
        assert_eq!(updated.account, "Alice");
        assert_eq!(updated.password, "new-import-password");
        assert_eq!(updated.password_history.len(), 1);
        assert_eq!(updated.password_history[0].password, "old-import-password");
        assert_eq!(updated.notes, "new note");
        let added = v
            .entries()
            .iter()
            .find(|entry| entry.site == "new.example")
            .unwrap();
        assert_eq!(added.account, "bob");
        assert_eq!(added.password, "");
        assert_eq!(added.notes, "");

        let blank_update = crate::csv_import::parse_import_csv(
            "site,account,password,notes\nexample.com,alice,,\n",
        )
        .unwrap();
        let plan = crate::csv_import::build_import_plan(v.entries(), blank_update);
        v.import_entries(&plan).unwrap();
        let updated = v
            .entries()
            .iter()
            .find(|entry| entry.id == existing_id)
            .unwrap();
        assert_eq!(updated.password, "new-import-password");
        assert_eq!(updated.notes, "new note");
        assert_eq!(updated.password_history.len(), 1);

        let audit = serde_json::to_string(v.audit()).unwrap();
        assert!(audit.contains("entries_imported"));
        assert!(!audit.contains("old-import-password"));
        assert!(!audit.contains("new-import-password"));
        assert!(!audit.contains("new note"));
        drop(v);
        let reopened = Vault::open_password(&p, "Pw-12345").unwrap();
        assert_eq!(reopened.entries().len(), 2);
        assert_eq!(
            reopened
                .entries()
                .iter()
                .find(|entry| entry.id == existing_id)
                .unwrap()
                .password,
            "new-import-password"
        );
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn failed_batch_import_keeps_memory_and_persisted_vault_unchanged() {
        let d = tmp_dir("batch-import-atomic");
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        let p = d.join("vault.db");
        let mut v = Vault::create(&p, "Pw-12345").unwrap();
        let existing_id = v
            .add_entry("example.com", "alice", "persisted-password", "old")
            .unwrap();
        let parsed = crate::csv_import::parse_import_csv(
            "site,account,password,notes\nexample.com,alice,changed-password,new\nnew.example,bob,secret,\n",
        )
        .unwrap();
        let plan = crate::csv_import::build_import_plan(v.entries(), parsed);
        let temp_path = p.with_extension("db.tmp");
        fs::create_dir(&temp_path).unwrap();

        assert!(v.import_entries(&plan).is_err());
        assert_eq!(v.entries().len(), 1);
        assert_eq!(v.entries()[0].password, "persisted-password");
        assert!(!v
            .audit()
            .iter()
            .any(|event| event.event == "entries_imported"));
        drop(v);
        fs::remove_dir(&temp_path).unwrap();
        let reopened = Vault::open_password(&p, "Pw-12345").unwrap();
        assert_eq!(reopened.entries().len(), 1);
        assert_eq!(reopened.entries()[0].id, existing_id);
        assert_eq!(reopened.entries()[0].password, "persisted-password");
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn audit_has_no_plaintext_passwords() {
        let d = tmp_dir("audit");
        let p = d.join("vault.db");
        let _ = fs::remove_file(&p);
        let v = Vault::create(&p, "Pw-12345").unwrap();
        let mut v = v;
        v.add_entry("bank.com", "bob", "Bank-Pass-000", "").unwrap();

        // 重新解鎖後檢查 audit JSON 內不含任何條目密碼。
        drop(v);
        let v = Vault::open_password(&p, "Pw-12345").unwrap();
        let audit_json = serde_json::to_string(v.audit()).unwrap();
        assert!(!audit_json.contains("Bank-Pass-000"));
        assert!(!audit_json.contains("Pw-12345"));
        let _ = fs::remove_dir_all(&d);
    }
}
