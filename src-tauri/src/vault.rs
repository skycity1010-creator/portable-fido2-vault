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
use std::time::{Duration, Instant};

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
    /// 雙人版金鑰登入前提未滿足：A、B 群組各至少一支金鑰。
    DualNotReady,
    /// 兩步驟登入第一步完成後，未在時限內完成第二步。
    DualStepExpired,
    /// 雙人版：不可刪除群組中的最後一支金鑰（§4.5）。
    LastKeyInGroup(KeyGroup),
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
            Self::DualNotReady => write!(
                f,
                "需 A、B 群組各至少一支金鑰才能以金鑰登入；目前請以主密碼登入"
            ),
            Self::LastKeyInGroup(group) => write!(
                f,
                "不可刪除 {} 群組的最後一支金鑰（A、B 群組各須保留至少一支）",
                group.as_str()
            ),
            Self::DualStepExpired => {
                write!(f, "第二位成員未在時限內完成驗證，請從第一步重新開始")
            }
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

/// Cleanup never rolls back a successfully persisted slot removal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlatformCleanupOutcome {
    NotApplicable,
    Removed,
    ManualRemovalRequired(PlatformCleanupWarning),
}

/// Non-secret result of cleaning a newly-created platform credential after a failed
/// registration. `NotAttempted` means the credential could not be re-proven local (or a
/// precondition failed) so it was deliberately not deleted, yet may still exist.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegistrationCleanupReport {
    Removed,
    DeleteFailed,
    NotAttempted,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlatformCleanupWarning {
    NotLocal,
    DiscoveryFailed,
    DeleteFailed,
}

/// 註冊第二階段（驗證斷言）因 Windows 未交回前景而被拒時保留的狀態（D9-F1）。
/// 只存在 Rust 端記憶體：不可序列化、不可複製；PIN 與建立時 PRF 在 drop 時清零。
pub enum PendingRegistration {
    Roaming {
        credential: RegisteredCredential,
        pin: Option<Zeroizing<String>>,
        custom_label: Option<String>,
        group: Option<KeyGroup>,
    },
    Platform {
        credential: RegisteredCredential,
        creation_prf: Zeroizing<[u8; 32]>,
        label: String,
    },
}

impl PendingRegistration {
    pub fn is_platform(&self) -> bool {
        matches!(self, Self::Platform { .. })
    }
}

impl std::fmt::Debug for PendingRegistration {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // 只顯示種類與 label；不含 PIN、PRF、credential ID。
        match self {
            Self::Roaming {
                credential,
                custom_label,
                ..
            } => f
                .debug_struct("PendingRegistration::Roaming")
                .field("label", custom_label.as_ref().unwrap_or(&credential.label))
                .finish_non_exhaustive(),
            Self::Platform { label, .. } => f
                .debug_struct("PendingRegistration::Platform")
                .field("label", label)
                .finish_non_exhaustive(),
        }
    }
}

#[derive(Debug)]
pub enum RegistrationOutcome {
    Registered(RegisteredCredential),
    HandoffRequired(PendingRegistration),
}

/// 放棄 pending 註冊後的清理結果。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CancelOutcome {
    /// 已刪除本次建立的 Windows Hello credential。
    Removed,
    /// 無法證明或無法刪除；需使用者到 Windows 設定手動刪除本次項目。
    ManualRemovalRequired,
    /// roaming：金庫未新增槽位，pending 已丟棄（金鑰端無法由程式刪除）。
    Discarded,
}

/// 放棄 pending 註冊（D9-F1）。Windows Hello：重新以 RP 清單證明後 best-effort 刪除。
pub fn cancel_registration(
    backend: &mut (dyn FidoBackend + 'static),
    pending: PendingRegistration,
) -> CancelOutcome {
    let PendingRegistration::Platform { credential, .. } = pending else {
        return CancelOutcome::Discarded;
    };
    // Native delete has no RP argument: fresh RP-scoped membership is mandatory.
    if !backend.platform_status().available() {
        return CancelOutcome::ManualRemovalRequired;
    }
    match backend.list_platform_credentials() {
        Ok(local) if local.contains(&credential.credential_id) => {
            match backend.delete_platform_credential(&credential.credential_id) {
                Ok(()) => CancelOutcome::Removed,
                Err(_) => CancelOutcome::ManualRemovalRequired,
            }
        }
        _ => CancelOutcome::ManualRemovalRequired,
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

/// 金鑰槽的 authenticator 種類（docs/plans/windows-hello-single.md §3）。
/// 明文、未認證的 metadata：只決定用哪種 attachment 去要 PRF；竄改只會讓該 slot 無法使用。
/// 欄位不存在 = roaming（YubiKey）。目前只有 `platform`；大小寫嚴格，未知值反序列化失敗（fail closed）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SlotAuthenticator {
    Platform,
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
    /// 單人版（v1）：`Some(Platform)` = Windows Hello slot；None = roaming（不序列化，舊檔 byte-identical）。
    /// 雙群組控管版（v2）必為 None。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authenticator: Option<SlotAuthenticator>,
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
/// 等待時限允許範圍（秒）；header 明文鏡像一律 clamp 到此範圍（§4.3）。
pub const MIN_DUAL_STEP_TIMEOUT_SECS: u32 = 30;
pub const MAX_DUAL_STEP_TIMEOUT_SECS: u32 = 600;
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
            // 雙群組控管版不支援 Windows Hello（docs/plans/windows-hello-single.md §4.5）。
            if header
                .key_slots
                .iter()
                .any(|slot| slot.authenticator.is_some())
            {
                return Err(VaultError::Format(
                    "v2 金庫的金鑰槽不應含 authenticator 欄位".into(),
                ));
            }
        }
    }
    Ok(())
}

/// 登入前可讀的等待時限：header 明文鏡像 clamp 到允許範圍；缺值用預設。
pub fn effective_dual_step_timeout_secs(header: &Header) -> u32 {
    header
        .dual_step_timeout_secs
        .map(|secs| secs.clamp(MIN_DUAL_STEP_TIMEOUT_SECS, MAX_DUAL_STEP_TIMEOUT_SECS))
        .unwrap_or(DEFAULT_DUAL_STEP_TIMEOUT_SECS)
}

/// 稽核用的成員識別：`<群組>:<跳脫後名稱>#<credential 指紋>`。名稱是 header 明文（未驗證），
/// 指紋取自已通過 AAD 驗證的 credential_id，讓竄改名稱無法冒名。
fn dual_audit_party(group: KeyGroup, label: &str, credential_id: &[u8]) -> String {
    use sha2::Digest;
    let digest = sha2::Sha256::digest(credential_id);
    let fingerprint: String = digest[..4].iter().map(|b| format!("{b:02x}")).collect();
    format!(
        "{}:{}#{fingerprint}",
        group.as_str(),
        escape_audit_label(label)
    )
}

/// 稽核 method 內的名稱跳脫（`%` `+` `:` `#`），避免分隔字元造成歧義。
fn escape_audit_label(label: &str) -> String {
    let mut out = String::with_capacity(label.len());
    for ch in label.chars() {
        match ch {
            '%' => out.push_str("%25"),
            '+' => out.push_str("%2B"),
            ':' => out.push_str("%3A"),
            '#' => out.push_str("%23"),
            other => out.push(other),
        }
    }
    out
}

/// 雙人版：若刪除此 credential 會讓它的群組歸零，回傳該群組（§4.5 一律禁止）。
/// 單人版或找不到槽位 → None。
pub fn last_key_in_group(header: &Header, credential_id_b64: &str) -> Option<KeyGroup> {
    if edition_of(header) != Edition::Dual {
        return None;
    }
    let group = header
        .key_slots
        .iter()
        .find(|slot| slot.credential_id == credential_id_b64)?
        .group?;
    let members = header
        .key_slots
        .iter()
        .filter(|slot| slot.group == Some(group))
        .count();
    (members <= 1).then_some(group)
}

/// 綁定值：created_at + dual_slot 密文（不含機密）。
fn dual_binding(header: &Header) -> Result<(String, String), VaultError> {
    let slot = header
        .dual_slot
        .as_ref()
        .ok_or_else(|| VaultError::Format("v2 金庫缺少 dual_slot".into()))?;
    Ok((header.created_at.clone(), slot.ct.clone()))
}

/// 以金鑰 PRF 解開群組槽位（AAD 綁定群組 + credential_id）→ 該群組 share。
fn unwrap_group_share(
    slot: &KeySlot,
    secret: &[u8; 32],
) -> Result<Zeroizing<[u8; 32]>, VaultError> {
    let group = slot
        .group
        .ok_or_else(|| VaultError::Format("v2 金庫的金鑰槽缺少群組".into()))?;
    let cred = base64_decode(&slot.credential_id)
        .map_err(|_| VaultError::Format("credential_id 解碼失敗".into()))?;
    let nonce = slot_nonce(&slot.nonce)?;
    let ct = base64_decode(&slot.ct).map_err(|_| VaultError::Format("key slot 解碼失敗".into()))?;
    let k = Zeroizing::new(kek_from_prf_secret(secret));
    let plain = Zeroizing::new(
        aes_gcm_decrypt_aad(&k, &nonce, &ct, &dual_key_slot_aad(group, &cred))
            .map_err(VaultError::Crypto)?,
    );
    if plain.len() != 32 {
        return Err(VaultError::Crypto(CryptoError::DecryptFailed));
    }
    let mut share = Zeroizing::new([0u8; 32]);
    share.copy_from_slice(&plain);
    Ok(share)
}

fn decode_credential_ids(slots: &[&KeySlot]) -> Result<Vec<Vec<u8>>, VaultError> {
    slots
        .iter()
        .map(|slot| {
            base64_decode(&slot.credential_id)
                .map_err(|_| VaultError::Format("credential_id 解碼失敗".into()))
        })
        .collect()
}

/// 兩步驟登入第一步完成後的暫存狀態（§4.3）。只存在 Rust 端記憶體、不可複製；
/// 第二步以 by-value 取用（一次性），drop 時 share 清零。
pub struct DualPending {
    path: PathBuf,
    first_group: KeyGroup,
    first_label: String,
    /// 稽核用的第一位成員識別（含 credential 指紋）。
    first_party: String,
    share: Zeroizing<[u8; 32]>,
    deadline: Instant,
    timeout_secs: u32,
    /// 綁定第一步讀到的金庫（created_at + dual_slot 密文），第二步前檔案被換掉即拒絕。
    binding: (String, String),
}

impl std::fmt::Debug for DualPending {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DualPending")
            .field("first_group", &self.first_group)
            .field("first_label", &self.first_label)
            .field("share", &"<redacted>")
            .field("timeout_secs", &self.timeout_secs)
            .finish()
    }
}

impl DualPending {
    pub fn first_group(&self) -> KeyGroup {
        self.first_group
    }

    pub fn first_label(&self) -> &str {
        &self.first_label
    }

    pub fn timeout_secs(&self) -> u32 {
        self.timeout_secs
    }

    /// 剩餘時間（逾時後為 0）。
    pub fn remaining(&self, now: Instant) -> Duration {
        self.deadline.saturating_duration_since(now)
    }

    pub fn is_expired(&self, now: Instant) -> bool {
        now > self.deadline
    }

    /// 逾時清除（app 層計時器呼叫）：記 sidecar `fido2-dual-timeout`，share 隨 drop 清零。
    pub fn expire(self) -> Result<(), VaultError> {
        record_login_failure(&self.path, "fido2-dual-timeout")
    }

    #[cfg(test)]
    pub(crate) fn for_test(path: PathBuf, deadline: Instant) -> Self {
        Self {
            path,
            first_group: KeyGroup::A,
            first_label: "test".into(),
            first_party: "A:test#00000000".into(),
            share: Zeroizing::new([7u8; 32]),
            deadline,
            timeout_secs: DEFAULT_DUAL_STEP_TIMEOUT_SECS,
            binding: (String::new(), String::new()),
        }
    }

    /// 使用者取消：記 sidecar（僅時間戳 + method），share 隨 drop 清零。
    pub fn cancel(self) -> Result<(), VaultError> {
        record_login_failure(&self.path, "fido2-dual-cancel")
    }
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
            let secs = data
                .settings
                .dual_step_timeout_secs
                .ok_or_else(|| VaultError::Format("v2 金庫 payload 缺少等待時限設定".into()))?;
            if !(MIN_DUAL_STEP_TIMEOUT_SECS..=MAX_DUAL_STEP_TIMEOUT_SECS).contains(&secs) {
                return Err(VaultError::Format(
                    "v2 金庫 payload 等待時限超出 30–600 秒".into(),
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

/// Audit and locked-login sidecar timestamps use the system's local wall clock.
/// Non-audit metadata retains RFC3339 so existing format and bindings stay unchanged.
fn now_audit_time() -> String {
    chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string()
}

// ─────────────────────────── Vault ───────────────────────────

pub struct Vault {
    pub path: PathBuf,
    header: Header,
    data: VaultData,
    kek: Zeroizing<[u8; 32]>,
    /// Non-secret one-shot side channel; preserves the original typed registration error.
    registration_cleanup_report: Option<RegistrationCleanupReport>,
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
                ts: now_audit_time(),
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
            registration_cleanup_report: None,
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

    /// One-shot, non-secret report of a failed deletion following a registration error.
    /// The caller must consume it after each ceremony; the original VaultError is unchanged.
    pub fn take_registration_cleanup_report(&mut self) -> Option<RegistrationCleanupReport> {
        self.registration_cleanup_report.take()
    }

    /// True when `id` names no existing slot, i.e. it can only be the pending new credential.
    fn is_new_platform_credential_id(&self, id: &[u8]) -> bool {
        !id.is_empty()
            && !self
                .header
                .key_slots
                .iter()
                .any(|slot| base64_decode(&slot.credential_id).is_ok_and(|known| known == id))
    }

    // ── 開啟（解鎖）──

    /// 雙群組控管版：主密碼緊急登入（break-glass，§4.4）。
    pub fn open_password_dual(path: &Path, password: &str) -> Result<Self, VaultError> {
        Self::open_password_with_edition(path, password, Edition::Dual)
    }

    /// 雙人版金鑰登入第一步：broker 允許清單 = 全部 A+B credential；解出所選金鑰群組的 share 暫存。
    pub fn dual_login_begin(
        path: &Path,
        pin: Option<&str>,
        backend: &mut (dyn FidoBackend + 'static),
        clock: &mut dyn FnMut() -> Instant,
    ) -> Result<DualPending, VaultError> {
        let (header, _payload) = Self::read_file(path, Edition::Dual)?;
        let has_group = |group: KeyGroup| header.key_slots.iter().any(|s| s.group == Some(group));
        if !(has_group(KeyGroup::A) && has_group(KeyGroup::B)) {
            return Err(VaultError::DualNotReady);
        }
        let all: Vec<&KeySlot> = header.key_slots.iter().collect();
        let credential_ids = decode_credential_ids(&all)?;
        let binding = dual_binding(&header)?;
        let timeout_secs = effective_dual_step_timeout_secs(&header);

        let (selected_id, secret) = backend.get_prf_secret_for_any(&credential_ids, pin)?;
        let secret = Zeroizing::new(secret);
        let selected_b64 = base64_encode(&selected_id);
        let slot = header
            .key_slots
            .iter()
            .find(|slot| slot.credential_id == selected_b64)
            .ok_or_else(|| {
                VaultError::Fido(FidoError::Internal(
                    "backend selected a credential not registered in this vault".into(),
                ))
            })?;
        let first_group = slot
            .group
            .ok_or_else(|| VaultError::Format("v2 金庫的金鑰槽缺少群組".into()))?;
        let share = match unwrap_group_share(slot, &secret) {
            Ok(share) => share,
            Err(_) => {
                record_login_failure(
                    path,
                    &format!("fido2-dual-step1:{}", escape_audit_label(&slot.label)),
                )?;
                return Err(VaultError::Crypto(CryptoError::DecryptFailed));
            }
        };
        let first_cred = base64_decode(&slot.credential_id)
            .map_err(|_| VaultError::Format("credential_id 解碼失敗".into()))?;
        // 倒數從「第一支金鑰完成」開始（§4.3），不吃掉第一步的互動時間。
        let now = clock();
        Ok(DualPending {
            path: path.to_path_buf(),
            first_group,
            first_label: slot.label.clone(),
            first_party: dual_audit_party(first_group, &slot.label, &first_cred),
            share,
            deadline: now + Duration::from_secs(u64::from(timeout_secs)),
            timeout_secs,
            binding,
        })
    }

    /// 雙人版金鑰登入第二步：允許清單只含另一群組；兩份 share → HKDF → 解 dual_slot 得 KEK。
    pub fn dual_login_complete(
        pending: DualPending,
        pin: Option<&str>,
        backend: &mut (dyn FidoBackend + 'static),
        clock: &mut dyn FnMut() -> Instant,
    ) -> Result<Self, VaultError> {
        let now = clock();
        // 逾時：不再提示第二支金鑰；pending（含 share）隨 drop 清零。
        if pending.is_expired(now) {
            record_login_failure(&pending.path, "fido2-dual-timeout")?;
            return Err(VaultError::DualStepExpired);
        }
        let path = pending.path.clone();
        let (header, payload) = Self::read_file(&path, Edition::Dual)?;
        if dual_binding(&header)? != pending.binding {
            record_login_failure(&path, "fido2-dual-binding-mismatch")?;
            return Err(VaultError::Format(
                "金庫在兩步驟之間已變更，請從第一步重新開始".into(),
            ));
        }
        let second_group = pending.first_group.other();
        let second_slots: Vec<&KeySlot> = header
            .key_slots
            .iter()
            .filter(|slot| slot.group == Some(second_group))
            .collect();
        if second_slots.is_empty() {
            return Err(VaultError::DualNotReady);
        }
        // 允許清單只含另一群組 → 同群組金鑰無法完成第二步。
        let credential_ids = decode_credential_ids(&second_slots)?;
        let (selected_id, secret) = backend.get_prf_secret_for_any(&credential_ids, pin)?;
        let secret = Zeroizing::new(secret);
        // 截止時間是硬上限：第二支金鑰互動結束後再檢查一次。
        if pending.is_expired(clock()) {
            record_login_failure(&path, "fido2-dual-timeout")?;
            return Err(VaultError::DualStepExpired);
        }
        let selected_b64 = base64_encode(&selected_id);
        // 不信任後端：所選 credential 必須屬於另一群組。
        let slot = match second_slots
            .iter()
            .find(|slot| slot.credential_id == selected_b64)
            .copied()
        {
            Some(slot) => slot,
            None => {
                record_login_failure(&path, "fido2-dual-step2-rejected")?;
                return Err(VaultError::Fido(FidoError::Internal(
                    "backend selected a credential outside the required group".into(),
                )));
            }
        };
        let step2_failure = |label: &str| -> VaultError {
            match record_login_failure(
                &path,
                &format!("fido2-dual-step2:{}", escape_audit_label(label)),
            ) {
                Ok(()) => VaultError::Crypto(CryptoError::DecryptFailed),
                Err(e) => e,
            }
        };
        let second_share = match unwrap_group_share(slot, &secret) {
            Ok(share) => share,
            Err(_) => return Err(step2_failure(&slot.label)),
        };
        let (share_a, share_b) = match pending.first_group {
            KeyGroup::A => (&pending.share, &second_share),
            KeyGroup::B => (&second_share, &pending.share),
        };
        let wrap = dual_wrap_key_from_shares(share_a, share_b);
        let dual_slot = header
            .dual_slot
            .as_ref()
            .ok_or_else(|| VaultError::Format("v2 金庫缺少 dual_slot".into()))?;
        let nonce = slot_nonce(&dual_slot.nonce)?;
        let ct = base64_decode(&dual_slot.ct)
            .map_err(|_| VaultError::Format("dual slot 解碼失敗".into()))?;
        let kek_bytes = match aes_gcm_decrypt_aad(&wrap, &nonce, &ct, DUAL_SLOT_AAD) {
            Ok(bytes) if bytes.len() == 32 => Zeroizing::new(bytes),
            _ => return Err(step2_failure(&slot.label)),
        };
        let mut kek = Zeroizing::new([0u8; 32]);
        kek.copy_from_slice(&kek_bytes);
        let second_cred = base64_decode(&slot.credential_id)
            .map_err(|_| VaultError::Format("credential_id 解碼失敗".into()))?;
        let method = format!(
            "fido2-dual:{}+{}",
            pending.first_party,
            dual_audit_party(second_group, &slot.label, &second_cred)
        );
        Self::unlock(&path, header, payload, kek, &method)
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

    /// Backend-aware password seam for R3; the original password API stays intact.
    pub fn open_password_with_platform(
        path: &Path,
        password: &str,
        edition: Edition,
        backend: &mut (dyn FidoBackend + 'static),
    ) -> Result<Self, VaultError> {
        Self::open_password_with_optional_platform(path, password, edition, Some(backend))
    }

    fn open_password_with_edition(
        path: &Path,
        password: &str,
        edition: Edition,
    ) -> Result<Self, VaultError> {
        Self::open_password_with_optional_platform(path, password, edition, None)
    }

    fn open_password_with_optional_platform(
        path: &Path,
        password: &str,
        edition: Edition,
        backend: Option<&mut (dyn FidoBackend + 'static)>,
    ) -> Result<Self, VaultError> {
        // 雙群組控管版的主密碼登入是 break-glass，稽核 method 與一般登入區分。
        let method = match edition {
            Edition::Single => "password",
            Edition::Dual => "password-breakglass",
        };
        let (mut header, payload) = Self::read_file(path, edition)?;
        if let Some(backend) = backend {
            classify_platform_best_effort(&mut header, backend)?;
        }
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

    /// Platform login is edition-explicit and never uses edition::current().
    pub fn open_windows_hello(
        path: &Path,
        backend: &mut (dyn FidoBackend + 'static),
        edition: Edition,
    ) -> Result<Self, VaultError> {
        let (mut header, payload) = Self::read_file(path, edition)?;
        if edition != Edition::Single {
            return Err(VaultError::Format("Windows Hello 僅支援單人版".into()));
        }
        if !backend.platform_status().available() {
            return Err(
                FidoError::NotSupported(crate::fido2::PLATFORM_UNSUPPORTED_MSG.into()).into(),
            );
        }
        let local = backend.list_platform_credentials()?;
        classify_local_platform_slots(&mut header, &local)?;
        let slots: Vec<&KeySlot> = header
            .key_slots
            .iter()
            .filter(|slot| slot.authenticator == Some(SlotAuthenticator::Platform))
            .collect();
        let ids = decode_credential_ids(&slots)?
            .into_iter()
            .filter(|id| local.contains(id))
            .collect::<Vec<_>>();
        if ids.is_empty() {
            return Err(FidoError::PlatformCredentialMissing.into());
        }
        let failure_label = slots
            .iter()
            .find(|slot| base64_decode(&slot.credential_id).is_ok_and(|id| ids.contains(&id)))
            .ok_or(FidoError::PlatformCredentialMissing)?
            .label
            .clone();
        let (selected, mut raw) = match backend.get_platform_prf_secret(&ids) {
            Ok(result) => result,
            Err(error) => {
                // Only a typed authentication rejection is evidence of a failed
                // login. Native cancellation and other opaque HRESULTs arrive as
                // Internal in the existing backend; never infer auth failure (or
                // cancellation) by parsing its human-readable error string.
                if matches!(error, FidoError::PinRejected) {
                    record_login_failure(path, &format!("windows-hello:{failure_label}"))?;
                }
                return Err(error.into());
            }
        };
        let secret = Zeroizing::new(raw);
        raw.zeroize();
        if !ids.contains(&selected) {
            let fallback = slots
                .iter()
                .find(|slot| base64_decode(&slot.credential_id).is_ok_and(|id| ids.contains(&id)))
                .ok_or(FidoError::PlatformCredentialMissing)?;
            record_login_failure(path, &format!("windows-hello:{}", fallback.label))?;
            return Err(FidoError::PlatformCredentialMissing.into());
        }
        let selected_b64 = base64_encode(&selected);
        let slot = header
            .key_slots
            .iter()
            .find(|slot| {
                slot.credential_id == selected_b64
                    && slot.authenticator == Some(SlotAuthenticator::Platform)
            })
            .ok_or(FidoError::PlatformCredentialMissing)?
            .clone();
        Self::open_with_key_secret(path, header, payload, slot, secret)
    }

    /// FIDO2 金鑰登入（credential_id_b64 須為 header.key_slots 之一）。
    pub fn open_key(
        path: &Path,
        credential_id_b64: &str,
        pin: Option<&str>,
        backend: &mut (dyn FidoBackend + 'static),
    ) -> Result<Self, VaultError> {
        let (mut header, payload) = Self::read_file(path, Edition::Single)?;
        classify_platform_best_effort(&mut header, backend)?;
        let slot = header
            .key_slots
            .iter()
            .find(|s| s.credential_id == credential_id_b64 && s.authenticator.is_none())
            .ok_or(VaultError::Fido(FidoError::NoDevice))?
            .clone();

        let cred_id = base64_decode(&slot.credential_id)
            .map_err(|_| VaultError::Format("credential_id 解碼失敗".into()))?;
        // PinRequired → 尚未真正嘗試，不記失敗（使用者只是還沒提供 PIN）。
        let mut raw = backend.get_prf_secret(&cred_id, pin)?;
        let secret = Zeroizing::new(raw);
        raw.zeroize();
        Self::open_with_key_secret(path, header, payload, slot, secret)
    }

    /// FIDO2 金鑰登入：一次交給 backend 所有槽位，由 broker 選擇 credential。
    pub fn open_any_key(
        path: &Path,
        pin: Option<&str>,
        backend: &mut (dyn FidoBackend + 'static),
    ) -> Result<Self, VaultError> {
        let (mut header, payload) = Self::read_file(path, Edition::Single)?;
        classify_platform_best_effort(&mut header, backend)?;
        let credential_ids = header
            .key_slots
            .iter()
            .filter(|slot| slot.authenticator.is_none())
            .map(|slot| {
                base64_decode(&slot.credential_id)
                    .map_err(|_| VaultError::Format("credential_id 解碼失敗".into()))
            })
            .collect::<Result<Vec<_>, _>>()?;
        if credential_ids.is_empty() {
            return Err(VaultError::Fido(FidoError::NoDevice));
        }

        let (selected_id, mut raw) = backend.get_prf_secret_for_any(&credential_ids, pin)?;
        let secret = Zeroizing::new(raw);
        raw.zeroize();
        if !credential_ids.contains(&selected_id) {
            return Err(FidoError::Internal(
                "backend selected a credential outside the roaming allow-list".into(),
            )
            .into());
        }
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
        secret: Zeroizing<[u8; 32]>,
    ) -> Result<Self, VaultError> {
        let k = Zeroizing::new(kek_from_prf_secret(&secret));
        let method = if slot.authenticator == Some(SlotAuthenticator::Platform) {
            format!("windows-hello:{}", slot.label)
        } else {
            format!("fido2:{}", slot.label)
        };
        let nonce = slot_nonce(&slot.nonce)?;
        let ct =
            base64_decode(&slot.ct).map_err(|_| VaultError::Format("key slot 解碼失敗".into()))?;

        match aes_gcm_decrypt(&k, &nonce, &ct).map(Zeroizing::new) {
            Ok(kek_bytes) if kek_bytes.len() == 32 => {
                let mut kek = Zeroizing::new([0u8; 32]);
                kek.copy_from_slice(&kek_bytes);
                Self::unlock(path, header, payload, kek, &method)
            }
            _ => {
                record_login_failure(path, &method)?;
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
        let mut header = header;
        if edition_of(&header) == Edition::Dual {
            // The encrypted payload is authoritative; compare the RAW mirror, not its clamp.
            let secs = data
                .settings
                .dual_step_timeout_secs
                .ok_or_else(|| VaultError::Format("v2 金庫 payload 缺少等待時限設定".into()))?;
            if header.dual_step_timeout_secs != Some(secs) {
                header.dual_step_timeout_secs = Some(secs);
                data.audit.push(AuditEvent {
                    ts: now_audit_time(),
                    event: "settings_tamper_detected".into(),
                    method: "system".into(),
                    detail: format!("dual_step_timeout_secs mirror repaired to {secs}"),
                });
            }
        }

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
            // Sidecar events occurred after the previous unlocked session. Append them
            // before login_success so reverse display and oldest-first trimming agree.
            data.audit.extend(events);
        }

        let mut vault = Self {
            path: path.to_path_buf(),
            header,
            data,
            kek,
            registration_cleanup_report: None,
        };
        vault.data.audit.push(AuditEvent {
            ts: now_audit_time(),
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

    /// Read-only R3 classification seam; errors remain visible to its caller.
    pub fn read_header_with_platform(
        path: &Path,
        edition: Edition,
        backend: &mut (dyn FidoBackend + 'static),
    ) -> Result<Header, VaultError> {
        let mut header = Self::read_header(path, edition)?;
        if edition == Edition::Single && backend.platform_status().available() {
            let local = backend.list_platform_credentials()?;
            classify_local_platform_slots(&mut header, &local)?;
        }
        Ok(header)
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
            ts: now_audit_time(),
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
            ts: now_audit_time(),
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

    /// Change the authenticated timeout and its login-screen mirror together.
    /// Only an unlocked dual vault may call this; invalid input never mutates state.
    pub fn set_dual_step_timeout(&mut self, secs: u32) -> Result<(), VaultError> {
        if self.edition() != Edition::Dual {
            return Err(VaultError::Format("單人版不支援雙群組等待時限".into()));
        }
        if !(MIN_DUAL_STEP_TIMEOUT_SECS..=MAX_DUAL_STEP_TIMEOUT_SECS).contains(&secs) {
            return Err(VaultError::Format("等待時限須介於 30–600 秒".into()));
        }
        let previous_setting = self.data.settings.dual_step_timeout_secs;
        let previous_mirror = self.header.dual_step_timeout_secs;
        let previous_audit = self.data.audit.clone();
        self.data.settings.dual_step_timeout_secs = Some(secs);
        self.header.dual_step_timeout_secs = Some(secs);
        let result = self.record(
            "settings_changed",
            "manual",
            &format!("dual_step_timeout_secs={secs}"),
        );
        if result.is_err() {
            self.data.settings.dual_step_timeout_secs = previous_setting;
            self.header.dual_step_timeout_secs = previous_mirror;
            self.data.audit = previous_audit;
        }
        result
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

    /// D9-F1：與 `register_key_for` 相同，但第二個 ceremony 因前景未交回被拒時回 `HandoffRequired`。
    pub fn begin_register_key_for(
        &mut self,
        backend: &mut (dyn FidoBackend + 'static),
        pin: Option<&str>,
        candidate_label: &str,
        group: Option<KeyGroup>,
    ) -> Result<RegistrationOutcome, VaultError> {
        // 與 register_key_for → register_key_with_label / register_key_in_group 相同的前置檢查。
        if group.is_some() && self.edition() != Edition::Dual {
            return Err(VaultError::Format("單人版金庫不支援金鑰群組".into()));
        }
        let label = self.validate_new_key_label(candidate_label)?;
        self.begin_register_key_internal(backend, pin, Some(&label), group)
    }

    /// D9-F1：與 `register_windows_hello` 相同，但前景未交回時保留 credential 並回 `HandoffRequired`。
    pub fn begin_register_windows_hello(
        &mut self,
        backend: &mut (dyn FidoBackend + 'static),
        computer_name: &str,
        edition: Edition,
    ) -> Result<RegistrationOutcome, VaultError> {
        self.registration_cleanup_report = None;
        check_header_edition(&self.header, edition)?;
        if edition != Edition::Single {
            return Err(VaultError::Format("Windows Hello 僅支援單人版".into()));
        }
        let computer_name = validate_key_label(computer_name, &[])?;
        let candidate = format!("Windows Hello（本機 {computer_name}）");
        validate_key_label(&candidate, &[])?;
        if !backend.platform_status().available() {
            return Err(
                FidoError::NotSupported(crate::fido2::PLATFORM_UNSUPPORTED_MSG.into()).into(),
            );
        }
        let local_before = backend.list_platform_credentials()?;
        let mut classified_header = self.header.clone();
        classify_local_platform_slots(&mut classified_header, &local_before)?;
        let slots: Vec<&KeySlot> = classified_header
            .key_slots
            .iter()
            .filter(|slot| slot.authenticator == Some(SlotAuthenticator::Platform))
            .collect();
        let exclude = decode_credential_ids(&slots)?;
        if exclude.iter().any(|id| local_before.contains(id)) {
            return Err(FidoError::PlatformCredentialExists.into());
        }
        // Display names are not machine/account identities. RP-local membership
        // above owns the duplicate decision; disambiguate identical computer names.
        let label = match self.validate_new_key_label(&candidate) {
            Ok(label) => label,
            Err(_) => {
                let existing = self
                    .header
                    .key_slots
                    .iter()
                    .map(|s| s.label.as_str())
                    .collect::<Vec<_>>();
                (2..=existing.len().saturating_add(2))
                    .find_map(|suffix| {
                        let suffix_text = format!(" {suffix}");
                        let budget = MAX_KEY_LABEL_CHARS
                            - "Windows Hello（本機 ）".chars().count()
                            - suffix_text.chars().count();
                        let shortened: String = computer_name.chars().take(budget).collect();
                        let label = format!("Windows Hello（本機 {shortened}）{suffix_text}");
                        validate_key_label(&label, &existing).ok()
                    })
                    .ok_or_else(|| VaultError::Format("無法產生唯一的 Windows Hello 名稱".into()))?
            }
        };
        let registration = backend.register_platform_credential(&label, &exclude)?;
        let reg = registration.credential;
        let all = match decode_credential_ids(&self.header.key_slots.iter().collect::<Vec<_>>()) {
            Ok(all) => all,
            Err(error) => {
                self.registration_cleanup_report = Some(RegistrationCleanupReport::NotAttempted);
                return Err(error);
            }
        };
        if reg.credential_id.is_empty()
            || all.contains(&reg.credential_id)
            || local_before.contains(&reg.credential_id)
        {
            // An existing ID is not evidence of a newly-created credential; never delete it.
            return Err(FidoError::PlatformCredentialExists.into());
        }
        // The RP-scoped local list must prove ownership before assertion or cleanup.
        // A new credential that cannot be re-proven is never deleted, but is reported.
        let proven = match backend.list_platform_credentials() {
            Ok(local) => local.contains(&reg.credential_id),
            Err(error) => {
                self.registration_cleanup_report = Some(RegistrationCleanupReport::NotAttempted);
                return Err(error.into());
            }
        };
        if !proven {
            self.registration_cleanup_report = Some(RegistrationCleanupReport::NotAttempted);
            return Err(FidoError::PlatformCredentialMissing.into());
        }
        self.complete_platform_registration(backend, reg, registration.creation_prf, label)
    }

    /// Windows Hello registration; caller supplies the local computer name.
    pub fn register_windows_hello(
        &mut self,
        backend: &mut (dyn FidoBackend + 'static),
        computer_name: &str,
        edition: Edition,
    ) -> Result<RegisteredCredential, VaultError> {
        match self.begin_register_windows_hello(backend, computer_name, edition)? {
            RegistrationOutcome::Registered(reg) => Ok(reg),
            // Legacy callers have no pending flow: keep delete-on-failure semantics.
            RegistrationOutcome::HandoffRequired(pending) => {
                if let PendingRegistration::Platform { credential, .. } = &pending {
                    let _ = backend.delete_platform_credential(&credential.credential_id);
                }
                Err(FidoError::ForegroundHandoffRequired.into())
            }
        }
    }

    /// D9-F1：使用者點擊「繼續驗證」後，以全新的一般斷言完成 pending 註冊。
    /// 不放寬任何守門：前置條件重新檢查；Windows Hello 先以 RP 清單重新證明本機持有。
    pub fn continue_registration(
        &mut self,
        backend: &mut (dyn FidoBackend + 'static),
        pending: PendingRegistration,
        edition: Edition,
    ) -> Result<RegistrationOutcome, VaultError> {
        self.registration_cleanup_report = None;
        let platform_id = match &pending {
            PendingRegistration::Platform { credential, .. } => {
                Some(credential.credential_id.clone())
            }
            PendingRegistration::Roaming { .. } => None,
        };
        let result = self.continue_registration_unreported(backend, pending, edition);
        // Any failure that consumed a new platform pending without a cleanup verdict
        // (availability, discovery, membership, label, edition...) leaves a credential that
        // may still exist: report it conservatively. Existing slot IDs are never "new".
        if let (Err(_), Some(id)) = (&result, platform_id) {
            if self.registration_cleanup_report.is_none() && self.is_new_platform_credential_id(&id)
            {
                self.registration_cleanup_report = Some(RegistrationCleanupReport::NotAttempted);
            }
        }
        result
    }

    fn continue_registration_unreported(
        &mut self,
        backend: &mut (dyn FidoBackend + 'static),
        pending: PendingRegistration,
        edition: Edition,
    ) -> Result<RegistrationOutcome, VaultError> {
        check_header_edition(&self.header, edition)?;
        let existing = decode_credential_ids(&self.header.key_slots.iter().collect::<Vec<_>>())?;
        match pending {
            PendingRegistration::Roaming {
                credential,
                pin,
                custom_label,
                group,
            } => {
                let share = self.roaming_group_share(group)?;
                if credential.credential_id.is_empty()
                    || existing.contains(&credential.credential_id)
                {
                    return Err(FidoError::CredentialExcluded.into());
                }
                let custom_label = match custom_label {
                    Some(label) => Some(self.validate_new_key_label(&label)?),
                    None => None,
                };
                self.complete_roaming_registration(
                    backend,
                    credential,
                    pin,
                    custom_label,
                    group,
                    share,
                )
            }
            PendingRegistration::Platform {
                credential,
                creation_prf,
                label,
            } => {
                if edition != Edition::Single {
                    return Err(VaultError::Format("Windows Hello 僅支援單人版".into()));
                }
                // An existing ID is not evidence of a newly-created credential; never delete it.
                if credential.credential_id.is_empty()
                    || existing.contains(&credential.credential_id)
                {
                    return Err(FidoError::PlatformCredentialExists.into());
                }
                let label = self.validate_new_key_label(&label)?;
                if !backend.platform_status().available() {
                    return Err(FidoError::NotSupported(
                        crate::fido2::PLATFORM_UNSUPPORTED_MSG.into(),
                    )
                    .into());
                }
                // Fresh RP-scoped proof; unproven credentials are never deleted.
                if !backend
                    .list_platform_credentials()?
                    .contains(&credential.credential_id)
                {
                    return Err(FidoError::PlatformCredentialMissing.into());
                }
                self.complete_platform_registration(backend, credential, creation_prf, label)
            }
        }
    }

    /// Second (assertion) ceremony + constant-time PRF comparison + wrap + audit.
    /// Membership was proven by the caller. A foreground handoff refusal keeps the
    /// credential and returns `HandoffRequired`; every other failure attempts deletion.
    /// A failed deletion is reported on a one-shot side channel without masking the primary error.
    fn cleanup_failed_platform_registration(
        &mut self,
        backend: &mut (dyn FidoBackend + 'static),
        id: &[u8],
        error: VaultError,
    ) -> VaultError {
        self.registration_cleanup_report = Some(match backend.delete_platform_credential(id) {
            Ok(()) => RegistrationCleanupReport::Removed,
            Err(_) => RegistrationCleanupReport::DeleteFailed,
        });
        error
    }

    fn complete_platform_registration(
        &mut self,
        backend: &mut (dyn FidoBackend + 'static),
        reg: RegisteredCredential,
        creation_prf: Zeroizing<[u8; 32]>,
        label: String,
    ) -> Result<RegistrationOutcome, VaultError> {
        let (selected, mut raw) =
            match backend.get_platform_prf_secret(&[reg.credential_id.clone()]) {
                Ok(result) => result,
                Err(error) if error.is_foreground_handoff() => {
                    return Ok(RegistrationOutcome::HandoffRequired(
                        PendingRegistration::Platform {
                            credential: reg,
                            creation_prf,
                            label,
                        },
                    ));
                }
                Err(error) => {
                    return Err(self.cleanup_failed_platform_registration(
                        backend,
                        &reg.credential_id,
                        error.into(),
                    ));
                }
            };
        let secret = Zeroizing::new(raw);
        raw.zeroize();
        if selected != reg.credential_id {
            return Err(self.cleanup_failed_platform_registration(
                backend,
                &reg.credential_id,
                FidoError::PlatformCredentialMissing.into(),
            ));
        }
        // CtOutput's PartialEq uses the digest crate's constant-time equality.
        // Use the existing hmac re-export (no new direct dependency); wipe both copies.
        let creation = hmac::digest::CtOutput::<sha2::Sha256>::new((*creation_prf).into());
        let assertion = hmac::digest::CtOutput::<sha2::Sha256>::new((*secret).into());
        let matches = creation == assertion;
        creation.into_bytes().as_mut_slice().zeroize();
        assertion.into_bytes().as_mut_slice().zeroize();
        if !matches {
            return Err(self.cleanup_failed_platform_registration(
                backend,
                &reg.credential_id,
                FidoError::PlatformPrfUnsupported.into(),
            ));
        }
        let wrap = Zeroizing::new(kek_from_prf_secret(&secret));
        let nonce = random_nonce();
        let ct = aes_gcm_encrypt(&wrap, &nonce, self.kek.as_slice());
        let previous_header = self.header.clone();
        let previous_audit = self.data.audit.clone();
        self.header.key_slots.push(KeySlot {
            credential_id: base64_encode(&reg.credential_id),
            aaguid: hex32_16(reg.aaguid),
            label,
            key_type: KeyKind::WindowsManaged,
            group: None,
            authenticator: Some(SlotAuthenticator::Platform),
            nonce: base64_encode(&nonce),
            ct: base64_encode(&ct),
        });
        use sha2::Digest;
        let digest = sha2::Sha256::digest(&reg.credential_id);
        let fingerprint = hex32(&digest[..4]);
        if let Err(error) = self.record(
            "key_registered",
            &format!("register_key:windows-hello:{fingerprint}"),
            "type=WindowsManaged",
        ) {
            self.header = previous_header;
            self.data.audit = previous_audit;
            return Err(self.cleanup_failed_platform_registration(
                backend,
                &reg.credential_id,
                error,
            ));
        }
        Ok(RegistrationOutcome::Registered(reg))
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
        match self.begin_register_key_internal(backend, pin, custom_label, group)? {
            RegistrationOutcome::Registered(reg) => Ok(reg),
            // 相容語意：舊呼叫方沒有 pending 流程 → 回報錯誤（roaming credential 無法由程式刪除）。
            RegistrationOutcome::HandoffRequired(_) => {
                Err(FidoError::ForegroundHandoffRequired.into())
            }
        }
    }

    /// 版本與群組必須一致；不一致時 fail closed，不呼叫 authenticator。
    fn roaming_group_share(
        &self,
        group: Option<KeyGroup>,
    ) -> Result<Option<Zeroizing<[u8; 32]>>, VaultError> {
        match (self.edition(), group) {
            (Edition::Dual, None) => Err(VaultError::Format(
                "雙群組控管版註冊金鑰須指定群組（A 或 B）".into(),
            )),
            (Edition::Single, Some(_)) => {
                Err(VaultError::Format("單人版金庫不支援金鑰群組".into()))
            }
            (Edition::Dual, Some(group)) => Ok(Some(self.group_share(group)?)),
            (Edition::Single, None) => Ok(None),
        }
    }

    fn begin_register_key_internal(
        &mut self,
        backend: &mut (dyn FidoBackend + 'static),
        pin: Option<&str>,
        custom_label: Option<&str>,
        group: Option<KeyGroup>,
    ) -> Result<RegistrationOutcome, VaultError> {
        let share = self.roaming_group_share(group)?;
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
        let reg = match exclude.as_deref() {
            Some(exclude) => backend.register_credential_excluding(&detected, pin, exclude)?,
            None => backend.register_credential(&detected, pin)?,
        };
        self.complete_roaming_registration(
            backend,
            reg,
            pin.map(|pin| Zeroizing::new(pin.to_owned())),
            custom_label.map(str::to_owned),
            group,
            share,
        )
    }

    /// 第二個 ceremony（驗證斷言）+ 包槽位 + audit。前景未交回 → `HandoffRequired`（金庫不變）。
    fn complete_roaming_registration(
        &mut self,
        backend: &mut (dyn FidoBackend + 'static),
        mut reg: RegisteredCredential,
        pin: Option<Zeroizing<String>>,
        custom_label: Option<String>,
        group: Option<KeyGroup>,
        share: Option<Zeroizing<[u8; 32]>>,
    ) -> Result<RegistrationOutcome, VaultError> {
        let secret =
            match backend.get_prf_secret(&reg.credential_id, pin.as_deref().map(String::as_str)) {
                Ok(secret) => secret,
                Err(error) if error.is_foreground_handoff() => {
                    return Ok(RegistrationOutcome::HandoffRequired(
                        PendingRegistration::Roaming {
                            credential: reg,
                            pin,
                            custom_label,
                            group,
                        },
                    ));
                }
                Err(error) => return Err(error.into()),
            };
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
            reg.label = label;
        }
        // 落盤失敗時還原完整舊值（含 audit 裁切）；roaming credential 無法由程式刪除，不嘗試。
        let previous_header = self.header.clone();
        let previous_audit = self.data.audit.clone();
        self.header.key_slots.push(KeySlot {
            credential_id: base64_encode(&reg.credential_id),
            aaguid: hex32_16(reg.aaguid),
            label: reg.label.clone(),
            key_type: reg.kind,
            group,
            authenticator: None,
            nonce: base64_encode(&nonce),
            ct: base64_encode(&ct),
        });
        let kind_str = format!("{}", reg.kind);
        let detail = match group {
            Some(group) => format!("type={kind_str} group={}", group.as_str()),
            None => format!("type={kind_str}"),
        };
        if let Err(error) = self.record("key_registered", &format!("fido2:{}", reg.label), &detail)
        {
            self.header = previous_header;
            self.data.audit = previous_audit;
            return Err(error);
        }
        Ok(RegistrationOutcome::Registered(reg))
    }

    /// 移除金鑰槽（不可逆：該金鑰將無法再解鎖）。
    pub fn remove_key(&mut self, credential_id_b64: &str) -> Result<(), VaultError> {
        let idx = self
            .header
            .key_slots
            .iter()
            .position(|s| s.credential_id == credential_id_b64)
            .ok_or(VaultError::Fido(FidoError::NoDevice))?;
        // 雙人版：群組歸零會讓金鑰登入永久失效 → 一律拒絕（不改 header、不寫檔、不記 audit）。
        if let Some(group) = last_key_in_group(&self.header, credential_id_b64) {
            return Err(VaultError::LastKeyInGroup(group));
        }
        let label = self.header.key_slots[idx].label.clone();
        let method =
            if self.header.key_slots[idx].authenticator == Some(SlotAuthenticator::Platform) {
                format!("windows-hello:{label}")
            } else {
                format!("fido2:{label}")
            };
        let group = self.header.key_slots[idx].group;
        self.header.key_slots.remove(idx);
        let detail = match group {
            Some(group) => format!("金鑰槽已移除（該金鑰無法再解鎖） group={}", group.as_str()),
            None => "金鑰槽已移除（該金鑰無法再解鎖）".to_owned(),
        };
        self.record("key_removed", &method, &detail)?;
        Ok(())
    }

    /// Backend-aware removal; existing remove_key remains available.
    pub fn remove_key_with_platform(
        &mut self,
        credential_id_b64: &str,
        backend: &mut (dyn FidoBackend + 'static),
        edition: Edition,
    ) -> Result<PlatformCleanupOutcome, VaultError> {
        check_header_edition(&self.header, edition)?;
        if edition != Edition::Single {
            return Err(VaultError::Format("Windows Hello 僅支援單人版".into()));
        }
        let mut classified_header = self.header.clone();
        let discovery_failed = if backend.platform_status().available() {
            match backend.list_platform_credentials() {
                Ok(local) => {
                    classify_local_platform_slots(&mut classified_header, &local)?;
                    false
                }
                Err(_) => true,
            }
        } else {
            // Without discovery, an unmarked slot may be a marker-lost platform
            // credential; removal succeeds but must warn about possible residue.
            true
        };
        let slot = classified_header
            .key_slots
            .iter()
            .find(|slot| slot.credential_id == credential_id_b64)
            .ok_or(FidoError::NoDevice)?
            .clone();
        let id = base64_decode(&slot.credential_id)
            .map_err(|_| VaultError::Format("credential_id 解碼失敗".into()))?;
        let previous_header = std::mem::replace(&mut self.header, classified_header);
        let previous_audit = self.data.audit.clone();
        if let Err(error) = self.remove_key(credential_id_b64) {
            self.header = previous_header;
            self.data.audit = previous_audit;
            return Err(error);
        }
        if slot.authenticator != Some(SlotAuthenticator::Platform) {
            return Ok(if discovery_failed {
                PlatformCleanupOutcome::ManualRemovalRequired(
                    PlatformCleanupWarning::DiscoveryFailed,
                )
            } else {
                PlatformCleanupOutcome::NotApplicable
            });
        }
        // Native delete has no RP argument: fresh RP-scoped membership is mandatory.
        if !backend.platform_status().available() {
            return Ok(PlatformCleanupOutcome::ManualRemovalRequired(
                PlatformCleanupWarning::DiscoveryFailed,
            ));
        }
        let local = match backend.list_platform_credentials() {
            Ok(local) => local,
            Err(_) => {
                return Ok(PlatformCleanupOutcome::ManualRemovalRequired(
                    PlatformCleanupWarning::DiscoveryFailed,
                ))
            }
        };
        if !local.contains(&id) {
            return Ok(PlatformCleanupOutcome::ManualRemovalRequired(
                PlatformCleanupWarning::NotLocal,
            ));
        }
        match backend.delete_platform_credential(&id) {
            Ok(()) => Ok(PlatformCleanupOutcome::Removed),
            Err(_) => Ok(PlatformCleanupOutcome::ManualRemovalRequired(
                PlatformCleanupWarning::DeleteFailed,
            )),
        }
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

/// Classify only verified RP-scoped local IDs, never labels/AAGUID/prefixes.
fn classify_local_platform_slots(header: &mut Header, local: &[Vec<u8>]) -> Result<(), VaultError> {
    if edition_of(header) != Edition::Single {
        return Ok(());
    }
    // Decode before mutating so malformed metadata cannot leave a partial repair.
    let ids = decode_credential_ids(&header.key_slots.iter().collect::<Vec<_>>())?;
    for (slot, id) in header.key_slots.iter_mut().zip(ids) {
        if slot.authenticator.is_none() && local.contains(&id) {
            slot.authenticator = Some(SlotAuthenticator::Platform);
        }
    }
    Ok(())
}

/// Legacy password/roaming remain usable if platform discovery is unavailable.
/// A list error is NOT an empty list: skip R3 repair, retain explicit markers.
/// read_header_with_platform exposes the error to callers needing strict discovery.
fn classify_platform_best_effort(
    header: &mut Header,
    backend: &mut (dyn FidoBackend + 'static),
) -> Result<(), VaultError> {
    if edition_of(header) == Edition::Single && backend.platform_status().available() {
        if let Ok(local) = backend.list_platform_credentials() {
            classify_local_platform_slots(header, &local)?;
        }
    }
    Ok(())
}

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
        ts: now_audit_time(),
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

    // Recording/malicious mock only: never invokes native authenticator APIs.
    struct WhBackend {
        inner: MockBackend,
        calls: std::cell::Cell<usize>,
        available: bool,
        list_error: bool,
        delete_error: bool,
        assertion_error: Option<FidoError>,
        selected: Option<Vec<u8>>,
        collision: Option<Vec<u8>>,
        wrong_secret: bool,
        allow: Vec<Vec<u8>>,
        exclude: Vec<Vec<u8>>,
        deleted: Vec<Vec<u8>>,
        roaming: Vec<Vec<u8>>,
        removal_path: Option<PathBuf>,
        deletion_saw_persisted: bool,
        scripted_lists: std::collections::VecDeque<Result<Vec<Vec<u8>>, FidoError>>,
    }

    impl WhBackend {
        fn new() -> Self {
            Self {
                inner: MockBackend::new(),
                calls: std::cell::Cell::new(0),
                available: true,
                list_error: false,
                delete_error: false,
                assertion_error: None,
                selected: None,
                collision: None,
                wrong_secret: false,
                allow: vec![],
                exclude: vec![],
                deleted: vec![],
                roaming: vec![],
                removal_path: None,
                deletion_saw_persisted: false,
                scripted_lists: std::collections::VecDeque::new(),
            }
        }
        fn touch(&self) {
            self.calls.set(self.calls.get() + 1);
        }
    }

    impl FidoBackend for WhBackend {
        fn detect(&mut self) -> Result<crate::fido2::DetectedKey, FidoError> {
            self.touch();
            self.inner.detect()
        }
        fn register_credential(
            &mut self,
            d: &crate::fido2::DetectedKey,
            p: Option<&str>,
        ) -> Result<RegisteredCredential, FidoError> {
            self.touch();
            self.inner.register_credential(d, p)
        }
        fn get_prf_secret(&mut self, id: &[u8], p: Option<&str>) -> Result<[u8; 32], FidoError> {
            self.touch();
            self.roaming = vec![id.to_vec()];
            self.inner.get_prf_secret(id, p)
        }
        fn get_prf_secret_for_any(
            &mut self,
            ids: &[Vec<u8>],
            p: Option<&str>,
        ) -> Result<(Vec<u8>, [u8; 32]), FidoError> {
            self.touch();
            self.roaming = ids.to_vec();
            if let Some(id) = &self.selected {
                return Ok((id.clone(), MockBackend::prf_for_credential(id)));
            }
            self.inner.get_prf_secret_for_any(ids, p)
        }
        fn prf_supported(&self) -> bool {
            true
        }
        fn platform_status(&self) -> crate::fido2::PlatformStatus {
            self.touch();
            crate::fido2::PlatformStatus {
                api_ok: self.available,
                uvpa: self.available,
                console: self.available,
            }
        }
        fn list_platform_credentials(&mut self) -> Result<Vec<Vec<u8>>, FidoError> {
            self.touch();
            if let Some(result) = self.scripted_lists.pop_front() {
                return result;
            }
            if self.list_error {
                return Err(FidoError::PlatformPrfUnsupported);
            }
            self.inner.list_platform_credentials()
        }
        fn register_platform_credential(
            &mut self,
            label: &str,
            ids: &[Vec<u8>],
        ) -> Result<crate::fido2::PlatformRegistration, FidoError> {
            self.touch();
            self.exclude = ids.to_vec();
            if let Some(id) = &self.collision {
                return Ok(crate::fido2::PlatformRegistration {
                    credential: RegisteredCredential {
                        credential_id: id.clone(),
                        aaguid: [0; 16],
                        label: label.into(),
                        kind: KeyKind::WindowsManaged,
                    },
                    creation_prf: Zeroizing::new(MockBackend::prf_for_credential(id)),
                });
            }
            self.inner.register_platform_credential(label, ids)
        }
        fn get_platform_prf_secret(
            &mut self,
            ids: &[Vec<u8>],
        ) -> Result<(Vec<u8>, [u8; 32]), FidoError> {
            self.touch();
            self.allow = ids.to_vec();
            if let Some(error) = self.assertion_error.take() {
                return Err(error);
            }
            if let Some(id) = &self.selected {
                // Deliberately return the requested PRF with a rogue selected ID.
                return Ok((id.clone(), MockBackend::prf_for_credential(&ids[0])));
            }
            if self.wrong_secret {
                return Ok((ids[0].clone(), [17; 32]));
            }
            self.inner.get_platform_prf_secret(ids)
        }
        fn delete_platform_credential(&mut self, id: &[u8]) -> Result<(), FidoError> {
            self.touch();
            self.deleted.push(id.to_vec());
            if let Some(path) = &self.removal_path {
                self.deletion_saw_persisted =
                    Vault::read_header(path, Edition::Single).is_ok_and(|h| {
                        h.key_slots
                            .iter()
                            .all(|slot| slot.credential_id != base64_encode(id))
                    });
            }
            if self.delete_error {
                return Err(FidoError::PlatformPrfUnsupported);
            }
            self.inner.delete_platform_credential(id)
        }
    }

    fn wh_drop_platform_marker(v: &mut Vault) {
        for slot in &mut v.header.key_slots {
            slot.authenticator = None;
        }
        v.write_file().unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn wh_d4_remove_persist_failure_restores_memory_before_cleanup() {
        for rename_failure in [false, true] {
            let p = fresh_path(if rename_failure {
                "wh-d4-remove-save-rename"
            } else {
                "wh-d4-remove-save-tmp"
            });
            let mut v = Vault::create(&p, "Synthetic-Pw-12345").unwrap();
            let mut b = WhBackend::new();
            let reg = v.register_windows_hello(&mut b, "TEST-PC", Edition::Single);
            assert!(reg.is_ok());
            let reg = reg.unwrap();
            v.data.audit = (0..MAX_AUDIT)
                .map(|index| AuditEvent {
                    ts: index.to_string(),
                    event: "synthetic".into(),
                    method: "test".into(),
                    detail: index.to_string(),
                })
                .collect();
            v.write_file().unwrap();
            let disk = fs::read(&p).unwrap();
            let header = serde_json::to_vec(&v.header).unwrap();
            let audit = serde_json::to_vec(&v.data.audit).unwrap();
            use std::os::windows::fs::OpenOptionsExt;
            let _guard = if rename_failure {
                Some(
                    fs::OpenOptions::new()
                        .read(true)
                        .share_mode(1)
                        .open(&p)
                        .unwrap(),
                )
            } else {
                fs::create_dir(p.with_extension("db.tmp")).unwrap();
                None
            };
            let result = v.remove_key_with_platform(
                &base64_encode(&reg.credential_id),
                &mut b,
                Edition::Single,
            );
            assert!(matches!(result, Err(VaultError::Io(_))));
            assert!(
                serde_json::to_vec(&v.header).unwrap() == header,
                "failed remove persist must restore header"
            );
            assert!(
                serde_json::to_vec(&v.data.audit).unwrap() == audit,
                "failed remove persist must restore trimmed audit"
            );
            assert!(fs::read(&p).unwrap() == disk);
            assert!(
                b.deleted.is_empty(),
                "no native deletion before successful persist"
            );
            assert_eq!(b.inner.platform_credential_ids().len(), 1);
        }
    }

    #[test]
    fn wh_d4_review_l3_lost_marker_unavailable_warns_without_native_calls() {
        let p = fresh_path("wh-d4-review-l3");
        let mut v = Vault::create(&p, "Synthetic-Pw-12345").unwrap();
        let mut b = WhBackend::new();
        let reg = v.register_windows_hello(&mut b, "TEST-PC", Edition::Single);
        assert!(reg.is_ok());
        let reg = reg.unwrap();
        wh_drop_platform_marker(&mut v);
        b.available = false;
        b.calls.set(0);
        let result =
            v.remove_key_with_platform(&base64_encode(&reg.credential_id), &mut b, Edition::Single);
        assert!(
            matches!(
                result,
                Ok(PlatformCleanupOutcome::ManualRemovalRequired(
                    PlatformCleanupWarning::DiscoveryFailed
                ))
            ),
            "unavailable discovery cannot rule out an unmarked platform credential"
        );
        assert!(Vault::read_header(&p, Edition::Single)
            .unwrap()
            .key_slots
            .is_empty());
        assert!(b.deleted.is_empty());
        assert_eq!(
            b.calls.get(),
            1,
            "only passive availability query; no native list or delete"
        );
        assert_eq!(b.inner.platform_credential_ids().len(), 1);
    }

    #[test]
    fn wh_d4_review_control_post_create_discovery_error_never_blind_deletes() {
        let p = fresh_path("wh-d4-review-post-create-list");
        let mut v = Vault::create(&p, "Synthetic-Pw-12345").unwrap();
        let mut b = WhBackend::new();
        b.scripted_lists.push_back(Ok(vec![]));
        b.scripted_lists
            .push_back(Err(FidoError::Internal("synthetic list failure".into())));
        let before = fs::read(&p).unwrap();
        let result = v.register_windows_hello(&mut b, "TEST-PC", Edition::Single);
        assert!(matches!(
            result,
            Err(VaultError::Fido(FidoError::Internal(_)))
        ));
        assert!(b.scripted_lists.is_empty());
        assert!(
            b.deleted.is_empty(),
            "unproved returned ID must never be blindly deleted"
        );
        assert!(b.allow.is_empty());
        assert!(v.header.key_slots.is_empty());
        assert!(fs::read(&p).unwrap() == before);
        assert_eq!(
            b.inner.platform_credential_ids().len(),
            1,
            "possible native residue is disclosed, not falsely claimed cleaned"
        );
    }

    #[test]
    fn wh_d4_review_control_empty_and_existing_local_nonvault_collision() {
        for empty in [true, false] {
            let p = fresh_path(if empty {
                "wh-d4-review-empty"
            } else {
                "wh-d4-review-local-nonvault"
            });
            let mut v = Vault::create(&p, "Synthetic-Pw-12345").unwrap();
            let mut b = WhBackend::new();
            let id = if empty { vec![] } else { vec![99; 32] };
            if !empty {
                b.inner = MockBackend::new().with_platform_credentials(vec![id.clone()]);
            }
            b.collision = Some(id);
            let before = fs::read(&p).unwrap();
            let result = v.register_windows_hello(&mut b, "TEST-PC", Edition::Single);
            assert!(matches!(
                result,
                Err(VaultError::Fido(FidoError::PlatformCredentialExists))
            ));
            assert!(b.deleted.is_empty());
            assert!(b.allow.is_empty());
            assert!(v.header.key_slots.is_empty());
            assert!(fs::read(&p).unwrap() == before);
        }
    }

    #[test]
    fn wh_d4_review_control_removal_rechecks_fresh_list() {
        for error in [true, false] {
            let p = fresh_path(if error {
                "wh-d4-review-fresh-error"
            } else {
                "wh-d4-review-fresh-missing"
            });
            let mut v = Vault::create(&p, "Synthetic-Pw-12345").unwrap();
            let mut b = WhBackend::new();
            let reg = v.register_windows_hello(&mut b, "TEST-PC", Edition::Single);
            assert!(reg.is_ok());
            let id = reg.unwrap().credential_id;
            b.scripted_lists.push_back(Ok(vec![id.clone()]));
            b.scripted_lists.push_back(if error {
                Err(FidoError::Internal("synthetic list failure".into()))
            } else {
                Ok(vec![])
            });
            let result = v.remove_key_with_platform(&base64_encode(&id), &mut b, Edition::Single);
            let expected = if error {
                PlatformCleanupWarning::DiscoveryFailed
            } else {
                PlatformCleanupWarning::NotLocal
            };
            assert!(
                matches!(result, Ok(PlatformCleanupOutcome::ManualRemovalRequired(w)) if w == expected)
            );
            assert!(
                b.scripted_lists.is_empty(),
                "after-persist list must actually be queried"
            );
            assert!(b.deleted.is_empty());
            assert!(Vault::read_header(&p, Edition::Single)
                .unwrap()
                .key_slots
                .is_empty());
        }
    }

    #[test]
    fn wh_d4_review_control_save_and_cleanup_failure_keep_primary_error() {
        let p = fresh_path("wh-d4-review-save-delete-errors");
        let mut v = Vault::create(&p, "Synthetic-Pw-12345").unwrap();
        let mut b = WhBackend::new();
        b.delete_error = true;
        let before = fs::read(&p).unwrap();
        let audit = serde_json::to_vec(&v.data.audit).unwrap();
        fs::create_dir(p.with_extension("db.tmp")).unwrap();
        let result = v.register_windows_hello(&mut b, "TEST-PC", Edition::Single);
        assert!(
            matches!(result, Err(VaultError::Io(_))),
            "cleanup failure must not mask original persist error"
        );
        assert!(v.header.key_slots.is_empty());
        assert!(serde_json::to_vec(&v.data.audit).unwrap() == audit);
        assert!(fs::read(&p).unwrap() == before);
        assert_eq!(b.deleted.len(), 1);
        assert_eq!(b.inner.platform_credential_ids().len(), 1);
    }

    #[test]
    fn wh_d4_review_s2_removal_audit_names_platform_method() {
        let p = fresh_path("wh-d4-review-s2");
        let mut v = Vault::create(&p, "Synthetic-Pw-12345").unwrap();
        let mut b = WhBackend::new();
        let reg = v.register_windows_hello(&mut b, "TEST-PC", Edition::Single);
        assert!(reg.is_ok());
        let removed = v.remove_key_with_platform(
            &base64_encode(&reg.unwrap().credential_id),
            &mut b,
            Edition::Single,
        );
        assert!(removed.is_ok());
        let event = v.audit().last().unwrap();
        assert_eq!(event.event, "key_removed");
        assert_eq!(event.method, "windows-hello:Windows Hello（本機 TEST-PC）");
    }

    #[test]
    fn wh_d4_review_s1_lost_marker_discovery_failure_warns() {
        let p = fresh_path("wh-d4-review-s1");
        let mut v = Vault::create(&p, "Synthetic-Pw-12345").unwrap();
        let mut b = WhBackend::new();
        let reg = v.register_windows_hello(&mut b, "TEST-PC", Edition::Single);
        assert!(reg.is_ok());
        let reg = reg.unwrap();
        wh_drop_platform_marker(&mut v);
        b.list_error = true;
        let removed =
            v.remove_key_with_platform(&base64_encode(&reg.credential_id), &mut b, Edition::Single);
        assert!(
            matches!(
                removed,
                Ok(PlatformCleanupOutcome::ManualRemovalRequired(
                    PlatformCleanupWarning::DiscoveryFailed
                ))
            ),
            "unknown type after discovery failure must warn of possible residue"
        );
        assert!(v.header.key_slots.is_empty());
        assert!(Vault::read_header(&p, Edition::Single)
            .unwrap()
            .key_slots
            .is_empty());
        assert!(b.deleted.is_empty());
        assert_eq!(b.inner.platform_credential_ids().len(), 1);
    }

    #[test]
    fn wh_d4_review_l2_opaque_native_cancellation_not_auth_failure() {
        let p = fresh_path("wh-d4-review-l2-cancel");
        let mut v = Vault::create(&p, "Synthetic-Pw-12345").unwrap();
        let mut b = WhBackend::new();
        assert!(v
            .register_windows_hello(&mut b, "TEST-PC", Edition::Single)
            .is_ok());
        drop(v);
        // Actual platform_prf_error/api_error contract maps cancellation (and
        // other unclassified HRESULTs) to Internal, not the mock NoDevice.
        b.assertion_error = Some(FidoError::Internal(
            "Windows WebAuthn GetAssertion failed: NotAllowedError (HRESULT 0x800704C7)".into(),
        ));
        let result = Vault::open_windows_hello(&p, &mut b, Edition::Single);
        assert!(matches!(
            result,
            Err(VaultError::Fido(FidoError::Internal(_)))
        ));
        assert!(
            read_failure_sidecar(&p).is_empty(),
            "opaque native cancellation is not proven authentication rejection"
        );
        assert!(!failures_path(&p).exists());
        b.assertion_error = Some(FidoError::PinRejected);
        assert!(Vault::open_windows_hello(&p, &mut b, Edition::Single).is_err());
        assert_eq!(
            read_failure_sidecar(&p).len(),
            1,
            "known typed rejection still audited"
        );
    }

    #[test]
    fn wh_d4_review_l1_same_hostname_distinct_accounts() {
        for name in [
            "TEST-PC".to_owned(),
            "測".repeat(MAX_KEY_LABEL_CHARS - "Windows Hello（本機 ）".chars().count()),
        ] {
            let p = fresh_path(if name == "TEST-PC" {
                "wh-d4-review-l1-short"
            } else {
                "wh-d4-review-l1-long"
            });
            let mut v = Vault::create(&p, "Synthetic-Pw-12345").unwrap();
            let mut a = WhBackend::new();
            let mut b = WhBackend::new();
            assert!(v
                .register_windows_hello(&mut a, &name, Edition::Single)
                .is_ok());
            let second = v.register_windows_hello(&mut b, &name, Edition::Single);
            assert!(
                second.is_ok(),
                "same COMPUTERNAME on another account/machine must not be identity duplicate"
            );
            assert_eq!(v.header.key_slots.len(), 2);
            assert_ne!(v.header.key_slots[0].label, v.header.key_slots[1].label);
            assert!(v
                .header
                .key_slots
                .iter()
                .all(|s| s.label.chars().count() <= MAX_KEY_LABEL_CHARS));
            assert!(v.header.key_slots[1].label.ends_with("） 2"));
            let duplicate = v.register_windows_hello(&mut a, &name, Edition::Single);
            assert!(matches!(
                duplicate,
                Err(VaultError::Fido(FidoError::PlatformCredentialExists))
            ));
        }
    }

    // Additional unchanged-behavior safety controls (GREEN -> GREEN, not RED).
    #[test]
    fn wh_d4_control_edition_guards_before_backend() {
        let p = fresh_path("wh-d4-control-dual");
        let mut v = Vault::create_for(&p, "Synthetic-Pw-12345", Edition::Dual).unwrap();
        let mut b = WhBackend::new();
        assert!(Vault::open_windows_hello(&p, &mut b, Edition::Dual).is_err());
        assert!(Vault::open_windows_hello(&p, &mut b, Edition::Single).is_err());
        assert!(v
            .remove_key_with_platform("unused", &mut b, Edition::Dual)
            .is_err());
        assert!(Vault::read_header_with_platform(&p, Edition::Dual, &mut b).is_ok());
        let result =
            Vault::open_password_with_platform(&p, "Synthetic-Pw-12345", Edition::Dual, &mut b);
        assert!(result.is_ok());
        assert_eq!(
            b.calls.get(),
            0,
            "v2 must never probe or repair platform credentials"
        );
    }

    #[test]
    fn wh_d4_control_legacy_login_despite_platform_discovery_errors() {
        for unavailable in [true, false] {
            let p = fresh_path(if unavailable {
                "wh-d4-control-unavailable"
            } else {
                "wh-d4-control-list-error"
            });
            let mut v = Vault::create(&p, "Synthetic-Pw-12345").unwrap();
            let mut b = WhBackend::new();
            let roaming = v.register_key(&mut b, None);
            assert!(roaming.is_ok());
            let roaming = roaming.unwrap();
            assert!(v
                .register_windows_hello(&mut b, "TEST-PC", Edition::Single)
                .is_ok());
            drop(v);
            b.available = !unavailable;
            b.list_error = !unavailable;
            let query = Vault::read_header_with_platform(&p, Edition::Single, &mut b);
            assert_eq!(
                query.is_err(),
                !unavailable,
                "list error must stay visible in strict query"
            );
            assert!(Vault::open_password_with_platform(
                &p,
                "Synthetic-Pw-12345",
                Edition::Single,
                &mut b
            )
            .is_ok());
            assert!(Vault::open_any_key(&p, None, &mut b).is_ok());
            assert!(b.roaming == vec![roaming.credential_id.clone()]);
            assert!(
                Vault::open_key(&p, &base64_encode(&roaming.credential_id), None, &mut b).is_ok()
            );
            let h = Vault::read_header(&p, Edition::Single).unwrap();
            assert_eq!(
                h.key_slots[1].authenticator,
                Some(SlotAuthenticator::Platform)
            );
            b.allow.clear();
            assert!(Vault::open_windows_hello(&p, &mut b, Edition::Single).is_err());
            assert!(
                b.allow.is_empty(),
                "discovery failure must not prompt assertion"
            );
        }
    }

    #[test]
    fn wh_d4_control_metadata_tamper_cannot_bypass_aead() {
        let p = fresh_path("wh-d4-control-tamper");
        let mut v = Vault::create(&p, "Synthetic-Pw-12345").unwrap();
        let mut b = WhBackend::new();
        assert!(v.register_key(&mut b, None).is_ok());
        assert!(v
            .register_windows_hello(&mut b, "TEST-PC", Edition::Single)
            .is_ok());
        // Point the password-independent platform path at a roaming slot's wrapped KEK.
        v.header.key_slots[1].ct = v.header.key_slots[0].ct.clone();
        v.header.key_slots[1].nonce = v.header.key_slots[0].nonce.clone();
        v.write_file().unwrap();
        drop(v);
        let result = Vault::open_windows_hello(&p, &mut b, Edition::Single);
        assert!(matches!(
            result,
            Err(VaultError::Crypto(CryptoError::DecryptFailed))
        ));
        assert!(
            Vault::open_password(&p, "Synthetic-Pw-12345").is_ok(),
            "password fallback remains independent"
        );
    }

    #[test]
    fn wh_d4_control_removal_membership_and_persist_order() {
        let p = fresh_path("wh-d4-control-delete-order");
        let mut v = Vault::create(&p, "Synthetic-Pw-12345").unwrap();
        let mut a = WhBackend::new();
        let mut b = WhBackend::new();
        let first = v.register_windows_hello(&mut a, "PC-A", Edition::Single);
        assert!(first.is_ok());
        let first = first.unwrap();
        let second = v.register_windows_hello(&mut b, "PC-B", Edition::Single);
        assert!(second.is_ok());
        let second = second.unwrap();
        let remote = v.remove_key_with_platform(
            &base64_encode(&second.credential_id),
            &mut a,
            Edition::Single,
        );
        assert!(matches!(
            remote,
            Ok(PlatformCleanupOutcome::ManualRemovalRequired(
                PlatformCleanupWarning::NotLocal
            ))
        ));
        assert!(a.deleted.is_empty());
        assert_eq!(b.inner.platform_credential_ids().len(), 1);
        a.removal_path = Some(p.clone());
        assert!(matches!(
            v.remove_key_with_platform(
                &base64_encode(&first.credential_id),
                &mut a,
                Edition::Single
            ),
            Ok(PlatformCleanupOutcome::Removed)
        ));
        assert!(
            a.deletion_saw_persisted,
            "delete callback must observe already-persisted removal"
        );
        let roaming = v.register_key(&mut a, None);
        assert!(roaming.is_ok());
        let deleted_before = a.deleted.len();
        assert!(matches!(
            v.remove_key_with_platform(
                &base64_encode(&roaming.unwrap().credential_id),
                &mut a,
                Edition::Single
            ),
            Ok(PlatformCleanupOutcome::NotApplicable)
        ));
        assert_eq!(
            a.deleted.len(),
            deleted_before,
            "roaming metadata never triggers platform deletion"
        );
    }

    #[test]
    fn wh_d4_control_cancel_and_cleanup_failure_preserve_primary_error() {
        let p = fresh_path("wh-d4-control-cancel");
        let mut v = Vault::create(&p, "Synthetic-Pw-12345").unwrap();
        let mut b = WhBackend::new();
        b.assertion_error = Some(FidoError::NoDevice);
        b.delete_error = true;
        let before = fs::read(&p).unwrap();
        let result = v.register_windows_hello(&mut b, "TEST-PC", Edition::Single);
        assert!(matches!(result, Err(VaultError::Fido(FidoError::NoDevice))));
        assert_eq!(
            b.deleted.len(),
            1,
            "cancel still attempts owned-new-credential cleanup"
        );
        assert!(v.header.key_slots.is_empty());
        assert!(fs::read(&p).unwrap() == before);
        assert!(!failures_path(&p).exists());
    }

    #[test]
    fn wh_d4_remove_unavailable_never_deletes() {
        let p = fresh_path("wh-d4-remove-unavailable");
        let mut v = Vault::create(&p, "Synthetic-Pw-12345").unwrap();
        let mut b = WhBackend::new();
        let reg = v.register_windows_hello(&mut b, "TEST-PC", Edition::Single);
        assert!(reg.is_ok());
        let reg = reg.unwrap();
        b.available = false;
        let result =
            v.remove_key_with_platform(&base64_encode(&reg.credential_id), &mut b, Edition::Single);
        assert!(matches!(
            result,
            Ok(PlatformCleanupOutcome::ManualRemovalRequired(
                PlatformCleanupWarning::DiscoveryFailed
            ))
        ));
        assert!(
            b.deleted.is_empty(),
            "unavailable platform cleanup must not delete"
        );
        assert!(v.header.key_slots.is_empty());
    }

    #[test]
    fn wh_d4_r3_remove_classifies_local_credential() {
        let p = fresh_path("wh-d4-r3-remove");
        let mut v = Vault::create(&p, "Synthetic-Pw-12345").unwrap();
        let mut b = WhBackend::new();
        let reg = v.register_windows_hello(&mut b, "TEST-PC", Edition::Single);
        assert!(reg.is_ok());
        let reg = reg.unwrap();
        wh_drop_platform_marker(&mut v);
        let result =
            v.remove_key_with_platform(&base64_encode(&reg.credential_id), &mut b, Edition::Single);
        assert!(
            matches!(result, Ok(PlatformCleanupOutcome::Removed)),
            "R3 local marker-loss must still clean platform credential"
        );
        assert!(b.inner.platform_credential_ids().is_empty());
    }

    #[test]
    fn wh_d4_remove_cleanup_errors_are_nonblocking() {
        for discovery in [true, false] {
            let p = fresh_path("wh-d4-remove-warning");
            let mut v = Vault::create(&p, "Synthetic-Pw-12345").unwrap();
            let mut b = WhBackend::new();
            let reg = v.register_windows_hello(&mut b, "TEST-PC", Edition::Single);
            assert!(reg.is_ok());
            let reg = reg.unwrap();
            b.list_error = discovery;
            b.delete_error = !discovery;
            let result = v.remove_key_with_platform(
                &base64_encode(&reg.credential_id),
                &mut b,
                Edition::Single,
            );
            let expected = if discovery {
                PlatformCleanupWarning::DiscoveryFailed
            } else {
                PlatformCleanupWarning::DeleteFailed
            };
            assert!(
                matches!(result, Ok(PlatformCleanupOutcome::ManualRemovalRequired(w)) if w == expected),
                "cleanup error must not report persisted removal as failure"
            );
            assert!(v.header.key_slots.is_empty());
            assert!(Vault::read_header(&p, Edition::Single)
                .unwrap()
                .key_slots
                .is_empty());
            assert_eq!(b.deleted.len(), usize::from(!discovery));
            assert_eq!(b.inner.platform_credential_ids().len(), 1);
        }
    }

    #[test]
    fn wh_d4_remove_local_platform_after_persist() {
        let p = fresh_path("wh-d4-remove-local");
        let mut v = Vault::create(&p, "Synthetic-Pw-12345").unwrap();
        let mut b = WhBackend::new();
        let reg = v.register_windows_hello(&mut b, "TEST-PC", Edition::Single);
        assert!(reg.is_ok());
        let reg = reg.unwrap();
        let result =
            v.remove_key_with_platform(&base64_encode(&reg.credential_id), &mut b, Edition::Single);
        assert!(
            matches!(result, Ok(PlatformCleanupOutcome::Removed)),
            "local platform removal must clean owned credential"
        );
        assert!(v.header.key_slots.is_empty());
        assert!(Vault::read_header(&p, Edition::Single)
            .unwrap()
            .key_slots
            .is_empty());
        assert!(b.deleted == vec![reg.credential_id]);
        assert!(b.inner.platform_credential_ids().is_empty());
    }

    #[test]
    fn wh_d4_r3_registration_duplicate_is_platform_exists() {
        let p = fresh_path("wh-d4-r3-duplicate");
        let mut v = Vault::create(&p, "Synthetic-Pw-12345").unwrap();
        let mut b = WhBackend::new();
        assert!(v
            .register_windows_hello(&mut b, "PC-A", Edition::Single)
            .is_ok());
        wh_drop_platform_marker(&mut v);
        let before = fs::read(&p).unwrap();
        let result = v.register_windows_hello(&mut b, "PC-A", Edition::Single);
        assert!(
            matches!(
                result,
                Err(VaultError::Fido(FidoError::PlatformCredentialExists))
            ),
            "lost marker must still count as same-machine platform"
        );
        assert_eq!(b.inner.platform_credential_ids().len(), 1);
        assert!(fs::read(&p).unwrap() == before);
        assert_eq!(
            v.header.key_slots[0].authenticator, None,
            "rejected registration must not persist or mutate repair"
        );
    }

    #[test]
    fn wh_d4_r3_password_repairs_only_after_authentication() {
        let p = fresh_path("wh-d4-r3-password");
        let mut v = Vault::create(&p, "Synthetic-Pw-12345").unwrap();
        let mut b = WhBackend::new();
        assert!(v
            .register_windows_hello(&mut b, "TEST-PC", Edition::Single)
            .is_ok());
        wh_drop_platform_marker(&mut v);
        drop(v);
        let before = fs::read(&p).unwrap();
        let wrong = Vault::open_password_with_platform(&p, "wrong", Edition::Single, &mut b);
        assert!(matches!(wrong, Err(VaultError::WrongPassword)));
        assert!(fs::read(&p).unwrap() == before);
        let opened =
            Vault::open_password_with_platform(&p, "Synthetic-Pw-12345", Edition::Single, &mut b);
        assert!(opened.is_ok());
        assert_eq!(
            Vault::read_header(&p, Edition::Single).unwrap().key_slots[0].authenticator,
            Some(SlotAuthenticator::Platform)
        );
    }

    #[test]
    fn wh_d4_r3_roaming_classifies_before_allow_and_save() {
        let p = fresh_path("wh-d4-r3-roaming");
        let mut v = Vault::create(&p, "Synthetic-Pw-12345").unwrap();
        let mut b = WhBackend::new();
        let roaming = v.register_key(&mut b, None);
        assert!(roaming.is_ok());
        let roaming = roaming.unwrap();
        let platform = v.register_windows_hello(&mut b, "TEST-PC", Edition::Single);
        assert!(platform.is_ok());
        let platform = platform.unwrap();
        wh_drop_platform_marker(&mut v);
        drop(v);
        b.roaming.clear();
        let before = fs::read(&p).unwrap();
        let direct = Vault::open_key(&p, &base64_encode(&platform.credential_id), None, &mut b);
        assert!(direct.is_err());
        assert!(
            b.roaming.is_empty(),
            "R3 platform ID must not reach explicit roaming assertion"
        );
        assert!(fs::read(&p).unwrap() == before);
        let opened = Vault::open_any_key(&p, None, &mut b);
        assert!(opened.is_ok());
        assert!(b.roaming == vec![roaming.credential_id]);
        assert_eq!(
            Vault::read_header(&p, Edition::Single).unwrap().key_slots[1].authenticator,
            Some(SlotAuthenticator::Platform)
        );
    }

    #[test]
    fn wh_d4_r3_platform_login_repairs_on_authenticated_save() {
        let p = fresh_path("wh-d4-r3-platform");
        let mut v = Vault::create(&p, "Synthetic-Pw-12345").unwrap();
        let mut b = WhBackend::new();
        assert!(v
            .register_windows_hello(&mut b, "TEST-PC", Edition::Single)
            .is_ok());
        wh_drop_platform_marker(&mut v);
        drop(v);
        let result = Vault::open_windows_hello(&p, &mut b, Edition::Single);
        assert!(
            result.is_ok(),
            "R3 local credential must remain platform-login usable"
        );
        assert_eq!(
            Vault::read_header(&p, Edition::Single).unwrap().key_slots[0].authenticator,
            Some(SlotAuthenticator::Platform)
        );
    }

    #[test]
    fn wh_d4_r3_readonly_local_list_classification() {
        let p = fresh_path("wh-d4-r3-read");
        let mut v = Vault::create(&p, "Synthetic-Pw-12345").unwrap();
        let mut a = WhBackend::new();
        let mut b = WhBackend::new();
        assert!(v
            .register_windows_hello(&mut a, "PC-A", Edition::Single)
            .is_ok());
        assert!(v
            .register_windows_hello(&mut b, "PC-B", Edition::Single)
            .is_ok());
        wh_drop_platform_marker(&mut v);
        drop(v);
        let before = fs::read(&p).unwrap();
        let h = Vault::read_header_with_platform(&p, Edition::Single, &mut a);
        assert!(h.is_ok());
        let h = h.unwrap();
        assert_eq!(
            h.key_slots[0].authenticator,
            Some(SlotAuthenticator::Platform),
            "verified local credential must classify platform"
        );
        assert_eq!(
            h.key_slots[1].authenticator, None,
            "unknown other-machine ID must not be guessed"
        );
        assert!(
            fs::read(&p).unwrap() == before,
            "query must not persist repair"
        );
        assert!(!failures_path(&p).exists());
    }

    #[test]
    fn wh_d4_roaming_rejects_backend_selected_platform() {
        let p = fresh_path("wh-d4-roaming-rogue");
        let mut v = Vault::create(&p, "Synthetic-Pw-12345").unwrap();
        let mut b = WhBackend::new();
        assert!(v.register_key(&mut b, None).is_ok());
        let reg = v.register_windows_hello(&mut b, "TEST-PC", Edition::Single);
        assert!(reg.is_ok());
        b.selected = Some(reg.unwrap().credential_id);
        drop(v);
        let before = fs::read(&p).unwrap();
        let result = Vault::open_any_key(&p, None, &mut b);
        assert!(
            matches!(result, Err(VaultError::Fido(FidoError::Internal(_)))),
            "backend must not bypass allow-list"
        );
        assert!(fs::read(&p).unwrap() == before);
    }

    #[test]
    fn wh_d4_roaming_excludes_marked_platform() {
        let p = fresh_path("wh-d4-roaming-filter");
        let mut v = Vault::create(&p, "Synthetic-Pw-12345").unwrap();
        let mut b = WhBackend::new();
        let roaming = v.register_key(&mut b, None);
        assert!(roaming.is_ok());
        let roaming = roaming.unwrap();
        let platform = v.register_windows_hello(&mut b, "TEST-PC", Edition::Single);
        assert!(platform.is_ok());
        let platform = platform.unwrap();
        drop(v);
        b.roaming.clear();
        let result = Vault::open_any_key(&p, None, &mut b);
        assert!(result.is_ok());
        assert!(
            b.roaming == vec![roaming.credential_id],
            "roaming allow-list must exclude platform"
        );
        drop(result);
        b.roaming.clear();
        let result = Vault::open_key(&p, &base64_encode(&platform.credential_id), None, &mut b);
        assert!(matches!(result, Err(VaultError::Fido(FidoError::NoDevice))));
        assert!(
            b.roaming.is_empty(),
            "explicit platform ID must not reach roaming backend"
        );
    }

    #[test]
    fn wh_d4_platform_rejection_audit() {
        let p = fresh_path("wh-d4-login-rejection");
        let mut v = Vault::create(&p, "Synthetic-Pw-12345").unwrap();
        let mut b = WhBackend::new();
        assert!(v
            .register_windows_hello(&mut b, "TEST-PC", Edition::Single)
            .is_ok());
        drop(v);
        b.assertion_error = Some(FidoError::PinRejected);
        let rejected = Vault::open_windows_hello(&p, &mut b, Edition::Single);
        assert!(matches!(
            rejected,
            Err(VaultError::Fido(FidoError::PinRejected))
        ));
        assert_eq!(
            read_failure_sidecar(&p).len(),
            1,
            "actual rejection must record failure"
        );
        b.assertion_error = Some(FidoError::NoDevice);
        assert!(Vault::open_windows_hello(&p, &mut b, Edition::Single).is_err());
        assert_eq!(
            read_failure_sidecar(&p).len(),
            1,
            "cancel/no-device must not record"
        );
        b.wrong_secret = true;
        let wrong = Vault::open_windows_hello(&p, &mut b, Edition::Single);
        assert!(matches!(
            wrong,
            Err(VaultError::Crypto(CryptoError::DecryptFailed))
        ));
        let stamps = read_failure_sidecar(&p);
        assert_eq!(stamps.len(), 2);
        assert!(stamps
            .iter()
            .all(|s| s.method == "windows-hello:Windows Hello（本機 TEST-PC）"));
    }

    #[test]
    fn wh_d4_platform_returned_id_membership() {
        let p = fresh_path("wh-d4-login-membership");
        let mut v = Vault::create(&p, "Synthetic-Pw-12345").unwrap();
        let mut b = WhBackend::new();
        assert!(v
            .register_windows_hello(&mut b, "PC-A", Edition::Single)
            .is_ok());
        let mut other = WhBackend::new();
        let remote = v.register_windows_hello(&mut other, "PC-B", Edition::Single);
        assert!(remote.is_ok());
        b.selected = Some(remote.unwrap().credential_id);
        drop(v);
        let result = Vault::open_windows_hello(&p, &mut b, Edition::Single);
        assert!(matches!(
            result,
            Err(VaultError::Fido(FidoError::PlatformCredentialMissing))
        ));
        assert_eq!(b.allow.len(), 1);
        let failures = read_failure_sidecar(&p);
        assert_eq!(failures.len(), 1);
        assert_eq!(
            failures[0].method,
            "windows-hello:Windows Hello（本機 PC-A）"
        );
    }

    #[test]
    fn wh_d4_platform_roundtrip_restart_and_sidecar() {
        let p = fresh_path("wh-d4-roundtrip");
        let mut v = Vault::create(&p, "Synthetic-Pw-12345").unwrap();
        v.add_entry("synthetic-site", "test", "synthetic-secret", "")
            .unwrap();
        let mut b = WhBackend::new();
        let reg = v.register_windows_hello(&mut b, "TEST-PC", Edition::Single);
        assert!(reg.is_ok());
        let reg = reg.unwrap();
        let local = b.inner.platform_credential_ids().to_vec();
        drop(v);
        record_login_failure(&p, "password").unwrap();
        b.inner = MockBackend::new().with_platform_credentials(local);
        let opened = Vault::open_windows_hello(&p, &mut b, Edition::Single);
        assert!(opened.is_ok(), "platform PRF must unlock after restart");
        let v = opened.unwrap();
        assert_eq!(v.entries().len(), 1);
        assert!(b.allow == vec![reg.credential_id]);
        assert!(!failures_path(&p).exists());
        assert_eq!(
            v.audit().last().unwrap().method,
            "windows-hello:Windows Hello（本機 TEST-PC）"
        );
        assert!(v
            .audit()
            .iter()
            .any(|e| e.event == "login_failed" && e.method == "password"));
        assert!(v
            .audit()
            .iter()
            .any(|e| e.method.starts_with("register_key:windows-hello:")));
    }

    fn wh_registration_fixture_tag(rename_failure: bool) -> &'static str {
        if rename_failure {
            "wh-d4-save-failure-rename"
        } else {
            "wh-d4-save-failure-tmp"
        }
    }

    #[test]
    fn wh_d4_registration_failure_fixtures_are_disjoint() {
        assert_ne!(
            wh_registration_fixture_tag(false),
            wh_registration_fixture_tag(true),
            "parallel tmp/rename rollback tests must not share a vault path"
        );
    }

    fn wh_registration_save_failure(rename_failure: bool) {
        let p = fresh_path(wh_registration_fixture_tag(rename_failure));
        let mut v = Vault::create(&p, "Synthetic-Pw-12345").unwrap();
        v.data.audit = (0..MAX_AUDIT)
            .map(|index| AuditEvent {
                ts: index.to_string(),
                event: "synthetic".into(),
                method: "test".into(),
                detail: index.to_string(),
            })
            .collect();
        v.write_file().unwrap();
        let disk = fs::read(&p).unwrap();
        let header = serde_json::to_vec(&v.header).unwrap();
        let audit = serde_json::to_vec(&v.data.audit).unwrap();
        let tmp = p.with_extension("db.tmp");
        #[cfg(windows)]
        let _guard = if rename_failure {
            use std::os::windows::fs::OpenOptionsExt;
            Some(
                fs::OpenOptions::new()
                    .read(true)
                    .share_mode(1)
                    .open(&p)
                    .unwrap(),
            )
        } else {
            None
        };
        if !rename_failure {
            fs::create_dir(&tmp).unwrap();
        }
        let mut b = WhBackend::new();
        let result = v.register_windows_hello(&mut b, "TEST-PC", Edition::Single);
        assert!(matches!(result, Err(VaultError::Io(_))));
        assert!(
            serde_json::to_vec(&v.header).unwrap() == header,
            "failed persist must restore all slots"
        );
        assert!(
            serde_json::to_vec(&v.data.audit).unwrap() == audit,
            "audit cap trimming must be undone"
        );
        assert!(fs::read(&p).unwrap() == disk);
        assert!(b.inner.platform_credential_ids().is_empty());
        assert_eq!(b.deleted.len(), 1);
    }

    #[test]
    fn wh_d4_register_tmp_write_rollback() {
        wh_registration_save_failure(false);
    }

    #[cfg(windows)]
    #[test]
    fn wh_d4_register_rename_rollback() {
        wh_registration_save_failure(true);
    }

    #[test]
    fn wh_d4_register_rogue_assertion_id() {
        let p = fresh_path("wh-d4-register-rogue");
        let mut v = Vault::create(&p, "Synthetic-Pw-12345").unwrap();
        let mut b = WhBackend::new();
        b.selected = Some(vec![99; 32]);
        let result = v.register_windows_hello(&mut b, "TEST-PC", Edition::Single);
        assert!(matches!(
            result,
            Err(VaultError::Fido(FidoError::PlatformCredentialMissing))
        ));
        assert_eq!(b.deleted.len(), 1);
        assert!(b.deleted == b.allow);
        assert!(b.inner.platform_credential_ids().is_empty());
        assert!(v.header.key_slots.is_empty());
    }

    #[test]
    fn wh_d4_creation_requires_local_ownership() {
        let p = fresh_path("wh-d4-ownership");
        let mut v = Vault::create(&p, "Synthetic-Pw-12345").unwrap();
        let mut b = WhBackend::new();
        b.collision = Some(vec![99; 32]);
        let result = v.register_windows_hello(&mut b, "TEST-PC", Edition::Single);
        assert!(matches!(
            result,
            Err(VaultError::Fido(FidoError::PlatformCredentialMissing))
        ));
        assert!(b.deleted.is_empty());
        assert!(b.allow.is_empty());
        assert!(v.header.key_slots.is_empty());
    }

    #[test]
    fn wh_d4_creation_collision_never_deletes_existing() {
        let p = fresh_path("wh-d4-collision");
        let mut v = Vault::create(&p, "Synthetic-Pw-12345").unwrap();
        let mut b = WhBackend::new();
        let roaming = v.register_key(&mut b, None);
        assert!(roaming.is_ok());
        let roaming = roaming.unwrap();
        b.collision = Some(roaming.credential_id);
        b.assertion_error = Some(FidoError::PlatformPrfUnsupported);
        let before = fs::read(&p).unwrap();
        let result = v.register_windows_hello(&mut b, "TEST-PC", Edition::Single);
        assert!(result.is_err());
        assert!(
            b.deleted.is_empty(),
            "a colliding creation ID must never be deleted"
        );
        assert!(b.allow.is_empty(), "collision precedes assertion");
        assert!(fs::read(&p).unwrap() == before);
        assert_eq!(v.header.key_slots.len(), 1);
    }

    #[test]
    fn wh_d4_register_exclude_and_machine_scope() {
        let p = fresh_path("wh-d4-exclude");
        let mut v = Vault::create(&p, "Synthetic-Pw-12345").unwrap();
        let mut first = WhBackend::new();
        let result = v.register_windows_hello(&mut first, "PC-A", Edition::Single);
        assert!(result.is_ok());
        let reg = result.unwrap();
        assert!(first.allow == vec![reg.credential_id.clone()]);
        let mut second = WhBackend::new();
        let result = v.register_windows_hello(&mut second, "PC-B", Edition::Single);
        assert!(result.is_ok());
        assert!(
            second.exclude == vec![reg.credential_id.clone()],
            "other machine must receive all vault platform IDs"
        );
        let count = first.inner.platform_credential_ids().len();
        let duplicate = v.register_windows_hello(&mut first, "PC-A", Edition::Single);
        assert!(matches!(
            duplicate,
            Err(VaultError::Fido(FidoError::PlatformCredentialExists))
        ));
        assert_eq!(first.inner.platform_credential_ids().len(), count);
        assert_eq!(v.header.key_slots.len(), 2);
    }

    #[test]
    fn wh_d4_register_unavailable_no_prompt() {
        let p = fresh_path("wh-d4-unavailable");
        let mut v = Vault::create(&p, "Synthetic-Pw-12345").unwrap();
        let mut b = WhBackend::new();
        b.available = false;
        let result = v.register_windows_hello(&mut b, "TEST-PC", Edition::Single);
        assert!(matches!(
            result,
            Err(VaultError::Fido(FidoError::NotSupported(_)))
        ));
        assert_eq!(b.calls.get(), 1);
        assert!(b.inner.platform_credential_ids().is_empty());
    }

    #[test]
    fn wh_d4_register_edition_gate_no_backend() {
        for (vault_edition, requested) in [
            (Edition::Dual, Edition::Single),
            (Edition::Single, Edition::Dual),
        ] {
            let p = fresh_path("wh-d4-edition");
            let mut v = Vault::create_for(&p, "Synthetic-Pw-12345", vault_edition).unwrap();
            let mut b = WhBackend::new();
            let result = v.register_windows_hello(&mut b, "TEST-PC", requested);
            assert!(result.is_err(), "non-single registration must reject");
            assert_eq!(b.calls.get(), 0, "edition gate precedes every backend call");
        }
    }

    #[test]
    fn wh_d4_creation_mismatch_cleanup() {
        let p = fresh_path("wh-d4-mismatch");
        let mut v = Vault::create(&p, "Synthetic-Pw-12345").unwrap();
        let mut b = MockBackend::new()
            .with_platform_mode(crate::fido2::MockPlatformMode::CreationPrfMismatch);
        let result = v.register_windows_hello(&mut b, "TEST-PC", Edition::Single);
        assert!(matches!(
            result,
            Err(VaultError::Fido(FidoError::PlatformPrfUnsupported))
        ));
        assert!(b.platform_credential_ids().is_empty());
        assert!(v.header.key_slots.is_empty());
    }

    #[test]
    fn wh_d4_registration_prf_failure_cleanup() {
        use crate::fido2::MockPlatformMode;
        for mode in [MockPlatformMode::AssertionPrfFails] {
            let p = fresh_path("wh-d4-prf-failure");
            let created = Vault::create(&p, "Synthetic-Pw-12345");
            assert!(created.is_ok());
            let mut v = created.unwrap();
            let before = fs::read(&p).unwrap();
            let mut b = MockBackend::new().with_platform_mode(mode);
            let result = v.register_windows_hello(&mut b, "TEST-PC", Edition::Single);
            assert!(matches!(
                result,
                Err(VaultError::Fido(FidoError::PlatformPrfUnsupported))
            ));
            assert!(
                b.platform_credential_ids().is_empty(),
                "failed verification must clean up new credential"
            );
            assert!(v.header.key_slots.is_empty());
            assert!(fs::read(&p).unwrap() == before);
        }
    }

    #[test]
    fn wh_d4_register_verified_slot() {
        let p = fresh_path("wh-d4-register");
        let created = Vault::create(&p, "Synthetic-Pw-12345");
        assert!(created.is_ok());
        let mut v = created.unwrap();
        let mut b = MockBackend::new();
        let result = v.register_windows_hello(&mut b, "TEST-PC", Edition::Single);
        assert!(
            result.is_ok(),
            "verified platform registration must succeed"
        );
        let reg = result.unwrap();
        assert_eq!(v.header.key_slots.len(), 1);
        let slot = &v.header.key_slots[0];
        assert_eq!(slot.authenticator, Some(SlotAuthenticator::Platform));
        assert_eq!(slot.label, "Windows Hello（本機 TEST-PC）");
        assert_eq!(slot.credential_id, base64_encode(&reg.credential_id));
        assert_eq!(
            Vault::read_header(&p, Edition::Single)
                .unwrap()
                .key_slots
                .len(),
            1
        );
    }

    #[test]
    fn d13_sidecar_events_follow_existing_audit_before_success() {
        let p = fresh_path("d13-audit-order");
        let mut v = Vault::create_dual(&p, "Synthetic-Pw-12345").unwrap();
        v.data.audit[0].ts = "2000-01-01T00:00:00Z".into();
        v.write_file().unwrap();
        drop(v);
        DualPending::for_test(p.clone(), Instant::now())
            .cancel()
            .unwrap();
        DualPending::for_test(p.clone(), Instant::now())
            .expire()
            .unwrap();
        let v = Vault::open_password_with_edition(&p, "Synthetic-Pw-12345", Edition::Dual).unwrap();
        let methods: Vec<&str> = v.audit().iter().map(|e| e.method.as_str()).collect();
        assert_eq!(
            methods,
            vec![
                "setup",
                "fido2-dual-cancel",
                "fido2-dual-timeout",
                "password-breakglass"
            ],
            "sidecar events must be merged after older audit, before the successful login"
        );
        let (_, payload) = Vault::read_file(&p, Edition::Dual).unwrap();
        let persisted = Vault::decrypt_payload(&v.kek, &payload).unwrap();
        assert_eq!(
            persisted
                .audit
                .iter()
                .map(|e| e.method.as_str())
                .collect::<Vec<_>>(),
            methods
        );
        assert!(!failures_path(&p).exists());
    }

    #[test]
    fn d13_new_audit_and_failure_timestamps_use_local_seconds() {
        let p = fresh_path("d13-audit-local");
        let before = chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
        let mut v = Vault::create_dual(&p, "Synthetic-Pw-12345").unwrap();
        v.record("settings_changed", "manual", "synthetic local time test")
            .unwrap();
        record_login_failure(&p, "fido2-dual-cancel").unwrap();
        let after = chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
        let stamps = read_failure_sidecar(&p);
        let times: Vec<&str> = v
            .audit()
            .iter()
            .map(|e| e.ts.as_str())
            .chain(stamps.iter().map(|e| e.ts.as_str()))
            .collect();
        assert_eq!(times.len(), 3);
        for ts in times {
            assert_eq!(
                ts.len(),
                19,
                "audit timestamp must be yyyy-MM-dd HH:mm:ss: {ts}"
            );
            assert!(chrono::NaiveDateTime::parse_from_str(ts, "%Y-%m-%d %H:%M:%S").is_ok());
            assert!(
                before.as_str() <= ts && ts <= after.as_str(),
                "timestamp must be local system time: {ts}"
            );
        }
        assert!(
            chrono::DateTime::parse_from_rfc3339(&v.header.created_at).is_ok(),
            "non-audit metadata stays RFC3339 for compatibility"
        );
        let (_, payload) = Vault::read_file(&p, Edition::Dual).unwrap();
        let persisted = Vault::decrypt_payload(&v.kek, &payload).unwrap();
        assert_eq!(persisted.audit.len(), 2);
        for e in &persisted.audit {
            assert_eq!(e.ts.len(), 19);
            assert!(chrono::NaiveDateTime::parse_from_str(&e.ts, "%Y-%m-%d %H:%M:%S").is_ok());
        }
        drop(v);
        let reopened =
            Vault::open_password_with_edition(&p, "Synthetic-Pw-12345", Edition::Dual).unwrap();
        assert_eq!(reopened.audit().len(), 4);
        assert_eq!(reopened.audit().last().unwrap().event, "login_success");
        assert!(reopened.audit().iter().all(|e| e.ts.len() == 19
            && chrono::NaiveDateTime::parse_from_str(&e.ts, "%Y-%m-%d %H:%M:%S").is_ok()));
    }

    #[test]
    fn d13_sidecar_merge_at_audit_cap_keeps_recent_failure_events() {
        for edition in [Edition::Single, Edition::Dual] {
            let p = fresh_path(if edition == Edition::Single {
                "d13-cap-single"
            } else {
                "d13-cap-dual"
            });
            let mut v = Vault::create_with_edition(&p, "Synthetic-Pw-12345", edition).unwrap();
            let old = AuditEvent {
                ts: "2000-01-01T00:00:00Z".into(),
                event: "synthetic-old".into(),
                method: "test".into(),
                detail: "non-secret".into(),
            };
            v.data.audit = vec![old; MAX_AUDIT];
            v.write_file().unwrap();
            drop(v);
            record_login_failure(&p, "fido2-dual-cancel").unwrap();
            record_login_failure(&p, "fido2-dual-timeout").unwrap();
            let v = Vault::open_password_with_edition(&p, "Synthetic-Pw-12345", edition).unwrap();
            assert_eq!(v.audit().len(), MAX_AUDIT);
            assert_eq!(v.audit()[MAX_AUDIT - 3].method, "fido2-dual-cancel");
            assert_eq!(v.audit()[MAX_AUDIT - 2].method, "fido2-dual-timeout");
            assert_eq!(v.audit()[MAX_AUDIT - 1].event, "login_success");
            assert_eq!(
                v.audit()[0].ts,
                "2000-01-01T00:00:00Z",
                "legacy timestamps are not rewritten"
            );
            let (_, payload) = Vault::read_file(&p, edition).unwrap();
            let persisted = Vault::decrypt_payload(&v.kek, &payload).unwrap();
            assert_eq!(persisted.audit.len(), MAX_AUDIT);
            assert_eq!(persisted.audit[MAX_AUDIT - 3].method, "fido2-dual-cancel");
            assert_eq!(persisted.audit[MAX_AUDIT - 2].method, "fido2-dual-timeout");
            assert_eq!(persisted.audit[MAX_AUDIT - 1].event, "login_success");
        }
    }

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
            authenticator: None,
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

    // ── windows-hello D1：KeySlot.authenticator 格式 ──

    fn platform_key_slot(group: Option<KeyGroup>) -> KeySlot {
        let mut slot = sample_key_slot(group);
        slot.authenticator = Some(SlotAuthenticator::Platform);
        slot
    }

    #[test]
    fn wh_d1_platform_authenticator_serializes_as_lowercase() {
        let raw = serde_json::to_value(platform_key_slot(None)).unwrap();
        assert_eq!(
            raw["authenticator"],
            serde_json::json!("platform"),
            "platform slot must serialize as \"platform\": {raw}"
        );
    }

    #[test]
    fn wh_d1_authenticator_deserialization_is_strict() {
        let with = |value: serde_json::Value| {
            let mut raw = serde_json::to_value(sample_key_slot(None)).unwrap();
            raw["authenticator"] = value;
            serde_json::from_value::<KeySlot>(raw).map(|slot| slot.authenticator)
        };
        let ok = with(serde_json::json!("platform"));
        assert!(
            matches!(ok, Ok(Some(SlotAuthenticator::Platform))),
            "\"platform\" must parse: {ok:?}"
        );
        for bad in ["Platform", "PLATFORM", "roaming", "cross-platform", ""] {
            let r = with(serde_json::json!(bad));
            assert!(r.is_err(), "{bad:?} must be rejected, got {r:?}");
        }
        let r = with(serde_json::json!(1));
        assert!(r.is_err(), "non-string must be rejected, got {r:?}");
    }

    /// 既有行為回歸（GREEN→GREEN）：沒有 platform slot 的 v1 KeySlot / header 序列化與變更前逐字相同。
    #[test]
    fn wh_d1_roaming_slot_serialization_is_unchanged() {
        let json = serde_json::to_string(&sample_key_slot(None)).unwrap();
        assert_eq!(
            json,
            format!(
                "{{\"credential_id\":\"Y3JlZA==\",\"aaguid\":\"{}\",\"label\":\"k1\",\"key_type\":\"touch_only\",\"nonce\":\"bm9uY2U=\",\"ct\":\"Y3Q=\"}}",
                "00".repeat(16)
            )
        );
        assert!(!json.contains("authenticator"));
    }

    /// 既有行為回歸（GREEN→GREEN）：真實 v1 檔案 header 經 Header 往返後 byte-for-byte 相同。
    #[test]
    fn wh_d1_v1_file_header_roundtrip_is_byte_identical() {
        let p = fresh_path("wh-d1-v1-bytes");
        let mut v = Vault::create(&p, "Pw-12345").unwrap();
        let mut backend = MockBackend::new();
        v.register_key(&mut backend, None).unwrap();
        drop(v);
        let buf = fs::read(&p).unwrap();
        let len = u32::from_le_bytes(buf[6..10].try_into().unwrap()) as usize;
        let raw = &buf[10..10 + len];
        let header: Header = serde_json::from_slice(raw).unwrap();
        assert_eq!(header.key_slots.len(), 1);
        assert_eq!(header.key_slots[0].authenticator, None);
        assert_eq!(serde_json::to_vec(&header).unwrap(), raw);
        assert!(!std::str::from_utf8(raw).unwrap().contains("authenticator"));
    }

    #[test]
    fn wh_d1_single_edition_accepts_and_preserves_platform_slot() {
        let p = fresh_path("wh-d1-v1-platform");
        let mut v = Vault::create(&p, "Pw-12345").unwrap();
        let mut backend = MockBackend::new();
        v.register_key(&mut backend, None).unwrap();
        drop(v);
        rewrite_header(&p, |h| {
            h["key_slots"][0]["authenticator"] = serde_json::json!("platform");
        });

        let header = Vault::read_header(&p, Edition::Single);
        assert!(
            header.is_ok(),
            "v1 platform slot must be readable: {:?}",
            header.err()
        );
        assert_eq!(
            header.unwrap().key_slots[0].authenticator,
            Some(SlotAuthenticator::Platform)
        );
        let opened = Vault::open_password(&p, "Pw-12345");
        assert!(
            opened.is_ok(),
            "v1 platform slot must open: {:?}",
            opened.err()
        );
        let mut v = opened.unwrap();
        v.set_idle_lock(7).unwrap();
        drop(v);
        assert_eq!(
            raw_header_json(&p)["key_slots"][0]["authenticator"],
            serde_json::json!("platform"),
            "a normal save must keep the platform marker"
        );
    }

    #[test]
    fn wh_d1_edition_check_platform_slot_single_ok_dual_rejected() {
        let mut v1 = sample_header(1);
        v1.key_slots = vec![platform_key_slot(None)];
        assert!(check_header_edition(&v1, Edition::Single).is_ok());

        let mut v2 = valid_v2_header();
        v2.key_slots.push(platform_key_slot(Some(KeyGroup::B)));
        let r = check_header_edition(&v2, Edition::Dual);
        assert!(
            matches!(r, Err(VaultError::Format(_))),
            "v2 slot with authenticator must be Format: {r:?}"
        );
    }

    #[test]
    fn wh_d1_dual_open_rejects_v2_file_with_authenticator_without_writing() {
        let p = fresh_path("wh-d1-v2-reject");
        let mut v = Vault::create_dual(&p, "Pw-12345").unwrap();
        let mut backend = MockBackend::new();
        v.register_key_in_group(&mut backend, None, "a1", KeyGroup::A)
            .unwrap();
        drop(v);
        rewrite_header(&p, |h| {
            h["key_slots"][0]["authenticator"] = serde_json::json!("platform");
        });
        let before = fs::read(&p).unwrap();

        let r = Vault::open_password_dual(&p, "Pw-12345");
        assert!(
            matches!(r, Err(VaultError::Format(_))),
            "dual edition must refuse a v2 slot with authenticator: {:?}",
            r.err()
        );
        let h = Vault::read_header(&p, Edition::Dual);
        assert!(
            matches!(h, Err(VaultError::Format(_))),
            "read_header must refuse it too: {:?}",
            h.err()
        );
        assert_eq!(
            fs::read(&p).unwrap(),
            before,
            "file must stay byte-identical"
        );
        assert!(!failures_path(&p).exists(), "no failure sidecar");
        assert!(!p.with_extension("db.tmp").exists());
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
    fn dual_corrupt_slot_credential_fails_before_authenticator() {
        let p = fresh_path("d6-corrupt-cred");
        let mut v = Vault::create_dual(&p, "Pw-12345").unwrap();
        let mut b1 = MockBackend::new();
        v.register_key_in_group(&mut b1, None, "a1", KeyGroup::A)
            .unwrap();
        v.header.key_slots[0].credential_id = "%%not-base64%%".into();
        let mut counting = CountingBackend::new();
        let r = v.register_key_in_group(&mut counting, None, "b1", KeyGroup::B);
        assert!(
            matches!(&r, Err(VaultError::Format(m)) if m.contains("credential_id")),
            "got {:?}",
            r.as_ref().map(|_| ())
        );
        assert_eq!(counting.detects, 0);
        assert_eq!(counting.registers, 0);
        assert_eq!(v.header.key_slots.len(), 1);
    }

    #[test]
    fn removed_key_can_register_again() {
        let p = fresh_path("d6-remove-reregister");
        let mut v = Vault::create_dual(&p, "Pw-12345").unwrap();
        let mut x = MockBackend::new();
        let first = v
            .register_key_in_group(&mut x, None, "x-a", KeyGroup::A)
            .unwrap();
        let mut y = MockBackend::new();
        v.register_key_in_group(&mut y, None, "y-a", KeyGroup::A)
            .unwrap();
        v.remove_key(&base64_encode(&first.credential_id)).unwrap();
        x.reuse_device();
        // mock detect 會循環類型（這次是 PIN 型），提供測試 PIN。
        let again = v.register_key_in_group(&mut x, Some("1234"), "x-b", KeyGroup::B);
        assert!(
            again.is_ok(),
            "exclude list must only contain current slots, got {:?}",
            again.err()
        );
        assert_eq!(v.header.key_slots.len(), 2);
    }

    // ── D7：兩步驟登入 ──

    /// 模擬「使用者在 broker 中刷了某一支金鑰」：只有該 credential 在允許清單內才成功
    /// （Windows broker 只接受 allow-list 內的 credential）；`rogue` 模擬不遵守允許清單的後端。
    struct TapBackend {
        tap: Vec<u8>,
        rogue: bool,
        offered: Vec<Vec<Vec<u8>>>,
        /// 設定後，金鑰互動發生時設為 true（驗證時鐘取樣時機）。
        prompted: Option<std::sync::Arc<std::sync::atomic::AtomicBool>>,
    }

    impl TapBackend {
        fn tap(cred: &[u8]) -> Self {
            Self {
                tap: cred.to_vec(),
                rogue: false,
                offered: Vec::new(),
                prompted: None,
            }
        }
    }

    impl FidoBackend for TapBackend {
        fn detect(&mut self) -> Result<crate::fido2::DetectedKey, FidoError> {
            Err(FidoError::NoDevice)
        }
        fn register_credential(
            &mut self,
            _: &crate::fido2::DetectedKey,
            _: Option<&str>,
        ) -> Result<crate::fido2::RegisteredCredential, FidoError> {
            Err(FidoError::NoDevice)
        }
        fn get_prf_secret(&mut self, id: &[u8], _: Option<&str>) -> Result<[u8; 32], FidoError> {
            Ok(MockBackend::prf_for_credential(id))
        }
        fn get_prf_secret_for_any(
            &mut self,
            ids: &[Vec<u8>],
            _: Option<&str>,
        ) -> Result<(Vec<u8>, [u8; 32]), FidoError> {
            self.offered.push(ids.to_vec());
            if let Some(flag) = &self.prompted {
                flag.store(true, std::sync::atomic::Ordering::SeqCst);
            }
            if self.rogue || ids.contains(&self.tap) {
                Ok((self.tap.clone(), MockBackend::prf_for_credential(&self.tap)))
            } else {
                Err(FidoError::Internal(
                    "simulated NotAllowed: key not in allow list".into(),
                ))
            }
        }
    }

    /// 建立雙人版金庫並依序註冊金鑰（每支一個新 mock = 不同實體金鑰）；回傳各 credential。
    fn dual_vault_with(tag: &str, keys: &[(&str, KeyGroup)]) -> (PathBuf, Vec<Vec<u8>>) {
        let p = fresh_path(tag);
        let mut v = Vault::create_dual(&p, "Pw-12345").unwrap();
        let mut creds = Vec::new();
        for (label, group) in keys {
            let mut b = MockBackend::new();
            let reg = v
                .register_key_in_group(&mut b, None, label, *group)
                .unwrap();
            creds.push(reg.credential_id);
        }
        drop(v.lock());
        (p, creds)
    }

    fn two_step(p: &Path, first: &[u8], second: &[u8]) -> Result<Vault, VaultError> {
        let t0 = Instant::now();
        let mut b1 = TapBackend::tap(first);
        let pending = Vault::dual_login_begin(p, None, &mut b1, &mut || t0)?;
        let mut b2 = TapBackend::tap(second);
        Vault::dual_login_complete(pending, None, &mut b2, &mut || t0 + Duration::from_secs(5))
    }

    #[test]
    fn dual_login_a_then_b_unlocks_and_audits_order() {
        let (p, c) = dual_vault_with("d7-ab", &[("王小明", KeyGroup::A), ("李大華", KeyGroup::B)]);
        let r = two_step(&p, &c[0], &c[1]);
        assert!(r.is_ok(), "A→B failed: {:?}", r.err());
        let v = r.unwrap();
        let last = v.audit().last().unwrap();
        assert_eq!(last.event, "login_success");
        assert_eq!(
            last.method,
            format!(
                "fido2-dual:A:王小明#{}+B:李大華#{}",
                cred_fp(&c[0]),
                cred_fp(&c[1])
            )
        );
    }

    #[test]
    fn dual_login_b_then_a_unlocks_and_audits_order() {
        let (p, c) = dual_vault_with("d7-ba", &[("a1", KeyGroup::A), ("b1", KeyGroup::B)]);
        let r = two_step(&p, &c[1], &c[0]);
        assert!(r.is_ok(), "B→A failed: {:?}", r.err());
        assert_eq!(
            r.unwrap().audit().last().unwrap().method,
            format!("fido2-dual:B:b1#{}+A:a1#{}", cred_fp(&c[1]), cred_fp(&c[0]))
        );
    }

    #[test]
    fn dual_login_begin_reports_first_group_and_timeout() {
        let (p, c) = dual_vault_with("d7-begin-info", &[("a1", KeyGroup::A), ("b1", KeyGroup::B)]);
        let t0 = Instant::now();
        let mut b = TapBackend::tap(&c[1]);
        let pending = Vault::dual_login_begin(&p, None, &mut b, &mut || t0);
        assert!(pending.is_ok(), "begin failed: {:?}", pending.err());
        let pending = pending.unwrap();
        assert_eq!(pending.first_group(), KeyGroup::B);
        assert_eq!(pending.first_label(), "b1");
        assert_eq!(pending.timeout_secs(), DEFAULT_DUAL_STEP_TIMEOUT_SECS);
        assert_eq!(pending.remaining(t0), Duration::from_secs(120));
        // 第一步允許清單 = 全部 A+B。
        assert_eq!(b.offered, vec![c.clone()]);
        let shown = format!("{pending:?}");
        assert!(shown.contains("<redacted>"), "{shown}");
    }

    #[test]
    fn dual_login_second_step_offers_only_other_group() {
        let (p, c) = dual_vault_with(
            "d7-other-group",
            &[
                ("a1", KeyGroup::A),
                ("a2", KeyGroup::A),
                ("b1", KeyGroup::B),
            ],
        );
        let t0 = Instant::now();
        let mut b1 = TapBackend::tap(&c[0]);
        let pending = Vault::dual_login_begin(&p, None, &mut b1, &mut || t0);
        assert!(pending.is_ok(), "begin failed: {:?}", pending.err());
        // 第二步刷同群組的 a2：不在允許清單 → 失敗，不可解鎖。
        let mut b2 = TapBackend::tap(&c[1]);
        let r = Vault::dual_login_complete(pending.unwrap(), None, &mut b2, &mut || t0);
        assert!(r.is_err(), "same-group second key must not unlock");
        assert_eq!(
            b2.offered,
            vec![vec![c[2].clone()]],
            "step 2 allow list must be group B only"
        );
    }

    #[test]
    fn dual_login_rejects_rogue_backend_returning_same_group() {
        let (p, c) = dual_vault_with(
            "d7-rogue",
            &[
                ("a1", KeyGroup::A),
                ("a2", KeyGroup::A),
                ("b1", KeyGroup::B),
            ],
        );
        let t0 = Instant::now();
        let mut b1 = TapBackend::tap(&c[0]);
        let pending = Vault::dual_login_begin(&p, None, &mut b1, &mut || t0);
        assert!(pending.is_ok(), "begin failed: {:?}", pending.err());
        let mut rogue = TapBackend::tap(&c[1]);
        rogue.rogue = true; // 無視允許清單，回傳 A 群組的 a2
        let before = fs::read(&p).unwrap();
        let r = Vault::dual_login_complete(pending.unwrap(), None, &mut rogue, &mut || t0);
        assert!(
            matches!(&r, Err(VaultError::Fido(FidoError::Internal(_)))),
            "credential outside the required group must be refused, got {:?}",
            r.as_ref().map(|_| ())
        );
        assert_eq!(fs::read(&p).unwrap(), before);
    }

    #[test]
    fn dual_login_requires_both_groups() {
        let (p, c) = dual_vault_with("d7-not-ready", &[("a1", KeyGroup::A)]);
        let mut b = TapBackend::tap(&c[0]);
        let r = Vault::dual_login_begin(&p, None, &mut b, &mut Instant::now);
        assert!(
            matches!(r, Err(VaultError::DualNotReady)),
            "got {:?}",
            r.as_ref().map(|_| ())
        );
        assert!(b.offered.is_empty(), "must not prompt for a key");
        assert!(!failures_path(&p).exists());
    }

    #[test]
    fn dual_login_expired_second_step_is_refused_and_recorded() {
        let (p, c) = dual_vault_with("d7-expired", &[("a1", KeyGroup::A), ("b1", KeyGroup::B)]);
        let t0 = Instant::now();
        let mut b1 = TapBackend::tap(&c[0]);
        let pending = Vault::dual_login_begin(&p, None, &mut b1, &mut || t0);
        assert!(pending.is_ok(), "begin failed: {:?}", pending.err());
        let pending = pending.unwrap();
        let late = t0 + Duration::from_secs(121);
        assert!(pending.is_expired(late));
        assert_eq!(pending.remaining(late), Duration::ZERO);
        let mut b2 = TapBackend::tap(&c[1]);
        let r = Vault::dual_login_complete(pending, None, &mut b2, &mut || late);
        assert!(
            matches!(r, Err(VaultError::DualStepExpired)),
            "got {:?}",
            r.as_ref().map(|_| ())
        );
        assert!(
            b2.offered.is_empty(),
            "expired pending must not prompt for the second key"
        );
        let stamps = read_failure_sidecar(&p);
        assert_eq!(
            stamps.last().map(|s| s.method.as_str()),
            Some("fido2-dual-timeout")
        );
    }

    #[test]
    fn dual_login_within_deadline_succeeds() {
        let (p, c) = dual_vault_with("d7-deadline", &[("a1", KeyGroup::A), ("b1", KeyGroup::B)]);
        let t0 = Instant::now();
        let mut b1 = TapBackend::tap(&c[0]);
        let pending = Vault::dual_login_begin(&p, None, &mut b1, &mut || t0);
        assert!(pending.is_ok(), "begin failed: {:?}", pending.err());
        let mut b2 = TapBackend::tap(&c[1]);
        let r = Vault::dual_login_complete(pending.unwrap(), None, &mut b2, &mut || {
            t0 + Duration::from_secs(120)
        });
        assert!(
            r.is_ok(),
            "exactly at the deadline must still succeed: {:?}",
            r.err()
        );
    }

    #[test]
    fn dual_login_cancel_is_recorded_without_touching_vault() {
        let (p, c) = dual_vault_with("d7-cancel", &[("a1", KeyGroup::A), ("b1", KeyGroup::B)]);
        let before = fs::read(&p).unwrap();
        let mut b1 = TapBackend::tap(&c[0]);
        let pending = Vault::dual_login_begin(&p, None, &mut b1, &mut Instant::now);
        assert!(pending.is_ok(), "begin failed: {:?}", pending.err());
        pending.unwrap().cancel().unwrap();
        assert_eq!(fs::read(&p).unwrap(), before);
        let stamps = read_failure_sidecar(&p);
        assert_eq!(
            stamps.last().map(|s| s.method.as_str()),
            Some("fido2-dual-cancel")
        );
    }

    #[test]
    fn dual_login_tampered_first_slot_group_fails_step1() {
        let (p, c) = dual_vault_with(
            "d7-tamper1",
            &[
                ("a1", KeyGroup::A),
                ("a2", KeyGroup::A),
                ("b1", KeyGroup::B),
            ],
        );
        rewrite_header(&p, |h| h["key_slots"][1]["group"] = serde_json::json!("B"));
        let mut b = TapBackend::tap(&c[1]);
        let r = Vault::dual_login_begin(&p, None, &mut b, &mut Instant::now);
        assert!(
            matches!(r, Err(VaultError::Crypto(CryptoError::DecryptFailed))),
            "got {:?}",
            r.as_ref().map(|_| ())
        );
        let stamps = read_failure_sidecar(&p);
        assert_eq!(
            stamps.last().map(|s| s.method.as_str()),
            Some("fido2-dual-step1:a2")
        );
    }

    #[test]
    fn dual_login_tampered_second_slot_group_fails_step2() {
        let (p, c) = dual_vault_with(
            "d7-tamper2",
            &[
                ("a1", KeyGroup::A),
                ("b1", KeyGroup::B),
                ("b2", KeyGroup::B),
            ],
        );
        rewrite_header(&p, |h| h["key_slots"][2]["group"] = serde_json::json!("A"));
        let t0 = Instant::now();
        let mut b1 = TapBackend::tap(&c[1]); // b1（B）
        let pending = Vault::dual_login_begin(&p, None, &mut b1, &mut || t0);
        assert!(pending.is_ok(), "begin failed: {:?}", pending.err());
        let before = fs::read(&p).unwrap();
        let mut b2 = TapBackend::tap(&c[2]); // b2 被改標成 A，出現在 A 允許清單
        let r = Vault::dual_login_complete(pending.unwrap(), None, &mut b2, &mut || t0);
        assert!(
            matches!(r, Err(VaultError::Crypto(CryptoError::DecryptFailed))),
            "got {:?}",
            r.as_ref().map(|_| ())
        );
        assert_eq!(fs::read(&p).unwrap(), before);
        let stamps = read_failure_sidecar(&p);
        assert_eq!(
            stamps.last().map(|s| s.method.as_str()),
            Some("fido2-dual-step2:b2")
        );
    }

    #[test]
    fn dual_login_refuses_when_vault_replaced_between_steps() {
        let (p, c) = dual_vault_with("d7-replaced", &[("a1", KeyGroup::A), ("b1", KeyGroup::B)]);
        let t0 = Instant::now();
        let mut b1 = TapBackend::tap(&c[0]);
        let pending = Vault::dual_login_begin(&p, None, &mut b1, &mut || t0);
        assert!(pending.is_ok(), "begin failed: {:?}", pending.err());
        // 兩步之間檔案被換成另一個金庫（不同 dual_slot）。
        let (other, _) = dual_vault_with(
            "d7-replaced-other",
            &[("a1", KeyGroup::A), ("b1", KeyGroup::B)],
        );
        fs::copy(&other, &p).unwrap();
        let mut b2 = TapBackend::tap(&c[1]);
        let r = Vault::dual_login_complete(pending.unwrap(), None, &mut b2, &mut || t0);
        assert!(
            matches!(&r, Err(VaultError::Format(m)) if m.contains("已變更")),
            "got {:?}",
            r.as_ref().map(|_| ())
        );
        assert!(b2.offered.is_empty());
    }

    #[test]
    fn dual_login_rejects_single_edition_file() {
        let p = fresh_path("d7-v1");
        drop(Vault::create(&p, "Pw-12345").unwrap());
        let mut b = TapBackend::tap(&[1u8; 32]);
        assert!(matches!(
            Vault::dual_login_begin(&p, None, &mut b, &mut Instant::now),
            Err(VaultError::WrongEdition {
                vault: Edition::Single
            })
        ));
    }

    fn cred_fp(cred: &[u8]) -> String {
        let digest = <sha2::Sha256 as sha2::Digest>::digest(cred);
        digest[..4].iter().map(|b| format!("{b:02x}")).collect()
    }

    // ── D7 追加修正（審查）──

    #[test]
    fn dual_login_deadline_starts_after_first_key_completes() {
        let (p, c) = dual_vault_with(
            "d7r-begin-clock",
            &[("a1", KeyGroup::A), ("b1", KeyGroup::B)],
        );
        let t0 = Instant::now();
        let prompted = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let mut b = TapBackend::tap(&c[0]);
        b.prompted = Some(prompted.clone());
        let mut sampled_after_prompt = Vec::new();
        let mut clock = || {
            sampled_after_prompt.push(prompted.load(std::sync::atomic::Ordering::SeqCst));
            // 第一步耗時 40 秒：截止時間必須以「第一支金鑰完成」為起點。
            t0 + Duration::from_secs(40)
        };
        let pending = Vault::dual_login_begin(&p, None, &mut b, &mut clock);
        assert!(pending.is_ok(), "begin failed: {:?}", pending.err());
        assert_eq!(
            sampled_after_prompt,
            vec![true],
            "deadline clock must be sampled once, after the first key completes"
        );
        let pending = pending.unwrap();
        assert_eq!(
            pending.remaining(t0 + Duration::from_secs(40)),
            Duration::from_secs(120)
        );
    }

    #[test]
    fn dual_login_second_key_completed_after_deadline_is_refused() {
        let (p, c) = dual_vault_with(
            "d7r-post-expiry",
            &[("a1", KeyGroup::A), ("b1", KeyGroup::B)],
        );
        let t0 = Instant::now();
        let mut b1 = TapBackend::tap(&c[0]);
        let pending = Vault::dual_login_begin(&p, None, &mut b1, &mut || t0);
        assert!(pending.is_ok(), "begin failed: {:?}", pending.err());
        let before = fs::read(&p).unwrap();
        // 第二步開始時尚未逾時（t0+100），刷完時已逾時（t0+121）。
        let mut samples = vec![t0 + Duration::from_secs(121), t0 + Duration::from_secs(100)];
        let mut clock = || samples.pop().unwrap_or(t0 + Duration::from_secs(121));
        let mut b2 = TapBackend::tap(&c[1]);
        let r = Vault::dual_login_complete(pending.unwrap(), None, &mut b2, &mut clock);
        assert!(
            matches!(r, Err(VaultError::DualStepExpired)),
            "completion after the deadline must be refused, got {:?}",
            r.as_ref().map(|_| ())
        );
        assert_eq!(
            b2.offered.len(),
            1,
            "the second key was prompted before the deadline"
        );
        assert_eq!(fs::read(&p).unwrap(), before);
        let stamps = read_failure_sidecar(&p);
        assert_eq!(
            stamps.last().map(|s| s.method.as_str()),
            Some("fido2-dual-timeout")
        );
    }

    #[test]
    fn dual_login_just_past_deadline_is_expired() {
        let (p, c) = dual_vault_with("d7r-just-past", &[("a1", KeyGroup::A), ("b1", KeyGroup::B)]);
        let t0 = Instant::now();
        let mut b1 = TapBackend::tap(&c[0]);
        let pending = Vault::dual_login_begin(&p, None, &mut b1, &mut || t0).unwrap();
        assert!(pending.is_expired(t0 + Duration::from_secs(120) + Duration::from_nanos(1)));
        assert!(!pending.is_expired(t0 + Duration::from_secs(120)));
    }

    #[test]
    fn dual_login_second_step_same_key_is_refused() {
        let (p, c) = dual_vault_with("d7r-same-key", &[("a1", KeyGroup::A), ("b1", KeyGroup::B)]);
        let t0 = Instant::now();
        let mut b1 = TapBackend::tap(&c[0]);
        let pending = Vault::dual_login_begin(&p, None, &mut b1, &mut || t0).unwrap();
        let mut again = TapBackend::tap(&c[0]);
        again.rogue = true;
        let r = Vault::dual_login_complete(pending, None, &mut again, &mut || t0);
        assert!(r.is_err(), "the first key must not satisfy step 2");
    }

    #[test]
    fn dual_login_step2_rejected_credential_is_recorded() {
        let (p, c) = dual_vault_with(
            "d7r-rogue-recorded",
            &[
                ("a1", KeyGroup::A),
                ("a2", KeyGroup::A),
                ("b1", KeyGroup::B),
            ],
        );
        let t0 = Instant::now();
        let mut b1 = TapBackend::tap(&c[0]);
        let pending = Vault::dual_login_begin(&p, None, &mut b1, &mut || t0).unwrap();
        let mut rogue = TapBackend::tap(&c[1]);
        rogue.rogue = true;
        let _ = Vault::dual_login_complete(pending, None, &mut rogue, &mut || t0);
        let stamps = read_failure_sidecar(&p);
        assert_eq!(
            stamps.last().map(|s| s.method.as_str()),
            Some("fido2-dual-step2-rejected")
        );
    }

    #[test]
    fn dual_login_step1_unknown_credential_creates_no_pending() {
        let (p, _c) = dual_vault_with(
            "d7r-step1-unknown",
            &[("a1", KeyGroup::A), ("b1", KeyGroup::B)],
        );
        let mut rogue = TapBackend::tap(&[9u8; 32]);
        rogue.rogue = true;
        let r = Vault::dual_login_begin(&p, None, &mut rogue, &mut Instant::now);
        assert!(matches!(r, Err(VaultError::Fido(FidoError::Internal(_)))));
    }

    #[test]
    fn dual_login_binding_mismatch_is_recorded_without_writing() {
        let (p, c) = dual_vault_with("d7r-binding", &[("a1", KeyGroup::A), ("b1", KeyGroup::B)]);
        let t0 = Instant::now();
        let mut b1 = TapBackend::tap(&c[0]);
        let pending = Vault::dual_login_begin(&p, None, &mut b1, &mut || t0).unwrap();
        let (other, _) = dual_vault_with(
            "d7r-binding-other",
            &[("a1", KeyGroup::A), ("b1", KeyGroup::B)],
        );
        fs::copy(&other, &p).unwrap();
        let before = fs::read(&p).unwrap();
        let mut b2 = TapBackend::tap(&c[1]);
        assert!(Vault::dual_login_complete(pending, None, &mut b2, &mut || t0).is_err());
        assert_eq!(fs::read(&p).unwrap(), before);
        let stamps = read_failure_sidecar(&p);
        assert_eq!(
            stamps.last().map(|s| s.method.as_str()),
            Some("fido2-dual-binding-mismatch")
        );
    }

    #[test]
    fn dual_login_tampered_timeout_mirror_is_clamped_end_to_end() {
        for (raw, expected) in [(5u32, 30u32), (99_999, 600)] {
            let (p, c) = dual_vault_with(
                &format!("d7r-timeout-{raw}"),
                &[("a1", KeyGroup::A), ("b1", KeyGroup::B)],
            );
            rewrite_header(&p, |h| h["dual_step_timeout_secs"] = serde_json::json!(raw));
            let t0 = Instant::now();
            let mut b = TapBackend::tap(&c[0]);
            let pending = Vault::dual_login_begin(&p, None, &mut b, &mut || t0).unwrap();
            assert_eq!(pending.timeout_secs(), expected);
            assert_eq!(
                pending.remaining(t0),
                Duration::from_secs(u64::from(expected))
            );
        }
    }

    #[test]
    fn same_group_shares_cannot_open_dual_slot() {
        let p = fresh_path("d7r-same-share");
        let v = Vault::create_dual(&p, "Pw-12345").unwrap();
        let shares = v.data.dual.clone().unwrap();
        let a = decode_share(&shares.share_a);
        let b = decode_share(&shares.share_b);
        let slot = v.header.dual_slot.clone().unwrap();
        let nonce = slot_nonce(&slot.nonce).unwrap();
        let ct = base64_decode(&slot.ct).unwrap();
        for (x, y) in [(a, a), (b, b), (b, a)] {
            let wrap = crate::crypto::dual_wrap_key_from_shares(&x, &y);
            assert!(aes_gcm_decrypt_aad(&wrap, &nonce, &ct, DUAL_SLOT_AAD).is_err());
        }
        let wrap = crate::crypto::dual_wrap_key_from_shares(&a, &b);
        assert!(aes_gcm_decrypt_aad(&wrap, &nonce, &ct, DUAL_SLOT_AAD).is_ok());
    }

    #[test]
    fn dual_pending_debug_never_shows_share_bytes() {
        let pending = DualPending::for_test(PathBuf::from("x"), Instant::now());
        let shown = format!("{pending:?}");
        let hex: String = pending.share.iter().map(|b| format!("{b:02x}")).collect();
        assert!(!shown.contains(&hex));
        assert!(!shown.contains("7, 7, 7"), "{shown}");
    }

    #[test]
    fn dual_pending_expire_records_timeout() {
        let p = fresh_path("d7r-expire");
        let pending = DualPending::for_test(p.clone(), Instant::now());
        pending.expire().unwrap();
        let stamps = read_failure_sidecar(&p);
        assert_eq!(
            stamps.last().map(|s| s.method.as_str()),
            Some("fido2-dual-timeout")
        );
    }

    #[test]
    fn audit_party_escapes_separators_and_adds_fingerprint() {
        let cred = [1u8, 2, 3];
        assert_eq!(
            dual_audit_party(KeyGroup::B, "x+B:y#%", &cred),
            format!("B:x%2BB%3Ay%23%25#{}", cred_fp(&cred))
        );
        assert_eq!(escape_audit_label("王小明"), "王小明");
    }

    #[test]
    fn dual_login_failure_methods_escape_labels() {
        let (p, c) = dual_vault_with(
            "d7r-escape-fail",
            &[
                ("a1", KeyGroup::A),
                ("x+y", KeyGroup::A),
                ("b1", KeyGroup::B),
            ],
        );
        rewrite_header(&p, |h| h["key_slots"][1]["group"] = serde_json::json!("B"));
        let mut b = TapBackend::tap(&c[1]);
        let _ = Vault::dual_login_begin(&p, None, &mut b, &mut Instant::now);
        let stamps = read_failure_sidecar(&p);
        assert_eq!(
            stamps.last().map(|s| s.method.as_str()),
            Some("fido2-dual-step1:x%2By")
        );
    }

    // ── D8：群組最後一支金鑰不可刪除 ──

    fn slot_id(v: &Vault, label: &str) -> String {
        v.header
            .key_slots
            .iter()
            .find(|s| s.label == label)
            .unwrap()
            .credential_id
            .clone()
    }

    fn reopen_dual(p: &Path) -> Vault {
        Vault::open_password_dual(p, "Pw-12345").unwrap()
    }

    #[test]
    fn dual_cannot_remove_last_key_of_a_group() {
        let (p, _) = dual_vault_with("d8-last", &[("a1", KeyGroup::A), ("b1", KeyGroup::B)]);
        let mut v = reopen_dual(&p);
        let audit_len = v.audit().len();
        let before = fs::read(&p).unwrap();
        for label in ["a1", "b1"] {
            let id = slot_id(&v, label);
            let r = v.remove_key(&id);
            let expected = if label == "a1" {
                KeyGroup::A
            } else {
                KeyGroup::B
            };
            assert!(
                matches!(r, Err(VaultError::LastKeyInGroup(g)) if g == expected),
                "removing the last {label} must be refused, got {:?}",
                r
            );
        }
        assert_eq!(v.header.key_slots.len(), 2);
        assert_eq!(
            v.audit().len(),
            audit_len,
            "refused removal must not be audited"
        );
        assert_eq!(
            fs::read(&p).unwrap(),
            before,
            "refused removal must not write"
        );
    }

    #[test]
    fn dual_can_remove_non_last_key_then_blocks_the_last() {
        let (p, _) = dual_vault_with(
            "d8-non-last",
            &[
                ("a1", KeyGroup::A),
                ("a2", KeyGroup::A),
                ("b1", KeyGroup::B),
            ],
        );
        let mut v = reopen_dual(&p);
        let a1 = slot_id(&v, "a1");
        let r = v.remove_key(&a1);
        assert!(r.is_ok(), "removing a1 (A still has a2) failed: {r:?}");
        let last = v.audit().last().unwrap().clone();
        assert_eq!(last.event, "key_removed");
        assert!(last.detail.contains("group=A"), "{}", last.detail);
        let a2 = slot_id(&v, "a2");
        assert!(matches!(
            v.remove_key(&a2),
            Err(VaultError::LastKeyInGroup(KeyGroup::A))
        ));
        drop(v.lock());
        assert_eq!(
            Vault::read_header(&p, Edition::Dual)
                .unwrap()
                .key_slots
                .len(),
            2
        );
    }

    #[test]
    fn dual_single_group_only_key_is_also_protected() {
        let (p, _) = dual_vault_with("d8-only-a", &[("a1", KeyGroup::A)]);
        let mut v = reopen_dual(&p);
        let a1 = slot_id(&v, "a1");
        assert!(matches!(
            v.remove_key(&a1),
            Err(VaultError::LastKeyInGroup(KeyGroup::A))
        ));
    }

    #[test]
    fn single_edition_can_still_remove_its_only_key() {
        let p = fresh_path("d8-single");
        let mut v = Vault::create(&p, "Pw-12345").unwrap();
        let mut b = MockBackend::new();
        let reg = v.register_key_with_label(&mut b, None, "s1").unwrap();
        assert!(v.remove_key(&base64_encode(&reg.credential_id)).is_ok());
        assert!(v.header.key_slots.is_empty());
        assert_eq!(
            v.audit().last().unwrap().detail,
            "金鑰槽已移除（該金鑰無法再解鎖）"
        );
    }

    #[test]
    fn last_key_in_group_reports_only_singletons() {
        let mut h = valid_v2_header();
        let mut a2 = sample_key_slot(Some(KeyGroup::A));
        a2.credential_id = "QTI=".into();
        let mut b1 = sample_key_slot(Some(KeyGroup::B));
        b1.credential_id = "QjE=".into();
        h.key_slots = vec![sample_key_slot(Some(KeyGroup::A)), a2, b1];
        assert_eq!(last_key_in_group(&h, "Y3JlZA=="), None);
        assert_eq!(last_key_in_group(&h, "QTI="), None);
        assert_eq!(last_key_in_group(&h, "QjE="), Some(KeyGroup::B));
        assert_eq!(last_key_in_group(&h, "bm9uZQ=="), None);
        let mut single = sample_header(1);
        single.key_slots = vec![sample_key_slot(None)];
        assert_eq!(last_key_in_group(&single, "Y3JlZA=="), None);
    }

    #[test]
    fn last_key_in_group_error_message_is_clear() {
        let m = VaultError::LastKeyInGroup(KeyGroup::B).to_string();
        assert!(m.contains("B 群組的最後一支金鑰"), "{m}");
    }

    #[test]
    fn d8_non_last_removal_persists_immediately_in_both_groups() {
        for (case, group, other) in [
            ("a-with-b", KeyGroup::A, true),
            ("b-with-a", KeyGroup::B, true),
            ("a-only", KeyGroup::A, false),
            ("b-only", KeyGroup::B, false),
        ] {
            let mut keys = vec![("first", group), ("remaining", group)];
            if other {
                keys.push(("other", group.other()));
            }
            let (p, _) = dual_vault_with(&format!("d8-persist-{case}"), &keys);
            let mut v = reopen_dual(&p);
            let removed = slot_id(&v, "first");
            let expected: Vec<_> = v
                .header
                .key_slots
                .iter()
                .filter(|s| s.credential_id != removed)
                .map(|s| (s.credential_id.clone(), s.group))
                .collect();
            assert!(v.remove_key(&removed).is_ok());
            // Read before lock/drop can independently save again.
            let persisted = Vault::read_header(&p, Edition::Dual).unwrap();
            let actual: Vec<_> = persisted
                .key_slots
                .iter()
                .map(|s| (s.credential_id.clone(), s.group))
                .collect();
            assert_eq!(actual, expected);
            let disk = reopen_dual(&p);
            assert!(disk.audit().iter().any(|a| a.event == "key_removed"
                && a.detail.ends_with(&format!(" group={}", group.as_str()))));
            let remaining = slot_id(&v, "remaining");
            assert!(matches!(v.remove_key(&remaining),
                Err(VaultError::LastKeyInGroup(g)) if g == group));
        }
    }

    #[test]
    fn d8_refusal_preserves_full_state_for_both_groups_and_unknown_ids() {
        for (case, keys) in [
            ("a-only", vec![("a1", KeyGroup::A)]),
            ("b-only", vec![("b1", KeyGroup::B)]),
            ("both", vec![("a1", KeyGroup::A), ("b1", KeyGroup::B)]),
        ] {
            let (p, _) = dual_vault_with(&format!("d8-state-{case}"), &keys);
            let mut v = reopen_dual(&p);
            let header = serde_json::to_value(&v.header).unwrap();
            let data = serde_json::to_value(&v.data).unwrap();
            let bytes = fs::read(&p).unwrap();
            let targets: Vec<_> = v
                .header
                .key_slots
                .iter()
                .map(|s| (s.credential_id.clone(), s.group))
                .collect();
            for (id, group) in targets {
                assert!(matches!(v.remove_key(&id),
                    Err(VaultError::LastKeyInGroup(g)) if Some(g) == group));
                // Boolean comparisons avoid dumping synthetic shares on assertion failure.
                assert!(serde_json::to_value(&v.header).unwrap() == header);
                assert!(serde_json::to_value(&v.data).unwrap() == data);
                assert!(fs::read(&p).unwrap() == bytes);
            }
            assert!(matches!(
                v.remove_key("d8-unknown-credential"),
                Err(VaultError::Fido(FidoError::NoDevice))
            ));
            assert!(serde_json::to_value(&v.header).unwrap() == header);
            assert!(serde_json::to_value(&v.data).unwrap() == data);
            assert!(fs::read(&p).unwrap() == bytes);
        }
    }

    #[test]
    fn d8_duplicate_ids_remove_one_first_match_without_emptying_a_group() {
        for cross_group in [false, true] {
            let (p, _) = dual_vault_with(
                &format!("d8-duplicate-{cross_group}"),
                &[("a1", KeyGroup::A), ("a2", KeyGroup::A)],
            );
            let mut v = reopen_dual(&p);
            let id = slot_id(&v, "a1");
            v.header.key_slots[1].credential_id = id.clone();
            if cross_group {
                v.header.key_slots[1].group = Some(KeyGroup::B);
            }
            // Existing structural validation accepts duplicate IDs. Do not relax it.
            assert!(check_header_edition(&v.header, Edition::Dual).is_ok());
            let before = serde_json::to_value(&v.header).unwrap();
            if cross_group {
                assert!(matches!(
                    v.remove_key(&id),
                    Err(VaultError::LastKeyInGroup(KeyGroup::A))
                ));
                assert!(serde_json::to_value(&v.header).unwrap() == before);
                assert_eq!(v.header.key_slots.len(), 2);
            } else {
                assert!(v.remove_key(&id).is_ok());
                assert_eq!(v.header.key_slots.len(), 1);
                assert_eq!(v.header.key_slots[0].label, "a2");
                assert!(matches!(
                    v.remove_key(&id),
                    Err(VaultError::LastKeyInGroup(KeyGroup::A))
                ));
                assert_eq!(
                    Vault::read_header(&p, Edition::Dual)
                        .unwrap()
                        .key_slots
                        .len(),
                    1
                );
            }
        }
    }

    #[test]
    fn d9_setting_updates_both_copies_and_persists_audit() {
        let p = fresh_path("d9-set");
        let mut v = Vault::create_dual(&p, "Pw-12345").unwrap();
        for secs in [30, 60, 120, 600] {
            let r = v.set_dual_step_timeout(secs);
            assert!(r.is_ok(), "valid timeout must succeed: {r:?}");
            assert_eq!(v.settings().dual_step_timeout_secs, Some(secs));
            assert_eq!(
                Vault::read_header(&p, Edition::Dual)
                    .unwrap()
                    .dual_step_timeout_secs,
                Some(secs)
            );
            let disk = reopen_dual(&p);
            assert_eq!(disk.settings().dual_step_timeout_secs, Some(secs));
            assert!(disk.audit().iter().any(|a| a.event == "settings_changed"
                && a.method == "manual"
                && a.detail == format!("dual_step_timeout_secs={secs}")));
        }
    }

    #[test]
    fn d9_setting_rejects_out_of_range_without_any_mutation() {
        let p = fresh_path("d9-bounds");
        let mut v = Vault::create_dual(&p, "Pw-12345").unwrap();
        let h = serde_json::to_value(&v.header).unwrap();
        let d = serde_json::to_value(&v.data).unwrap();
        let b = fs::read(&p).unwrap();
        for secs in [0, 29, 601, u32::MAX] {
            assert!(matches!(
                v.set_dual_step_timeout(secs),
                Err(VaultError::Format(_))
            ));
            assert!(serde_json::to_value(&v.header).unwrap() == h);
            assert!(serde_json::to_value(&v.data).unwrap() == d);
            assert!(fs::read(&p).unwrap() == b);
        }
    }

    #[test]
    fn d9_single_edition_refuses_timeout_and_remains_unchanged() {
        let p = fresh_path("d9-single");
        let mut v = Vault::create(&p, "Pw-12345").unwrap();
        let h = serde_json::to_value(&v.header).unwrap();
        let d = serde_json::to_value(&v.data).unwrap();
        let b = fs::read(&p).unwrap();
        assert!(matches!(
            v.set_dual_step_timeout(60),
            Err(VaultError::Format(_))
        ));
        assert!(serde_json::to_value(&v.header).unwrap() == h);
        assert!(serde_json::to_value(&v.data).unwrap() == d);
        assert!(fs::read(&p).unwrap() == b);
    }

    #[test]
    fn d9_setting_write_failure_restores_settings_mirror_and_audit() {
        let p = fresh_path("d9-write-failure");
        let mut v = Vault::create_dual(&p, "Pw-12345").unwrap();
        // Exercise rollback after record() has also trimmed the audit cap.
        while v.data.audit.len() < 1000 {
            v.data.audit.push(AuditEvent {
                ts: now_rfc3339(),
                event: "synthetic".into(),
                method: "test".into(),
                detail: String::new(),
            });
        }
        v.write_file().unwrap();
        let h = serde_json::to_value(&v.header).unwrap();
        let d = serde_json::to_value(&v.data).unwrap();
        let b = fs::read(&p).unwrap();
        let tmp = p.with_extension("db.tmp");
        assert!(!tmp.exists());
        fs::create_dir(&tmp).unwrap(); // synthetic obstruction, never a real vault.
        let result = v.set_dual_step_timeout(60);
        fs::remove_dir(&tmp).unwrap();
        assert!(matches!(result, Err(VaultError::Io(_))));
        assert!(serde_json::to_value(&v.header).unwrap() == h);
        assert!(serde_json::to_value(&v.data).unwrap() == d);
        assert!(fs::read(&p).unwrap() == b);
    }

    #[test]
    fn d9_password_unlock_repairs_raw_mirror_once_from_authenticated_settings() {
        for raw in [
            None,
            Some(0u32),
            Some(29),
            Some(30),
            Some(60),
            Some(120),
            Some(600),
            Some(u32::MAX),
        ] {
            let p = fresh_path(&format!("d9-repair-{raw:?}"));
            let mut v = Vault::create_dual(&p, "Pw-12345").unwrap();
            assert!(v.set_dual_step_timeout(90).is_ok());
            drop(v);
            rewrite_header(&p, |h| {
                if let Some(raw) = raw {
                    h["dual_step_timeout_secs"] = serde_json::json!(raw);
                } else {
                    h.as_object_mut().unwrap().remove("dual_step_timeout_secs");
                }
            });
            let v = reopen_dual(&p);
            assert_eq!(v.settings().dual_step_timeout_secs, Some(90));
            assert_eq!(
                Vault::read_header(&p, Edition::Dual)
                    .unwrap()
                    .dual_step_timeout_secs,
                Some(90)
            );
            let repair: Vec<_> = v
                .audit()
                .iter()
                .filter(|a| a.event == "settings_tamper_detected")
                .collect();
            assert_eq!(repair.len(), 1);
            assert_eq!(repair[0].method, "system");
            assert_eq!(
                repair[0].detail,
                "dual_step_timeout_secs mirror repaired to 90"
            );
            assert_eq!(v.audit().last().unwrap().event, "login_success");
            let disk = reopen_dual(&p);
            assert_eq!(
                disk.audit()
                    .iter()
                    .filter(|a| a.event == "settings_tamper_detected")
                    .count(),
                1
            );
        }
    }

    #[test]
    fn d9_successful_two_key_unlock_repairs_mirror_using_payload() {
        let (p, c) = dual_vault_with("d9-key-repair", &[("a", KeyGroup::A), ("b", KeyGroup::B)]);
        let mut v = reopen_dual(&p);
        assert!(v.set_dual_step_timeout(60).is_ok());
        drop(v);
        rewrite_header(&p, |h| h["dual_step_timeout_secs"] = serde_json::json!(600));
        let before = fs::read(&p).unwrap();
        let now = Instant::now();
        let pending =
            Vault::dual_login_begin(&p, None, &mut TapBackend::tap(&c[0]), &mut || now).unwrap();
        assert_eq!(pending.timeout_secs(), 600); // locked reads bounded, unauthenticated mirror.
        assert!(
            fs::read(&p).unwrap() == before,
            "begin must not repair before authentication"
        );
        let result =
            Vault::dual_login_complete(pending, None, &mut TapBackend::tap(&c[1]), &mut || now);
        assert!(result.is_ok(), "two-key login failed: {:?}", result.err());
        let v = result.unwrap();
        assert_eq!(v.settings().dual_step_timeout_secs, Some(60));
        assert_eq!(v.header.dual_step_timeout_secs, Some(60));
        assert_eq!(
            v.audit()
                .iter()
                .filter(|a| a.event == "settings_tamper_detected")
                .count(),
            1
        );
        assert_eq!(
            Vault::read_header(&p, Edition::Dual)
                .unwrap()
                .dual_step_timeout_secs,
            Some(60)
        );
        drop(v);
        let persisted = reopen_dual(&p);
        assert_eq!(
            persisted
                .audit()
                .iter()
                .filter(|a| a.event == "settings_tamper_detected")
                .count(),
            1
        );
    }

    #[test]
    fn d9_matching_mirror_and_single_edition_never_report_tamper() {
        for (tag, edition) in [("single", Edition::Single), ("dual", Edition::Dual)] {
            let p = fresh_path(&format!("d9-no-tamper-{tag}"));
            drop(Vault::create_for(&p, "Pw-12345", edition).unwrap());
            let result = Vault::open_password_for(&p, "Pw-12345", edition);
            assert!(result.is_ok(), "matching mirror login failed");
            let v = result.unwrap();
            assert!(!v
                .audit()
                .iter()
                .any(|a| a.event == "settings_tamper_detected"));
            if edition == Edition::Single {
                assert!(serde_json::to_value(&v.header)
                    .unwrap()
                    .get("dual_step_timeout_secs")
                    .is_none());
                assert!(serde_json::to_value(v.settings())
                    .unwrap()
                    .get("dual_step_timeout_secs")
                    .is_none());
            }
        }
    }

    #[test]
    fn d9_failed_authentication_does_not_repair_a_mirror() {
        let p = fresh_path("d9-failed-auth");
        drop(Vault::create_dual(&p, "Pw-12345").unwrap());
        rewrite_header(&p, |h| h["dual_step_timeout_secs"] = serde_json::json!(600));
        let before = fs::read(&p).unwrap();
        assert!(Vault::open_password_dual(&p, "synthetic-wrong-password").is_err());
        assert!(fs::read(&p).unwrap() == before);
        assert_eq!(
            Vault::read_header(&p, Edition::Dual)
                .unwrap()
                .dual_step_timeout_secs,
            Some(600)
        );
    }

    #[test]
    fn d9_invalid_authenticated_timeout_fails_before_repair_or_write() {
        for secs in [0, 29, 601, u32::MAX] {
            let p = fresh_path(&format!("d9-invalid-payload-{secs}"));
            let mut v = Vault::create_dual(&p, "Pw-12345").unwrap();
            v.data.settings.dual_step_timeout_secs = Some(secs);
            v.write_file().unwrap(); // re-encrypt synthetic invalid payload with fixture KEK.
            drop(v);
            rewrite_header(&p, |h| h["dual_step_timeout_secs"] = serde_json::json!(60));
            let before = fs::read(&p).unwrap();
            let sidecar = failures_path(&p);
            assert!(!sidecar.exists());
            let r = Vault::open_password_dual(&p, "Pw-12345");
            assert!(
                matches!(r, Err(VaultError::Format(_))),
                "invalid payload timeout must fail closed"
            );
            assert!(fs::read(&p).unwrap() == before);
            assert!(!sidecar.exists());
            assert!(!p.with_extension("db.tmp").exists());
        }
    }

    #[test]
    fn d9_custom_setting_controls_new_pending_deadline() {
        for secs in [30u32, 60, 120, 600] {
            let (p, c) = dual_vault_with(
                &format!("d9-pending-{secs}"),
                &[("a", KeyGroup::A), ("b", KeyGroup::B)],
            );
            let mut v = reopen_dual(&p);
            v.set_dual_step_timeout(secs).unwrap();
            drop(v);
            let now = Instant::now();
            let pending =
                Vault::dual_login_begin(&p, None, &mut TapBackend::tap(&c[0]), &mut || now)
                    .unwrap();
            assert_eq!(pending.timeout_secs(), secs);
            assert!(!pending.is_expired(now + Duration::from_secs((secs - 1) as u64)));
            assert!(!pending.is_expired(now + Duration::from_secs(secs as u64)));
            assert!(pending
                .is_expired(now + Duration::from_secs(secs as u64) + Duration::from_nanos(1)));
            pending.cancel().unwrap();
        }
    }

    #[test]
    fn d9_failed_second_key_does_not_repair_before_full_authentication() {
        let (p, c) = dual_vault_with(
            "d9-second-failure",
            &[("a", KeyGroup::A), ("b", KeyGroup::B)],
        );
        rewrite_header(&p, |h| h["dual_step_timeout_secs"] = serde_json::json!(600));
        let before = fs::read(&p).unwrap();
        let now = Instant::now();
        let pending =
            Vault::dual_login_begin(&p, None, &mut TapBackend::tap(&c[0]), &mut || now).unwrap();
        let result =
            Vault::dual_login_complete(pending, None, &mut TapBackend::tap(&c[0]), &mut || now);
        assert!(result.is_err());
        assert!(fs::read(&p).unwrap() == before);
        assert_eq!(
            Vault::read_header(&p, Edition::Dual)
                .unwrap()
                .dual_step_timeout_secs,
            Some(600)
        );
    }

    #[test]
    fn d9_raw_mismatch_is_repaired_even_when_clamp_matches_authority() {
        for (secs, mirror) in [(30, Some(0u32)), (600, Some(u32::MAX)), (120, None)] {
            let p = fresh_path(&format!("d9-raw-not-clamp-{secs}"));
            let mut v = Vault::create_dual(&p, "Pw-12345").unwrap();
            v.set_dual_step_timeout(secs).unwrap();
            drop(v);
            rewrite_header(&p, |h| {
                if let Some(raw) = mirror {
                    h["dual_step_timeout_secs"] = serde_json::json!(raw);
                } else {
                    h.as_object_mut().unwrap().remove("dual_step_timeout_secs");
                }
            });
            let h = Vault::read_header(&p, Edition::Dual).unwrap();
            assert_eq!(effective_dual_step_timeout_secs(&h), secs);
            let v = reopen_dual(&p);
            assert_eq!(v.header.dual_step_timeout_secs, Some(secs));
            assert_eq!(
                v.audit()
                    .iter()
                    .filter(|a| a.event == "settings_tamper_detected")
                    .count(),
                1
            );
            let persisted = reopen_dual(&p);
            assert_eq!(
                persisted
                    .audit()
                    .iter()
                    .filter(|a| a.event == "settings_tamper_detected")
                    .count(),
                1
            );
        }
    }

    #[test]
    fn d9_missing_authoritative_setting_fails_without_repair_or_write() {
        let p = fresh_path("d9-missing-authority");
        let mut v = Vault::create_dual(&p, "Pw-12345").unwrap();
        v.data.settings.dual_step_timeout_secs = None;
        v.write_file().unwrap();
        drop(v);
        rewrite_header(&p, |h| h["dual_step_timeout_secs"] = serde_json::json!(60));
        let before = fs::read(&p).unwrap();
        assert!(!failures_path(&p).exists());
        assert!(matches!(
            Vault::open_password_dual(&p, "Pw-12345"),
            Err(VaultError::Format(_))
        ));
        assert!(fs::read(&p).unwrap() == before);
        assert!(!failures_path(&p).exists());
        assert!(!p.with_extension("db.tmp").exists());
    }

    #[test]
    fn d9_non_u32_header_values_keep_existing_fail_closed_parse() {
        for value in [
            serde_json::json!("120"),
            serde_json::json!(-1),
            serde_json::json!(1.5),
            serde_json::json!(4294967296u64),
        ] {
            let p = fresh_path("d9-malformed-header");
            drop(Vault::create_dual(&p, "Pw-12345").unwrap());
            rewrite_header(&p, |h| h["dual_step_timeout_secs"] = value);
            let before = fs::read(&p).unwrap();
            assert!(Vault::read_header(&p, Edition::Dual).is_err());
            assert!(Vault::open_password_dual(&p, "Pw-12345").is_err());
            assert!(fs::read(&p).unwrap() == before);
            assert!(!p.with_extension("db.tmp").exists());
            assert!(!failures_path(&p).exists());
        }
    }

    #[test]
    fn d9_setting_rename_failure_restores_state_and_keeps_original_vault() {
        let p = fresh_path("d9-rename-failure");
        let mut v = Vault::create_dual(&p, "Pw-12345").unwrap();
        let h = serde_json::to_value(&v.header).unwrap();
        let d = serde_json::to_value(&v.data).unwrap();
        let before = fs::read(&p).unwrap();
        // Synthetic directory destination makes write(tmp) succeed, rename fail.
        let blocked = p.with_extension("synthetic-blocked");
        fs::create_dir(&blocked).unwrap();
        v.path = blocked.clone();
        let result = v.set_dual_step_timeout(60);
        let tmp = blocked.with_extension("db.tmp");
        let temp_was_written = tmp.is_file();
        if temp_was_written {
            fs::remove_file(&tmp).unwrap();
        }
        fs::remove_dir(&blocked).unwrap();
        v.path = p.clone();
        assert!(
            temp_was_written,
            "failure must occur AFTER temporary ciphertext write"
        );
        assert!(matches!(result, Err(VaultError::Io(_))));
        assert!(serde_json::to_value(&v.header).unwrap() == h);
        assert!(serde_json::to_value(&v.data).unwrap() == d);
        assert!(fs::read(&p).unwrap() == before);
    }

    #[test]
    fn d9_repair_save_failure_preserves_vault_and_failure_sidecar() {
        let p = fresh_path("d9-repair-save-failure");
        drop(Vault::create_dual(&p, "Pw-12345").unwrap());
        rewrite_header(&p, |h| h["dual_step_timeout_secs"] = serde_json::json!(600));
        record_login_failure(&p, "synthetic-existing-failure").unwrap();
        let before = fs::read(&p).unwrap();
        let failure_before = fs::read(failures_path(&p)).unwrap();
        let tmp = p.with_extension("db.tmp");
        fs::create_dir(&tmp).unwrap();
        let result = Vault::open_password_dual(&p, "Pw-12345");
        fs::remove_dir(&tmp).unwrap();
        assert!(matches!(result, Err(VaultError::Io(_))));
        assert!(fs::read(&p).unwrap() == before);
        assert!(fs::read(failures_path(&p)).unwrap() == failure_before);
        let v = reopen_dual(&p);
        assert_eq!(v.header.dual_step_timeout_secs, Some(120));
        assert_eq!(
            v.audit()
                .iter()
                .filter(|a| a.event == "settings_tamper_detected")
                .count(),
            1
        );
        assert!(v
            .audit()
            .iter()
            .any(|a| a.event == "login_failed" && a.method == "synthetic-existing-failure"));
        assert!(!failures_path(&p).exists());
    }

    #[test]
    fn d11_mirror_mismatch_with_corrupted_payload_tag_does_not_repair() {
        let p = fresh_path("d11-corrupt-tag");
        drop(Vault::create_dual(&p, "Pw-12345").unwrap());
        rewrite_header(&p, |h| h["dual_step_timeout_secs"] = serde_json::json!(600));
        let mut bytes = fs::read(&p).unwrap();
        *bytes.last_mut().unwrap() ^= 0x01; // synthetic payload GCM tag corruption.
        fs::write(&p, &bytes).unwrap();
        record_login_failure(&p, "synthetic-existing-failure").unwrap();
        let before = fs::read(&p).unwrap();
        let failure_before = fs::read(failures_path(&p)).unwrap();
        let r = Vault::open_password_dual(&p, "Pw-12345");
        // Password slot opens; payload decrypt fails via `?` in unlock(), which records no failure.
        assert!(
            matches!(r, Err(VaultError::Crypto(CryptoError::DecryptFailed))),
            "corrupted payload tag must fail closed: {:?}",
            r.err()
        );
        assert!(fs::read(&p).unwrap() == before);
        assert!(!p.with_extension("db.tmp").exists());
        assert!(fs::read(failures_path(&p)).unwrap() == failure_before);
        assert_eq!(
            Vault::read_header(&p, Edition::Dual)
                .unwrap()
                .dual_step_timeout_secs,
            Some(600)
        );
    }

    #[test]
    fn d11_dual_key_login_rejects_missing_or_out_of_range_authority_with_sidecar() {
        for authority in [None, Some(29u32), Some(601)] {
            let (p, c) = dual_vault_with(
                &format!("d11-key-authority-{authority:?}"),
                &[("a", KeyGroup::A), ("b", KeyGroup::B)],
            );
            let mut v = reopen_dual(&p);
            v.data.settings.dual_step_timeout_secs = authority;
            v.write_file().unwrap(); // re-encrypt synthetic invalid payload with fixture KEK.
            drop(v);
            assert_eq!(
                Vault::read_header(&p, Edition::Dual)
                    .unwrap()
                    .dual_step_timeout_secs,
                Some(120)
            );
            record_login_failure(&p, "synthetic-existing-failure").unwrap();
            let before = fs::read(&p).unwrap();
            let failure_before = fs::read(failures_path(&p)).unwrap();
            let r = two_step(&p, &c[0], &c[1]);
            assert!(
                matches!(r, Err(VaultError::Format(_))),
                "authority {authority:?} must fail closed: {:?}",
                r.err()
            );
            assert!(fs::read(&p).unwrap() == before);
            assert!(!p.with_extension("db.tmp").exists());
            assert!(fs::read(failures_path(&p)).unwrap() == failure_before);
        }
    }

    #[cfg(windows)]
    #[test]
    fn d11_repair_login_rename_failure_preserves_vault_and_failure_sidecar() {
        use std::os::windows::fs::OpenOptionsExt;
        const FILE_SHARE_READ: u32 = 0x1;
        let p = fresh_path("d11-repair-rename-failure");
        drop(Vault::create_dual(&p, "Pw-12345").unwrap());
        rewrite_header(&p, |h| h["dual_step_timeout_secs"] = serde_json::json!(600));
        record_login_failure(&p, "synthetic-existing-failure").unwrap();
        let before = fs::read(&p).unwrap();
        let failure_before = fs::read(failures_path(&p)).unwrap();
        let tmp = p.with_extension("db.tmp");
        assert!(!tmp.exists());
        // Synthetic reader that denies delete sharing: reads still work, replacing vault.db fails.
        let guard = fs::OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ)
            .open(&p)
            .unwrap();
        assert!(
            fs::read(&p).unwrap() == before,
            "login read must work with guard open"
        );
        let result = Vault::open_password_dual(&p, "Pw-12345");
        let temp_was_written = tmp.is_file();
        drop(guard);
        if temp_was_written {
            fs::remove_file(&tmp).unwrap();
        }
        assert!(
            temp_was_written,
            "failure must occur AFTER temporary ciphertext write"
        );
        assert!(
            matches!(result, Err(VaultError::Io(_))),
            "rename failure must surface as Io: {:?}",
            result.err()
        );
        assert!(fs::read(&p).unwrap() == before);
        assert!(fs::read(failures_path(&p)).unwrap() == failure_before);
        let v = reopen_dual(&p);
        assert_eq!(v.header.dual_step_timeout_secs, Some(120));
        assert_eq!(
            v.audit()
                .iter()
                .filter(|a| a.event == "settings_tamper_detected")
                .count(),
            1
        );
        assert!(v
            .audit()
            .iter()
            .any(|a| a.event == "login_failed" && a.method == "synthetic-existing-failure"));
        assert!(!failures_path(&p).exists());
        assert!(!tmp.exists());
    }

    #[test]
    fn dual_step_timeout_mirror_is_clamped() {
        let mut h = valid_v2_header();
        h.dual_step_timeout_secs = None;
        assert_eq!(effective_dual_step_timeout_secs(&h), 120);
        h.dual_step_timeout_secs = Some(5);
        assert_eq!(effective_dual_step_timeout_secs(&h), 30);
        h.dual_step_timeout_secs = Some(99_999);
        assert_eq!(effective_dual_step_timeout_secs(&h), 600);
        h.dual_step_timeout_secs = Some(90);
        assert_eq!(effective_dual_step_timeout_secs(&h), 90);
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

    // ── D9-F1：註冊第二階段前景交接 ──

    use crate::fido2::{MockCall, MockHandoffRefusal};

    /// header JSON、audit JSON、磁碟位元組：用來證明 handoff 時金庫完全未變。
    fn d9f1_snapshot(v: &Vault) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        (
            serde_json::to_vec(&v.header).unwrap(),
            serde_json::to_vec(&v.data.audit).unwrap(),
            fs::read(&v.path).unwrap(),
        )
    }

    fn d9f1_roaming_backend(times: usize) -> MockBackend {
        MockBackend::new()
            .with_next_kind(KeyKind::TouchOnly)
            .with_roaming_handoff(MockHandoffRefusal::ForegroundHandoffRequired, times)
    }

    fn d9f1_pending_id(pending: &PendingRegistration) -> Vec<u8> {
        match pending {
            PendingRegistration::Roaming { credential, .. }
            | PendingRegistration::Platform { credential, .. } => credential.credential_id.clone(),
        }
    }

    #[test]
    fn d9f1_roaming_handoff_keeps_pending_without_slot_audit_or_write() {
        let p = fresh_path("d9f1-roaming-handoff");
        let mut v = Vault::create(&p, "Synthetic-Pw-12345").unwrap();
        let before = d9f1_snapshot(&v);
        let mut b = d9f1_roaming_backend(1);
        let outcome = v.begin_register_key_for(&mut b, Some("1234"), "my-key", None);
        let pending = match outcome {
            Ok(RegistrationOutcome::HandoffRequired(pending)) => pending,
            other => panic!("expected HandoffRequired, got {other:?}"),
        };
        assert!(matches!(
            &pending,
            PendingRegistration::Roaming { custom_label: Some(l), group: None, pin: Some(_), .. } if l == "my-key"
        ));
        assert!(
            d9f1_snapshot(&v) == before,
            "handoff must not change header/audit/disk"
        );
        assert_eq!(
            b.calls(),
            &[
                MockCall::Detect,
                MockCall::RegisterCredential,
                MockCall::GetPrfSecret
            ]
        );
        let shown = format!("{pending:?}");
        let id_b64 = base64_encode(&d9f1_pending_id(&pending));
        assert!(shown.contains("my-key"), "{shown}");
        assert!(
            !shown.contains("1234") && !shown.contains(&id_b64),
            "{shown}"
        );
        assert!(!shown.contains("credential_id"), "{shown}");
    }

    #[test]
    fn d9f1_roaming_continue_single_wraps_kek_and_audits_like_original() {
        let p = fresh_path("d9f1-roaming-continue");
        let mut v = Vault::create(&p, "Synthetic-Pw-12345").unwrap();
        let mut b = d9f1_roaming_backend(1);
        let pending = match v.begin_register_key_for(&mut b, None, "my-key", None) {
            Ok(RegistrationOutcome::HandoffRequired(pending)) => pending,
            other => panic!("expected HandoffRequired, got {other:?}"),
        };
        let id = d9f1_pending_id(&pending);
        let result = v.continue_registration(&mut b, pending, Edition::Single);
        let reg = match result {
            Ok(RegistrationOutcome::Registered(reg)) => reg,
            other => panic!("expected Registered, got {other:?}"),
        };
        assert_eq!(reg.credential_id, id);
        assert_eq!(reg.label, "my-key");
        // 只建立一次 credential；第二次斷言是全新的一般斷言。
        assert_eq!(
            b.calls(),
            &[
                MockCall::Detect,
                MockCall::RegisterCredential,
                MockCall::GetPrfSecret,
                MockCall::GetPrfSecret
            ]
        );
        assert_eq!(v.header.key_slots.len(), 1);
        let slot = &v.header.key_slots[0];
        assert_eq!(slot.credential_id, base64_encode(&id));
        assert_eq!(
            (slot.label.as_str(), slot.group, slot.authenticator),
            ("my-key", None, None)
        );
        let k = kek_from_prf_secret(&MockBackend::prf_for_credential(&id));
        let plain = aes_gcm_decrypt(
            &k,
            &slot_nonce(&slot.nonce).unwrap(),
            &base64_decode(&slot.ct).unwrap(),
        );
        assert!(matches!(plain, Ok(ref kek) if kek.as_slice() == v.kek.as_slice()));
        let last = v.data.audit.last().unwrap();
        assert_eq!(
            (
                last.event.as_str(),
                last.method.as_str(),
                last.detail.clone()
            ),
            (
                "key_registered",
                "fido2:my-key",
                format!("type={}", reg.kind)
            )
        );
        // 落盤且可用該金鑰登入。
        let reopened = Vault::open_key(&p, &base64_encode(&id), None, &mut MockBackend::new());
        assert!(reopened.is_ok(), "{:?}", reopened.err());
    }

    #[test]
    fn d9f1_roaming_continue_dual_wraps_group_share_with_aad() {
        let p = fresh_path("d9f1-roaming-dual");
        let mut v = Vault::create_dual(&p, "Synthetic-Pw-12345").unwrap();
        let mut b = d9f1_roaming_backend(1);
        let pending = match v.begin_register_key_for(&mut b, None, "王小明", Some(KeyGroup::A)) {
            Ok(RegistrationOutcome::HandoffRequired(pending)) => pending,
            other => panic!("expected HandoffRequired, got {other:?}"),
        };
        assert!(v.header.key_slots.is_empty());
        let result = v.continue_registration(&mut b, pending, Edition::Dual);
        assert!(
            matches!(result, Ok(RegistrationOutcome::Registered(_))),
            "{result:?}"
        );
        assert_eq!(v.header.key_slots.len(), 1);
        let slot = v.header.key_slots[0].clone();
        assert_eq!(slot.group, Some(KeyGroup::A));
        let share_a = decode_share(&v.data.dual.clone().unwrap().share_a);
        let unwrapped = unwrap_group_slot(&slot, &mut MockBackend::new(), KeyGroup::A);
        assert!(matches!(unwrapped, Ok(ref s) if s.as_slice() == share_a));
        assert!(unwrap_group_slot(&slot, &mut MockBackend::new(), KeyGroup::B).is_err());
        let last = v.data.audit.last().unwrap();
        assert_eq!(last.method, "fido2:王小明");
        assert!(last.detail.ends_with(" group=A"), "{}", last.detail);
    }

    #[test]
    fn d9f1_roaming_continue_handoff_again_returns_same_pending() {
        let p = fresh_path("d9f1-roaming-again");
        let mut v = Vault::create(&p, "Synthetic-Pw-12345").unwrap();
        let before = d9f1_snapshot(&v);
        let mut b = d9f1_roaming_backend(2);
        let pending = match v.begin_register_key_for(&mut b, None, "my-key", None) {
            Ok(RegistrationOutcome::HandoffRequired(pending)) => pending,
            other => panic!("expected HandoffRequired, got {other:?}"),
        };
        let id = d9f1_pending_id(&pending);
        let again = match v.continue_registration(&mut b, pending, Edition::Single) {
            Ok(RegistrationOutcome::HandoffRequired(pending)) => pending,
            other => panic!("expected HandoffRequired again, got {other:?}"),
        };
        assert_eq!(d9f1_pending_id(&again), id);
        assert!(
            matches!(&again, PendingRegistration::Roaming { custom_label: Some(l), .. } if l == "my-key")
        );
        assert!(d9f1_snapshot(&v) == before);
        let result = v.continue_registration(&mut b, again, Edition::Single);
        assert!(
            matches!(result, Ok(RegistrationOutcome::Registered(_))),
            "{result:?}"
        );
        assert_eq!(v.header.key_slots.len(), 1);
    }

    #[test]
    fn d9f1_roaming_continue_rejects_credential_already_in_vault() {
        let p = fresh_path("d9f1-roaming-dup");
        let mut v = Vault::create(&p, "Synthetic-Pw-12345").unwrap();
        let mut b = MockBackend::new().with_next_kind(KeyKind::TouchOnly);
        let existing = v.register_key_with_label(&mut b, None, "existing");
        assert!(existing.is_ok());
        let existing = existing.unwrap();
        let before = d9f1_snapshot(&v);
        let calls_before = b.calls().len();
        let forged = PendingRegistration::Roaming {
            credential: existing,
            pin: None,
            custom_label: Some("dup".into()),
            group: None,
        };
        let result = v.continue_registration(&mut b, forged, Edition::Single);
        assert!(
            matches!(result, Err(VaultError::Fido(FidoError::CredentialExcluded))),
            "{result:?}"
        );
        assert!(d9f1_snapshot(&v) == before);
        assert_eq!(
            b.calls().len(),
            calls_before,
            "no assertion for a duplicate"
        );
    }

    #[test]
    fn d9f1_roaming_compat_wrapper_reports_handoff_error_without_slot() {
        let p = fresh_path("d9f1-roaming-compat");
        let mut v = Vault::create(&p, "Synthetic-Pw-12345").unwrap();
        let before = d9f1_snapshot(&v);
        let mut b = d9f1_roaming_backend(1);
        let result = v.register_key_for(&mut b, None, "my-key", None);
        assert!(
            matches!(
                result,
                Err(VaultError::Fido(FidoError::ForegroundHandoffRequired))
            ),
            "{result:?}"
        );
        assert!(d9f1_snapshot(&v) == before);
    }

    fn d9f1_platform_backend(refusal: MockHandoffRefusal, times: usize) -> WhBackend {
        let mut b = WhBackend::new();
        b.inner.set_platform_handoff(refusal, times);
        b
    }

    #[test]
    fn d9f1_platform_handoff_keeps_credential_without_delete_or_slot() {
        for refusal in [
            MockHandoffRefusal::OwnerNotForeground,
            MockHandoffRefusal::ForegroundHandoffRequired,
        ] {
            let p = fresh_path("d9f1-platform-handoff");
            let mut v = Vault::create(&p, "Synthetic-Pw-12345").unwrap();
            let before = d9f1_snapshot(&v);
            let mut b = d9f1_platform_backend(refusal, 1);
            let pending = match v.begin_register_windows_hello(&mut b, "TEST-PC", Edition::Single) {
                Ok(RegistrationOutcome::HandoffRequired(pending)) => pending,
                other => panic!("expected HandoffRequired, got {other:?}"),
            };
            assert!(
                matches!(&pending, PendingRegistration::Platform { label, .. } if label == "Windows Hello（本機 TEST-PC）")
            );
            assert!(
                b.deleted.is_empty(),
                "handoff must not delete the new credential"
            );
            assert!(b
                .inner
                .platform_credential_ids()
                .contains(&d9f1_pending_id(&pending)));
            assert!(d9f1_snapshot(&v) == before);
            assert!(!format!("{pending:?}").contains("creation_prf"));
        }
    }

    #[test]
    fn d9f1_platform_continue_succeeds_with_fresh_membership_proof() {
        let p = fresh_path("d9f1-platform-continue");
        let mut v = Vault::create(&p, "Synthetic-Pw-12345").unwrap();
        let mut b = d9f1_platform_backend(MockHandoffRefusal::OwnerNotForeground, 1);
        let pending = match v.begin_register_windows_hello(&mut b, "TEST-PC", Edition::Single) {
            Ok(RegistrationOutcome::HandoffRequired(pending)) => pending,
            other => panic!("expected HandoffRequired, got {other:?}"),
        };
        let id = d9f1_pending_id(&pending);
        let lists_before = b
            .inner
            .calls()
            .iter()
            .filter(|c| **c == MockCall::ListPlatform)
            .count();
        let result = v.continue_registration(&mut b, pending, Edition::Single);
        assert!(
            matches!(result, Ok(RegistrationOutcome::Registered(ref r)) if r.credential_id == id),
            "{result:?}"
        );
        let lists_after = b
            .inner
            .calls()
            .iter()
            .filter(|c| **c == MockCall::ListPlatform)
            .count();
        assert!(
            lists_after > lists_before,
            "continue must re-prove RP membership"
        );
        assert!(b.deleted.is_empty());
        assert_eq!(v.header.key_slots.len(), 1);
        let slot = &v.header.key_slots[0];
        assert_eq!(slot.authenticator, Some(SlotAuthenticator::Platform));
        assert_eq!(slot.label, "Windows Hello（本機 TEST-PC）");
        assert!(v
            .data
            .audit
            .last()
            .unwrap()
            .method
            .starts_with("register_key:windows-hello:"));
        let reopened = Vault::open_windows_hello(&p, &mut b, Edition::Single);
        assert!(reopened.is_ok(), "{:?}", reopened.err());
    }

    #[test]
    fn d9f1_platform_continue_unproven_membership_does_not_delete() {
        let p = fresh_path("d9f1-platform-missing");
        let mut v = Vault::create(&p, "Synthetic-Pw-12345").unwrap();
        let mut b = d9f1_platform_backend(MockHandoffRefusal::OwnerNotForeground, 1);
        let pending = match v.begin_register_windows_hello(&mut b, "TEST-PC", Edition::Single) {
            Ok(RegistrationOutcome::HandoffRequired(pending)) => pending,
            other => panic!("expected HandoffRequired, got {other:?}"),
        };
        let id = d9f1_pending_id(&pending);
        // Simulate the user/Windows removing it meanwhile (bypasses the recording wrapper).
        assert!(b.inner.delete_platform_credential(&id).is_ok());
        let before = d9f1_snapshot(&v);
        let result = v.continue_registration(&mut b, pending, Edition::Single);
        assert!(
            matches!(
                result,
                Err(VaultError::Fido(FidoError::PlatformCredentialMissing))
            ),
            "{result:?}"
        );
        assert!(
            b.deleted.is_empty(),
            "unproven membership must never delete"
        );
        let asserts = b
            .inner
            .calls()
            .iter()
            .filter(|c| **c == MockCall::GetPlatformPrf)
            .count();
        assert_eq!(asserts, 1, "no assertion without membership proof");
        assert!(d9f1_snapshot(&v) == before);
    }

    #[test]
    fn d9f1_platform_continue_prf_mismatch_deletes_credential() {
        let p = fresh_path("d9f1-platform-mismatch");
        let mut v = Vault::create(&p, "Synthetic-Pw-12345").unwrap();
        let mut b = d9f1_platform_backend(MockHandoffRefusal::OwnerNotForeground, 1);
        let pending = match v.begin_register_windows_hello(&mut b, "TEST-PC", Edition::Single) {
            Ok(RegistrationOutcome::HandoffRequired(pending)) => pending,
            other => panic!("expected HandoffRequired, got {other:?}"),
        };
        let id = d9f1_pending_id(&pending);
        b.wrong_secret = true;
        let before = d9f1_snapshot(&v);
        let result = v.continue_registration(&mut b, pending, Edition::Single);
        assert!(
            matches!(
                result,
                Err(VaultError::Fido(FidoError::PlatformPrfUnsupported))
            ),
            "{result:?}"
        );
        assert_eq!(b.deleted, vec![id]);
        assert!(d9f1_snapshot(&v) == before);
    }

    #[test]
    fn d9f1_platform_continue_cleanup_failure_is_typed_and_not_silenced() {
        let p = fresh_path("d9f1-platform-cleanup-failure");
        let mut v = Vault::create(&p, "Synthetic-Pw-12345").unwrap();
        let mut b = d9f1_platform_backend(MockHandoffRefusal::OwnerNotForeground, 1);
        let pending = match v.begin_register_windows_hello(&mut b, "TEST-PC", Edition::Single) {
            Ok(RegistrationOutcome::HandoffRequired(pending)) => pending,
            other => panic!("expected HandoffRequired, got {other:?}"),
        };
        let id = d9f1_pending_id(&pending);
        b.wrong_secret = true;
        b.delete_error = true;
        let before = d9f1_snapshot(&v);
        let result = v.continue_registration(&mut b, pending, Edition::Single);
        assert!(
            matches!(
                result,
                Err(VaultError::Fido(FidoError::PlatformPrfUnsupported))
            ),
            "{result:?}"
        );
        assert_eq!(
            v.take_registration_cleanup_report(),
            Some(RegistrationCleanupReport::DeleteFailed),
            "failed deletion must be reported separately"
        );
        assert_eq!(
            v.take_registration_cleanup_report(),
            None,
            "report is one-shot"
        );
        assert_eq!(b.deleted, vec![id]);
        assert!(
            d9f1_snapshot(&v) == before,
            "failed cleanup must not write a slot"
        );
    }

    #[test]
    fn d9f1_r4_cleanup_report_is_one_shot_and_reset_by_each_ceremony() {
        // (1) Begin: post-create discovery failure → NotAttempted, never deleted.
        let p = fresh_path("d9f1-r4-report-reset");
        let mut v = Vault::create(&p, "Synthetic-Pw-12345").unwrap();
        let mut b = d9f1_platform_backend(MockHandoffRefusal::OwnerNotForeground, 1);
        let pending = match v.begin_register_windows_hello(&mut b, "TEST-PC", Edition::Single) {
            Ok(RegistrationOutcome::HandoffRequired(pending)) => pending,
            other => panic!("expected HandoffRequired, got {other:?}"),
        };
        assert_eq!(
            v.take_registration_cleanup_report(),
            None,
            "handoff is not a cleanup event"
        );
        let current = b.inner.platform_credential_ids().to_vec();
        b.scripted_lists.push_back(Ok(current));
        b.scripted_lists.push_back(Err(FidoError::Internal(
            "synthetic discovery failure".into(),
        )));
        let failed = v.begin_register_windows_hello(&mut b, "TEST-PC", Edition::Single);
        assert!(failed.is_err(), "{failed:?}");
        assert!(
            b.deleted.is_empty(),
            "unproven credential must not be deleted"
        );
        // (2) Not taken on purpose: the next ceremony must reset the stale report.
        let resumed = v.continue_registration(&mut b, pending, Edition::Single);
        assert!(
            matches!(resumed, Ok(RegistrationOutcome::Registered(_))),
            "{resumed:?}"
        );
        assert_eq!(
            v.take_registration_cleanup_report(),
            None,
            "a successful continue must not surface a stale report"
        );
        // (3) One-shot read (fresh vault: this machine already has a Hello slot in `v`,
        // so V5 would refuse before creating anything).
        let p = fresh_path("d9f1-r4-report-one-shot");
        let mut v = Vault::create(&p, "Synthetic-Pw-12345").unwrap();
        let mut b = WhBackend::new();
        b.scripted_lists.push_back(Ok(Vec::new()));
        b.scripted_lists.push_back(Err(FidoError::Internal(
            "synthetic discovery failure".into(),
        )));
        assert!(v
            .begin_register_windows_hello(&mut b, "TEST-PC", Edition::Single)
            .is_err());
        assert!(b.deleted.is_empty());
        assert_eq!(
            v.take_registration_cleanup_report(),
            Some(RegistrationCleanupReport::NotAttempted)
        );
        assert_eq!(
            v.take_registration_cleanup_report(),
            None,
            "report is one-shot"
        );
    }

    #[test]
    fn d9f1_r4_save_and_assertion_failures_report_delete_outcome_without_masking() {
        // Save failure + delete failure: primary Io error kept, DeleteFailed reported.
        let p = fresh_path("d9f1-r4-save-delete");
        let mut v = Vault::create(&p, "Synthetic-Pw-12345").unwrap();
        let mut b = WhBackend::new();
        b.delete_error = true;
        fs::create_dir(p.with_extension("db.tmp")).unwrap();
        let result = v.begin_register_windows_hello(&mut b, "TEST-PC", Edition::Single);
        assert!(matches!(result, Err(VaultError::Io(_))), "{result:?}");
        assert_eq!(
            v.take_registration_cleanup_report(),
            Some(RegistrationCleanupReport::DeleteFailed)
        );
        fs::remove_dir(p.with_extension("db.tmp")).unwrap();
        // Assertion failure + successful delete: primary error kept, Removed reported.
        let p = fresh_path("d9f1-r4-assert-delete");
        let mut v = Vault::create(&p, "Synthetic-Pw-12345").unwrap();
        let mut b = WhBackend::new();
        b.assertion_error = Some(FidoError::NoDevice);
        let result = v.begin_register_windows_hello(&mut b, "TEST-PC", Edition::Single);
        assert!(
            matches!(result, Err(VaultError::Fido(FidoError::NoDevice))),
            "{result:?}"
        );
        assert_eq!(
            v.take_registration_cleanup_report(),
            Some(RegistrationCleanupReport::Removed)
        );
        assert_eq!(b.deleted.len(), 1);
    }

    #[test]
    fn d9f1_r5_begin_resets_stale_report_and_continue_keeps_removed() {
        // continue: assertion failure + successful delete → Removed (never upgraded).
        let p = fresh_path("d9f1-r5-continue-removed");
        let mut v = Vault::create(&p, "Synthetic-Pw-12345").unwrap();
        let mut b = d9f1_platform_backend(MockHandoffRefusal::OwnerNotForeground, 1);
        let pending = match v.begin_register_windows_hello(&mut b, "TEST-PC", Edition::Single) {
            Ok(RegistrationOutcome::HandoffRequired(pending)) => pending,
            other => panic!("expected HandoffRequired, got {other:?}"),
        };
        b.assertion_error = Some(FidoError::NoDevice);
        let result = v.continue_registration(&mut b, pending, Edition::Single);
        assert!(
            matches!(result, Err(VaultError::Fido(FidoError::NoDevice))),
            "{result:?}"
        );
        assert_eq!(b.deleted.len(), 1);
        assert_eq!(
            v.take_registration_cleanup_report(),
            Some(RegistrationCleanupReport::Removed),
            "a successful delete must not be reported as NotAttempted"
        );
        // continue leaves DeleteFailed un-taken; the next begin must reset it.
        let mut b = d9f1_platform_backend(MockHandoffRefusal::OwnerNotForeground, 1);
        let pending = match v.begin_register_windows_hello(&mut b, "TEST-PC", Edition::Single) {
            Ok(RegistrationOutcome::HandoffRequired(pending)) => pending,
            other => panic!("expected HandoffRequired, got {other:?}"),
        };
        b.wrong_secret = true;
        b.delete_error = true;
        assert!(v
            .continue_registration(&mut b, pending, Edition::Single)
            .is_err());
        let mut fresh_backend = WhBackend::new();
        let registered =
            v.begin_register_windows_hello(&mut fresh_backend, "TEST-PC", Edition::Single);
        assert!(
            matches!(registered, Ok(RegistrationOutcome::Registered(_))),
            "{registered:?}"
        );
        assert_eq!(
            v.take_registration_cleanup_report(),
            None,
            "a successful begin must not surface a stale continue report"
        );
    }

    #[test]
    fn d9f1_platform_continue_handoff_again_keeps_credential() {
        let p = fresh_path("d9f1-platform-again");
        let mut v = Vault::create(&p, "Synthetic-Pw-12345").unwrap();
        let mut b = d9f1_platform_backend(MockHandoffRefusal::OwnerNotForeground, 2);
        let pending = match v.begin_register_windows_hello(&mut b, "TEST-PC", Edition::Single) {
            Ok(RegistrationOutcome::HandoffRequired(pending)) => pending,
            other => panic!("expected HandoffRequired, got {other:?}"),
        };
        let id = d9f1_pending_id(&pending);
        let again = v.continue_registration(&mut b, pending, Edition::Single);
        assert!(
            matches!(&again, Ok(RegistrationOutcome::HandoffRequired(p)) if d9f1_pending_id(p) == id),
            "{again:?}"
        );
        assert!(b.deleted.is_empty());
        assert!(v.header.key_slots.is_empty());
    }

    #[test]
    fn d9f1_platform_compat_wrapper_deletes_and_reports_handoff() {
        let p = fresh_path("d9f1-platform-compat");
        let mut v = Vault::create(&p, "Synthetic-Pw-12345").unwrap();
        let before = d9f1_snapshot(&v);
        let mut b = d9f1_platform_backend(MockHandoffRefusal::OwnerNotForeground, 1);
        let result = v.register_windows_hello(&mut b, "TEST-PC", Edition::Single);
        assert!(
            matches!(
                result,
                Err(VaultError::Fido(FidoError::ForegroundHandoffRequired))
            ),
            "{result:?}"
        );
        assert_eq!(b.deleted.len(), 1, "legacy wrapper keeps delete-on-failure");
        assert!(b.inner.platform_credential_ids().is_empty());
        assert!(d9f1_snapshot(&v) == before);
    }

    #[test]
    fn d9f1_cancel_platform_removes_or_requires_manual_removal() {
        for delete_error in [false, true] {
            let p = fresh_path("d9f1-cancel-platform");
            let mut v = Vault::create(&p, "Synthetic-Pw-12345").unwrap();
            let mut b = d9f1_platform_backend(MockHandoffRefusal::OwnerNotForeground, 1);
            let pending = match v.begin_register_windows_hello(&mut b, "TEST-PC", Edition::Single) {
                Ok(RegistrationOutcome::HandoffRequired(pending)) => pending,
                other => panic!("expected HandoffRequired, got {other:?}"),
            };
            let id = d9f1_pending_id(&pending);
            b.delete_error = delete_error;
            let before = d9f1_snapshot(&v);
            let outcome = cancel_registration(&mut b, pending);
            assert_eq!(
                outcome,
                if delete_error {
                    CancelOutcome::ManualRemovalRequired
                } else {
                    CancelOutcome::Removed
                }
            );
            assert_eq!(b.deleted, vec![id]);
            assert!(d9f1_snapshot(&v) == before);
        }
        // Not provably local any more → never blind-delete.
        let p = fresh_path("d9f1-cancel-platform-missing");
        let mut v = Vault::create(&p, "Synthetic-Pw-12345").unwrap();
        let mut b = d9f1_platform_backend(MockHandoffRefusal::OwnerNotForeground, 1);
        let pending = match v.begin_register_windows_hello(&mut b, "TEST-PC", Edition::Single) {
            Ok(RegistrationOutcome::HandoffRequired(pending)) => pending,
            other => panic!("expected HandoffRequired, got {other:?}"),
        };
        assert!(b
            .inner
            .delete_platform_credential(&d9f1_pending_id(&pending))
            .is_ok());
        assert_eq!(
            cancel_registration(&mut b, pending),
            CancelOutcome::ManualRemovalRequired
        );
        assert!(b.deleted.is_empty());
    }

    #[test]
    fn d9f1_cancel_roaming_discards_without_backend_calls() {
        let p = fresh_path("d9f1-cancel-roaming");
        let mut v = Vault::create(&p, "Synthetic-Pw-12345").unwrap();
        let mut b = d9f1_roaming_backend(1);
        let pending = match v.begin_register_key_for(&mut b, None, "my-key", None) {
            Ok(RegistrationOutcome::HandoffRequired(pending)) => pending,
            other => panic!("expected HandoffRequired, got {other:?}"),
        };
        let calls = b.calls().len();
        assert_eq!(
            cancel_registration(&mut b, pending),
            CancelOutcome::Discarded
        );
        assert_eq!(b.calls().len(), calls);
        assert!(v.header.key_slots.is_empty());
    }

    // ── D9-F1 R2 L3：roaming 註冊落盤失敗必須回滾 header 與 audit ──

    /// tmp 寫入失敗：在 tmp 路徑放目錄。rename 失敗（Windows）：以不允許刪除/改名的共享模式開著原檔。
    fn d9f1_save_obstacle(p: &Path, rename_failure: bool) -> Option<fs::File> {
        let tmp = p.with_extension("db.tmp");
        if !rename_failure {
            fs::create_dir(&tmp).unwrap();
            return None;
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt;
            Some(
                fs::OpenOptions::new()
                    .read(true)
                    .share_mode(1)
                    .open(p)
                    .unwrap(),
            )
        }
        #[cfg(not(windows))]
        {
            unreachable!("rename failure injection is Windows-only")
        }
    }

    fn d9f1_roaming_save_failure(dual: bool, rename_failure: bool, via_continue: bool) {
        let tag = format!(
            "d9f1-r2-roaming-save-{}-{}-{}",
            if dual { "dual" } else { "single" },
            if rename_failure { "rename" } else { "tmp" },
            if via_continue { "continue" } else { "direct" }
        );
        let p = fresh_path(&tag);
        let _ = fs::remove_dir_all(p.with_extension("db.tmp"));
        let mut v = if dual {
            Vault::create_dual(&p, "Synthetic-Pw-12345").unwrap()
        } else {
            Vault::create(&p, "Synthetic-Pw-12345").unwrap()
        };
        // 滿額 audit：新增一筆會裁掉最舊一筆，回滾必須連裁切一起還原。
        v.data.audit = (0..MAX_AUDIT)
            .map(|index| AuditEvent {
                ts: index.to_string(),
                event: "synthetic".into(),
                method: "test".into(),
                detail: index.to_string(),
            })
            .collect();
        v.write_file().unwrap();
        let group = dual.then_some(KeyGroup::A);
        let mut b = d9f1_roaming_backend(usize::from(via_continue));
        let pending = if via_continue {
            let outcome = v.begin_register_key_for(&mut b, None, "my-key", group);
            assert!(
                matches!(&outcome, Ok(RegistrationOutcome::HandoffRequired(_))),
                "{outcome:?}"
            );
            let Ok(RegistrationOutcome::HandoffRequired(pending)) = outcome else {
                unreachable!()
            };
            Some(pending)
        } else {
            None
        };
        let before = d9f1_snapshot(&v);
        let guard = d9f1_save_obstacle(&p, rename_failure);
        let edition = if dual { Edition::Dual } else { Edition::Single };
        let result = match pending {
            Some(pending) => v
                .continue_registration(&mut b, pending, edition)
                .map(|_| ()),
            None => v
                .register_key_for(&mut b, None, "my-key", group)
                .map(|_| ()),
        };
        drop(guard);
        let _ = fs::remove_dir_all(p.with_extension("db.tmp"));
        assert!(matches!(result, Err(VaultError::Io(_))), "{result:?}");
        assert!(
            serde_json::to_vec(&v.header).unwrap() == before.0,
            "failed persist must restore the header (no new slot)"
        );
        assert!(
            serde_json::to_vec(&v.data.audit).unwrap() == before.1,
            "failed persist must restore audit including the trimmed entry"
        );
        assert!(fs::read(&p).unwrap() == before.2, "disk bytes unchanged");
        // 之後另一個成功寫入不得把失敗的槽位帶入磁碟。
        assert!(v.record("synthetic_after", "test", "").is_ok());
        let on_disk = Vault::read_header(&p, edition).unwrap();
        assert_eq!(
            on_disk.key_slots.len(),
            0,
            "failed slot must never reach disk"
        );
        assert!(!v.data.audit.iter().any(|e| e.event == "key_registered"));
    }

    #[test]
    fn d9f1_r2_roaming_continue_single_tmp_write_failure_rolls_back() {
        d9f1_roaming_save_failure(false, false, true);
    }

    #[test]
    fn d9f1_r2_roaming_continue_dual_tmp_write_failure_rolls_back() {
        d9f1_roaming_save_failure(true, false, true);
    }

    #[cfg(windows)]
    #[test]
    fn d9f1_r2_roaming_continue_single_rename_failure_rolls_back() {
        d9f1_roaming_save_failure(false, true, true);
    }

    #[cfg(windows)]
    #[test]
    fn d9f1_r2_roaming_continue_dual_rename_failure_rolls_back() {
        d9f1_roaming_save_failure(true, true, true);
    }

    /// 原 register_key_internal 共用 complete_roaming_registration：回滾同樣適用。
    #[test]
    fn d9f1_r2_roaming_direct_register_tmp_write_failure_rolls_back() {
        d9f1_roaming_save_failure(false, false, false);
        d9f1_roaming_save_failure(true, false, false);
    }
}
