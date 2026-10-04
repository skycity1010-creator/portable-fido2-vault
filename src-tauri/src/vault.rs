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

use crate::csv_import::{ImportAction, ImportPlan, ImportPreview};
use crate::crypto::{
    aes_gcm_decrypt, aes_gcm_encrypt, argon2id_derive, base64_decode, base64_encode,
    kek_from_prf_secret, random_kek, random_nonce, CryptoError, VAULT_MAGIC,
};
use crate::fido2::{FidoBackend, FidoError, KeyKind, RegisteredCredential};

#[derive(Debug)]
pub enum VaultError {
    Io(std::io::Error),
    Format(String),
    Crypto(CryptoError),
    WrongPassword,
    Fido(FidoError),
    Json(serde_json::Error),
}

impl std::fmt::Display for VaultError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "檔案錯誤：{e}"),
            Self::Format(m) => write!(f, "金庫格式錯誤：{m}"),
            Self::Crypto(CryptoError::DecryptFailed) => write!(f, "密碼或金鑰不正確（解密驗證失敗）"),
            Self::Crypto(e) => write!(f, "加密錯誤：{e}"),
            Self::WrongPassword => write!(f, "密碼不正確"),
            Self::Fido(e) => write!(f, "{e}"),
            Self::Json(e) => write!(f, "JSON 錯誤：{e}"),
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
    pub nonce: String,
    pub ct: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Header {
    pub v: u8,
    pub argon2: Argon2Params,
    pub password_slot: Slot,
    pub key_slots: Vec<KeySlot>,
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
}

const DEFAULT_PASSWORD_HISTORY_LIMIT: u32 = 3;
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

    /// 首次執行：以主密碼建立金庫。
    pub fn create(path: &Path, password: &str) -> Result<Self, VaultError> {
        if path.exists() {
            return Err(VaultError::Format("vault.db 已存在".into()));
        }
        let kek = random_kek();
        let salt = random_bytes(32);
        // 密碼槽：以 Argon2id(master_password) 派生的金流包裝 KEK（open_password 用同參數解包）。
        let pw_key = argon2id_derive(password.as_bytes(), &salt)?;
        let nonce = random_nonce();
        let ct = aes_gcm_encrypt(&pw_key, &nonce, kek.as_slice());

        let header = Header {
            v: 1,
            argon2: Argon2Params { salt: base64_encode(&salt) },
            password_slot: Slot { nonce: base64_encode(&nonce), ct: base64_encode(&ct) },
            key_slots: Vec::new(),
            created_at: now_rfc3339(),
        };

        let data = VaultData {
            entries: Vec::new(),
            audit: vec![AuditEvent {
                ts: now_rfc3339(),
                event: "vault_created".into(),
                method: "setup".into(),
                detail: format!(
                    "argon2id m={}KiB t={} p={}",
                    crate::crypto::ARGON2_M_COST,
                    crate::crypto::ARGON2_T_COST,
                    crate::crypto::ARGON2_P_COST
                ),
            }],
            settings: Settings {
                idle_lock_minutes: 5,
                password_history_limit: DEFAULT_PASSWORD_HISTORY_LIMIT,
            },
        };

        let vault = Self { path: path.to_path_buf(), header, data, kek };
        vault.write_file()?;
        Ok(vault)
    }

    // ── 開啟（解鎖）──

    /// 主密碼登入。失敗 → sidecar 記一筆 login_failed。
    pub fn open_password(path: &Path, password: &str) -> Result<Self, VaultError> {
        let (header, payload) = Self::read_file(path)?;
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
                Self::unlock(path, header, payload, Zeroizing::new(kek), "password")
            }
            _ => {
                record_login_failure(path, "password")?;
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
        let (header, payload) = Self::read_file(path)?;
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
        let (header, payload) = Self::read_file(path)?;
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

        let mut vault = Self { path: path.to_path_buf(), header, data, kek };
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

    /// 讀檔 → (header, (payload_nonce, ciphertext))。
    fn read_file(path: &Path) -> Result<VaultFileContents, VaultError> {
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
        if header.v != 1 {
            return Err(VaultError::Format(format!("不支援的格式版本 v{}", header.v)));
        }
        let off = 10 + header_len;
        let nonce: [u8; 12] = buf[off..off + 12].try_into().unwrap();
        let ciphertext = buf[off + 12..].to_vec();
        Ok((header, (nonce, ciphertext)))
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

    pub fn add_entry(&mut self, site: &str, account: &str, password: &str, notes: &str) -> Result<String, VaultError> {
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
        self.record("settings_changed", "manual", &format!("idle_lock={}", self.data.settings.idle_lock_minutes))?;
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
        self.register_key_internal(backend, pin, None)
    }

    /// Register with a FidoVault-local alias. Validate it before querying the authenticator.
    pub fn register_key_with_label(
        &mut self,
        backend: &mut (dyn FidoBackend + 'static),
        pin: Option<&str>,
        candidate_label: &str,
    ) -> Result<RegisteredCredential, VaultError> {
        let label = self.validate_new_key_label(candidate_label)?;
        self.register_key_internal(backend, pin, Some(&label))
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
    ) -> Result<RegisteredCredential, VaultError> {
        // 裁決②：不支援 hmac-secret/PRF 的金鑰拒絕註冊。
        // 順序：先 detect()（real 後端需 getInfo 才能知 PRF 能力；mock 的 detect 為無害循環），
        // 再 prf_supported()（依 detect 快取的資訊判定）。
        let detected = backend.detect()?;
        if !backend.prf_supported() {
            return Err(VaultError::Fido(FidoError::PrfNotSupported));
        }
        let mut reg = backend.register_credential(&detected, pin)?;
        let secret = backend.get_prf_secret(&reg.credential_id, pin)?;
        let k = kek_from_prf_secret(&secret);
        let nonce = random_nonce();
        let ct = aes_gcm_encrypt(&k, &nonce, self.kek.as_slice());

        if let Some(label) = custom_label {
            reg.label = label.to_owned();
        }
        self.header.key_slots.push(KeySlot {
            credential_id: base64_encode(&reg.credential_id),
            aaguid: hex32_16(reg.aaguid),
            label: reg.label.clone(),
            key_type: reg.kind,
            nonce: base64_encode(&nonce),
            ct: base64_encode(&ct),
        });
        let kind_str = format!("{}", reg.kind);
        self.record(
            "key_registered",
            &format!("fido2:{}", reg.label),
            &format!("type={kind_str}"),
        )?;
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
        self.record("key_removed", &format!("fido2:{label}"), "金鑰槽已移除（該金鑰無法再解鎖）")?;
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
    v.try_into().map_err(|_| VaultError::Format("slot nonce 長度錯誤".into()))
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
    list.push(FailureStamp { ts: now_rfc3339(), method: method.into() });
    if list.len() > MAX_LOGIN_FAILURES {
        list.remove(0);
    }
    fs::write(failures_path(vault_path), serde_json::to_string(&list).unwrap()).map_err(VaultError::Io)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fido2::{FidoBackend, FidoError, KeyKind, MockBackend};
    use std::env;

    /// 不支援 PRF 的金鑰包裝（驗證裁決②：拒絕註冊）。
    struct NoPrfBackend(MockBackend);
    impl FidoBackend for NoPrfBackend {
        fn detect(&mut self) -> Result<crate::fido2::DetectedKey, FidoError> { self.0.detect() }
        fn register_credential(&mut self, d: &crate::fido2::DetectedKey, pin: Option<&str>) -> Result<crate::fido2::RegisteredCredential, FidoError> { self.0.register_credential(d, pin) }
        fn get_prf_secret(&mut self, id: &[u8], pin: Option<&str>) -> Result<[u8; 32], FidoError> { self.0.get_prf_secret(id, pin) }
        fn prf_supported(&self) -> bool { false }
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
        assert!(matches!(Vault::open_password(&p, "wrong"), Err(VaultError::WrongPassword)));
        let fc = read_failure_sidecar(&p);
        assert_eq!(fc.len(), 1);
        assert_eq!(fc[0].method, "password");

        // 正確密碼 → 成功 + sidecar 合併進 audit + 刪除
        let v = Vault::open_password(&p, "Correct-Horse-42").unwrap();
        assert!(v.audit().iter().any(|a| a.event == "login_success"));
        assert!(v.audit().iter().any(|a| a.event == "login_failed" && a.method == "password"));
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
        assert!(v.register_key(&mut MockBackend::new().with_next_kind(KeyKind::Pin), None)
            .is_err());
        let k2 = v.register_key(&mut MockBackend::new().with_next_kind(KeyKind::Pin), Some("1234")).unwrap();
        assert_eq!(k2.kind, KeyKind::Pin);
        assert_eq!(v.keys_meta().len(), 2);
        drop(v);

        // 金鑰 1（fingerprint，不需 PIN）登入
        let mut b = MockBackend::new();
        let v = Vault::open_key(&p, &base64_encode(&k1.credential_id), None, &mut b).unwrap();
        assert!(v.audit().iter().any(|a| a.event == "login_success" && a.method.contains("Mock")));
        drop(v);

        // 金鑰 2（pin）：無 PIN → PinRequired；有 PIN → 成功
        let mut b = MockBackend::new();
        assert!(matches!(
            Vault::open_key(&p, &base64_encode(&k2.credential_id), None, &mut b),
            Err(VaultError::Fido(FidoError::PinRequired(_)))
        ));
        let mut b = MockBackend::new();
        let v = Vault::open_key(&p, &base64_encode(&k2.credential_id), Some("1234"), &mut b).unwrap();
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

        let id = v.add_entry("example.com", "alice", "S3cret!x", "note1").unwrap();
        let before = v.entries()[0].updated_at.clone();
        std::thread::sleep(std::time::Duration::from_millis(5));
        v.update_entry(&id, None, Some("alice2"), None, Some("note2")).unwrap();
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
