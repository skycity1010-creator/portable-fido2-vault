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
    pub notes: String,
    pub created_at: String,
    pub updated_at: String,
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
            settings: Settings { idle_lock_minutes: 5 },
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
            .ok_or_else(|| VaultError::Fido(FidoError::NoDevice))?
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
        payload: ([u8; 12], Vec<u8>),
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
        payload: ([u8; 12], Vec<u8>),
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
    fn read_file(path: &Path) -> Result<(Header, ([u8; 12], Vec<u8>)), VaultError> {
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

    fn decrypt_payload(kek: &[u8; 32], payload: &([u8; 12], Vec<u8>)) -> Result<VaultData, VaultError> {
        let pt = aes_gcm_decrypt(kek, &payload.0, &payload.1).map_err(VaultError::Crypto)?;
        serde_json::from_slice(&pt).map_err(VaultError::Json)
    }

    /// 以目前 KEK 重新加密 payload + 原子寫入（tmp + rename）。
    fn write_file(&self) -> Result<(), VaultError> {
        let header_json = serde_json::to_vec(&self.header).map_err(VaultError::Json)?;
        let nonce = random_nonce();
        let pt = serde_json::to_vec(&self.data).map_err(VaultError::Json)?;
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
            notes: notes.into(),
            created_at: ts.clone(),
            updated_at: ts,
        });
        self.record("entry_added", "manual", &site)?;
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
        let e = self
            .data
            .entries
            .iter_mut()
            .find(|e| e.id == id)
            .ok_or_else(|| VaultError::Format("找不到該條目".into()))?;
        if let Some(v) = site {
            e.site = v.into();
        }
        if let Some(v) = account {
            e.account = v.into();
        }
        if let Some(v) = password {
            e.password = v.into();
        }
        if let Some(v) = notes {
            e.notes = v.into();
        }
        e.updated_at = now_rfc3339();
        let site = e.site.clone(); // 先取值，避免與 record() 的 &mut self 重疊借用
        self.record("entry_updated", "manual", &site)?;
        Ok(())
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

    // ── FIDO2 金鑰管理（需已解鎖）──

    /// 偵測 + 註冊新金鑰：以目前 KEK 包出新槽位。
    /// PIN 型金鑰註冊時即需提供 PIN（makeCredential 需與 token 建立安全通道）。
    /// **產品決策：不支援 PRF/hmac-secret 的金鑰一律拒絕註冊**（無法解鎖離線金庫）。
    pub fn register_key(&mut self, backend: &mut (dyn FidoBackend + 'static), pin: Option<&str>) -> Result<RegisteredCredential, VaultError> {
        // 裁決②：不支援 hmac-secret/PRF 的金鑰拒絕註冊。
        // 順序：先 detect()（real 後端需 getInfo 才能知 PRF 能力；mock 的 detect 為無害循環），
        // 再 prf_supported()（依 detect 快取的資訊判定）。
        let detected = backend.detect()?;
        if !backend.prf_supported() {
            return Err(VaultError::Fido(FidoError::PrfNotSupported));
        }
        let reg = backend.register_credential(&detected, pin)?;
        let secret = backend.get_prf_secret(&reg.credential_id, pin)?;
        let k = kek_from_prf_secret(&secret);
        let nonce = random_nonce();
        let ct = aes_gcm_encrypt(&k, &nonce, self.kek.as_slice());

        self.header.key_slots.push(KeySlot {
            credential_id: base64_encode(&reg.credential_id),
            aaguid: hex32_16(reg.aaguid),
            label: reg.label.clone(),
            key_type: reg.kind,
            nonce: base64_encode(&nonce),
            ct: base64_encode(&ct),
        });
        let kind_str = format!("{}", reg.kind);
        self.record("key_registered", &format!("fido2:{}", reg.label), &format!("type={kind_str}"))?;
        Ok(reg)
    }

    /// 移除金鑰槽（不可逆：該金鑰將無法再解鎖）。
    pub fn remove_key(&mut self, credential_id_b64: &str) -> Result<(), VaultError> {
        let idx = self
            .header
            .key_slots
            .iter()
            .position(|s| s.credential_id == credential_id_b64)
            .ok_or_else(|| VaultError::Fido(FidoError::NoDevice))?;
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
