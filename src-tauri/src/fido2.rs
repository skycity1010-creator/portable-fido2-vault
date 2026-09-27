//! FIDO2 後端抽象：偵測金鑰類型、註冊 credential、取 PRF secret（hmac-secret）。
//!
//! - [`MockBackend`]（預設，feature `mock-fido`）：軟體金鑰。以純函數方式實作
//!   hmac-secret 語義（PRF secret = HMAC-SHA256(credential_id ‖ PRF_SALT)），
//!   無硬體環境下 Gate 3/4 仍可端到端驗證；跨行程/重啟結果一致。
//!   credential_id[0] 為保留位元組，編碼金鑰類型 → 登入時可還原「是否需要 PIN」。
//! - Real CTAP2 後端：待硬體裁決後接入（CTAP2 getInfo / authenticatorBioEnrollment
//!   0x09 / makeCredential / getAssertion+hmac-secret）。選型見 docs/spec.md §5.4。

use hmac::{Hmac, Mac};
use sha2::Sha256;

/// 金鑰類型（自動偵測結果，存入金庫、登入時依此給提示）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyKind {
    /// CTAP2 getBioEnrollment → fingerprint：提示「按指紋」
    Fingerprint,
    /// clientPin + pinProtocols：提示「輸入 PIN」
    Pin,
    /// 其他：提示「觸碰金鑰」
    TouchOnly,
}

impl KeyKind {
    pub const KINDS: [KeyKind; 3] = [KeyKind::Fingerprint, KeyKind::Pin, KeyKind::TouchOnly];

    pub fn from_u8(v: u8) -> Self {
        match v % 3 {
            0 => KeyKind::Fingerprint,
            1 => KeyKind::Pin,
            _ => KeyKind::TouchOnly,
        }
    }

    pub fn to_u8(self) -> u8 {
        match self {
            KeyKind::Fingerprint => 0,
            KeyKind::Pin => 1,
            KeyKind::TouchOnly => 2,
        }
    }

    pub fn label_zh(&self) -> &'static str {
        match self {
            KeyKind::Fingerprint => "指紋型",
            KeyKind::Pin => "PIN 型",
            KeyKind::TouchOnly => "觸碰型 (touch-only)",
        }
    }

    /// 登入時的硬體操作提示（繁中）。
    pub fn prompt_zh(&self) -> &'static str {
        match self {
            KeyKind::Fingerprint => "請插入金鑰並按指紋",
            KeyKind::Pin => "請插入金鑰並輸入 PIN",
            KeyKind::TouchOnly => "請插入金鑰並觸碰金屬面",
        }
    }

    /// 由字串解析（CLI/測試用）。
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "fingerprint" | "fp" => Some(KeyKind::Fingerprint),
            "pin" => Some(KeyKind::Pin),
            "touch_only" | "touch" | "touch-only" => Some(KeyKind::TouchOnly),
            _ => None,
        }
    }
}

/// 偵測結果（註冊前預覽用）。
#[derive(Debug, Clone, serde::Serialize)]
pub struct DetectedKey {
    pub kind: KeyKind,
    pub label: String,
    pub aaguid: [u8; 16],
}

/// 註冊完成後回傳（credentialId + 偵測結果；PRF secret 於登入時取）。
#[derive(Debug, Clone, serde::Serialize)]
pub struct RegisteredCredential {
    pub credential_id: Vec<u8>,
    pub aaguid: [u8; 16],
    pub label: String,
    pub kind: KeyKind,
}

#[derive(Debug)]
pub enum FidoError {
    NoDevice,
    PinRequired(String),
    PinRejected,
    NotSupported(String),
    Internal(String),
}

impl std::fmt::Display for FidoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoDevice => write!(f, "未偵測到 FIDO2 金鑰（請插入後重試）"),
            Self::PinRequired(hint) => write!(f, "此金鑰需要 PIN：{hint}"),
            Self::PinRejected => write!(f, "PIN 錯誤，請重試"),
            Self::NotSupported(m) => write!(f, "不支援：{m}"),
            Self::Internal(m) => write!(f, "FIDO2 內部錯誤：{m}"),
        }
    }
}

impl std::error::Error for FidoError {}

/// FIDO2 後端 trait。`get_prf_secret` 對應 CTAP2 getAssertion + hmac-secret extension
/// （固定 salt = crate::crypto::PRF_SALT），回傳 32-byte secret → HKDF → KEK。
pub trait FidoBackend: Send {
    /// 偵測目前金鑰類型（CTAP2 getInfo / getBioEnrollment）。
    fn detect(&mut self) -> Result<DetectedKey, FidoError>;

    /// 註冊新 credential（makeCredential，resident + hmac-secret extension）。
    fn register_credential(&mut self, detected: &DetectedKey) -> Result<RegisteredCredential, FidoError>;

    /// 取 PRF secret（getAssertion + hmac-secret）。PIN 型金鑰需先提供 PIN。
    fn get_prf_secret(&mut self, credential_id: &[u8], pin: Option<&str>) -> Result<[u8; 32], FidoError>;

    /// 預覽「下一支」偵測到的金鑰類型（**不消耗狀態**，供 UI 決定要不要收 PIN）。
    /// 實體後端回目前金鑰類型；mock 回循環中的下一個。
    fn peek_kind(&self) -> KeyKind {
        KeyKind::TouchOnly
    }
}

// ─────────────────────────── MockBackend ───────────────────────────

/// 模擬金鑰：無狀態、純函數。PRF secret 由 credential_id 決定 → 跨行程一致。
pub struct MockBackend {
    /// detect() 計數（模擬依序插入不同金鑰；類型循環 fingerprint→pin→touch-only）。
    detect_count: u32,
    /// CLI/測試可指定「下一支偵測到的金鑰類型」（覆蓋自動循環）。
    next_kind_override: Option<KeyKind>,
}

impl Default for MockBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl MockBackend {
    pub fn new() -> Self {
        Self {
            detect_count: 0,
            next_kind_override: None,
        }
    }

    /// 設定下一支偵測到的金鑰類型（CLI register-key --kind pin 用）。
    pub fn with_next_kind(mut self, kind: KeyKind) -> Self {
        self.next_kind_override = Some(kind);
        self
    }

    /// hmac-secret 語義：HMAC-SHA256(key=MOCK_TOKEN_MASTER, msg=credential_id ‖ PRF_SALT)。
    pub fn prf_for_credential(credential_id: &[u8]) -> [u8; 32] {
        let mut mac = Hmac::<Sha256>::new_from_slice(b"f2vlt-mock-token-master-key-v1")
            .expect("hmac key any len");
        mac.update(credential_id);
        mac.update(crate::crypto::PRF_SALT);
        let out = mac.finalize().into_bytes();
        let mut s = [0u8; 32];
        s.copy_from_slice(&out);
        s
    }

    /// credential_id[0] = kind 編碼（保留位元組，讓無狀態 mock 在登入時還原類型）。
    fn make_credential_id(kind: KeyKind) -> Vec<u8> {
        let mut id = [0u8; 32];
        use rand::RngCore;
        rand::rngs::OsRng.fill_bytes(&mut id);
        id[0] = kind.to_u8();
        id.to_vec()
    }

    /// 模擬 PIN 驗證：PIN 型金鑰要求非空且長度 ≥4（不儲存、不記錄 PIN）。
    fn check_pin(kind: KeyKind, pin: Option<&str>) -> Result<(), FidoError> {
        if kind != KeyKind::Pin {
            return Ok(()); // 指紋/touch-only 不需 PIN
        }
        match pin {
            Some(p) if p.len() >= 4 => Ok(()),
            Some(_) => Err(FidoError::PinRejected),
            None => Err(FidoError::PinRequired("請輸入金鑰 PIN".into())),
        }
    }
}

impl FidoBackend for MockBackend {
    fn detect(&mut self) -> Result<DetectedKey, FidoError> {
        let kind = self
            .next_kind_override
            .take()
            .unwrap_or_else(|| KeyKind::from_u8(self.detect_count % 3));
        self.detect_count += 1;
        let aaguid = mock_aaguid(self.detect_count);
        Ok(DetectedKey {
            kind,
            label: format!("Mock YubiKey #{}", self.detect_count),
            aaguid,
        })
    }

    fn register_credential(&mut self, detected: &DetectedKey) -> Result<RegisteredCredential, FidoError> {
        Ok(RegisteredCredential {
            credential_id: Self::make_credential_id(detected.kind),
            aaguid: detected.aaguid,
            label: detected.label.clone(),
            kind: detected.kind,
        })
    }

    fn get_prf_secret(&mut self, credential_id: &[u8], pin: Option<&str>) -> Result<[u8; 32], FidoError> {
        if credential_id.is_empty() {
            return Err(FidoError::Internal("credential_id 為空".into()));
        }
        let kind = KeyKind::from_u8(credential_id[0]);
        Self::check_pin(kind, pin)?;
        Ok(Self::prf_for_credential(credential_id))
    }

    fn peek_kind(&self) -> KeyKind {
        // 與 detect() 的取值邏輯一致（override 優先，否則循環）→ UI 預覽不偏。
        self.next_kind_override.unwrap_or_else(|| KeyKind::from_u8(self.detect_count % 3))
    }
}

/// 模擬 AAGUID：固定前綴 + 編號。
fn mock_aaguid(n: u32) -> [u8; 16] {
    let mut a = [0u8; 16];
    a[0..8].copy_from_slice(b"f2vlmock");
    a[12..16].copy_from_slice(&n.to_be_bytes());
    a
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mock_prf_deterministic() {
        let id = vec![0u8, 2, 3, 4];
        assert_eq!(MockBackend::prf_for_credential(&id), MockBackend::prf_for_credential(&id));
        assert_ne!(MockBackend::prf_for_credential(&id), MockBackend::prf_for_credential(&[0, 9]));
    }

    #[test]
    fn mock_detect_cycles_kinds() {
        let mut b = MockBackend::new();
        assert_eq!(b.detect().unwrap().kind, KeyKind::Fingerprint);
        assert_eq!(b.detect().unwrap().kind, KeyKind::Pin);
        assert_eq!(b.detect().unwrap().kind, KeyKind::TouchOnly);
        assert_eq!(b.detect().unwrap().kind, KeyKind::Fingerprint); // 循環
    }

    #[test]
    fn mock_kind_override() {
        let mut b = MockBackend::new().with_next_kind(KeyKind::Pin);
        assert_eq!(b.detect().unwrap().kind, KeyKind::Pin);
        // override 只生效一次 → 回自動循環
        assert_eq!(b.detect().unwrap().kind, KeyKind::Fingerprint);
    }

    #[test]
    fn mock_pin_flow_roundtrip() {
        let mut b = MockBackend::new();
        let d = b.detect().unwrap(); // fingerprint（不需 PIN）
        let reg = b.register_credential(&d).unwrap();
        assert!(b.get_prf_secret(&reg.credential_id, None).is_ok());

        // 第二支：pin 型 → 註冊後登入需 PIN，且跨「新行程」仍一致
        let mut b2 = MockBackend::new().with_next_kind(KeyKind::Pin);
        let d2 = b2.detect().unwrap();
        assert_eq!(d2.kind, KeyKind::Pin);
        let reg2 = b2.register_credential(&d2).unwrap();
        let mut fresh = MockBackend::new(); // 模擬重啟
        assert!(matches!(fresh.get_prf_secret(&reg2.credential_id, None), Err(FidoError::PinRequired(_))));
        assert!(matches!(fresh.get_prf_secret(&reg2.credential_id, Some("12")), Err(FidoError::PinRejected)));
        let s = fresh.get_prf_secret(&reg2.credential_id, Some("1234")).unwrap();
        assert_eq!(s, MockBackend::prf_for_credential(&reg2.credential_id));
    }

    #[test]
    fn kind_parse_and_prompts() {
        assert_eq!(KeyKind::parse("pin"), Some(KeyKind::Pin));
        assert_eq!(KeyKind::parse("TOUCH_ONLY"), Some(KeyKind::TouchOnly));
        assert!(KeyKind::Fingerprint.prompt_zh().contains("指紋"));
        assert!(KeyKind::Pin.prompt_zh().contains("PIN"));
        assert!(KeyKind::TouchOnly.prompt_zh().contains("觸碰"));
    }
}
