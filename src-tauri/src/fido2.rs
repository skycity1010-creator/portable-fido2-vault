//! FIDO2 後端抽象：偵測金鑰類型、註冊 credential、取 PRF secret（hmac-secret）。
//!
//! - [`MockBackend`]（預設，feature `mock-fido`）：軟體金鑰。以純函數方式實作
//!   hmac-secret 語義（PRF secret = HMAC-SHA256(credential_id ‖ PRF_SALT)），
//!   無硬體環境下 Gate 3/4 仍可端到端驗證；跨行程/重啟結果一致。
//!   credential_id[0] 為保留位元組，編碼金鑰類型 → 登入時可還原「是否需要 PIN」。
//! - RealBackend（CLI/診斷）：authenticator-rs raw CTAP2 over HID。
//! - Windows GUI hardware backend: Windows WebAuthn API broker owns device selection and PIN/UV/touch UI.
//!   Both paths use the same RP ID and raw hmac-secret salt so existing vault slots remain usable.

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
    /// Windows WebAuthn API 管理互動提示（PIN/UV/觸碰由 Windows 安全性 UI 處理）。
    WindowsManaged,
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
            KeyKind::WindowsManaged => 2,
        }
    }

    pub fn label_zh(&self) -> &'static str {
        match self {
            KeyKind::Fingerprint => "指紋型",
            KeyKind::Pin => "PIN 型",
            KeyKind::TouchOnly => "觸碰型 (touch-only)",
            KeyKind::WindowsManaged => "Windows 安全金鑰",
        }
    }

    /// 登入時的硬體操作提示（繁中）。
    pub fn prompt_zh(&self) -> &'static str {
        match self {
            KeyKind::Fingerprint => "請插入金鑰並按指紋",
            KeyKind::Pin => "請插入金鑰並輸入 PIN",
            KeyKind::TouchOnly => "請插入金鑰並觸碰金屬面",
            KeyKind::WindowsManaged => "請依 Windows 安全性提示完成驗證",
        }
    }

    /// 由字串解析（CLI/測試用）。
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "fingerprint" | "fp" => Some(KeyKind::Fingerprint),
            "pin" => Some(KeyKind::Pin),
            "touch_only" | "touch" | "touch-only" => Some(KeyKind::TouchOnly),
            "windows_managed" | "windows" => Some(KeyKind::WindowsManaged),
            _ => None,
        }
    }
}

impl std::fmt::Display for KeyKind {
    /// 與 serde snake_case 命名一致（軌跡/CLI 顯示用）。
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            KeyKind::Fingerprint => "fingerprint",
            KeyKind::Pin => "pin",
            KeyKind::TouchOnly => "touch_only",
            KeyKind::WindowsManaged => "windows_managed",
        };
        f.write_str(s)
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
    /// 金鑰不支援 hmac-secret/PRF → 依產品決策拒絕寫入 vault slot。
    PrfNotSupported,
    /// Windows WebAuthn 未回報 hmac-secret 建立成功；系統端可能已留下一個無 vault slot 的 credential。
    PrfNotConfirmed,
    /// makeCredential 的 excludeCredentials 命中：此實體金鑰已持有本金庫的 credential（dual-control Q3）。
    CredentialExcluded,
    /// Windows Hello：本機已持有金庫的 platform credential（excludeCredentials 命中，NTE_EXISTS）。
    PlatformCredentialExists,
    /// Windows Hello：斷言時無法取得 PRF（例：TPM 1.2／software KSP 的 NTE_BAD_KEY_STATE）。
    PlatformPrfUnsupported,
    /// Windows Hello：本機沒有允許清單中的任何 credential（另一台電腦、已刪除或重設）。
    PlatformCredentialMissing,
    NotSupported(String),
    Internal(String),
    /// FIDO HID open 被 Win32 拒絕（os error 5/32）：只證明此次 open 失敗，不代表已識別 holder；
    /// 錯誤碼本身不能識別 holder 或區分 share lock/access policy；此變體在重試耗盡後取代 vendor 模糊
    /// timeout fallback（U2FToken(NotAllowed) / CancelledByUser），避免把底層 open denied 誤報為金鑰拒絕。
    DeviceOpenDenied {
        what: String,
        last_err: String,
        attempts: usize,
    },
    /// 註冊第二階段：第一個 ceremony 已建立 credential，但 Windows 未把前景交回 FidoVault，
    /// 驗證斷言依既有守門被拒（未呼叫 API）。呼叫方可保留 pending 註冊，待使用者點擊後重試。
    ForegroundHandoffRequired,
    /// pre-API 守門：owner 視窗不是前景，未呼叫 Windows WebAuthn（訊息與舊 Internal 文字相同）。
    OwnerNotForeground,
    /// D9-F2：要求 PLATFORM 的 attestation 並非由本機（INTERNAL transport）完成，例如 Windows 在 Ngc
    /// 失敗後讓使用者以安全性金鑰完成。不寫 slot、也不對該 ID 做 platform 刪除。
    PlatformAuthenticatorSubstituted,
}

/// pre-API owner 前景守門拒絕時的原文（`OwnerNotForeground` 的 Display 與舊 Internal 顯示逐字相同）。
pub const OWNER_NOT_FOREGROUND_MSG: &str =
    "Windows WebAuthn was not started because its owner window is not foreground. Bring FidoVault to the foreground and retry.";

impl FidoError {
    /// 第二個 ceremony 因前景未交回而被拒（未呼叫 API）；註冊流程可保留 pending 讓使用者重試。
    pub fn is_foreground_handoff(&self) -> bool {
        matches!(
            self,
            Self::ForegroundHandoffRequired | Self::OwnerNotForeground
        )
    }
}

impl std::fmt::Display for FidoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoDevice => write!(f, "未偵測到 FIDO2 金鑰（請插入後重試）"),
            Self::PinRequired(hint) => write!(f, "此金鑰需要 PIN：{hint}"),
            Self::PinRejected => write!(f, "PIN 錯誤，請重試"),
            Self::PrfNotSupported => write!(
                f,
                "此金鑰不支援 hmac-secret/PRF extension，無法用來解鎖離線金庫（未建立 vault slot）。請改用支援 PRF 的金鑰（例：YubiKey 5+）"
            ),
            Self::PrfNotConfirmed => write!(
                f,
                "Windows WebAuthn 未確認此金鑰支援 hmac-secret/PRF；vault 未新增金鑰槽，但金鑰端可能已建立一筆未被金庫使用的 credential。"
            ),
            Self::CredentialExcluded => write!(
                f,
                "此安全性金鑰已註冊於本金庫（同一支實體金鑰只能註冊一次，且只能屬於 A 或 B 其中一個群組）；未新增金鑰槽。"
            ),
            Self::PlatformCredentialExists => write!(
                f,
                "這台電腦（此 Windows 帳號）已註冊 Windows Hello 到本金庫；每台電腦只能註冊一個，未新增金鑰槽。"
            ),
            Self::PlatformPrfUnsupported => write!(
                f,
                "此電腦的 Windows Hello 不支援金庫解鎖所需的 PRF（斷言時無法取得 hmac-secret）；未新增金鑰槽。請改用 YubiKey 或主密碼。"
            ),
            Self::PlatformCredentialMissing => write!(
                f,
                "這台電腦沒有此金庫的 Windows Hello 憑證（可能在其他電腦註冊，或已被刪除／重設）；請改用 YubiKey 或主密碼。"
            ),
            Self::NotSupported(m) => write!(f, "不支援：{m}"),
            Self::Internal(m) => write!(f, "FIDO2 內部錯誤：{m}"),
            Self::DeviceOpenDenied { what, last_err, attempts } => write!(
                f,
                "YubiKey FIDO HID open 被 Windows 拒絕（os error 5/32）；重試 {attempts} 次皆失敗（{what}）。 \
                 此錯誤無法確認 holder 身分或區分 share-lock/access policy；可能是其他 FIDO client、Windows WebAuthN / Windows Hello 正在使用介面，或 Windows access policy 拒絕。最後 vendor 回報：{last_err}。\
                 請先完成/取消安全金鑰操作並關閉瀏覽器 WebAuthn/Windows Hello 頁面；勿 force-kill svchost / BioEnrollmentHost。 \
                 本 CLI 目前走 raw HID；非管理員情境需採用 Windows WebAuthN API backend（Yubico sample 的路徑），或在管理員互動 session 執行。"
            ),
            Self::ForegroundHandoffRequired => write!(
                f,
                "金鑰已建立，但 Windows 未將焦點交回 FidoVault；請按「繼續驗證」完成註冊，或按「取消」放棄。"
            ),
            // 與舊 `Internal(OWNER_NOT_FOREGROUND_MSG)` 顯示相同，登入路徑文字不變。
            Self::OwnerNotForeground => write!(f, "FIDO2 內部錯誤：{OWNER_NOT_FOREGROUND_MSG}"),
            Self::PlatformAuthenticatorSubstituted => write!(
                f,
                "Windows 以安全性金鑰完成，而非本機 Windows Hello；未註冊。該安全性金鑰上可能留下一筆 fido-vault.local 測試憑證，可用 YubiKey 管理工具移除。"
            ),
        }
    }
}

impl std::error::Error for FidoError {}

/// 硬體後端建構失敗分類：只有 WebAuthn API 能力不足（< v4 HMAC-secret）可改用
/// [`UnavailableBackend`]；其餘錯誤一律維持啟動失敗（fail closed）。
#[derive(Debug)]
pub enum BackendInitError {
    WebAuthnApiBelowV4 { api_version: u32 },
    Fido(FidoError),
}

impl From<FidoError> for BackendInitError {
    fn from(error: FidoError) -> Self {
        Self::Fido(error)
    }
}

impl std::fmt::Display for BackendInitError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::WebAuthnApiBelowV4 { api_version } => write!(
                f,
                "Windows WebAuthn API v{api_version} lacks HMAC-secret assertion support (requires v4+)"
            ),
            Self::Fido(error) => error.fmt(f),
        }
    }
}

/// Windows Hello（平台 authenticator）可用性，不跳任何提示（docs/plans/windows-hello-single.md §4.1）。
/// 三項皆真才可註冊／登入；預設全為 false（fail closed）。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize)]
pub struct PlatformStatus {
    /// `WebAuthNGetApiVersionNumber() >= 8`（PRF 需 API v8）。
    pub api_ok: bool,
    /// `WebAuthNIsUserVerifyingPlatformAuthenticatorAvailable`。
    pub uvpa: bool,
    /// 本機 Console 工作階段（RDP／session 0 不提供 Windows Hello）。
    pub console: bool,
}

impl PlatformStatus {
    pub fn available(&self) -> bool {
        self.api_ok && self.uvpa && self.console
    }
}

/// Windows Hello credential 建立結果：credential + 建立時的 PRF 輸出（API v8 `pHmacSecret`，32 bytes）。
/// 建立時有 PRF 不代表斷言時有 PRF（Win11-NB），所以 vault 必須再做一次斷言並比對此值。
pub struct PlatformRegistration {
    pub credential: RegisteredCredential,
    pub creation_prf: zeroize::Zeroizing<[u8; 32]>,
}

impl std::fmt::Debug for PlatformRegistration {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PlatformRegistration")
            .field("credential", &self.credential)
            .field("creation_prf", &"<redacted>")
            .finish()
    }
}

/// 後端未實作 Windows Hello 時的共用訊息（不影響 YubiKey／主密碼）。
pub const PLATFORM_UNSUPPORTED_MSG: &str =
    "此金鑰後端不支援 Windows Hello；YubiKey 與主密碼登入不受影響";

fn platform_unsupported() -> FidoError {
    FidoError::NotSupported(PLATFORM_UNSUPPORTED_MSG.into())
}

/// FIDO2 後端 trait。`get_prf_secret` 對應 CTAP2 getAssertion + hmac-secret extension
/// （固定 salt = crate::crypto::PRF_SALT），回傳 32-byte secret → HKDF → KEK。
pub trait FidoBackend: Send {
    /// 偵測/分類金鑰；raw CTAP 後端用 getInfo/bioEnroll，Windows WebAuthn 由系統 broker 延後選擇裝置。
    fn detect(&mut self) -> Result<DetectedKey, FidoError>;

    /// 註冊新 credential（makeCredential + hmac-secret）。Windows backend 的 PIN/UV/觸碰由系統 UI 處理。
    fn register_credential(
        &mut self,
        detected: &DetectedKey,
        pin: Option<&str>,
    ) -> Result<RegisteredCredential, FidoError>;

    /// 取 PRF secret（getAssertion + hmac-secret）；Windows backend 忽略 app PIN，交由系統 UI 處理。
    fn get_prf_secret(
        &mut self,
        credential_id: &[u8],
        pin: Option<&str>,
    ) -> Result<[u8; 32], FidoError>;

    /// 註冊新 credential，並要求 authenticator 排除 `exclude` 中的 credential（excludeCredentials）。
    /// 同一支實體金鑰已持有其中任一筆 → `FidoError::CredentialExcluded`，不建立新 credential。
    /// 預設實作：清單為空時等同 `register_credential`；清單非空而後端未實作排除時 fail closed。
    fn register_credential_excluding(
        &mut self,
        detected: &DetectedKey,
        pin: Option<&str>,
        exclude: &[Vec<u8>],
    ) -> Result<RegisteredCredential, FidoError> {
        if exclude.is_empty() {
            return self.register_credential(detected, pin);
        }
        Err(FidoError::NotSupported(
            "此金鑰後端無法排除已註冊的金鑰；為避免同一支金鑰重複註冊，已拒絕註冊".into(),
        ))
    }

    /// Selects one credential from the registered candidates and returns its ID with its PRF secret.
    /// Interactive broker backends should submit all candidates in one operation and report the
    /// authenticator-selected credential. The default keeps deterministic mock/single-key behavior.
    fn get_prf_secret_for_any(
        &mut self,
        credential_ids: &[Vec<u8>],
        pin: Option<&str>,
    ) -> Result<(Vec<u8>, [u8; 32]), FidoError> {
        let credential_id = credential_ids.first().ok_or(FidoError::NoDevice)?;
        let secret = self.get_prf_secret(credential_id, pin)?;
        Ok((credential_id.clone(), secret))
    }

    /// Update the native owner HWND before a Windows broker interaction; other backends ignore it.
    fn set_webauthn_parent_hwnd(&mut self, _handle: isize) {}

    /// Whether this backend delegates credential selection and PIN/UV prompts to a native broker.
    fn uses_brokered_key_selection(&self) -> bool {
        false
    }

    /// 預覽「下一支」偵測到的金鑰類型（**不消耗狀態**，供 UI 決定要不要收 PIN）。
    /// 實體後端回目前金鑰類型；mock 回循環中的下一個。
    fn peek_kind(&self) -> KeyKind {
        KeyKind::TouchOnly
    }

    /// 目前 backend 是否能執行 hmac-secret/PRF：raw CTAP 依 getInfo，Windows WebAuthn 依 OS API 版本。
    /// Windows WebAuthn 對實際 authenticator 的能力仍須由註冊結果確認。
    fn prf_supported(&self) -> bool {
        false
    }

    /// 診斷：已註冊指紋 template 數（getBioEnrollment GetEnrollments）。
    /// **Ok(0) = 金鑰未 enroll 指紋 → UV=true 的 makeCredential 无法满足（notAllowed）**。
    /// None = mock / probe 不可用；Some(Err) = probe 失敗原因。
    fn enrollment_count(&mut self) -> Option<Result<usize, String>> {
        None
    }

    /// 診斷：完整 CTAP2 getInfo 關鍵欄位 dump（clientPin/uv/bioEnroll/pin_protocols/fw）。
    /// mock 回 "mock"；hw 偵測後回實際值。供遠端排程不須使用者互動。
    fn info_diag(&self) -> String {
        "mock".to_string()
    }

    /// Some(訊息) = 此工作階段無任何可用金鑰路徑（UI 不得假裝偵測到金鑰）。
    fn key_unavailable_reason(&self) -> Option<String> {
        None
    }

    // ── Windows Hello（平台 authenticator）；預設全部 fail closed ──

    /// 不跳提示的可用性檢查。預設：全部不可用。
    fn platform_status(&self) -> PlatformStatus {
        PlatformStatus::default()
    }

    /// 建立 Windows Hello credential（PLATFORM、UV required、resident key、PRF v8）。
    /// `exclude` = 金庫內所有 platform slot 的 credential ID；本機已持有其一 →
    /// `FidoError::PlatformCredentialExists`，不建立新 credential。
    fn register_platform_credential(
        &mut self,
        _label: &str,
        _exclude: &[Vec<u8>],
    ) -> Result<PlatformRegistration, FidoError> {
        Err(platform_unsupported())
    }

    /// Windows Hello 斷言 + 固定 raw salt 的 PRF；回傳實際使用的 credential ID 與 32-byte secret。
    /// 呼叫方必須自行確認回傳 ID 屬於金庫的 platform slot（不信任 backend 選擇）。
    fn get_platform_prf_secret(
        &mut self,
        _credential_ids: &[Vec<u8>],
    ) -> Result<(Vec<u8>, [u8; 32]), FidoError> {
        Err(platform_unsupported())
    }

    /// 本機（此 Windows 帳號）在本 RP 下的 Windows Hello credential ID；空清單 = Ok(vec![])。
    fn list_platform_credentials(&mut self) -> Result<Vec<Vec<u8>>, FidoError> {
        Err(platform_unsupported())
    }

    /// 刪除本機的 Windows Hello credential（best effort，由呼叫方決定失敗是否阻擋）。
    fn delete_platform_credential(&mut self, _credential_id: &[u8]) -> Result<(), FidoError> {
        Err(platform_unsupported())
    }
}

// ─────────────────────────── UnavailableBackend ───────────────────────────

/// Windows WebAuthn API 能力不足（< v4）時的「金鑰不可用」後端：每個金鑰操作 fail closed，
/// 讓 GUI 仍可啟動並使用主密碼。絕不 fallback 到 MockBackend。
pub struct UnavailableBackend {
    api_version: u32,
}

impl UnavailableBackend {
    pub fn new(api_version: u32) -> Self {
        Self { api_version }
    }

    fn message(&self) -> String {
        format!(
            "此工作階段無法使用 Windows 安全金鑰（WebAuthn API v{}，需 v4 以上）。請在 RDP 啟用 WebAuthn（Windows Hello 或安全性金鑰）重新導向，或改在本機 Console 使用金鑰；主密碼登入不受影響。",
            self.api_version
        )
    }

    fn error(&self) -> FidoError {
        FidoError::NotSupported(self.message())
    }
}

impl FidoBackend for UnavailableBackend {
    fn detect(&mut self) -> Result<DetectedKey, FidoError> {
        Err(self.error())
    }

    fn register_credential(
        &mut self,
        _detected: &DetectedKey,
        _pin: Option<&str>,
    ) -> Result<RegisteredCredential, FidoError> {
        Err(self.error())
    }

    fn get_prf_secret(
        &mut self,
        _credential_id: &[u8],
        _pin: Option<&str>,
    ) -> Result<[u8; 32], FidoError> {
        Err(self.error())
    }

    fn get_prf_secret_for_any(
        &mut self,
        _credential_ids: &[Vec<u8>],
        _pin: Option<&str>,
    ) -> Result<(Vec<u8>, [u8; 32]), FidoError> {
        Err(self.error())
    }

    fn register_credential_excluding(
        &mut self,
        _detected: &DetectedKey,
        _pin: Option<&str>,
        _exclude: &[Vec<u8>],
    ) -> Result<RegisteredCredential, FidoError> {
        Err(self.error())
    }

    /// 維持 Windows 單一「以金鑰登入」入口的 UI。
    fn uses_brokered_key_selection(&self) -> bool {
        true
    }

    fn peek_kind(&self) -> KeyKind {
        KeyKind::WindowsManaged
    }

    fn info_diag(&self) -> String {
        format!(
            "windows-webauthn-unavailable api_version={}",
            self.api_version
        )
    }

    fn key_unavailable_reason(&self) -> Option<String> {
        Some(self.message())
    }
}

// ─────────────────────────── MockBackend ───────────────────────────

/// 模擬金鑰：無狀態、純函數。PRF secret 由 credential_id 決定 → 跨行程一致。
pub struct MockBackend {
    /// detect() 自動循環計數（fingerprint→pin→touch-only；override 不推進）。
    detect_count: u32,
    /// 依序偵測到的金鑰編號（label/AAGUID 用，恆 +1 → 每支 label 唯一）。
    seq: u32,
    /// CLI/測試可指定「下一支偵測到的金鑰類型」（覆蓋自動循環）。
    next_kind_override: Option<KeyKind>,
    /// 模擬金鑰是否支援 hmac-secret/PRF（預設 true = YubiKey 5+；--no-prf 驗證裁決②）。
    prf_enabled: bool,
    /// 測試用：下一次 detect 視為「同一支實體金鑰再次插入」（不推進 seq）。
    reuse_device_next: bool,
    /// 每個 mock 實例代表一組獨立的實體金鑰；與 seq 一起決定「裝置標記」。
    instance_key: [u8; 16],
    /// 模擬 Windows Hello 的行為模式（預設 Supported = SKYCITY-PC 型）。
    platform_mode: MockPlatformMode,
    /// 模擬「這台電腦 × Windows 帳號」持有的 Windows Hello credential（每個 mock 實例 = 一台電腦）。
    platform_credentials: Vec<Vec<u8>>,
    /// 測試用：接下來 N 次 roaming 斷言回傳「前景未交回」拒絕（不碰 authenticator）。
    roaming_handoff: Option<(MockHandoffRefusal, usize)>,
    /// 測試用：接下來 N 次 Windows Hello 斷言回傳「前景未交回」拒絕。
    platform_handoff: Option<(MockHandoffRefusal, usize)>,
    /// 呼叫順序紀錄（供測試驗證 delete 等是否被呼叫）。
    call_log: Vec<MockCall>,
}

/// MockBackend 模擬的「前景未交回」拒絕種類（對應 Windows backend 的兩個守門）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MockHandoffRefusal {
    /// roaming continuation 拒絕（broker 未觀察到／前景非 broker／被動期限）。
    ForegroundHandoffRequired,
    /// pre-API owner 前景守門拒絕。
    OwnerNotForeground,
}

impl MockHandoffRefusal {
    fn error(self) -> FidoError {
        match self {
            Self::ForegroundHandoffRequired => FidoError::ForegroundHandoffRequired,
            Self::OwnerNotForeground => FidoError::OwnerNotForeground,
        }
    }
}

/// MockBackend 呼叫紀錄（不含任何參數或秘密）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MockCall {
    Detect,
    RegisterCredential,
    GetPrfSecret,
    RegisterPlatform,
    GetPlatformPrf,
    ListPlatform,
    DeletePlatform,
}

/// MockBackend 的 Windows Hello 模擬模式（docs/plans/windows-hello-single.md §6.1）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MockPlatformMode {
    /// 建立與斷言都有 PRF，且輸出相同（SKYCITY-PC 實測）。
    Supported,
    /// 建立有 PRF，但所有帶 salt 的斷言失敗（Win11-NB：TPM 1.2／software KSP）。
    AssertionPrfFails,
    /// 建立回報的 PRF 與斷言輸出不同（驗證 vault 的比對）。
    CreationPrfMismatch,
    /// 此電腦／工作階段沒有可用的 Windows Hello。
    Unavailable,
    /// D9-F2：註冊請求被 Windows 改由安全性金鑰完成（transport 非 INTERNAL）。
    Substituted,
}

/// Mock Windows Hello credential ID 前綴（與 roaming mock ID 的 kind 位元組 0..=2 不會衝突）。
pub const MOCK_PLATFORM_ID_PREFIX: &[u8; 8] = b"f2vl-wh:";

impl Default for MockBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl MockBackend {
    pub fn new() -> Self {
        Self {
            detect_count: 0,
            seq: 0,
            next_kind_override: None,
            prf_enabled: true,
            reuse_device_next: false,
            instance_key: {
                let mut k = [0u8; 16];
                use rand::RngCore;
                rand::rngs::OsRng.fill_bytes(&mut k);
                k
            },
            platform_mode: MockPlatformMode::Supported,
            platform_credentials: Vec::new(),
            roaming_handoff: None,
            platform_handoff: None,
            call_log: Vec::new(),
        }
    }

    /// 接下來 `times` 次 roaming 斷言（get_prf_secret）回傳 `refusal`。
    pub fn with_roaming_handoff(mut self, refusal: MockHandoffRefusal, times: usize) -> Self {
        self.set_roaming_handoff(refusal, times);
        self
    }

    pub fn set_roaming_handoff(&mut self, refusal: MockHandoffRefusal, times: usize) {
        self.roaming_handoff = (times > 0).then_some((refusal, times));
    }

    /// 接下來 `times` 次 Windows Hello 斷言回傳 `refusal`。
    pub fn with_platform_handoff(mut self, refusal: MockHandoffRefusal, times: usize) -> Self {
        self.set_platform_handoff(refusal, times);
        self
    }

    pub fn set_platform_handoff(&mut self, refusal: MockHandoffRefusal, times: usize) {
        self.platform_handoff = (times > 0).then_some((refusal, times));
    }

    /// 測試檢視：呼叫順序。
    pub fn calls(&self) -> &[MockCall] {
        &self.call_log
    }

    /// 設定 Windows Hello 模擬模式。
    pub fn with_platform_mode(mut self, mode: MockPlatformMode) -> Self {
        self.platform_mode = mode;
        self
    }

    /// 模擬同一台電腦重新啟動程式：預先載入本機已持有的 Windows Hello credential。
    pub fn with_platform_credentials(mut self, ids: Vec<Vec<u8>>) -> Self {
        self.platform_credentials = ids;
        self
    }

    /// 測試檢視：目前本機持有的 Windows Hello credential。
    pub fn platform_credential_ids(&self) -> &[Vec<u8>] {
        &self.platform_credentials
    }

    pub fn is_mock_platform_credential(credential_id: &[u8]) -> bool {
        credential_id.len() == 32 && credential_id[..8] == MOCK_PLATFORM_ID_PREFIX[..]
    }

    /// 目前這支模擬金鑰的裝置標記（8B）：嵌在 credential_id[1..9]，供 excludeCredentials 判斷
    /// 「是否由同一支金鑰簽發」——模擬實體 authenticator 只認得自己簽發的 credential。
    fn device_tag(&self) -> [u8; 8] {
        let mut mac = Hmac::<Sha256>::new_from_slice(&self.instance_key).expect("hmac key any len");
        mac.update(b"f2vlt-mock-device-v1");
        mac.update(&self.seq.to_le_bytes());
        let out = mac.finalize().into_bytes();
        let mut tag = [0u8; 8];
        tag.copy_from_slice(&out[..8]);
        tag
    }

    /// 模擬「同一支實體金鑰再次插入」：下一次 detect 沿用上一支金鑰（驗證 excludeCredentials）。
    pub fn reuse_device(&mut self) {
        self.reuse_device_next = true;
    }

    /// 設定下一支偵測到的金鑰類型（CLI register-key --kind pin 用）。
    pub fn with_next_kind(mut self, kind: KeyKind) -> Self {
        self.next_kind_override = Some(kind);
        self
    }

    /// 模擬不支援 hmac-secret/PRF 的金鑰（CLI register-key --no-prf 驗證裁決②）。
    pub fn with_prf(mut self, enabled: bool) -> Self {
        self.prf_enabled = enabled;
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
    /// credential_id 版面：`[kind, device_tag(8), random(23)]`（長度 32 與 kind 前綴不變）。
    fn make_credential_id(&self, kind: KeyKind) -> Vec<u8> {
        let mut id = [0u8; 32];
        use rand::RngCore;
        rand::rngs::OsRng.fill_bytes(&mut id);
        id[0] = kind.to_u8();
        id[1..9].copy_from_slice(&self.device_tag());
        id.to_vec()
    }

    /// 消耗一次注入的「前景未交回」拒絕（剩餘次數歸零即解除）。
    fn take_handoff(slot: &mut Option<(MockHandoffRefusal, usize)>) -> Option<FidoError> {
        let (refusal, remaining) = slot.as_mut()?;
        let error = refusal.error();
        *remaining -= 1;
        if *remaining == 0 {
            *slot = None;
        }
        Some(error)
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
        self.call_log.push(MockCall::Detect);
        // override（CLI --kind / UI 指定）只生效一次，**不推進自動循環計數** →
        // 其後回到的仍是循環起點（與 peek_kind 一致）。
        let kind = match self.next_kind_override.take() {
            Some(k) => k,
            None => {
                let k = KeyKind::from_u8((self.detect_count % 3) as u8);
                self.detect_count += 1;
                k
            }
        };
        if self.reuse_device_next {
            // 同一支實體金鑰再次插入：沿用 seq（裝置標記相同）。
            self.reuse_device_next = false;
        } else {
            self.seq += 1; // 每支偵測到的金鑰都有獨立編號（label/AAGUID 唯一）
        }
        let aaguid = mock_aaguid(self.seq);
        Ok(DetectedKey {
            kind,
            label: format!("Mock YubiKey #{}", self.seq),
            aaguid,
        })
    }

    fn register_credential(
        &mut self,
        detected: &DetectedKey,
        _pin: Option<&str>,
    ) -> Result<RegisteredCredential, FidoError> {
        self.call_log.push(MockCall::RegisterCredential);
        Ok(RegisteredCredential {
            credential_id: self.make_credential_id(detected.kind),
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
        // 模擬 authenticator：排除清單中有本裝置簽發的 credential → CTAP2_ERR_CREDENTIAL_EXCLUDED。
        let tag = self.device_tag();
        if exclude
            .iter()
            .any(|id| id.len() >= 9 && id[1..9] == tag[..])
        {
            return Err(FidoError::CredentialExcluded);
        }
        self.register_credential(detected, pin)
    }

    fn get_prf_secret(
        &mut self,
        credential_id: &[u8],
        pin: Option<&str>,
    ) -> Result<[u8; 32], FidoError> {
        self.call_log.push(MockCall::GetPrfSecret);
        if let Some(error) = Self::take_handoff(&mut self.roaming_handoff) {
            return Err(error);
        }
        if credential_id.is_empty() {
            return Err(FidoError::Internal("credential_id 為空".into()));
        }
        // 模擬實體 YubiKey：不持有 Windows Hello credential。
        if Self::is_mock_platform_credential(credential_id) {
            return Err(FidoError::NoDevice);
        }
        let kind = KeyKind::from_u8(credential_id[0]);
        Self::check_pin(kind, pin)?;
        Ok(Self::prf_for_credential(credential_id))
    }

    fn peek_kind(&self) -> KeyKind {
        // 與 detect() 的取值邏輯一致（override 優先，否則循環）→ UI 預覽不偏。
        self.next_kind_override
            .unwrap_or_else(|| KeyKind::from_u8((self.detect_count % 3) as u8))
    }

    fn prf_supported(&self) -> bool {
        // mock 預設模擬支援 PRF 的金鑰（YubiKey 5+）；with_prf(false) 模擬不支援者。
        self.prf_enabled
    }

    fn platform_status(&self) -> PlatformStatus {
        let on = self.platform_mode != MockPlatformMode::Unavailable;
        PlatformStatus {
            api_ok: on,
            uvpa: on,
            console: on,
        }
    }

    fn register_platform_credential(
        &mut self,
        label: &str,
        exclude: &[Vec<u8>],
    ) -> Result<PlatformRegistration, FidoError> {
        self.call_log.push(MockCall::RegisterPlatform);
        if self.platform_mode == MockPlatformMode::Unavailable {
            return Err(platform_unsupported());
        }
        if self.platform_mode == MockPlatformMode::Substituted {
            return Err(FidoError::PlatformAuthenticatorSubstituted);
        }
        // 模擬 excludeCredentials：本機已持有其中任一筆 → NTE_EXISTS，不建立、不提示。
        if exclude
            .iter()
            .any(|id| self.platform_credentials.contains(id))
        {
            return Err(FidoError::PlatformCredentialExists);
        }
        let mut id = [0u8; 32];
        use rand::RngCore;
        rand::rngs::OsRng.fill_bytes(&mut id);
        id[..8].copy_from_slice(MOCK_PLATFORM_ID_PREFIX);
        let id = id.to_vec();
        let mut creation = Self::prf_for_credential(&id);
        if self.platform_mode == MockPlatformMode::CreationPrfMismatch {
            creation[0] ^= 0xFF;
        }
        self.platform_credentials.push(id.clone());
        Ok(PlatformRegistration {
            credential: RegisteredCredential {
                credential_id: id,
                aaguid: [0u8; 16],
                label: label.to_owned(),
                kind: KeyKind::WindowsManaged,
            },
            creation_prf: zeroize::Zeroizing::new(creation),
        })
    }

    fn get_platform_prf_secret(
        &mut self,
        credential_ids: &[Vec<u8>],
    ) -> Result<(Vec<u8>, [u8; 32]), FidoError> {
        self.call_log.push(MockCall::GetPlatformPrf);
        if self.platform_mode == MockPlatformMode::Unavailable {
            return Err(platform_unsupported());
        }
        // 模擬 Windows backend 的前景守門：在呼叫 authenticator 之前拒絕。
        if let Some(error) = Self::take_handoff(&mut self.platform_handoff) {
            return Err(error);
        }
        let id = credential_ids
            .iter()
            .find(|id| self.platform_credentials.contains(id))
            .ok_or(FidoError::PlatformCredentialMissing)?;
        if self.platform_mode == MockPlatformMode::AssertionPrfFails {
            return Err(FidoError::PlatformPrfUnsupported);
        }
        Ok((id.clone(), Self::prf_for_credential(id)))
    }

    fn list_platform_credentials(&mut self) -> Result<Vec<Vec<u8>>, FidoError> {
        self.call_log.push(MockCall::ListPlatform);
        if self.platform_mode == MockPlatformMode::Unavailable {
            return Err(platform_unsupported());
        }
        Ok(self.platform_credentials.clone())
    }

    fn delete_platform_credential(&mut self, credential_id: &[u8]) -> Result<(), FidoError> {
        self.call_log.push(MockCall::DeletePlatform);
        if self.platform_mode == MockPlatformMode::Unavailable {
            return Err(platform_unsupported());
        }
        let pos = self
            .platform_credentials
            .iter()
            .position(|id| id.as_slice() == credential_id)
            .ok_or(FidoError::PlatformCredentialMissing)?;
        self.platform_credentials.remove(pos);
        Ok(())
    }
}

/// 模擬 AAGUID：固定前綴 + 編號。
fn mock_aaguid(n: u32) -> [u8; 16] {
    let mut a = [0u8; 16];
    a[0..8].copy_from_slice(b"f2vlmock");
    a[12..16].copy_from_slice(&n.to_be_bytes());
    a
}

// ─────────────────────────── RealBackend（real-ctap）───────────────────────────
//
// 實體 CTAP2 金鑰後端（PM 裁決③：mozilla authenticator-rs v0.6.1，vendored）。
//
// PRF secret 語義（與 MockBackend 對齊 → vault 格式跨 mock/real 相容）：
//   getAssertion + hmac-secret extension，salt1 = crate::crypto::prf_salt_bytes()（固定）。
//   金鑰端回傳 HMAC(authenticator_key, salt1)；函式庫以本 session ECDH shared secret 解密 →
//   output1: [u8;32]。authenticator_key 對該 resident credential 恆定、salt1 固定 →
//   output1 跨行程/重啟可重現 → HKDF(kek_from_prf_secret) → KEK。即「金鑰單獨即可解鎖」。
//
// UV 策略：user_verification_req = Preferred（**不可用 Discouraged**）——
//   Discouraged 會令 can_skip_user_verification=true → 不建立 shared secret →
//   hmac 輸出無法解密 → PRF 抽取失敗。Preferred 下函式庫走 UV/PIN 路徑：
//     - touch-only（YubiKey 5）：GetPinUvAuthTokenUsingUvWithPermissions → 觸碰一次
//     - 指紋型：按指紋
//     - PIN 型：需 pin（呼叫方提供；None 時回 PinRequired）
//   shared secret 在該路徑內建立 → finalize_result 得以解密 hmac 輸出。

#[cfg(feature = "real-ctap")]
mod real {
    use super::*;
    use authenticator::authenticatorservice::{AuthenticatorService, RegisterArgs, SignArgs};
    use authenticator::crypto::COSEAlgorithm;
    use authenticator::ctap2::commands::client_pin::Pin;
    use authenticator::ctap2::commands::get_info::AuthenticatorInfo;
    use authenticator::ctap2::server::{
        AuthenticationExtensionsClientInputs, HMACGetSecretInput, PublicKeyCredentialDescriptor,
        PublicKeyCredentialParameters, PublicKeyCredentialUserEntity, RelyingParty,
        ResidentKeyRequirement, UserVerificationRequirement,
    };
    use authenticator::statecallback::StateCallback;
    use authenticator::{BioEnrollmentCmd, BioEnrollmentResult};
    use sha2::{Digest, Sha256};
    use std::sync::mpsc::channel;
    use std::sync::{Arc, Mutex};

    /// YubiKey 系列 VID/PID（contention 偵測用：diag log 中該裝置 open 被拒 = handle 被外部持有）。
    const FIDO_VID_PID: &str = "hid#vid_1050&pid_0402";

    /// RP id / origin（離線工具，固定值；跨行程一致即可）。
    const RP_ID: &str = "fido-vault.local";
    /// 偵測（getInfo）超時（ms）：含 Windows HID 列舉 + 裝置選擇。
    const DETECT_TIMEOUT_MS: u64 = 30_000;
    /// 註冊 / PRF 操作超時（ms）：需 key-agreement + 觸碰/指紋/PIN 互動，給足時間。
    const OP_TIMEOUT_MS: u64 = 90_000;

    pub struct RealBackend {
        service: AuthenticatorService,
        /// detect() 後快取的 AuthenticatorInfo（供 prf_supported()/peek_kind() 免再碰硬體）。
        info: Option<AuthenticatorInfo>,
    }

    impl RealBackend {
        // The constructor installs a process-global HID filter; keep that side effect explicit
        // rather than disguising it behind `Default`.
        #[allow(clippy::new_without_default)]
        pub fn new() -> Self {
            let mut service = AuthenticatorService::new().expect("authenticator service init");
            // Windows raw HID transport（CLI/診斷用；一般權限會受 Windows FIDO access policy 限制）。
            // Windows GUI 改走 WebAuthn broker，不由這個 backend 開 HID。
            service.add_u2f_usb_hid_platform_transports();
            // [vendor patch] Targeted HID filter: open only Yubico (VID 0x1050)
            // HID interfaces — never the laptop's keyboard/mouse/touchpad.
            // pid==0 => "any PID for this VID", so the whole Yubico FIDO HID
            // family is covered while non-FIDO devices are excluded. This is
            // what makes detect work on a machine with ~30 HID devices:
            // yk_open_test proved the YubiKey itself opens + answers CTAP2
            // Init/GetInfo cleanly; the full-scan was the failure. See
            // vendor authenticator-rs `device_filter`.
            authenticator::device_filter::set_target_devices(&[(0x1050, 0)]);
            Self {
                service,
                info: None,
            }
        }

        /// 以既有 AuthenticatorService 建立（測試用：可注入 mock transport）。
        pub fn with_service(service: AuthenticatorService) -> Self {
            Self {
                service,
                info: None,
            }
        }

        /// 同步橋：authenticator-rs 是「callback + status channel」非同步模型；此處以
        /// StateCallback::wait() 阻塞，並在泵執行緒消化 status（PIN 要求 / 多裝置選擇）。
        fn run_op<T: Send + 'static>(
            &mut self,
            _timeout_ms: u64,
            submit: impl FnOnce(
                &mut AuthenticatorService,
                std::sync::mpsc::Sender<authenticator::StatusUpdate>,
                StateCallback<authenticator::Result<T>>,
            ) -> authenticator::Result<()>,
        ) -> Result<T, FidoError> {
            use std::sync::atomic::{AtomicBool, Ordering};
            let (status_tx, status_rx) = channel::<authenticator::StatusUpdate>();
            // 結果槽 + done flag：callback（另一執行緒）寫入；本執行緒輪詢 done。
            let slot: Arc<Mutex<Option<Result<T, authenticator::errors::AuthenticatorError>>>> =
                Arc::new(Mutex::new(None));
            let done = Arc::new(AtomicBool::new(false));

            // 泵執行緒：消化 status channel（避免塞爆 / 死鎖）。
            //   - PinUvError(PinRequired/InvalidPin)：把內嵌 Sender drop 掉 → 函式庫收到
            //     RecvError → CancelledByUser → transaction timeout 收場（不 hang）。
            //   - SelectResultNotice（多結果）：allow_list 單項 → 實務上不會發生。
            std::thread::spawn(move || {
                for msg in status_rx.iter() {
                    if let authenticator::StatusUpdate::PinUvError(ref e) = msg {
                        log_pin_error(e);
                    }
                }
            });

            // 自建 callback（與 service 端的 StateCallback 同型別，經 submit 注入）：
            // 寫 slot + set done。不用 StateCallback::wait()（其 clone/wait 在
            // generic 情境下的暫時物件生命周期會卡 borrow checker）。
            let cb = StateCallback::new(Box::new({
                let (slot2, done2) = (slot.clone(), done.clone());
                move |rv: authenticator::Result<T>| {
                    *slot2.lock().unwrap() = Some(rv);
                    done2.store(true, Ordering::SeqCst);
                }
            }));

            if let Err(e) = submit(&mut self.service, status_tx, cb) {
                return Err(map_auth_error(e));
            }
            // 阻塞直到 callback 觸發（成功 / 失敗 / timeout）。輪詢 done flag（避免
            // wait_while 的 guard 生命周期/lint 問題；5ms 粒度對 30s 超時無影響）。
            // 看門狗：vendor fallback 在 _timeout_ms 觸發 U2FToken(NotAllowed)；
            // 若再超 5s 仍無 callback = vendor transaction 卡死（device thread 阻塞
            // 在非 alive-aware 路徑）→ 回報明確錯誤而非無限 hang（CLI one-shot，exit 即清理）。
            let deadline = std::time::Instant::now()
                + std::time::Duration::from_millis(_timeout_ms.saturating_add(5_000));
            while !done.load(Ordering::SeqCst) {
                if std::time::Instant::now() >= deadline {
                    return Err(FidoError::Internal(format!(
                        "run_op 看門狗超時（>{_timeout_ms}ms+5s）：vendor callback 未觸發 — \
                         見 fido2-diag.log 定位卡死點"
                    )));
                }
                std::thread::sleep(std::time::Duration::from_millis(5));
            }
            let got = {
                let mut g = slot.lock().unwrap();
                g.take()
            };
            match got {
                Some(Ok(v)) => Ok(v),
                Some(Err(e)) => Err(map_auth_error(e)),
                None => Err(FidoError::Internal("callback 未觸發".into())),
            }
        }

        /// detect → AuthenticatorInfo（CTAP2 getInfo，免互動）。
        fn get_info(&mut self) -> Result<AuthenticatorInfo, FidoError> {
            self.run_op(DETECT_TIMEOUT_MS, |svc, status, cb| {
                svc.get_info(DETECT_TIMEOUT_MS, status, cb)?;
                Ok(())
            })
        }

        /// getBioEnrollment CBOR 0x09（GetFingerprintSensorInfo）— 互動式 manage() 流程：
        /// Phase 1: service.manage() → state machine 經 status 送 StartManagement((tx, info))；
        ///          泵執行緒回 InteractiveRequest::BioEnrollment(GetFingerprintSensorInfo, None)。
        /// Phase 2: 結果經 status(BioEnrollmentUpdate) 或 callback(Err/Success) 回來。
        /// **Best-effort**：任何失敗（不支援 / 無感測器 / 需 PIN 未提供）→ false，呼叫方退回
        /// getInfo flag 分類（不阻斷註冊）。僅在 bioEnroll 宣告且無 clientPin 時呼叫
        /// （有 PIN 的金鑰 probe 會要求 UV 互動 → 偵測階段不應阻塞）。
        fn probe_bio_sensor(&mut self) -> bool {
            use authenticator::{InteractiveRequest, InteractiveUpdate};
            use std::sync::atomic::{AtomicBool, Ordering};

            let (status_tx, status_rx) = channel::<authenticator::StatusUpdate>();
            let result: Arc<
                Mutex<
                    Option<Result<BioEnrollmentResult, authenticator::errors::AuthenticatorError>>,
                >,
            > = Arc::new(Mutex::new(None));
            let done = Arc::new(AtomicBool::new(false));

            // 泵執行緒：處理互動兩階段 + PIN 要求（drop sender → 函式庫中止，不 hang）。
            {
                let (result3, done3) = (result.clone(), done.clone());
                std::thread::spawn(move || {
                    for msg in status_rx.iter() {
                        match msg {
                            authenticator::StatusUpdate::InteractiveManagement(
                                InteractiveUpdate::StartManagement((tx, _info)),
                            ) => {
                                // 每個 transport 一個 session → 逐一回覆 probe。
                                if tx
                                    .send(InteractiveRequest::BioEnrollment(
                                        BioEnrollmentCmd::GetFingerprintSensorInfo,
                                        None,
                                    ))
                                    .is_err()
                                {
                                    break;
                                }
                            }
                            authenticator::StatusUpdate::InteractiveManagement(
                                InteractiveUpdate::BioEnrollmentUpdate((res, _puat)),
                            ) => {
                                *result3.lock().unwrap() = Some(Ok(res));
                                done3.store(true, Ordering::SeqCst);
                            }
                            authenticator::StatusUpdate::PinUvError(ref e) => log_pin_error(e),
                            _ => {}
                        }
                    }
                });
            }

            let cb = StateCallback::new(Box::new({
                let (result2, done2) = (result.clone(), done.clone());
                move |rv: authenticator::Result<authenticator::ManageResult>| {
                    match rv {
                        Ok(authenticator::ManageResult::BioEnrollment(res)) => {
                            *result2.lock().unwrap() = Some(Ok(res));
                        }
                        Err(e) => *result2.lock().unwrap() = Some(Err(e)),
                        Ok(_) => {} // Success（Quit 路徑）等 status 端結果；無則視為失敗
                    }
                    done2.store(true, Ordering::SeqCst);
                }
            }));

            if self
                .service
                .manage(DETECT_TIMEOUT_MS, status_tx, cb)
                .is_err()
            {
                return false; // 無 transport / 非同步錯誤
            }
            // 阻塞直到結果或 callback（transaction timeout 兜底 → 不超過 DETECT_TIMEOUT_MS）。
            while !done.load(Ordering::SeqCst) {
                std::thread::sleep(std::time::Duration::from_millis(5));
            }
            let got = {
                let mut g = result.lock().unwrap();
                g.take()
            };
            match got {
                Some(Ok(BioEnrollmentResult::FingerprintSensorInfo(ref s))) => {
                    eprintln!(
                        "[fido2] getBioEnrollment 0x09: fingerprint sensor = {:?}（確認指紋感測器）",
                        s.fingerprint_kind
                    );
                    true
                }
                other => {
                    let desc = other
                        .as_ref()
                        .map(|r| match r {
                            Ok(BioEnrollmentResult::FingerprintSensorInfo(_)) => {
                                "sensor-info".to_string()
                            }
                            Ok(BioEnrollmentResult::EnrollmentList(v)) => {
                                format!("enroll-list({})", v.len())
                            }
                            Ok(_) => "other-result".to_string(),
                            Err(e) => format!("err: {e:?}"),
                        })
                        .unwrap_or_else(|| "no-result".to_string());
                    eprintln!("[fido2] getBioEnrollment 0x09 probe 未取得感測器資訊（{desc}）→ 依 getInfo flag 分類");
                    false
                }
            }
        }

        /// getBioEnrollment CBOR 0x09（GetEnrollments）— 讀已註冊指紋 template 清單。
        /// 診斷用：enrollmentCount=0 → UV=true 的 makeCredential 无法满足（notAllowed 根因①）。
        /// best-effort：Ok(n) = n 支 template；Err(msg) / None = probe 失敗（如 notAllowed/無 PIN）。
        fn probe_enrollments(&mut self) -> Option<Result<usize, String>> {
            use authenticator::{InteractiveRequest, InteractiveUpdate};
            use std::sync::atomic::{AtomicBool, Ordering};

            let (status_tx, status_rx) = channel::<authenticator::StatusUpdate>();
            let result: Arc<
                Mutex<
                    Option<Result<BioEnrollmentResult, authenticator::errors::AuthenticatorError>>,
                >,
            > = Arc::new(Mutex::new(None));
            let done = Arc::new(AtomicBool::new(false));

            {
                let (result3, done3) = (result.clone(), done.clone());
                std::thread::spawn(move || {
                    for msg in status_rx.iter() {
                        match msg {
                            authenticator::StatusUpdate::InteractiveManagement(
                                InteractiveUpdate::StartManagement((tx, _info)),
                            ) => {
                                if tx
                                    .send(InteractiveRequest::BioEnrollment(
                                        BioEnrollmentCmd::GetEnrollments,
                                        None,
                                    ))
                                    .is_err()
                                {
                                    break;
                                }
                            }
                            authenticator::StatusUpdate::InteractiveManagement(
                                InteractiveUpdate::BioEnrollmentUpdate((res, _puat)),
                            ) => {
                                *result3.lock().unwrap() = Some(Ok(res));
                                done3.store(true, Ordering::SeqCst);
                            }
                            authenticator::StatusUpdate::PinUvError(ref e) => log_pin_error(e),
                            _ => {}
                        }
                    }
                });
            }

            let cb = StateCallback::new(Box::new({
                let (result2, done2) = (result.clone(), done.clone());
                move |rv: authenticator::Result<authenticator::ManageResult>| {
                    match rv {
                        Ok(authenticator::ManageResult::BioEnrollment(res)) => {
                            *result2.lock().unwrap() = Some(Ok(res));
                        }
                        Err(e) => *result2.lock().unwrap() = Some(Err(e)),
                        Ok(_) => {}
                    }
                    done2.store(true, Ordering::SeqCst);
                }
            }));

            if self
                .service
                .manage(DETECT_TIMEOUT_MS, status_tx, cb)
                .is_err()
            {
                return None; // 無 transport / 非同步錯誤
            }
            while !done.load(Ordering::SeqCst) {
                std::thread::sleep(std::time::Duration::from_millis(5));
            }
            let got = {
                let mut g = result.lock().unwrap();
                g.take()
            };
            Some(match got {
                Some(Ok(BioEnrollmentResult::EnrollmentList(v))) => Ok(v.len()),
                Some(Ok(other)) => Err(format!("unexpected-result: {other:?}")),
                Some(Err(e)) => Err(format!("{e:?}")),
                None => Err("no-result（timeout）".to_string()),
            })
        }

        fn kind_from_info(i: &AuthenticatorInfo) -> KeyKind {
            // 指紋（bioEnrollment）> PIN（clientPin）> touch-only。
            if i.options.bio_enroll == Some(true) {
                KeyKind::Fingerprint
            } else if i.options.client_pin.is_some() {
                KeyKind::Pin
            } else {
                KeyKind::TouchOnly
            }
        }

        fn label_from_info(i: &AuthenticatorInfo, seq: u32) -> String {
            format!("FIDO2 金鑰 #{}（AAGUID {}）", seq, hex16(&i.aaguid.0))
        }

        /// makeCredential（resident + hmac-secret create）。PIN 型金鑰需 pin。
        fn do_register(
            &mut self,
            detected: &DetectedKey,
            pin: Option<&str>,
            exclude: &[Vec<u8>],
        ) -> Result<RegisteredCredential, FidoError> {
            let args = RegisterArgs {
                client_data_hash: Self::op_client_data_hash(b"register"),
                relying_party: RelyingParty::from(RP_ID),
                origin: RP_ID.to_string(),
                user: PublicKeyCredentialUserEntity {
                    id: random_bytes16(),
                    name: Some("vault-user".to_string()),
                    display_name: None,
                },
                pub_cred_params: vec![PublicKeyCredentialParameters {
                    alg: COSEAlgorithm::ES256,
                }],
                // excludeCredentials：金鑰已持有其中任一筆 → CTAP2_ERR_CREDENTIAL_EXCLUDED。
                exclude_list: exclude_descriptors(exclude),
                user_verification_req: UserVerificationRequirement::Preferred,
                resident_key_req: ResidentKeyRequirement::Preferred,
                extensions: AuthenticationExtensionsClientInputs {
                    hmac_create_secret: Some(true), // 註冊即宣告支援 hmac-secret（裁決②）
                    ..Default::default()
                },
                pin: pin.map(Pin::new),
                use_ctap1_fallback: false,
            };

            let res = self.run_op(OP_TIMEOUT_MS, |svc, status, cb| {
                svc.register(OP_TIMEOUT_MS, args, status, cb)?;
                Ok(())
            })?;

            // credential_id 來自 att_obj.auth_data.credential_data。
            let cred = res
                .att_obj
                .auth_data
                .credential_data
                .as_ref()
                .ok_or_else(|| {
                    FidoError::Internal("makeCredential 未回傳 credential data".into())
                })?;
            Ok(RegisteredCredential {
                credential_id: cred.credential_id.clone(),
                aaguid: cred.aaguid.0,
                label: detected.label.clone(),
                kind: detected.kind,
            })
        }

        /// getAssertion + hmac-secret（固定 salt1）→ 解密後 output1 = PRF secret。
        fn do_get_prf_secret(
            &mut self,
            credential_id: &[u8],
            pin: Option<&str>,
        ) -> Result<[u8; 32], FidoError> {
            let args = SignArgs {
                client_data_hash: Self::op_client_data_hash(b"prf"),
                origin: RP_ID.to_string(),
                relying_party_id: RP_ID.to_string(),
                allow_list: vec![PublicKeyCredentialDescriptor {
                    id: credential_id.to_vec(),
                    transports: vec![],
                }],
                user_verification_req: UserVerificationRequirement::Preferred,
                user_presence_req: true,
                extensions: AuthenticationExtensionsClientInputs {
                    hmac_get_secret: Some(HMACGetSecretInput {
                        salt1: crate::crypto::prf_salt_bytes(),
                        salt2: None,
                    }),
                    ..Default::default()
                },
                pin: pin.map(Pin::new),
                use_ctap1_fallback: false,
            };

            let res = self.run_op(OP_TIMEOUT_MS, |svc, status, cb| {
                svc.sign(OP_TIMEOUT_MS, args, status, cb)?;
                Ok(())
            })?;

            // 函式庫已以 shared secret 解密 hmac 輸出 → extensions.hmac_get_secret.output1。
            let out = res.extensions.hmac_get_secret.ok_or_else(|| {
                FidoError::Internal("金鑰未回傳 hmac-secret 輸出（不支援 PRF 或 UV 未完成）".into())
            })?;
            Ok(out.output1)
        }

        /// 固定操作 salt → clientDataHash（32B，跨行程一致）。
        fn op_client_data_hash(op: &[u8]) -> [u8; 32] {
            let mut h = Sha256::new();
            h.update(b"f2vlt-op:");
            h.update(op);
            h.update(crate::crypto::PRF_SALT);
            let d = h.finalize();
            let mut out = [0u8; 32];
            out.copy_from_slice(&d);
            out
        }

        // ── contention-aware retry（HID open denial：CreateFile ACCESS_DENIED / SHARING_VIOLATION）──
        //
        // Windows HID interface open 可能因既有 handle 的 incompatible share/access 或 OS policy
        // 而回 ACCESS_DENIED (os error 5) / SHARING_VIOLATION (os error 32)。NB 15:33 的
        // YubiKey FIDO interface open = os error 5；同 binary 15:25 又 detect 成功，顯示為間歇性。
        // authenticator-rs open 一次失敗後該 device 不進 token selector；getInfo 最後 timeout，
        // 所以錯誤被映射為 CancelledByUser/U2FToken(NotAllowed)，不是直接 open error。
        // 安全性：per-transaction 架構（Manager::new 不開 device、每 op 重新列舉、handle 於
        // transaction 結束釋放、cancel join）→ 重試不 self-contend。

        /// 判斷單行是否為**本 process** 對 YubiKey FIDO HID 的 open-denied signature。
        fn is_fido_open_denied_line(line: &str, pid: u32) -> bool {
            let pid_tag = format!("[pid={pid}]");
            line.contains(&pid_tag)
                && line.contains(FIDO_VID_PID)
                && line.contains("Ioerror")
                && (line.contains("os error 5") || line.contains("os error 32"))
        }

        /// 只掃本次 operation attempt 的 checkpoint 之後，且 PID 屬於本 process 的行。
        fn fido_open_denied_since(checkpoint: usize) -> bool {
            let pid = std::process::id();
            crate::diag_log::scan_from(checkpoint)
                .iter()
                .any(|line| Self::is_fido_open_denied_line(line, pid))
        }

        /// contention-aware 重試包裝：最多 MAX 次嘗試（首次 + MAX-1 次重試），backoff 2s/4s。
        /// op 每次嘗試重新執行整個 vendor op（重新列舉裝置）；以 &mut Self 參數傳入
        /// （非 closure capture）→ 避免 receiver 與 capture 雙重 mut borrow。
        fn retry_on_contention<T>(
            &mut self,
            what: &str,
            mut op: impl FnMut(&mut Self) -> Result<T, FidoError>,
        ) -> Result<T, FidoError> {
            const MAX_ATTEMPTS: usize = 3;
            let mut last_err = None;
            for attempt in 1..=MAX_ATTEMPTS {
                // 每個 attempt 單獨 checkpoint：UV timeout 不會因 detect 階段的舊 open error 而誤重試。
                let checkpoint = crate::diag_log::checkpoint();
                match op(self) {
                    Ok(v) => return Ok(v),
                    Err(e) => {
                        // 依實際 open-denied log signature 判 contention，而非依賴上層錯誤映射。
                        // authenticator-rs 在 CreateFile 失敗後不送 callback，最後只回 timeout /
                        // CancelledByUser；舊版只認 NoDevice/NotAllowed，漏掉這條 30s 路徑。
                        let open_denied = Self::fido_open_denied_since(checkpoint);
                        if !open_denied {
                            return Err(e);
                        }
                        if attempt == MAX_ATTEMPTS {
                            // 本次 attempt 的 log 確認本 process 的 FIDO HID open 被拒（不等於已識別 holder）（FIDO HID open-denied）→
                            // 回傳點名原因的 DeviceOpenDenied，取代 vendor 的模糊 timeout
                            // fallback（U2FToken(NotAllowed) / CancelledByUser）以讓 UI/CLI
                            // 能呈現 open denied，而非誤報「金鑰拒絕」。
                            let msg = format!(
                                "[fido2][contention] op={what} 重試 {MAX_ATTEMPTS}/{MAX_ATTEMPTS} 皆被拒；\
                                 FIDO HID open 被 Windows 拒絕（os error 5/32）；vendor 最終={e}。\
                                 → 對照 Windows WebAuthN/Windows Hello 是否正在使用安全金鑰；\
                                 先完成/取消該操作；勿強制終止 Windows 系統服務。"
                            );
                            log::error!("{msg}");
                            eprintln!("{msg}");
                            return Err(FidoError::DeviceOpenDenied {
                                what: what.to_string(),
                                last_err: e.to_string(),
                                attempts: attempt,
                            });
                        }
                        let backoff = 2_000u64 * attempt as u64;
                        log::warn!(
                            "[fido2][contention] op={what} attempt={attempt}/{MAX_ATTEMPTS}; \
                             YubiKey HID open denied in this attempt; retrying after {backoff}ms; \
                             previous error={e}"
                        );
                        eprintln!(
                            "[fido2] {what}：本次操作的 log 確認 YubiKey FIDO HID open 被拒（os error 5/32）；\
                             {backoff}ms 後自動重試（{attempt}/{MAX_ATTEMPTS}）"
                        );
                        std::thread::sleep(std::time::Duration::from_millis(backoff));
                        last_err = Some(e);
                    }
                }
            }
            Err(last_err.unwrap_or_else(|| FidoError::Internal("retry exhausted".into())))
        }
    }

    impl FidoBackend for RealBackend {
        fn detect(&mut self) -> Result<DetectedKey, FidoError> {
            // contention-aware retry：YubiKey 被其他 process 占用（os error 5）時整 op 重試。
            self.retry_on_contention("detect", |b: &mut Self| {
                let info = b.get_info()?;
                // PRF 能力診斷（PM 預先排程）：若 getInfo 未宣告 hmac-secret → 抓原始
                // extensions + firmware version 回報（裁決②會拒絕註冊；據此定論是升級
                // firmware 還是該型號不在支援範圍）。
                let has_prf = info.extensions.iter().any(|e| e == "hmac-secret");
                if !has_prf {
                    eprintln!("[fido2][DIAG] getInfo 未宣告 hmac-secret（註冊將被 PrfNotSupported 拒絕）：");
                    eprintln!(
                        "[fido2][DIAG]   extensions = {:?}\n[fido2][DIAG]   firmware_version = {:?}\n[fido2][DIAG]   versions = {:?}\n[fido2][DIAG]   algorithms = {:?}\n[fido2][DIAG]   aaguid = {}",
                        info.extensions, info.firmware_version, info.versions, info.algorithms, hex16(&info.aaguid.0)
                    );
                }
                // 分類以 getInfo flag 為準（CTAP2 spec：bioEnroll=true = 「已設定至少一個 bio
                // enrollment」→ 指紋型；clientPin 存在 → PIN 型；皆無 → touch-only）。
                // getBioEnrollment CBOR 0x09 probe 僅作確認/記錄（best-effort，不影響分類、
                // 不阻斷註冊）— YubiKey Bio：bioEnroll=true + clientPin=absent → Fingerprint。
                if info.options.bio_enroll == Some(true) && info.options.client_pin.is_none() {
                    b.probe_bio_sensor();
                }
                let kind = Self::kind_from_info(&info);
                let label = Self::label_from_info(&info, 1);
                b.info = Some(info.clone());
                Ok(DetectedKey { kind, label, aaguid: info.aaguid.0 })
            })
        }

        fn register_credential(
            &mut self,
            detected: &DetectedKey,
            pin: Option<&str>,
        ) -> Result<RegisteredCredential, FidoError> {
            // contention-aware retry：makeCredential 前 device open 被拒 → backoff 重試。
            self.retry_on_contention("register", |b: &mut Self| b.do_register(detected, pin, &[]))
        }

        fn register_credential_excluding(
            &mut self,
            detected: &DetectedKey,
            pin: Option<&str>,
            exclude: &[Vec<u8>],
        ) -> Result<RegisteredCredential, FidoError> {
            self.retry_on_contention("register", |b: &mut Self| {
                b.do_register(detected, pin, exclude)
            })
        }

        fn get_prf_secret(
            &mut self,
            credential_id: &[u8],
            pin: Option<&str>,
        ) -> Result<[u8; 32], FidoError> {
            if credential_id.is_empty() {
                return Err(FidoError::Internal("credential_id 為空".into()));
            }
            // contention-aware retry：getInfo/getAssertion 任一被 device open 拒絕 → backoff 重試。
            self.retry_on_contention("login", |b: &mut Self| {
                // 登入路徑（open_key）不會先 detect() → 若無快取資訊，先 getInfo 補上。
                if b.info.is_none() {
                    let _ = b.get_info()?;
                }
                b.do_get_prf_secret(credential_id, pin)
            })
        }

        fn peek_kind(&self) -> KeyKind {
            // 實體後端：偵測前不確定類型（getInfo 需碰硬體）→ 預設 touch-only 提示。
            match &self.info {
                Some(i) => Self::kind_from_info(i),
                None => KeyKind::TouchOnly,
            }
        }

        fn prf_supported(&self) -> bool {
            // detect() 後依 getInfo：extensions 含 "hmac-secret"。未偵測 → false（保守；
            // register_key 會先 detect()，故不影響流程）。
            match &self.info {
                Some(i) => i.extensions.iter().any(|e| e == "hmac-secret"),
                None => false,
            }
        }

        fn enrollment_count(&mut self) -> Option<Result<usize, String>> {
            // 僅對 bioEnroll 金鑰有意義；非指紋型 → None（不發 probe）。
            let is_bio = matches!(&self.info, Some(i) if i.options.bio_enroll == Some(true));
            if !is_bio {
                return None;
            }
            self.probe_enrollments()
        }

        fn info_diag(&self) -> String {
            match &self.info {
                Some(i) => format!(
                    "clientPin={:?} uv={:?} bioEnroll={:?} pin_protocols={:?} fw_version={:?} \
                     versions={:?} extensions={:?} alwaysUv={:?} makeCredUvNotRqd={:?} \
                     uvBioEnroll={:?} min_pin_length={:?}",
                    i.options.client_pin,
                    i.options.user_verification,
                    i.options.bio_enroll,
                    i.pin_protocols,
                    i.firmware_version,
                    i.versions,
                    i.extensions,
                    i.options.always_uv,
                    i.options.make_cred_uv_not_rqd,
                    i.options.uv_bio_enroll,
                    i.min_pin_length,
                ),
                None => "not-detected".to_string(),
            }
        }
    }

    fn log_pin_error(e: &authenticator::StatusPinUv) {
        use authenticator::StatusPinUv as S;
        match e {
            S::PinRequired(_) => eprintln!("[fido2] 金鑰要求 PIN（需由呼叫方提供 pin）"),
            S::InvalidPin(_, r) => eprintln!("[fido2] PIN 錯誤，重試次數={:?}", r),
            S::PinIsTooShort => eprintln!("[fido2] PIN 過短"),
            S::PinIsTooLong(_) => eprintln!("[fido2] PIN 過長"),
            S::InvalidUv(_) => eprintln!("[fido2] UV（指紋）驗證失敗"),
            S::PinAuthBlocked => eprintln!("[fido2] PIN auth 已鎖定"),
            S::PinBlocked => eprintln!("[fido2] PIN 已鎖定"),
            _ => {}
        }
    }

    /// excludeCredentials → CTAP2 descriptors（transports 不限定）。清單過長時由 authenticator-rs
    /// preflight 分批；仍無法送出則註冊失敗（fail closed，不會在未排除下建立 credential）。
    fn exclude_descriptors(exclude: &[Vec<u8>]) -> Vec<PublicKeyCredentialDescriptor> {
        exclude
            .iter()
            .map(|id| PublicKeyCredentialDescriptor {
                id: id.clone(),
                transports: vec![],
            })
            .collect()
    }

    fn map_auth_error(e: authenticator::errors::AuthenticatorError) -> FidoError {
        use authenticator::errors::AuthenticatorError as AE;
        match e {
            AE::NoConfiguredTransports => FidoError::NoDevice,
            AE::CancelledByUser => FidoError::Internal("使用者取消 / 超時".into()),
            AE::CredentialExcluded => FidoError::CredentialExcluded,
            other => FidoError::Internal(format!("authenticator-rs: {other:?}")),
        }
    }

    fn hex16(a: &[u8; 16]) -> String {
        a.iter().map(|b| format!("{b:02x}")).collect()
    }

    fn random_bytes16() -> Vec<u8> {
        use rand::RngCore;
        let mut b = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut b);
        b.to_vec()
    }

    #[cfg(test)]
    mod real_tests {
        use super::*;
        use authenticator::ctap2::commands::get_info::{AuthenticatorInfo, AuthenticatorOptions};

        fn info_with(opts: AuthenticatorOptions) -> AuthenticatorInfo {
            AuthenticatorInfo {
                options: opts,
                ..Default::default()
            }
        }

        #[test]
        fn exclude_descriptors_keep_every_id() {
            let ids = vec![vec![1u8, 2], vec![3u8; 40]];
            let d = exclude_descriptors(&ids);
            assert_eq!(d.len(), 2);
            assert_eq!(d[0].id, ids[0]);
            assert_eq!(d[1].id, ids[1]);
            assert!(d.iter().all(|x| x.transports.is_empty()));
            assert!(exclude_descriptors(&[]).is_empty());
        }

        #[test]
        fn credential_excluded_status_maps_to_fido_error() {
            let mapped =
                map_auth_error(authenticator::errors::AuthenticatorError::CredentialExcluded);
            assert!(
                matches!(mapped, FidoError::CredentialExcluded),
                "got {mapped:?}"
            );
        }

        /// YubiKey 5 系列：無 clientPin、無 bioEnroll → touch-only（PM 預先提醒的預期結果）。
        #[test]
        fn real_kind_touch_only_yubikey5_profile() {
            let o = AuthenticatorOptions::default();
            assert_eq!(
                RealBackend::kind_from_info(&info_with(o)),
                KeyKind::TouchOnly
            );
        }

        /// 指紋優先於 PIN（YubiKey Bio：兩者皆有）。
        #[test]
        fn real_kind_fingerprint_wins_over_pin() {
            let mut o = AuthenticatorOptions::default();
            o.bio_enroll = Some(true);
            o.client_pin = Some(true);
            assert_eq!(
                RealBackend::kind_from_info(&info_with(o)),
                KeyKind::Fingerprint
            );
        }

        /// YubiKey Bio（PM 回報的實際型號）：bioEnroll=true + clientPin=absent → Fingerprint。
        /// 分類純看 flag，不依賴 0x09 probe 結果（probe 僅確認/記錄）。
        #[test]
        fn real_kind_yubikey_bio_profile() {
            let o = AuthenticatorOptions {
                bio_enroll: Some(true), // 已設定指紋 enrollment
                client_pin: None,       // 無 PIN protocol
                user_verification: Some(true),
                ..Default::default()
            };
            assert_eq!(
                RealBackend::kind_from_info(&info_with(o)),
                KeyKind::Fingerprint
            );
        }

        /// 有 clientPin（含「已支援但未設定」=Some(false)）→ PIN 型。
        #[test]
        fn real_kind_pin() {
            let mut o = AuthenticatorOptions::default();
            o.client_pin = Some(false);
            assert_eq!(RealBackend::kind_from_info(&info_with(o)), KeyKind::Pin);
        }

        /// clientDataHash 固定 salt → 跨行程一致（register / prf 各異）。
        #[test]
        fn real_op_client_data_hash_deterministic() {
            let a = RealBackend::op_client_data_hash(b"register");
            assert_eq!(a, RealBackend::op_client_data_hash(b"register"));
            assert_ne!(a, RealBackend::op_client_data_hash(b"prf"));
        }

        /// PRF salt1 固定 32B（hmac-secret 的 eval input；跨行程一致）。
        #[test]
        fn real_prf_salt_fixed_32b() {
            let s = crate::crypto::prf_salt_bytes();
            assert_eq!(s.len(), 32);
            assert_eq!(&s[..17], b"f2vlt-prf-salt-v1");
            assert_eq!(s, crate::crypto::prf_salt_bytes());
        }

        /// Retry signature 必須同時符合 process PID、YubiKey FIDO VID/PID、Ioerror 與 Win32 5/32。
        /// 這可捕捉被 vendor 映射成 timeout/CancelledByUser 的 CreateFile open failure。
        #[test]
        fn real_contention_signature_is_pid_scoped() {
            let denied = r#"[INFO] [pid=42] [ts] authenticator::statemachine: Ioerror(Some("\\\\?\\hid#vid_1050&pid_0402#instance")): access denied (os error 5)"#;
            let sharing = r#"[INFO] [pid=42] [ts] authenticator::statemachine: Ioerror(Some("\\\\?\\hid#vid_1050&pid_0402#instance")): sharing violation (os error 32)"#;
            let unrelated = r#"[INFO] [pid=42] [ts] authenticator::statemachine: Ioerror(Some("\\\\?\\hid#vid_045e&pid_079c")): access denied (os error 5)"#;
            assert!(RealBackend::is_fido_open_denied_line(denied, 42));
            assert!(RealBackend::is_fido_open_denied_line(sharing, 42));
            assert!(!RealBackend::is_fido_open_denied_line(denied, 99));
            assert!(!RealBackend::is_fido_open_denied_line(unrelated, 42));
        }
    }
}

#[cfg(feature = "real-ctap")]
pub use real::RealBackend;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mock_backend_keeps_non_brokered_key_selection_ui() {
        assert!(!MockBackend::new().uses_brokered_key_selection());
    }

    fn assert_key_unavailable_message(error: &FidoError, api_version: u32) {
        assert!(matches!(error, FidoError::NotSupported(_)), "{error:?}");
        let message = error.to_string();
        for expected in [
            format!("v{api_version}"),
            "v4".to_string(),
            "Windows 安全金鑰".to_string(),
            "RDP".to_string(),
            "Console".to_string(),
            "主密碼".to_string(),
        ] {
            assert!(message.contains(&expected), "missing {expected}: {message}");
        }
        // Inputs of the failed operation (PIN, credential bytes) never leak into the message.
        for secret in ["924613", "c0ffee", "192, 254"] {
            assert!(!message.contains(secret), "leaked {secret}: {message}");
        }
    }

    #[test]
    fn unavailable_backend_fails_every_key_operation_closed() {
        let mut backend = UnavailableBackend::new(3);
        let pin = Some("924613");
        let credential_id = vec![0xc0, 0xfe, 0xee];

        assert!(backend.uses_brokered_key_selection());
        assert!(!backend.prf_supported());
        let reason = backend.key_unavailable_reason().expect("reason");
        assert_key_unavailable_message(&FidoError::NotSupported(reason), 3);

        let error = backend.detect().expect_err("detect");
        assert_key_unavailable_message(&error, 3);
        let detected = DetectedKey {
            kind: KeyKind::WindowsManaged,
            label: "x".into(),
            aaguid: [0; 16],
        };
        let error = backend
            .register_credential(&detected, pin)
            .expect_err("register");
        assert_key_unavailable_message(&error, 3);
        let error = backend
            .get_prf_secret(&credential_id, pin)
            .expect_err("get_prf_secret");
        assert_key_unavailable_message(&error, 3);
        let error = backend
            .get_prf_secret_for_any(&[credential_id.clone()], pin)
            .expect_err("get_prf_secret_for_any");
        assert_key_unavailable_message(&error, 3);
        let error = backend
            .get_prf_secret_for_any(&[], pin)
            .expect_err("get_prf_secret_for_any empty");
        assert_key_unavailable_message(&error, 3);
        backend.set_webauthn_parent_hwnd(1234);
        assert!(backend.enrollment_count().is_none());
    }

    #[test]
    fn unavailable_backend_leaves_password_vault_untouched_and_password_login_working() {
        use crate::vault::{Vault, VaultError};

        let dir = std::env::temp_dir().join(format!(
            "f2v-test-unavailable-backend-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("vault.db");

        // Password-created vault with one existing slot so key login reaches the backend.
        let mut vault = Vault::create(&path, "Pw-12345").unwrap();
        vault
            .register_key_with_label(&mut MockBackend::new(), None, "Existing Key")
            .unwrap();
        let existing_id = vault.keys_meta()[0].0.clone();
        drop(vault);

        let mut unavailable = UnavailableBackend::new(0);
        let before = std::fs::read(&path).unwrap();
        let any = Vault::open_any_key(&path, None, &mut unavailable);
        assert!(
            matches!(&any, Err(VaultError::Fido(e)) if matches!(e, FidoError::NotSupported(m) if m.contains("主密碼"))),
            "open_any_key must fail with the unavailable error"
        );
        let one = Vault::open_key(&path, &existing_id, None, &mut unavailable);
        assert!(
            matches!(&one, Err(VaultError::Fido(FidoError::NotSupported(_)))),
            "open_key must fail with the unavailable error"
        );
        assert_eq!(
            std::fs::read(&path).unwrap(),
            before,
            "key login wrote vault"
        );

        let mut vault = Vault::open_password(&path, "Pw-12345").expect("password login");
        assert_eq!(vault.keys_meta().len(), 1);
        let after_password_login = std::fs::read(&path).unwrap();
        let register = vault.register_key_with_label(&mut unavailable, None, "New Key");
        assert!(
            matches!(&register, Err(VaultError::Fido(FidoError::NotSupported(_)))),
            "register must fail with the unavailable error"
        );
        assert_eq!(vault.keys_meta().len(), 1);
        assert_eq!(
            std::fs::read(&path).unwrap(),
            after_password_login,
            "failed registration wrote vault"
        );
        drop(vault);
        assert!(Vault::open_password(&path, "Pw-12345").is_ok());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn mock_prf_deterministic() {
        let id = vec![0u8, 2, 3, 4];
        assert_eq!(
            MockBackend::prf_for_credential(&id),
            MockBackend::prf_for_credential(&id)
        );
        assert_ne!(
            MockBackend::prf_for_credential(&id),
            MockBackend::prf_for_credential(&[0, 9])
        );
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
        let reg = b.register_credential(&d, None).unwrap();
        assert!(b.get_prf_secret(&reg.credential_id, None).is_ok());

        // 第二支：pin 型 → 註冊後登入需 PIN，且跨「新行程」仍一致
        let mut b2 = MockBackend::new().with_next_kind(KeyKind::Pin);
        let d2 = b2.detect().unwrap();
        assert_eq!(d2.kind, KeyKind::Pin);
        let reg2 = b2.register_credential(&d2, None).unwrap();
        let mut fresh = MockBackend::new(); // 模擬重啟
        assert!(matches!(
            fresh.get_prf_secret(&reg2.credential_id, None),
            Err(FidoError::PinRequired(_))
        ));
        assert!(matches!(
            fresh.get_prf_secret(&reg2.credential_id, Some("12")),
            Err(FidoError::PinRejected)
        ));
        let s = fresh
            .get_prf_secret(&reg2.credential_id, Some("1234"))
            .unwrap();
        assert_eq!(s, MockBackend::prf_for_credential(&reg2.credential_id));
    }

    #[test]
    fn device_open_denied_guidance_names_windows_broker_without_claiming_known_holder() {
        let message = FidoError::DeviceOpenDenied {
            what: "detect".into(),
            last_err: "U2FToken(NotAllowed)".into(),
            attempts: 3,
        }
        .to_string();
        assert!(message.contains("Windows WebAuthN"), "{message}");
        assert!(message.contains("Windows Hello"), "{message}");
        assert!(!message.contains("taskkill"), "{message}");
        assert!(
            !message.contains("handle 被其他 process / USB session 鎖定"),
            "{message}"
        );
    }

    // ── D6：excludeCredentials ──

    // ── windows-hello D2：平台 authenticator trait + Mock ──

    fn wh_label() -> &'static str {
        "Windows Hello（本機 TEST-PC）"
    }

    #[test]
    fn wh_d2_trait_defaults_fail_closed() {
        let mut b = MinimalBackend(MockBackend::new());
        assert_eq!(b.platform_status(), PlatformStatus::default());
        assert!(!b.platform_status().available());
        assert!(matches!(
            b.register_platform_credential(wh_label(), &[]),
            Err(FidoError::NotSupported(_))
        ));
        assert!(matches!(
            b.get_platform_prf_secret(&[vec![1u8; 32]]),
            Err(FidoError::NotSupported(_))
        ));
        assert!(matches!(
            b.list_platform_credentials(),
            Err(FidoError::NotSupported(_))
        ));
        assert!(matches!(
            b.delete_platform_credential(&[1u8; 32]),
            Err(FidoError::NotSupported(_))
        ));
    }

    #[test]
    fn wh_d2_unavailable_backend_platform_ops_fail_closed() {
        let mut b = UnavailableBackend::new(1);
        assert!(!b.platform_status().available());
        assert!(matches!(
            b.register_platform_credential(wh_label(), &[]),
            Err(FidoError::NotSupported(_))
        ));
        assert!(matches!(
            b.get_platform_prf_secret(&[vec![1u8; 32]]),
            Err(FidoError::NotSupported(_))
        ));
        assert!(matches!(
            b.list_platform_credentials(),
            Err(FidoError::NotSupported(_))
        ));
    }

    #[test]
    fn wh_d2_platform_status_requires_all_three() {
        let all = PlatformStatus {
            api_ok: true,
            uvpa: true,
            console: true,
        };
        assert!(all.available());
        for missing in 0..3 {
            let mut s = all;
            match missing {
                0 => s.api_ok = false,
                1 => s.uvpa = false,
                _ => s.console = false,
            }
            assert!(!s.available(), "{s:?}");
        }
    }

    #[test]
    fn wh_d2_mock_platform_available_by_default() {
        let b = MockBackend::new();
        assert!(
            b.platform_status().available(),
            "default mock models a supported machine: {:?}",
            b.platform_status()
        );
    }

    #[test]
    fn wh_d2_mock_register_then_assert_returns_creation_prf() {
        let mut b = MockBackend::new();
        let reg = b.register_platform_credential(wh_label(), &[]);
        assert!(reg.is_ok(), "register: {:?}", reg.err());
        let reg = reg.unwrap();
        let id = reg.credential.credential_id.clone();
        assert!(MockBackend::is_mock_platform_credential(&id), "{id:?}");
        assert_eq!(reg.credential.kind, KeyKind::WindowsManaged);
        assert_eq!(reg.credential.label, wh_label());
        let got = b.get_platform_prf_secret(std::slice::from_ref(&id));
        assert!(got.is_ok(), "assert: {:?}", got.err());
        let (got_id, secret) = got.unwrap();
        assert_eq!(got_id, id);
        assert_eq!(
            secret, *reg.creation_prf,
            "create output must equal assertion output"
        );
        let listed = b.list_platform_credentials();
        assert!(
            matches!(&listed, Ok(ids) if ids == &vec![id.clone()]),
            "{listed:?}"
        );
    }

    #[test]
    fn wh_d2_mock_exclude_existing_rejects_without_creating() {
        let mut b = MockBackend::new();
        let first = b.register_platform_credential(wh_label(), &[]);
        assert!(first.is_ok(), "{:?}", first.err());
        let id = first.unwrap().credential.credential_id;
        let again = b.register_platform_credential(wh_label(), std::slice::from_ref(&id));
        assert!(
            matches!(again, Err(FidoError::PlatformCredentialExists)),
            "same machine must be excluded: {:?}",
            again.err()
        );
        assert_eq!(b.platform_credential_ids().len(), 1, "no second credential");

        // 另一台電腦的 platform ID 不會命中本機（每台電腦各可註冊一個，Q3）。
        let mut other = MockBackend::new();
        let foreign = other
            .register_platform_credential(wh_label(), &[])
            .map(|r| r.credential.credential_id);
        assert!(foreign.is_ok(), "{:?}", foreign.err());
        let mut third = MockBackend::new();
        let ok = third.register_platform_credential(wh_label(), &[foreign.unwrap()]);
        assert!(ok.is_ok(), "foreign id must not block: {:?}", ok.err());
    }

    #[test]
    fn wh_d2_mock_nb_mode_creation_prf_but_assertion_fails() {
        let mut b = MockBackend::new().with_platform_mode(MockPlatformMode::AssertionPrfFails);
        let reg = b.register_platform_credential(wh_label(), &[]);
        assert!(reg.is_ok(), "NB type still creates: {:?}", reg.err());
        let id = reg.unwrap().credential.credential_id;
        let got = b.get_platform_prf_secret(std::slice::from_ref(&id));
        assert!(
            matches!(got, Err(FidoError::PlatformPrfUnsupported)),
            "salted assertion must fail: {:?}",
            got.err()
        );
        assert_eq!(
            b.platform_credential_ids(),
            &[id.clone()][..],
            "still present until deleted"
        );
        let del = b.delete_platform_credential(&id);
        assert!(del.is_ok(), "{:?}", del.err());
        assert!(matches!(b.list_platform_credentials(), Ok(ids) if ids.is_empty()));
    }

    #[test]
    fn wh_d2_mock_creation_prf_mismatch_mode() {
        let mut b = MockBackend::new().with_platform_mode(MockPlatformMode::CreationPrfMismatch);
        let reg = b.register_platform_credential(wh_label(), &[]);
        assert!(reg.is_ok(), "{:?}", reg.err());
        let reg = reg.unwrap();
        let id = reg.credential.credential_id.clone();
        let got = b.get_platform_prf_secret(std::slice::from_ref(&id));
        assert!(got.is_ok(), "{:?}", got.err());
        assert_ne!(got.unwrap().1, *reg.creation_prf);
    }

    #[test]
    fn wh_d2_mock_unavailable_mode() {
        let mut b = MockBackend::new().with_platform_mode(MockPlatformMode::Unavailable);
        assert!(!b.platform_status().available());
        assert!(matches!(
            b.register_platform_credential(wh_label(), &[]),
            Err(FidoError::NotSupported(_))
        ));
        assert!(matches!(
            b.get_platform_prf_secret(&[vec![1u8; 32]]),
            Err(FidoError::NotSupported(_))
        ));
        assert!(matches!(
            b.list_platform_credentials(),
            Err(FidoError::NotSupported(_))
        ));
        assert!(b.platform_credential_ids().is_empty());
    }

    #[test]
    fn wh_d2_mock_assert_picks_local_credential_only() {
        let mut b = MockBackend::new();
        let own = b
            .register_platform_credential(wh_label(), &[])
            .map(|r| r.credential.credential_id);
        assert!(own.is_ok(), "{:?}", own.err());
        let own = own.unwrap();
        let mut other = MockBackend::new();
        let foreign = other
            .register_platform_credential(wh_label(), &[])
            .map(|r| r.credential.credential_id);
        assert!(foreign.is_ok(), "{:?}", foreign.err());
        let foreign = foreign.unwrap();

        assert!(b.get_platform_prf_secret(&[]).is_err(), "empty allow list");
        let missing = b.get_platform_prf_secret(std::slice::from_ref(&foreign));
        assert!(
            matches!(missing, Err(FidoError::PlatformCredentialMissing)),
            "{:?}",
            missing.err()
        );
        let got = b.get_platform_prf_secret(&[foreign, own.clone()]);
        assert!(matches!(&got, Ok((id, _)) if id == &own), "{:?}", got.err());
    }

    #[test]
    fn wh_d2_mock_restart_keeps_machine_credentials() {
        let mut first = MockBackend::new();
        let reg = first.register_platform_credential(wh_label(), &[]);
        assert!(reg.is_ok(), "{:?}", reg.err());
        let reg = reg.unwrap();
        let id = reg.credential.credential_id.clone();

        let mut restarted = MockBackend::new().with_platform_credentials(vec![id.clone()]);
        let got = restarted.get_platform_prf_secret(std::slice::from_ref(&id));
        assert!(
            matches!(&got, Ok((_, s)) if s == &*reg.creation_prf),
            "same machine after restart: {:?}",
            got.err()
        );
        let mut other_machine = MockBackend::new();
        assert!(matches!(
            other_machine.get_platform_prf_secret(std::slice::from_ref(&id)),
            Err(FidoError::PlatformCredentialMissing)
        ));
    }

    #[test]
    fn wh_d2_mock_roaming_path_rejects_platform_ids() {
        let mut b = MockBackend::new();
        let reg = b.register_platform_credential(wh_label(), &[]);
        assert!(reg.is_ok(), "{:?}", reg.err());
        let id = reg.unwrap().credential.credential_id;
        let one = b.get_prf_secret(&id, None);
        assert!(one.is_err(), "YubiKey path must not assert a platform id");
        let any = b.get_prf_secret_for_any(std::slice::from_ref(&id), None);
        assert!(any.is_err(), "YubiKey path must not assert a platform id");
        // roaming ID 仍正常
        let d = b.detect().unwrap();
        let roaming = b.register_credential(&d, None).unwrap();
        assert!(!MockBackend::is_mock_platform_credential(
            &roaming.credential_id
        ));
        assert!(b.get_prf_secret(&roaming.credential_id, None).is_ok());
    }

    #[test]
    fn wh_d2_mock_delete_unknown_and_twice() {
        let mut b = MockBackend::new();
        let reg = b.register_platform_credential(wh_label(), &[]);
        assert!(reg.is_ok(), "{:?}", reg.err());
        let id = reg.unwrap().credential.credential_id;
        assert!(b.delete_platform_credential(&id).is_ok());
        assert!(matches!(
            b.delete_platform_credential(&id),
            Err(FidoError::PlatformCredentialMissing)
        ));
        assert!(matches!(
            b.get_platform_prf_secret(std::slice::from_ref(&id)),
            Err(FidoError::PlatformCredentialMissing)
        ));
    }

    #[test]
    fn wh_d2_platform_registration_debug_redacts_prf() {
        let reg = PlatformRegistration {
            credential: RegisteredCredential {
                credential_id: vec![7u8; 4],
                aaguid: [0u8; 16],
                label: "L".into(),
                kind: KeyKind::WindowsManaged,
            },
            creation_prf: zeroize::Zeroizing::new([0xABu8; 32]),
        };
        let shown = format!("{reg:?}");
        assert!(!shown.contains("171"), "PRF bytes leaked: {shown}");
        assert!(
            !shown.to_lowercase().contains("ab, ab"),
            "PRF bytes leaked: {shown}"
        );
        assert!(shown.contains("redacted"), "{shown}");
    }

    #[test]
    fn wh_d2_platform_error_messages() {
        let exists = FidoError::PlatformCredentialExists.to_string();
        assert!(exists.contains("已註冊 Windows Hello"), "{exists}");
        assert!(exists.contains("未新增"), "{exists}");
        let prf = FidoError::PlatformPrfUnsupported.to_string();
        assert!(prf.contains("不支援金庫解鎖所需的 PRF"), "{prf}");
        assert!(prf.contains("未新增"), "{prf}");
        let missing = FidoError::PlatformCredentialMissing.to_string();
        assert!(missing.contains("這台電腦沒有"), "{missing}");
        // 既有 YubiKey 訊息不變
        assert!(FidoError::CredentialExcluded.to_string().contains("A 或 B"));
    }

    #[test]
    fn d9f1_mock_roaming_handoff_once_then_succeeds_and_logs_calls() {
        let mut b = MockBackend::new()
            .with_next_kind(KeyKind::TouchOnly)
            .with_roaming_handoff(MockHandoffRefusal::ForegroundHandoffRequired, 1);
        let detected = b.detect().expect("detect");
        let reg = b.register_credential(&detected, None).expect("register");
        assert!(matches!(
            b.get_prf_secret(&reg.credential_id, None),
            Err(FidoError::ForegroundHandoffRequired)
        ));
        assert!(matches!(
            b.get_prf_secret(&reg.credential_id, None),
            Ok(secret) if secret == MockBackend::prf_for_credential(&reg.credential_id)
        ));
        assert_eq!(
            b.calls(),
            &[
                MockCall::Detect,
                MockCall::RegisterCredential,
                MockCall::GetPrfSecret,
                MockCall::GetPrfSecret
            ]
        );
    }

    #[test]
    fn d9f1_mock_platform_handoff_counts_down_and_logs_delete() {
        let mut b =
            MockBackend::new().with_platform_handoff(MockHandoffRefusal::OwnerNotForeground, 2);
        let reg = b.register_platform_credential("x", &[]).expect("register");
        let ids = vec![reg.credential.credential_id.clone()];
        for _ in 0..2 {
            assert!(matches!(
                b.get_platform_prf_secret(&ids),
                Err(FidoError::OwnerNotForeground)
            ));
        }
        assert!(b.get_platform_prf_secret(&ids).is_ok());
        assert!(b.list_platform_credentials().is_ok());
        assert!(b.delete_platform_credential(&ids[0]).is_ok());
        assert_eq!(
            b.calls(),
            &[
                MockCall::RegisterPlatform,
                MockCall::GetPlatformPrf,
                MockCall::GetPlatformPrf,
                MockCall::GetPlatformPrf,
                MockCall::ListPlatform,
                MockCall::DeletePlatform
            ]
        );
        // roaming 注入不影響平台，反之亦然。
        let mut r = MockBackend::new()
            .with_next_kind(KeyKind::TouchOnly)
            .with_platform_handoff(MockHandoffRefusal::ForegroundHandoffRequired, 1);
        let d = r.detect().expect("detect");
        let reg = r.register_credential(&d, None).expect("register");
        assert!(r.get_prf_secret(&reg.credential_id, None).is_ok());
    }

    #[test]
    fn d9f1_handoff_error_messages() {
        assert_eq!(
            FidoError::ForegroundHandoffRequired.to_string(),
            "金鑰已建立，但 Windows 未將焦點交回 FidoVault；請按「繼續驗證」完成註冊，或按「取消」放棄。"
        );
        // 登入路徑使用者看到的文字不變：與舊 Internal(OWNER_NOT_FOREGROUND_MSG) 的顯示逐字相同。
        assert_eq!(
            FidoError::OwnerNotForeground.to_string(),
            FidoError::Internal(OWNER_NOT_FOREGROUND_MSG.into()).to_string()
        );
        assert!(FidoError::ForegroundHandoffRequired.is_foreground_handoff());
        assert!(FidoError::OwnerNotForeground.is_foreground_handoff());
        for other in [
            FidoError::NoDevice,
            FidoError::PlatformPrfUnsupported,
            FidoError::PlatformCredentialMissing,
            FidoError::Internal(OWNER_NOT_FOREGROUND_MSG.into()),
            FidoError::Internal("Windows WebAuthn continuation refused: owner-invalid".into()),
        ] {
            assert!(!other.is_foreground_handoff(), "{other:?}");
        }
    }

    #[test]
    fn credential_excluded_message_is_clear() {
        let m = FidoError::CredentialExcluded.to_string();
        assert!(m.contains("已註冊"), "{m}");
        assert!(m.contains("未新增"), "{m}");
    }

    /// 只實作必要方法的後端：驗證 trait 預設實作在非空排除清單時 fail closed。
    struct MinimalBackend(MockBackend);
    impl FidoBackend for MinimalBackend {
        fn detect(&mut self) -> Result<DetectedKey, FidoError> {
            self.0.detect()
        }
        fn register_credential(
            &mut self,
            d: &DetectedKey,
            pin: Option<&str>,
        ) -> Result<RegisteredCredential, FidoError> {
            self.0.register_credential(d, pin)
        }
        fn get_prf_secret(&mut self, id: &[u8], pin: Option<&str>) -> Result<[u8; 32], FidoError> {
            self.0.get_prf_secret(id, pin)
        }
    }

    #[test]
    fn default_excluding_registration_fails_closed_for_nonempty_list() {
        let mut b = MinimalBackend(MockBackend::new());
        let d = b.detect().unwrap();
        assert!(b.register_credential_excluding(&d, None, &[]).is_ok());
        let d = b.detect().unwrap();
        let r = b.register_credential_excluding(&d, Some("1234"), &[vec![0u8; 32]]);
        assert!(
            matches!(r, Err(FidoError::NotSupported(_))),
            "backend without exclusion support must refuse, got {:?}",
            r.map(|c| c.credential_id)
        );
    }

    #[test]
    fn mock_same_device_is_excluded() {
        let mut b = MockBackend::new();
        let d = b.detect().unwrap();
        let first = b.register_credential_excluding(&d, None, &[]).unwrap();
        b.reuse_device();
        let d = b.detect().unwrap();
        let again = b.register_credential_excluding(&d, None, &[first.credential_id.clone()]);
        assert!(
            matches!(again, Err(FidoError::CredentialExcluded)),
            "same mock device must be excluded, got {:?}",
            again.map(|c| c.credential_id)
        );
    }

    #[test]
    fn mock_other_device_is_not_excluded() {
        let mut b = MockBackend::new();
        let d = b.detect().unwrap();
        let first = b.register_credential_excluding(&d, None, &[]).unwrap();
        let d = b.detect().unwrap(); // 下一支（不同裝置）
        assert!(b
            .register_credential_excluding(&d, Some("1234"), &[first.credential_id.clone()])
            .is_ok());
        // 另一個 mock 實例 = 另一支實體金鑰，即使 seq 相同也不可誤判。
        let mut other = MockBackend::new();
        let d = other.detect().unwrap();
        assert!(other
            .register_credential_excluding(&d, None, &[first.credential_id.clone()])
            .is_ok());
    }

    #[test]
    fn mock_ignores_malformed_short_exclude_entries() {
        let mut b = MockBackend::new();
        let d = b.detect().unwrap();
        assert!(b
            .register_credential_excluding(&d, None, &[vec![], vec![1u8; 8]])
            .is_ok());
    }

    #[test]
    fn unavailable_backend_excluding_keeps_its_own_message() {
        let mut b = UnavailableBackend::new(1);
        let d = DetectedKey {
            kind: KeyKind::WindowsManaged,
            label: "x".into(),
            aaguid: [0; 16],
        };
        let e = b
            .register_credential_excluding(&d, None, &[vec![1u8; 16]])
            .unwrap_err();
        assert!(e.to_string().contains("WebAuthn API v1"), "{e}");
    }

    #[test]
    fn mock_credential_id_keeps_kind_prefix_and_prf_semantics() {
        let mut b = MockBackend::new().with_next_kind(KeyKind::Pin);
        let d = b.detect().unwrap();
        let reg = b
            .register_credential_excluding(&d, Some("1234"), &[])
            .unwrap();
        assert_eq!(reg.credential_id.len(), 32);
        assert_eq!(KeyKind::from_u8(reg.credential_id[0]), KeyKind::Pin);
        assert_eq!(
            b.get_prf_secret(&reg.credential_id, Some("1234")).unwrap(),
            MockBackend::prf_for_credential(&reg.credential_id)
        );
    }

    #[test]
    fn d9f2_platform_authenticator_substituted_message_is_exact_and_not_a_handoff() {
        let error = FidoError::PlatformAuthenticatorSubstituted;
        assert_eq!(
            error.to_string(),
            "Windows 以安全性金鑰完成，而非本機 Windows Hello；未註冊。該安全性金鑰上可能留下一筆 fido-vault.local 測試憑證，可用 YubiKey 管理工具移除。"
        );
        assert!(!error.is_foreground_handoff());
    }

    #[test]
    fn kind_parse_and_prompts() {
        assert_eq!(KeyKind::parse("pin"), Some(KeyKind::Pin));
        assert_eq!(KeyKind::parse("TOUCH_ONLY"), Some(KeyKind::TouchOnly));
        assert!(KeyKind::Fingerprint.prompt_zh().contains("指紋"));
        assert!(KeyKind::Pin.prompt_zh().contains("PIN"));
        assert!(KeyKind::TouchOnly.prompt_zh().contains("觸碰"));
        assert_eq!(
            KeyKind::parse("windows_managed"),
            Some(KeyKind::WindowsManaged)
        );
        assert!(KeyKind::WindowsManaged.prompt_zh().contains("Windows"));
    }
}
