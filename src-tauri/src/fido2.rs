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
            Self::NotSupported(m) => write!(f, "不支援：{m}"),
            Self::Internal(m) => write!(f, "FIDO2 內部錯誤：{m}"),
            Self::DeviceOpenDenied { what, last_err, attempts } => write!(
                f,
                "YubiKey FIDO HID open 被 Windows 拒絕（os error 5/32）；重試 {attempts} 次皆失敗（{what}）。 \
                 此錯誤無法確認 holder 身分或區分 share-lock/access policy；可能是其他 FIDO client、Windows WebAuthN / Windows Hello 正在使用介面，或 Windows access policy 拒絕。最後 vendor 回報：{last_err}。\
                 請先完成/取消安全金鑰操作並關閉瀏覽器 WebAuthn/Windows Hello 頁面；勿 force-kill svchost / BioEnrollmentHost。 \
                 本 CLI 目前走 raw HID；非管理員情境需採用 Windows WebAuthN API backend（Yubico sample 的路徑），或在管理員互動 session 執行。"
            ),
        }
    }
}

impl std::error::Error for FidoError {}

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
            seq: 0,
            next_kind_override: None,
            prf_enabled: true,
        }
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
        self.seq += 1; // 每支偵測到的金鑰都有獨立編號（label/AAGUID 唯一）
        let aaguid = mock_aaguid(self.seq);
        Ok(DetectedKey {
            kind,
            label: format!("Mock YubiKey #{}", self.seq),
            aaguid,
        })
    }

    fn register_credential(&mut self, detected: &DetectedKey, _pin: Option<&str>) -> Result<RegisteredCredential, FidoError> {
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
        self.next_kind_override.unwrap_or_else(|| KeyKind::from_u8((self.detect_count % 3) as u8))
    }

    fn prf_supported(&self) -> bool {
        // mock 預設模擬支援 PRF 的金鑰（YubiKey 5+）；with_prf(false) 模擬不支援者。
        self.prf_enabled
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
    use authenticator::ctap2::commands::client_pin::Pin;
    use authenticator::ctap2::commands::get_info::AuthenticatorInfo;
    use authenticator::{BioEnrollmentCmd, BioEnrollmentResult};
    use authenticator::ctap2::server::{
        AuthenticationExtensionsClientInputs, HMACGetSecretInput, PublicKeyCredentialDescriptor,
        PublicKeyCredentialParameters, PublicKeyCredentialUserEntity, RelyingParty,
        ResidentKeyRequirement, UserVerificationRequirement,
    };
    use authenticator::crypto::COSEAlgorithm;
    use authenticator::statecallback::StateCallback;
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
            Self { service, info: None }
        }

        /// 以既有 AuthenticatorService 建立（測試用：可注入 mock transport）。
        pub fn with_service(service: AuthenticatorService) -> Self {
            Self { service, info: None }
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
            let result: Arc<Mutex<Option<Result<BioEnrollmentResult, authenticator::errors::AuthenticatorError>>>> =
                Arc::new(Mutex::new(None));
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
                                if tx.send(InteractiveRequest::BioEnrollment(
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

            if self.service.manage(DETECT_TIMEOUT_MS, status_tx, cb).is_err() {
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
                    let desc = other.as_ref().map(|r| match r {
                        Ok(BioEnrollmentResult::FingerprintSensorInfo(_)) => "sensor-info".to_string(),
                        Ok(BioEnrollmentResult::EnrollmentList(v)) => format!("enroll-list({})", v.len()),
                        Ok(_) => "other-result".to_string(),
                        Err(e) => format!("err: {e:?}"),
                    }).unwrap_or_else(|| "no-result".to_string());
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
            let result: Arc<Mutex<Option<Result<BioEnrollmentResult, authenticator::errors::AuthenticatorError>>>> =
                Arc::new(Mutex::new(None));
            let done = Arc::new(AtomicBool::new(false));

            {
                let (result3, done3) = (result.clone(), done.clone());
                std::thread::spawn(move || {
                    for msg in status_rx.iter() {
                        match msg {
                            authenticator::StatusUpdate::InteractiveManagement(
                                InteractiveUpdate::StartManagement((tx, _info)),
                            ) => {
                                if tx.send(InteractiveRequest::BioEnrollment(
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

            if self.service.manage(DETECT_TIMEOUT_MS, status_tx, cb).is_err() {
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
        fn do_register(&mut self, detected: &DetectedKey, pin: Option<&str>) -> Result<RegisteredCredential, FidoError> {
            let args = RegisterArgs {
                client_data_hash: Self::op_client_data_hash(b"register"),
                relying_party: RelyingParty::from(RP_ID),
                origin: RP_ID.to_string(),
                user: PublicKeyCredentialUserEntity {
                    id: random_bytes16(),
                    name: Some("vault-user".to_string()),
                    display_name: None,
                },
                pub_cred_params: vec![PublicKeyCredentialParameters { alg: COSEAlgorithm::ES256 }],
                exclude_list: vec![],
                user_verification_req: UserVerificationRequirement::Preferred,
                resident_key_req: ResidentKeyRequirement::Preferred,
                extensions: AuthenticationExtensionsClientInputs {
                    hmac_create_secret: Some(true), // 註冊即宣告支援 hmac-secret（裁決②）
                    ..Default::default()
                },
                pin: pin.map(|p| Pin::new(p)),
                use_ctap1_fallback: false,
            };

            let res = self.run_op(OP_TIMEOUT_MS, |svc, status, cb| {
                svc.register(OP_TIMEOUT_MS, args, status, cb)?;
                Ok(())
            })?;

            // credential_id 來自 att_obj.auth_data.credential_data。
            let cred = res.att_obj.auth_data.credential_data.as_ref().ok_or_else(|| {
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
                pin: pin.map(|p| Pin::new(p)),
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

        fn register_credential(&mut self, detected: &DetectedKey, pin: Option<&str>) -> Result<RegisteredCredential, FidoError> {
            // contention-aware retry：makeCredential 前 device open 被拒 → backoff 重試。
            self.retry_on_contention("register", |b: &mut Self| b.do_register(detected, pin))
        }

        fn get_prf_secret(&mut self, credential_id: &[u8], pin: Option<&str>) -> Result<[u8; 32], FidoError> {
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

    fn map_auth_error(e: authenticator::errors::AuthenticatorError) -> FidoError {
        use authenticator::errors::AuthenticatorError as AE;
        match e {
            AE::NoConfiguredTransports => FidoError::NoDevice,
            AE::CancelledByUser => FidoError::Internal("使用者取消 / 超時".into()),
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
            AuthenticatorInfo { options: opts, ..Default::default() }
        }

        /// YubiKey 5 系列：無 clientPin、無 bioEnroll → touch-only（PM 預先提醒的預期結果）。
        #[test]
        fn real_kind_touch_only_yubikey5_profile() {
            let o = AuthenticatorOptions::default();
            assert_eq!(RealBackend::kind_from_info(&info_with(o)), KeyKind::TouchOnly);
        }

        /// 指紋優先於 PIN（YubiKey Bio：兩者皆有）。
        #[test]
        fn real_kind_fingerprint_wins_over_pin() {
            let mut o = AuthenticatorOptions::default();
            o.bio_enroll = Some(true);
            o.client_pin = Some(true);
            assert_eq!(RealBackend::kind_from_info(&info_with(o)), KeyKind::Fingerprint);
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
            assert_eq!(RealBackend::kind_from_info(&info_with(o)), KeyKind::Fingerprint);
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
        let reg = b.register_credential(&d, None).unwrap();
        assert!(b.get_prf_secret(&reg.credential_id, None).is_ok());

        // 第二支：pin 型 → 註冊後登入需 PIN，且跨「新行程」仍一致
        let mut b2 = MockBackend::new().with_next_kind(KeyKind::Pin);
        let d2 = b2.detect().unwrap();
        assert_eq!(d2.kind, KeyKind::Pin);
        let reg2 = b2.register_credential(&d2, None).unwrap();
        let mut fresh = MockBackend::new(); // 模擬重啟
        assert!(matches!(fresh.get_prf_secret(&reg2.credential_id, None), Err(FidoError::PinRequired(_))));
        assert!(matches!(fresh.get_prf_secret(&reg2.credential_id, Some("12")), Err(FidoError::PinRejected)));
        let s = fresh.get_prf_secret(&reg2.credential_id, Some("1234")).unwrap();
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
