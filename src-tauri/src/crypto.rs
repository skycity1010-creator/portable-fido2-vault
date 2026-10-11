//! 加密原語：Argon2id KDF、AES-256-GCM、HKDF-SHA256。
//! 參數與 domain separation 字串定義於 docs/spec.md §4。

use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Nonce,
};
use argon2::{Algorithm, Argon2, Version};
use hkdf::Hkdf;
use rand::{rngs::OsRng, RngCore};
use sha2::Sha256;
use zeroize::Zeroizing;

/// 金庫檔案魔數（magic）與格式版本。
pub const VAULT_MAGIC: &[u8; 6] = b"F2VLT\x01";
pub const FORMAT_VERSION: u8 = 1;
/// 雙群組控管版（dual-control）金庫格式版本。
pub const FORMAT_VERSION_DUAL: u8 = 2;

/// Argon2id 參數（OWASP 建議量級；t=3, m=19MiB, p=4）。
pub const ARGON2_T_COST: u32 = 3;
pub const ARGON2_M_COST: u32 = 19_456; // KiB = 19 MiB
pub const ARGON2_P_COST: u32 = 4;

/// 固定 PRF salt（domain separation，非機密）。
pub const PRF_SALT: &[u8] = b"f2vlt-prf-salt-v1";
/// HKDF domain 字串。
pub const HKDF_SALT_DOMAIN: &[u8] = b"f2vlt-domain-v1";
pub const HKDF_INFO_KEK_WRAP: &[u8] = b"f2vlt-kek-wrap-v1";
/// 雙群組控管版：由 share_A ‖ share_B 派生 dual_slot 包裝金鑰（docs/plans/dual-control.md §2.2）。
pub const HKDF_INFO_DUAL_KEK: &[u8] = b"f2vlt-dual-v2";
/// 雙群組控管版：金鑰槽 AES-GCM AAD 前綴；後接群組標記、`|`、credential_id 原始位元組。
pub const DUAL_KEY_SLOT_AAD_PREFIX: &[u8] = b"f2vlt-v2|";
/// 雙群組控管版：dual_slot（包裝 KEK）的 AES-GCM AAD（domain separation）。
pub const DUAL_SLOT_AAD: &[u8] = b"f2vlt-v2|dual-slot";

#[derive(Debug)]
pub enum CryptoError {
    BadLength,
    DecryptFailed,
    Kdf(String),
}

impl std::fmt::Display for CryptoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BadLength => write!(f, "金流/參數長度錯誤"),
            Self::DecryptFailed => write!(f, "解密失敗（tag 驗證不符）"),
            Self::Kdf(m) => write!(f, "Argon2 派生失敗: {m}"),
        }
    }
}

impl std::error::Error for CryptoError {}

/// Argon2id → 32-byte KEK。salt 為原始位元組（建議 32B）。
pub fn argon2id_derive(password: &[u8], salt: &[u8]) -> Result<[u8; 32], CryptoError> {
    let mut out = [0u8; 32];
    Argon2::new(
        Algorithm::Argon2id,
        Version::V0x13,
        // argon2 crate 的 m_cost 單位是 KiB（直接傳 19456，勿再乘 1024）
        argon2::Params::new(ARGON2_M_COST, ARGON2_T_COST, ARGON2_P_COST, None)
            .map_err(|e| CryptoError::Kdf(e.to_string()))?,
    )
    // hash_password_into 直接吃原始 salt byte（不需 base64 包裝）
    .hash_password_into(password, salt, &mut out)
    .map_err(|e| CryptoError::Kdf(e.to_string()))?;
    Ok(out)
}

/// AES-256-GCM 加密；回傳 ciphertext(含 16B tag)。
pub fn aes_gcm_encrypt(key: &[u8; 32], nonce: &[u8; 12], plaintext: &[u8]) -> Vec<u8> {
    let cipher = Aes256Gcm::new_from_slice(key).expect("32-byte key");
    cipher
        .encrypt(Nonce::from_slice(nonce), plaintext)
        .expect("GCM encrypt cannot fail")
}

/// AES-256-GCM 解密；ciphertext 含尾端 16B tag。
pub fn aes_gcm_decrypt(
    key: &[u8; 32],
    nonce: &[u8; 12],
    ciphertext_with_tag: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let cipher = Aes256Gcm::new_from_slice(key).expect("32-byte key");
    cipher
        .decrypt(Nonce::from_slice(nonce), ciphertext_with_tag)
        .map_err(|_| CryptoError::DecryptFailed)
}

/// HKDF-SHA256 → 32 bytes。
pub fn hkdf_derive(ikm: &[u8], info: &[u8]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(Some(HKDF_SALT_DOMAIN), ikm);
    let mut okm = [0u8; 32];
    hk.expand(info, &mut okm).expect("HKDF expand 32B");
    okm
}

/// 隨機 32-byte KEK（以 Zeroizing 包裝，落盤/上鎖時清零）。
pub fn random_kek() -> Zeroizing<[u8; 32]> {
    let mut b = [0u8; 32];
    OsRng.fill_bytes(&mut b);
    Zeroizing::new(b)
}

/// 隨機 12-byte GCM nonce。
pub fn random_nonce() -> [u8; 12] {
    let mut b = [0u8; 12];
    OsRng.fill_bytes(&mut b);
    b
}

/// base64（standard, padded）。
pub fn base64_encode(b: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(b)
}

pub fn base64_decode(s: &str) -> Result<Vec<u8>, CryptoError> {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD
        .decode(s.trim())
        .map_err(|_| CryptoError::BadLength)
}

/// 以 PRF secret（32B，來自 FIDO2 hmac-secret）派生 KEK。
pub fn kek_from_prf_secret(prf_secret: &[u8; 32]) -> [u8; 32] {
    hkdf_derive(prf_secret, HKDF_INFO_KEK_WRAP)
}

/// 以固定 PRF salt 計算 hmac-secret 的 salt1（32B）。
pub fn prf_salt_bytes() -> [u8; 32] {
    let mut s = [0u8; 32];
    s[..PRF_SALT.len().min(32)].copy_from_slice(&PRF_SALT[..PRF_SALT.len().min(32)]);
    s
}

// ─────────────────────────── 雙群組控管（dual-control） ───────────────────────────

/// 金鑰群組。header 以 "A" / "B" 存放；群組綁定於金鑰槽 AAD，竄改即解包失敗。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum KeyGroup {
    A,
    B,
}

impl KeyGroup {
    /// AAD 用的單一位元組標記（固定長度，避免與 credential_id 串接產生歧義）。
    pub const fn aad_tag(self) -> u8 {
        match self {
            Self::A => b'A',
            Self::B => b'B',
        }
    }

    /// 另一個群組（兩步驟登入第二步要求的群組）。
    pub const fn other(self) -> Self {
        match self {
            Self::A => Self::B,
            Self::B => Self::A,
        }
    }
}

/// AES-256-GCM 加密（含 AAD）；回傳 ciphertext(含 16B tag)。
pub fn aes_gcm_encrypt_aad(
    key: &[u8; 32],
    nonce: &[u8; 12],
    plaintext: &[u8],
    aad: &[u8],
) -> Vec<u8> {
    let cipher = Aes256Gcm::new_from_slice(key).expect("32-byte key");
    cipher
        .encrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .expect("GCM encrypt cannot fail")
}

/// AES-256-GCM 解密（含 AAD）；AAD 或 ciphertext 不符 → DecryptFailed。
pub fn aes_gcm_decrypt_aad(
    key: &[u8; 32],
    nonce: &[u8; 12],
    ciphertext_with_tag: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let cipher = Aes256Gcm::new_from_slice(key).expect("32-byte key");
    cipher
        .decrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: ciphertext_with_tag,
                aad,
            },
        )
        .map_err(|_| CryptoError::DecryptFailed)
}

/// 金鑰槽 AAD：`"f2vlt-v2|" ‖ group_tag ‖ "|" ‖ credential_id`。
pub fn dual_key_slot_aad(group: KeyGroup, credential_id: &[u8]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(DUAL_KEY_SLOT_AAD_PREFIX.len() + 2 + credential_id.len());
    aad.extend_from_slice(DUAL_KEY_SLOT_AAD_PREFIX);
    aad.push(group.aad_tag());
    aad.push(b'|');
    aad.extend_from_slice(credential_id);
    aad
}

/// 由兩群組 share 派生 dual_slot 包裝金鑰：HKDF(share_A ‖ share_B, "f2vlt-dual-v2")。
/// 參數順序固定為 A、B（與登入時哪一群組先驗證無關）。
pub fn dual_wrap_key_from_shares(share_a: &[u8; 32], share_b: &[u8; 32]) -> Zeroizing<[u8; 32]> {
    let mut ikm = Zeroizing::new([0u8; 64]);
    ikm[..32].copy_from_slice(share_a);
    ikm[32..].copy_from_slice(share_b);
    Zeroizing::new(hkdf_derive(ikm.as_slice(), HKDF_INFO_DUAL_KEK))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gcm_roundtrip() {
        let key = [7u8; 32];
        let nonce = [1u8; 12];
        let ct = aes_gcm_encrypt(&key, &nonce, b"hello vault");
        let pt = aes_gcm_decrypt(&key, &nonce, &ct).unwrap();
        assert_eq!(pt, b"hello vault");
    }

    #[test]
    fn gcm_tamper_fails() {
        let key = [7u8; 32];
        let nonce = [1u8; 12];
        let mut ct = aes_gcm_encrypt(&key, &nonce, b"hello vault");
        ct[0] ^= 0xFF;
        assert!(aes_gcm_decrypt(&key, &nonce, &ct).is_err());
    }

    #[test]
    fn argon2_deterministic() {
        let salt = [9u8; 32];
        let a = argon2id_derive(b"pw", &salt).unwrap();
        let b = argon2id_derive(b"pw", &salt).unwrap();
        assert_eq!(a, b);
        let c = argon2id_derive(b"pw2", &salt).unwrap();
        assert_ne!(a, c);
    }

    #[test]
    fn hkdf_stable() {
        let a = hkdf_derive(b"ikm", HKDF_INFO_KEK_WRAP);
        let b = hkdf_derive(b"ikm", HKDF_INFO_KEK_WRAP);
        assert_eq!(a, b);
    }

    // ── dual-control（D2）──

    #[test]
    fn gcm_aad_roundtrip() {
        let key = [7u8; 32];
        let nonce = [1u8; 12];
        let ct = aes_gcm_encrypt_aad(&key, &nonce, b"share", b"aad-1");
        let pt = aes_gcm_decrypt_aad(&key, &nonce, &ct, b"aad-1").unwrap();
        assert_eq!(pt, b"share");
    }

    #[test]
    fn gcm_aad_mismatch_fails() {
        let key = [7u8; 32];
        let nonce = [1u8; 12];
        let ct = aes_gcm_encrypt_aad(&key, &nonce, b"share", b"aad-1");
        assert!(matches!(
            aes_gcm_decrypt_aad(&key, &nonce, &ct, b"aad-2"),
            Err(CryptoError::DecryptFailed)
        ));
        assert!(matches!(
            aes_gcm_decrypt_aad(&key, &nonce, &ct, b""),
            Err(CryptoError::DecryptFailed)
        ));
    }

    #[test]
    fn gcm_aad_empty_is_compatible_with_v1_gcm() {
        let key = [7u8; 32];
        let nonce = [1u8; 12];
        let v1 = aes_gcm_encrypt(&key, &nonce, b"kek");
        assert_eq!(aes_gcm_encrypt_aad(&key, &nonce, b"kek", b""), v1);
        assert_eq!(aes_gcm_decrypt_aad(&key, &nonce, &v1, b"").unwrap(), b"kek");
    }

    #[test]
    fn dual_key_slot_aad_layout_is_prefix_group_separator_credential() {
        let aad = dual_key_slot_aad(KeyGroup::A, &[0x01, 0x02, 0xff]);
        assert_eq!(aad, b"f2vlt-v2|A|\x01\x02\xff".to_vec());
        let aad_b = dual_key_slot_aad(KeyGroup::B, &[0x01, 0x02, 0xff]);
        assert_eq!(aad_b, b"f2vlt-v2|B|\x01\x02\xff".to_vec());
    }

    #[test]
    fn dual_key_slot_aad_binds_group_and_credential() {
        let cred = [9u8; 16];
        assert_ne!(
            dual_key_slot_aad(KeyGroup::A, &cred),
            dual_key_slot_aad(KeyGroup::B, &cred)
        );
        assert_ne!(
            dual_key_slot_aad(KeyGroup::A, &cred),
            dual_key_slot_aad(KeyGroup::A, &[8u8; 16])
        );
    }

    #[test]
    fn relabeled_group_slot_fails_to_unwrap() {
        let wrap = [5u8; 32];
        let nonce = [2u8; 12];
        let cred = [3u8; 20];
        let ct = aes_gcm_encrypt_aad(
            &wrap,
            &nonce,
            &[0x11; 32],
            &dual_key_slot_aad(KeyGroup::A, &cred),
        );
        assert!(
            aes_gcm_decrypt_aad(&wrap, &nonce, &ct, &dual_key_slot_aad(KeyGroup::B, &cred))
                .is_err()
        );
        assert!(
            aes_gcm_decrypt_aad(&wrap, &nonce, &ct, &dual_key_slot_aad(KeyGroup::A, &cred)).is_ok()
        );
    }

    #[test]
    fn dual_wrap_key_known_answer() {
        // 獨立計算（Python hmac/hashlib RFC 5869）：salt=f2vlt-domain-v1, ikm=0x11*32‖0x22*32, info=f2vlt-dual-v2
        let k = dual_wrap_key_from_shares(&[0x11; 32], &[0x22; 32]);
        let hex: String = k.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(
            hex,
            "a1d775d82fcbede061f7786fd7f05b29c02287767fd1c06e71d64e29feaa988b"
        );
    }

    #[test]
    fn dual_wrap_key_depends_on_both_shares_and_order() {
        let a = [0x11u8; 32];
        let b = [0x22u8; 32];
        let base = dual_wrap_key_from_shares(&a, &b);
        assert_ne!(*base, *dual_wrap_key_from_shares(&a, &[0x23; 32]));
        assert_ne!(*base, *dual_wrap_key_from_shares(&[0x12; 32], &b));
        assert_ne!(*base, *dual_wrap_key_from_shares(&b, &a));
        assert_ne!(*base, kek_from_prf_secret(&a));
    }

    #[test]
    fn key_group_tags_other_and_serde() {
        assert_eq!(KeyGroup::A.aad_tag(), b'A');
        assert_eq!(KeyGroup::B.aad_tag(), b'B');
        assert_eq!(KeyGroup::A.other(), KeyGroup::B);
        assert_eq!(KeyGroup::B.other(), KeyGroup::A);
        assert_eq!(serde_json::to_value(KeyGroup::A).unwrap(), "A");
        assert_eq!(
            serde_json::from_str::<KeyGroup>("\"B\"").unwrap(),
            KeyGroup::B
        );
        assert!(serde_json::from_str::<KeyGroup>("\"C\"").is_err());
        assert!(serde_json::from_str::<KeyGroup>("\"a\"").is_err());
    }
}
