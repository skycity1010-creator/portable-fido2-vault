//! 加密原語：Argon2id KDF、AES-256-GCM、HKDF-SHA256。
//! 參數與 domain separation 字串定義於 docs/spec.md §4。

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use argon2::{
    Argon2, Algorithm, Version,
};
use hkdf::Hkdf;
use rand::{rngs::OsRng, RngCore};
use sha2::Sha256;
use zeroize::Zeroizing;

/// 金庫檔案魔數（magic）與格式版本。
pub const VAULT_MAGIC: &[u8; 6] = b"F2VLT\x01";
pub const FORMAT_VERSION: u8 = 1;

/// Argon2id 參數（OWASP 建議量級；t=3, m=19MiB, p=4）。
pub const ARGON2_T_COST: u32 = 3;
pub const ARGON2_M_COST: u32 = 19_456; // KiB = 19 MiB
pub const ARGON2_P_COST: u32 = 4;

/// 固定 PRF salt（domain separation，非機密）。
pub const PRF_SALT: &[u8] = b"f2vlt-prf-salt-v1";
/// HKDF domain 字串。
pub const HKDF_SALT_DOMAIN: &[u8] = b"f2vlt-domain-v1";
pub const HKDF_INFO_KEK_WRAP: &[u8] = b"f2vlt-kek-wrap-v1";

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
pub fn aes_gcm_decrypt(key: &[u8; 32], nonce: &[u8; 12], ciphertext_with_tag: &[u8]) -> Result<Vec<u8>, CryptoError> {
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
}
