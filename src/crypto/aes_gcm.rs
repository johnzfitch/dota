//! AES-256-GCM authenticated encryption

use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm, Nonce,
};
use anyhow::{Context, Result};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// AES-256 key (256 bits)
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct AesKey([u8; 32]);

impl AesKey {
    /// Create from raw bytes
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Access the raw key bytes
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Generate a random 96-bit nonce for AES-GCM
pub fn generate_nonce() -> [u8; 12] {
    use aes_gcm::aead::rand_core::RngCore;
    let mut nonce = [0u8; 12];
    OsRng.fill_bytes(&mut nonce);
    nonce
}

/// Encrypt plaintext using AES-256-GCM
pub fn encrypt(key: &AesKey, plaintext: &[u8]) -> Result<(Vec<u8>, [u8; 12])> {
    let cipher = Aes256Gcm::new_from_slice(key.as_bytes())
        .context("Invalid AES key length")?;

    let nonce_bytes = generate_nonce();
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| anyhow::anyhow!("AES-GCM encryption failed: {}", e))?;

    Ok((ciphertext, nonce_bytes))
}

/// Decrypt ciphertext using AES-256-GCM
pub fn decrypt(key: &AesKey, ciphertext: &[u8], nonce: &[u8; 12]) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new_from_slice(key.as_bytes())
        .context("Invalid AES key length")?;

    let nonce = Nonce::from_slice(nonce);

    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| anyhow::anyhow!("AES-GCM decryption failed (wrong key or corrupted data): {}", e))?;

    Ok(plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_round_trip() {
        let key = AesKey::from_bytes([42u8; 32]);
        let plaintext = b"secret message for testing";

        let (ciphertext, nonce) = encrypt(&key, plaintext).unwrap();
        let decrypted = decrypt(&key, &ciphertext, &nonce).unwrap();

        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_different_keys_fail_decryption() {
        let key1 = AesKey::from_bytes([1u8; 32]);
        let key2 = AesKey::from_bytes([2u8; 32]);
        let plaintext = b"secret";

        let (ciphertext, nonce) = encrypt(&key1, plaintext).unwrap();
        let result = decrypt(&key2, &ciphertext, &nonce);

        assert!(result.is_err());
    }

    #[test]
    fn test_wrong_nonce_fails_decryption() {
        let key = AesKey::from_bytes([42u8; 32]);
        let plaintext = b"secret";

        let (ciphertext, _nonce) = encrypt(&key, plaintext).unwrap();
        let wrong_nonce = [99u8; 12];
        let result = decrypt(&key, &ciphertext, &wrong_nonce);

        assert!(result.is_err());
    }

    #[test]
    fn test_nonce_uniqueness() {
        let nonce1 = generate_nonce();
        let nonce2 = generate_nonce();

        assert_ne!(nonce1, nonce2);
    }

    #[test]
    fn test_ciphertext_differs_from_plaintext() {
        let key = AesKey::from_bytes([42u8; 32]);
        let plaintext = b"hello world";

        let (ciphertext, _nonce) = encrypt(&key, plaintext).unwrap();

        assert_ne!(plaintext.as_slice(), &ciphertext[..plaintext.len()]);
    }
}
