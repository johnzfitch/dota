//! Key derivation using Argon2id
//!
//! Derives a 256-bit master key from a passphrase using Argon2id with
//! hardened parameters: t=3, m=65536 KiB (64 MiB), p=4

use anyhow::Result;
use argon2::{
    password_hash::SaltString,
    Algorithm, Argon2, Params, Version,
};
use rand::rngs::OsRng;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Master key derived from passphrase (256 bits)
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct MasterKey([u8; 32]);

impl MasterKey {
    /// Access the raw key bytes
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Create from raw bytes (for testing)
    #[cfg(test)]
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

/// KDF configuration matching vault format
#[derive(Debug, Clone)]
pub struct KdfConfig {
    pub salt: Vec<u8>,
    pub time_cost: u32,
    pub memory_cost: u32,
    pub parallelism: u32,
}

impl Default for KdfConfig {
    fn default() -> Self {
        Self {
            salt: Vec::new(), // Will be generated
            time_cost: 3,
            memory_cost: 65536, // 64 MiB
            parallelism: 4,
        }
    }
}

/// Generate a random salt for KDF
pub fn generate_salt() -> Vec<u8> {
    SaltString::generate(&mut OsRng).as_str().as_bytes().to_vec()
}

/// Derive master key from passphrase using Argon2id
pub fn derive_key(passphrase: &str, config: &KdfConfig) -> Result<MasterKey> {
    let params = Params::new(
        config.memory_cost,
        config.time_cost,
        config.parallelism,
        Some(32), // Output length: 32 bytes
    )
    .map_err(|e| anyhow::anyhow!("Invalid Argon2 parameters: {}", e))?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    // Use raw salt bytes directly
    let mut output = [0u8; 32];
    argon2
        .hash_password_into(passphrase.as_bytes(), &config.salt, &mut output)
        .map_err(|e| anyhow::anyhow!("Argon2 derivation failed: {}", e))?;

    Ok(MasterKey(output))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_derive_key_deterministic() {
        let passphrase = "test-passphrase-123";
        let config = KdfConfig {
            salt: b"fixed-salt-for-testing-12345".to_vec(),
            time_cost: 1, // Faster for tests
            memory_cost: 8192,
            parallelism: 1,
        };

        let key1 = derive_key(passphrase, &config).unwrap();
        let key2 = derive_key(passphrase, &config).unwrap();

        assert_eq!(key1.as_bytes(), key2.as_bytes());
    }

    #[test]
    fn test_different_passphrases_different_keys() {
        let config = KdfConfig {
            salt: b"fixed-salt-for-testing-12345".to_vec(),
            time_cost: 1,
            memory_cost: 8192,
            parallelism: 1,
        };

        let key1 = derive_key("password1", &config).unwrap();
        let key2 = derive_key("password2", &config).unwrap();

        assert_ne!(key1.as_bytes(), key2.as_bytes());
    }

    #[test]
    fn test_different_salts_different_keys() {
        let passphrase = "test-passphrase";

        let config1 = KdfConfig {
            salt: b"salt1-for-testing-1234567890".to_vec(),
            time_cost: 1,
            memory_cost: 8192,
            parallelism: 1,
        };

        let config2 = KdfConfig {
            salt: b"salt2-for-testing-0987654321".to_vec(),
            time_cost: 1,
            memory_cost: 8192,
            parallelism: 1,
        };

        let key1 = derive_key(passphrase, &config1).unwrap();
        let key2 = derive_key(passphrase, &config2).unwrap();

        assert_ne!(key1.as_bytes(), key2.as_bytes());
    }

    #[test]
    fn test_salt_generation() {
        let salt1 = generate_salt();
        let salt2 = generate_salt();

        assert_ne!(salt1, salt2);
        assert!(!salt1.is_empty());
        assert!(!salt2.is_empty());
    }

    #[test]
    fn test_from_bytes_constructor() {
        let key = MasterKey::from_bytes([0x17; 32]);
        assert_eq!(key.as_bytes(), &[0x17; 32]);
    }
}
