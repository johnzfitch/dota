//! Vault file format (JSON serialization)

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Current vault file format version.
///
/// Version history:
/// v3:       Initial stable format. Master key used directly as AES wrapping key.
/// v3 → v4: Purpose-labeled HKDF-Expand for key wrapping (key separation).
///           The master key is no longer used directly as an AES key. Instead,
///           separate wrapping keys are derived via HKDF-Expand with distinct
///           purpose labels for ML-KEM and X25519 private key encryption.
/// v4 → v5: Refreshed HKDF wrapping labels (v5-specific domain separation).
///           Added min_version anti-rollback field. Automatic migration with
///           backup. No downgrade path: once upgraded, older binaries refuse
///           to open the vault.
pub const VAULT_VERSION: u32 = 5;

/// Minimum vault version that can be migrated forward to VAULT_VERSION.
/// Vaults older than this require an intermediate binary version first.
pub const MIN_SUPPORTED_VERSION: u32 = 3;

/// Top-level vault structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Vault {
    pub version: u32,
    /// Anti-rollback floor: the minimum binary version required to open this
    /// vault. Set to VAULT_VERSION on creation and on every migration. Older
    /// binaries that do not understand this field will already fail on the
    /// `version` check, but this provides an additional explicit safeguard
    /// against targeted downgrade attacks.
    #[serde(default)]
    pub min_version: u32,
    pub created: DateTime<Utc>,
    pub kdf: KdfParams,
    pub kem: KemKeyPair,
    pub x25519: X25519KeyPair,
    pub secrets: HashMap<String, EncryptedSecret>,
}

/// KDF parameters for passphrase derivation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KdfParams {
    pub algorithm: String, // Always "argon2id" for now
    #[serde(with = "base64_serde")]
    pub salt: Vec<u8>,
    pub time_cost: u32,
    pub memory_cost: u32,
    pub parallelism: u32,
}

/// ML-KEM keypair (public key + encrypted private key)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KemKeyPair {
    pub algorithm: String, // "ML-KEM-768"
    #[serde(with = "base64_serde")]
    pub public_key: Vec<u8>,
    #[serde(with = "base64_serde")]
    pub encrypted_private_key: Vec<u8>,
    #[serde(with = "base64_serde")]
    pub private_key_nonce: Vec<u8>,
}

/// X25519 keypair (public key + encrypted private key)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct X25519KeyPair {
    #[serde(with = "base64_serde")]
    pub public_key: Vec<u8>,
    #[serde(with = "base64_serde")]
    pub encrypted_private_key: Vec<u8>,
    #[serde(with = "base64_serde")]
    pub private_key_nonce: Vec<u8>,
}

/// Encrypted secret with hybrid KEM
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedSecret {
    pub algorithm: String, // "hybrid-mlkem768-x25519"
    #[serde(with = "base64_serde")]
    pub kem_ciphertext: Vec<u8>,
    #[serde(with = "base64_serde")]
    pub x25519_ephemeral_public: Vec<u8>,
    #[serde(with = "base64_serde")]
    pub nonce: Vec<u8>,
    #[serde(with = "base64_serde")]
    pub ciphertext: Vec<u8>,
    pub created: DateTime<Utc>,
    pub modified: DateTime<Utc>,
}

/// Helper module for base64 serialization
mod base64_serde {
    use base64::{Engine, engine::general_purpose::STANDARD};
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&STANDARD.encode(bytes))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        STANDARD.decode(s).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vault_serialization_round_trip() {
        let vault = Vault {
            version: VAULT_VERSION,
            min_version: VAULT_VERSION,
            created: Utc::now(),
            kdf: KdfParams {
                algorithm: "argon2id".to_string(),
                salt: vec![1, 2, 3, 4],
                time_cost: 3,
                memory_cost: 65536,
                parallelism: 4,
            },
            kem: KemKeyPair {
                algorithm: "ML-KEM-768".to_string(),
                public_key: vec![5; 1184],
                encrypted_private_key: vec![6; 2400],
                private_key_nonce: vec![7; 12],
            },
            x25519: X25519KeyPair {
                public_key: vec![8; 32],
                encrypted_private_key: vec![9; 32],
                private_key_nonce: vec![10; 12],
            },
            secrets: HashMap::new(),
        };

        let json = serde_json::to_string_pretty(&vault).unwrap();
        let deserialized: Vault = serde_json::from_str(&json).unwrap();

        assert_eq!(vault.version, deserialized.version);
        assert_eq!(vault.kdf.salt, deserialized.kdf.salt);
        assert_eq!(vault.kem.public_key, deserialized.kem.public_key);
    }
}
