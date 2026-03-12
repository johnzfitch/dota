//! Legacy vault format definitions for migration
//!
//! Contains deserialization-only structs for reading vault formats v1-v5.
//! These are never serialized back — vaults are always written in the current format.

use chrono::{DateTime, Utc};
use serde::Deserialize;
use std::collections::HashMap;

/// Minimal probe to read just the version number from any vault JSON.
#[derive(Deserialize)]
pub struct VaultVersionProbe {
    pub version: u32,
}

// ---------------------------------------------------------------------------
// v1: X25519-only, master key used directly as AES wrapping key,
//     per-secret encryption via raw X25519 DH output as AES key.
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
#[allow(dead_code)]
pub struct VaultV1 {
    pub version: u32,
    pub created: DateTime<Utc>,
    pub kdf: super::format::KdfParams,
    #[serde(with = "super::format::base64_serde")]
    pub x25519_public_key: Vec<u8>,
    #[serde(with = "super::format::base64_serde")]
    pub encrypted_private_key: Vec<u8>,
    #[serde(with = "super::format::base64_serde")]
    pub private_key_nonce: Vec<u8>,
    pub secrets: HashMap<String, EncryptedSecretV1>,
}

#[derive(Deserialize)]
pub struct EncryptedSecretV1 {
    #[serde(with = "super::format::base64_serde")]
    pub x25519_ephemeral_public: Vec<u8>,
    #[serde(with = "super::format::base64_serde")]
    pub nonce: Vec<u8>,
    #[serde(with = "super::format::base64_serde")]
    pub ciphertext: Vec<u8>,
    pub created: DateTime<Utc>,
    pub modified: DateTime<Utc>,
}

// ---------------------------------------------------------------------------
// v2: Added hybrid KEM (ML-KEM-768 + X25519), flat field layout,
//     master key still used directly as AES wrapping key.
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
#[allow(dead_code)]
pub struct VaultV2 {
    pub version: u32,
    pub created: DateTime<Utc>,
    pub kdf: super::format::KdfParams,
    #[serde(with = "super::format::base64_serde")]
    pub mlkem_public_key: Vec<u8>,
    #[serde(with = "super::format::base64_serde")]
    pub encrypted_mlkem_private_key: Vec<u8>,
    #[serde(with = "super::format::base64_serde")]
    pub mlkem_private_key_nonce: Vec<u8>,
    #[serde(with = "super::format::base64_serde")]
    pub x25519_public_key: Vec<u8>,
    #[serde(with = "super::format::base64_serde")]
    pub encrypted_x25519_private_key: Vec<u8>,
    #[serde(with = "super::format::base64_serde")]
    pub x25519_private_key_nonce: Vec<u8>,
    pub secrets: HashMap<String, super::format::EncryptedSecret>,
}

// ---------------------------------------------------------------------------
// v3: Nested struct layout (same crypto as v2 — master key used directly).
//     Same JSON shape as v4/v5 but without HKDF key separation.
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
#[allow(dead_code)]
pub struct VaultV3 {
    pub version: u32,
    pub created: DateTime<Utc>,
    pub kdf: super::format::KdfParams,
    pub kem: super::format::KemKeyPair,
    pub x25519: super::format::X25519KeyPair,
    pub secrets: HashMap<String, super::format::EncryptedSecret>,
}

// ---------------------------------------------------------------------------
// v4: Same cryptography as v3, but with HKDF-derived wrapping keys.
//     No key commitment, no migration metadata, no v6 suite labeling.
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
#[allow(dead_code)]
pub struct VaultV4 {
    pub version: u32,
    pub created: DateTime<Utc>,
    pub kdf: super::format::KdfParams,
    pub kem: super::format::KemKeyPair,
    pub x25519: LegacyX25519KeyPair,
    pub secrets: HashMap<String, super::format::EncryptedSecret>,
}

// ---------------------------------------------------------------------------
// v5: Adds key commitment and migration metadata, but still lacks v6 suite
//     labeling and explicit X25519 algorithm metadata.
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
#[allow(dead_code)]
pub struct VaultV5 {
    pub version: u32,
    pub created: DateTime<Utc>,
    pub kdf: super::format::KdfParams,
    #[serde(default, with = "super::format::opt_base64_serde")]
    pub key_commitment: Option<Vec<u8>>,
    pub kem: super::format::KemKeyPair,
    pub x25519: LegacyX25519KeyPair,
    pub secrets: HashMap<String, super::format::EncryptedSecret>,
    #[serde(default)]
    pub migrated_from: Option<super::format::MigrationInfo>,
    #[serde(default)]
    pub min_version: u32,
}

/// Pre-v6 X25519 keypair layout, which had no explicit algorithm field.
#[derive(Deserialize)]
#[allow(dead_code)]
pub struct LegacyX25519KeyPair {
    #[serde(with = "super::format::base64_serde")]
    pub public_key: Vec<u8>,
    #[serde(with = "super::format::base64_serde")]
    pub encrypted_private_key: Vec<u8>,
    #[serde(with = "super::format::base64_serde")]
    pub private_key_nonce: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{Engine as _, engine::general_purpose::STANDARD};

    #[test]
    fn test_v5_legacy_shape_parses_without_v6_fields() {
        let json = serde_json::json!({
            "version": 5,
            "created": "2026-01-01T00:00:00Z",
            "kdf": {
                "algorithm": "argon2id",
                "salt": STANDARD.encode(b"legacy-salt-12345"),
                "time_cost": 3,
                "memory_cost": 65536,
                "parallelism": 4
            },
            "key_commitment": STANDARD.encode(vec![0xAB; 32]),
            "kem": {
                "algorithm": "ML-KEM-768",
                "public_key": STANDARD.encode(vec![5u8; 1184]),
                "encrypted_private_key": STANDARD.encode(vec![6u8; 2400]),
                "private_key_nonce": STANDARD.encode(vec![7u8; 12])
            },
            "x25519": {
                "public_key": STANDARD.encode(vec![8u8; 32]),
                "encrypted_private_key": STANDARD.encode(vec![9u8; 32]),
                "private_key_nonce": STANDARD.encode(vec![10u8; 12])
            },
            "secrets": {},
            "min_version": 5
        })
        .to_string();

        let vault: VaultV5 = serde_json::from_str(&json).unwrap();
        assert_eq!(vault.version, 5);
        assert_eq!(vault.x25519.public_key.len(), 32);
        assert!(vault.key_commitment.is_some());
    }
}
