//! Legacy vault format definitions for migration
//!
//! Contains deserialization-only structs for reading vault formats v1-v3.
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
