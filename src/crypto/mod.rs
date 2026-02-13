//! Cryptographic primitives for dota
//!
//! Implements hybrid post-quantum + classical encryption:
//! - ML-KEM-768 (FIPS 203) for post-quantum security
//! - X25519 for classical ECDH
//! - AES-256-GCM for symmetric encryption
//! - Argon2id for passphrase-based key derivation
//! - HKDF-SHA256 for combining shared secrets

pub mod aes_gcm;
pub mod hybrid;
pub mod kdf;
pub mod mlkem;
pub mod x25519;

// Re-export commonly used types
pub use aes_gcm::{AesKey, decrypt as aes_decrypt, encrypt as aes_encrypt};
pub use hybrid::{hybrid_decapsulate, hybrid_encapsulate};
pub use kdf::{derive_key, generate_salt, KdfConfig, MasterKey};
pub use mlkem::{
    generate_keypair as mlkem_generate_keypair, MlKemCiphertext, MlKemPrivateKey, MlKemPublicKey,
};
pub use x25519::{
    generate_keypair as x25519_generate_keypair, X25519PrivateKey, X25519PublicKey,
};
