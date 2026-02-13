//! Hybrid KEM combining ML-KEM-768 and X25519
//!
//! Combines post-quantum (ML-KEM-768) and classical (X25519) shared secrets
//! using HKDF-SHA256 to derive a final AES-256 key for secret encryption.
//!
//! This provides defense-in-depth: even if ML-KEM is broken, X25519 provides
//! classical security. Conversely, X25519 protects against harvest-now-decrypt-later
//! attacks by quantum computers.

use super::{
    aes_gcm::AesKey,
    mlkem::{self, MlKemCiphertext, MlKemPublicKey, MlKemSharedSecret},
    x25519::{self, X25519PublicKey, X25519SharedSecret},
};
use anyhow::Result;
use hkdf::Hkdf;
use sha2::Sha256;

/// Context string for HKDF (prevents cross-protocol attacks)
const HKDF_CONTEXT: &[u8] = b"dota-v2-secret";

/// Fixed protocol salt for HKDF-Extract (defense-in-depth domain separation)
const HKDF_SALT: &[u8] = b"dota-v2-hkdf-salt";

/// Result of hybrid encapsulation
pub struct HybridEncapsulation {
    pub kem_ciphertext: MlKemCiphertext,
    pub x25519_ephemeral_public: X25519PublicKey,
    pub derived_key: AesKey,
}

/// Perform hybrid encapsulation: ML-KEM + X25519 → AES key
pub fn hybrid_encapsulate(
    mlkem_public: &MlKemPublicKey,
    x25519_public: &X25519PublicKey,
) -> Result<HybridEncapsulation> {
    // 1. ML-KEM encapsulation
    let (kem_ss, kem_ct) = mlkem::encapsulate(mlkem_public)?;

    // 2. X25519 ephemeral key generation and DH
    let (x25519_eph_public, x25519_eph_private) = x25519::generate_ephemeral_keypair();
    let x25519_ss = x25519::diffie_hellman(&x25519_eph_private, x25519_public)?;

    // 3. Combine shared secrets with HKDF
    let derived_key = combine_shared_secrets(&kem_ss, &x25519_ss)?;

    Ok(HybridEncapsulation {
        kem_ciphertext: kem_ct,
        x25519_ephemeral_public: x25519_eph_public,
        derived_key,
    })
}

/// Perform hybrid decapsulation: recover AES key from ciphertexts
pub fn hybrid_decapsulate(
    mlkem_private: &super::mlkem::MlKemPrivateKey,
    x25519_private: &super::x25519::X25519PrivateKey,
    kem_ciphertext: &MlKemCiphertext,
    x25519_ephemeral_public: &X25519PublicKey,
) -> Result<AesKey> {
    // 1. ML-KEM decapsulation
    let kem_ss = mlkem::decapsulate(mlkem_private, kem_ciphertext)?;

    // 2. X25519 DH with ephemeral public key
    let x25519_ss = x25519::diffie_hellman(x25519_private, x25519_ephemeral_public)?;

    // 3. Combine shared secrets with HKDF
    combine_shared_secrets(&kem_ss, &x25519_ss)
}

/// Combine ML-KEM and X25519 shared secrets using HKDF-SHA256
fn combine_shared_secrets(
    kem_ss: &MlKemSharedSecret,
    x25519_ss: &X25519SharedSecret,
) -> Result<AesKey> {
    // Concatenate shared secrets: kem_ss || x25519_ss
    let mut ikm = Vec::with_capacity(64);
    ikm.extend_from_slice(kem_ss.as_bytes());
    ikm.extend_from_slice(x25519_ss.as_bytes());

    // HKDF-Extract and HKDF-Expand to derive 256-bit AES key
    let hk = Hkdf::<Sha256>::new(Some(HKDF_SALT), &ikm);
    let mut okm = [0u8; 32];
    hk.expand(HKDF_CONTEXT, &mut okm)
        .map_err(|e| anyhow::anyhow!("HKDF expansion failed: {}", e))?;

    Ok(AesKey::from_bytes(okm))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hybrid_round_trip() {
        // Generate vault keypairs
        let (mlkem_pk, mlkem_sk) = mlkem::generate_keypair().unwrap();
        let (x25519_pk, x25519_sk) = x25519::generate_keypair();

        // Encapsulate
        let encap = hybrid_encapsulate(&mlkem_pk, &x25519_pk).unwrap();

        // Decapsulate
        let decap_key = hybrid_decapsulate(
            &mlkem_sk,
            &x25519_sk,
            &encap.kem_ciphertext,
            &encap.x25519_ephemeral_public,
        )
        .unwrap();

        // Keys should match
        assert_eq!(encap.derived_key.as_bytes(), decap_key.as_bytes());
    }

    #[test]
    fn test_different_encapsulations_different_keys() {
        let (mlkem_pk, _mlkem_sk) = mlkem::generate_keypair().unwrap();
        let (x25519_pk, _x25519_sk) = x25519::generate_keypair();

        let encap1 = hybrid_encapsulate(&mlkem_pk, &x25519_pk).unwrap();
        let encap2 = hybrid_encapsulate(&mlkem_pk, &x25519_pk).unwrap();

        // Different ephemeral keys → different derived keys
        assert_ne!(encap1.derived_key.as_bytes(), encap2.derived_key.as_bytes());
    }

    #[test]
    fn test_wrong_mlkem_key_produces_different_aes_key() {
        let (mlkem_pk, _mlkem_sk1) = mlkem::generate_keypair().unwrap();
        let (_mlkem_pk2, mlkem_sk2) = mlkem::generate_keypair().unwrap();
        let (x25519_pk, x25519_sk) = x25519::generate_keypair();

        let encap = hybrid_encapsulate(&mlkem_pk, &x25519_pk).unwrap();

        let decap_key = hybrid_decapsulate(
            &mlkem_sk2, // Wrong ML-KEM key
            &x25519_sk,
            &encap.kem_ciphertext,
            &encap.x25519_ephemeral_public,
        )
        .unwrap();

        // Should produce different key (ML-KEM property: wrong key → different SS)
        assert_ne!(encap.derived_key.as_bytes(), decap_key.as_bytes());
    }

    #[test]
    fn test_wrong_x25519_key_produces_different_aes_key() {
        let (mlkem_pk, mlkem_sk) = mlkem::generate_keypair().unwrap();
        let (x25519_pk, _x25519_sk1) = x25519::generate_keypair();
        let (_x25519_pk2, x25519_sk2) = x25519::generate_keypair();

        let encap = hybrid_encapsulate(&mlkem_pk, &x25519_pk).unwrap();

        let decap_key = hybrid_decapsulate(
            &mlkem_sk,
            &x25519_sk2, // Wrong X25519 key
            &encap.kem_ciphertext,
            &encap.x25519_ephemeral_public,
        )
        .unwrap();

        // Should produce different key
        assert_ne!(encap.derived_key.as_bytes(), decap_key.as_bytes());
    }
}
