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
    legacy_kyber::{self, LegacyKyberCiphertext, LegacyKyberPublicKey},
    mlkem::{self, MlKemCiphertext, MlKemPublicKey},
    x25519::{self, X25519PublicKey},
};
use anyhow::Result;
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroize;

/// Legacy hybrid HKDF context for v2-v5 vaults.
const LEGACY_HKDF_CONTEXT: &[u8] = b"dota-v2-secret";
/// Legacy hybrid HKDF salt for v2-v5 vaults.
const LEGACY_HKDF_SALT: &[u8] = b"dota-v2-hkdf-salt";
/// v6 hybrid HKDF context.
const V6_HKDF_CONTEXT: &[u8] = b"dota-v6-secret";
/// v6 hybrid HKDF salt.
const V6_HKDF_SALT: &[u8] = b"dota-v6-hkdf-salt";

/// Result of hybrid encapsulation
pub struct HybridEncapsulation {
    pub kem_ciphertext: MlKemCiphertext,
    pub x25519_ephemeral_public: X25519PublicKey,
    pub derived_key: AesKey,
}

/// Perform v6 hybrid encapsulation: real ML-KEM + X25519 → AES key
pub fn hybrid_encapsulate(
    mlkem_public: &MlKemPublicKey,
    x25519_public: &X25519PublicKey,
) -> Result<HybridEncapsulation> {
    hybrid_encapsulate_v6(mlkem_public, x25519_public)
}

/// Perform v6 hybrid encapsulation: real ML-KEM + X25519 → AES key
pub fn hybrid_encapsulate_v6(
    mlkem_public: &MlKemPublicKey,
    x25519_public: &X25519PublicKey,
) -> Result<HybridEncapsulation> {
    // 1. ML-KEM encapsulation
    let (kem_ss, kem_ct) = mlkem::encapsulate(mlkem_public)?;

    // 2. X25519 ephemeral key generation and DH
    let (x25519_eph_public, x25519_eph_private) = x25519::generate_ephemeral_keypair();
    let x25519_ss = x25519::diffie_hellman(&x25519_eph_private, x25519_public)?;

    // 3. Combine shared secrets with HKDF
    let derived_key = combine_shared_secrets_with_labels(
        kem_ss.as_bytes(),
        x25519_ss.as_bytes(),
        V6_HKDF_SALT,
        V6_HKDF_CONTEXT,
    )?;

    Ok(HybridEncapsulation {
        kem_ciphertext: kem_ct,
        x25519_ephemeral_public: x25519_eph_public,
        derived_key,
    })
}

/// Perform legacy hybrid encapsulation: Kyber768 + X25519 → AES key.
pub fn hybrid_encapsulate_legacy(
    mlkem_public: &LegacyKyberPublicKey,
    x25519_public: &X25519PublicKey,
) -> Result<(LegacyKyberCiphertext, X25519PublicKey, AesKey)> {
    let (kem_ss, kem_ct) = legacy_kyber::encapsulate(mlkem_public)?;
    let (x25519_eph_public, x25519_eph_private) = x25519::generate_ephemeral_keypair();
    let x25519_ss = x25519::diffie_hellman(&x25519_eph_private, x25519_public)?;
    let derived_key = combine_shared_secrets_with_labels(
        kem_ss.as_bytes(),
        x25519_ss.as_bytes(),
        LEGACY_HKDF_SALT,
        LEGACY_HKDF_CONTEXT,
    )?;
    Ok((kem_ct, x25519_eph_public, derived_key))
}

/// Perform v6 hybrid decapsulation: recover AES key from ciphertexts
pub fn hybrid_decapsulate(
    mlkem_private: &super::mlkem::MlKemPrivateKey,
    x25519_private: &super::x25519::X25519PrivateKey,
    kem_ciphertext: &MlKemCiphertext,
    x25519_ephemeral_public: &X25519PublicKey,
) -> Result<AesKey> {
    hybrid_decapsulate_v6(
        mlkem_private,
        x25519_private,
        kem_ciphertext,
        x25519_ephemeral_public,
    )
}

/// Perform v6 hybrid decapsulation: recover AES key from ciphertexts
pub fn hybrid_decapsulate_v6(
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
    combine_shared_secrets_with_labels(
        kem_ss.as_bytes(),
        x25519_ss.as_bytes(),
        V6_HKDF_SALT,
        V6_HKDF_CONTEXT,
    )
}

/// Perform legacy hybrid decapsulation: Kyber768 + X25519 → AES key.
pub fn hybrid_decapsulate_legacy(
    mlkem_private: &super::legacy_kyber::LegacyKyberPrivateKey,
    x25519_private: &super::x25519::X25519PrivateKey,
    kem_ciphertext: &LegacyKyberCiphertext,
    x25519_ephemeral_public: &X25519PublicKey,
) -> Result<AesKey> {
    let kem_ss = legacy_kyber::decapsulate(mlkem_private, kem_ciphertext)?;
    let x25519_ss = x25519::diffie_hellman(x25519_private, x25519_ephemeral_public)?;
    combine_shared_secrets_with_labels(
        kem_ss.as_bytes(),
        x25519_ss.as_bytes(),
        LEGACY_HKDF_SALT,
        LEGACY_HKDF_CONTEXT,
    )
}

/// Combine KEM and X25519 shared secrets using HKDF-SHA256 with explicit labels.
fn combine_shared_secrets_with_labels(
    kem_ss: &[u8; 32],
    x25519_ss: &[u8; 32],
    hkdf_salt: &[u8],
    hkdf_context: &[u8],
) -> Result<AesKey> {
    // Concatenate shared secrets: kem_ss || x25519_ss
    let mut ikm = vec![0u8; 64];
    ikm[..32].copy_from_slice(kem_ss);
    ikm[32..].copy_from_slice(x25519_ss);

    // HKDF-Extract and HKDF-Expand to derive 256-bit AES key
    let hk = Hkdf::<Sha256>::new(Some(hkdf_salt), &ikm);
    let mut okm = [0u8; 32];
    let result = hk
        .expand(hkdf_context, &mut okm)
        .map_err(|e| anyhow::anyhow!("HKDF expansion failed: {}", e));

    // Zeroize IKM containing both shared secrets before returning
    ikm.zeroize();

    result?;
    let key = AesKey::from_bytes(okm);
    // Zeroize the stack buffer — data now lives inside AesKey (ZeroizeOnDrop)
    okm.zeroize();
    std::hint::black_box(&okm);
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{mlkem::MlKemSharedSecret, x25519::X25519SharedSecret};

    #[test]
    fn test_v6_hybrid_round_trip() {
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
    fn test_v6_different_encapsulations_different_keys() {
        let (mlkem_pk, _mlkem_sk) = mlkem::generate_keypair().unwrap();
        let (x25519_pk, _x25519_sk) = x25519::generate_keypair();

        let encap1 = hybrid_encapsulate(&mlkem_pk, &x25519_pk).unwrap();
        let encap2 = hybrid_encapsulate(&mlkem_pk, &x25519_pk).unwrap();

        // Different ephemeral keys → different derived keys
        assert_ne!(encap1.derived_key.as_bytes(), encap2.derived_key.as_bytes());
    }

    #[test]
    fn test_v6_wrong_mlkem_key_produces_different_aes_key() {
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
    fn test_v6_wrong_x25519_key_produces_different_aes_key() {
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

    #[test]
    fn test_legacy_hybrid_round_trip() {
        let (mlkem_pk, mlkem_sk) = legacy_kyber::generate_keypair().unwrap();
        let (x25519_pk, x25519_sk) = x25519::generate_keypair();

        let (kem_ct, eph_pk, encap_key) = hybrid_encapsulate_legacy(&mlkem_pk, &x25519_pk).unwrap();
        let decap_key = hybrid_decapsulate_legacy(&mlkem_sk, &x25519_sk, &kem_ct, &eph_pk).unwrap();

        assert_eq!(encap_key.as_bytes(), decap_key.as_bytes());
    }

    #[test]
    fn test_legacy_and_v6_hybrid_labels_diverge() {
        let kem_ss = MlKemSharedSecret::from_bytes([0x11; 32]);
        let x25519_ss = X25519SharedSecret::from_bytes([0x22; 32]);

        let legacy = combine_shared_secrets_with_labels(
            kem_ss.as_bytes(),
            x25519_ss.as_bytes(),
            LEGACY_HKDF_SALT,
            LEGACY_HKDF_CONTEXT,
        )
        .unwrap();
        let v6 = combine_shared_secrets_with_labels(
            kem_ss.as_bytes(),
            x25519_ss.as_bytes(),
            V6_HKDF_SALT,
            V6_HKDF_CONTEXT,
        )
        .unwrap();

        assert_ne!(legacy.as_bytes(), v6.as_bytes());
    }
}
