//! X25519 elliptic curve Diffie-Hellman key exchange

use anyhow::Result;
use rand_core::OsRng;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// X25519 public key (32 bytes)
#[derive(Clone)]
pub struct X25519PublicKey([u8; 32]);

/// X25519 private key (32 bytes)
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct X25519PrivateKey([u8; 32]);

/// X25519 shared secret (32 bytes)
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct X25519SharedSecret([u8; 32]);

impl X25519PublicKey {
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl X25519PrivateKey {
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl X25519SharedSecret {
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    #[cfg(test)]
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

/// Generate X25519 static keypair (for vault storage)
pub fn generate_keypair() -> (X25519PublicKey, X25519PrivateKey) {
    // Use StaticSecret for proper key clamping and generation
    let secret = StaticSecret::random_from_rng(OsRng);
    let public = PublicKey::from(&secret);

    (
        X25519PublicKey(public.to_bytes()),
        X25519PrivateKey(secret.to_bytes()),
    )
}

/// Generate ephemeral X25519 keypair (for per-secret encryption)
pub fn generate_ephemeral_keypair() -> (X25519PublicKey, X25519PrivateKey) {
    // For per-secret ephemeral keys, just generate a regular keypair
    generate_keypair()
}

/// Perform Diffie-Hellman key exchange
pub fn diffie_hellman(
    private_key: &X25519PrivateKey,
    public_key: &X25519PublicKey,
) -> Result<X25519SharedSecret> {
    // Reconstruct StaticSecret from bytes (applies proper clamping)
    let secret = StaticSecret::from(*private_key.as_bytes());
    let public = PublicKey::from(*public_key.as_bytes());

    // Perform DH key exchange
    let shared_secret = secret.diffie_hellman(&public);

    let shared_bytes = shared_secret.to_bytes();
    anyhow::ensure!(
        shared_bytes.iter().any(|&b| b != 0),
        "X25519 DH produced all-zero shared secret (small-subgroup public key)"
    );

    Ok(X25519SharedSecret(shared_bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keygen() {
        let (pk, sk) = generate_keypair();
        assert_eq!(pk.as_bytes().len(), 32);
        assert_eq!(sk.as_bytes().len(), 32);
    }

    #[test]
    fn test_diffie_hellman_symmetric() {
        let (pk1, sk1) = generate_keypair();
        let (pk2, sk2) = generate_keypair();

        // Both parties compute the same shared secret
        let ss1 = diffie_hellman(&sk1, &pk2).unwrap();
        let ss2 = diffie_hellman(&sk2, &pk1).unwrap();

        assert_eq!(ss1.as_bytes(), ss2.as_bytes());
    }

    #[test]
    fn test_different_keypairs_different_shared_secrets() {
        let (_pk1, sk1) = generate_keypair();
        let (pk2, _sk2) = generate_keypair();
        let (pk3, _sk3) = generate_keypair();

        let ss1 = diffie_hellman(&sk1, &pk2).unwrap();
        let ss2 = diffie_hellman(&sk1, &pk3).unwrap();

        assert_ne!(ss1.as_bytes(), ss2.as_bytes());
    }

    #[test]
    fn test_ephemeral_keygen() {
        let (pk, sk) = generate_ephemeral_keypair();
        assert_eq!(pk.as_bytes().len(), 32);
        assert_eq!(sk.as_bytes().len(), 32);
    }

    #[test]
    fn test_from_bytes_shared_secret() {
        let ss = X25519SharedSecret::from_bytes([0x5a; 32]);
        assert_eq!(ss.as_bytes(), &[0x5a; 32]);
    }

    #[test]
    fn test_all_zero_shared_secret_rejected() {
        // The all-zero public key is a small-subgroup point (order 1).
        // DH with it produces an all-zero shared secret which must be rejected.
        let (_, sk) = generate_keypair();
        let zero_pk = X25519PublicKey::from_bytes([0u8; 32]);
        match diffie_hellman(&sk, &zero_pk) {
            Ok(_) => panic!("should reject all-zero DH output"),
            Err(e) => assert!(
                e.to_string().contains("all-zero shared secret"),
                "unexpected error: {e}"
            ),
        }
    }
}
