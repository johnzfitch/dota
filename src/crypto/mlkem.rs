//! ML-KEM-768 (FIPS 203) post-quantum key encapsulation mechanism

use anyhow::Result;
use pqcrypto_kyber::kyber768;
use pqcrypto_traits::kem::{Ciphertext as _, PublicKey as _, SecretKey as _, SharedSecret as _};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// ML-KEM-768 public key (encapsulation key)
#[derive(Clone)]
pub struct MlKemPublicKey(Vec<u8>);

/// ML-KEM-768 private key (decapsulation key)
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct MlKemPrivateKey(Vec<u8>);

/// ML-KEM-768 ciphertext (encapsulated shared secret)
#[derive(Clone)]
pub struct MlKemCiphertext(Vec<u8>);

/// ML-KEM-768 shared secret (32 bytes)
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct MlKemSharedSecret([u8; 32]);

impl MlKemPublicKey {
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self> {
        anyhow::ensure!(
            bytes.len() == 1184,
            "Invalid ML-KEM public key length: {} (expected 1184)",
            bytes.len()
        );
        Ok(Self(bytes))
    }
}

impl MlKemPrivateKey {
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self> {
        anyhow::ensure!(
            bytes.len() == 2400,
            "Invalid ML-KEM private key length: {} (expected 2400)",
            bytes.len()
        );
        Ok(Self(bytes))
    }
}

impl MlKemCiphertext {
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self> {
        anyhow::ensure!(
            bytes.len() == 1088,
            "Invalid ML-KEM ciphertext length: {} (expected 1088)",
            bytes.len()
        );
        Ok(Self(bytes))
    }
}

impl MlKemSharedSecret {
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    #[cfg(test)]
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

/// Generate ML-KEM-768 keypair
pub fn generate_keypair() -> Result<(MlKemPublicKey, MlKemPrivateKey)> {
    let (pk, sk) = kyber768::keypair();

    Ok((
        MlKemPublicKey(pk.as_bytes().to_vec()),
        MlKemPrivateKey(sk.as_bytes().to_vec()),
    ))
}

/// Encapsulate: generate shared secret and ciphertext from public key
pub fn encapsulate(public_key: &MlKemPublicKey) -> Result<(MlKemSharedSecret, MlKemCiphertext)> {
    let pk = kyber768::PublicKey::from_bytes(public_key.as_bytes())
        .map_err(|e| anyhow::anyhow!("Invalid ML-KEM public key: {:?}", e))?;

    let (ss, ct) = kyber768::encapsulate(&pk);

    let mut ss_bytes = [0u8; 32];
    ss_bytes.copy_from_slice(ss.as_bytes());

    Ok((
        MlKemSharedSecret(ss_bytes),
        MlKemCiphertext(ct.as_bytes().to_vec()),
    ))
}

/// Decapsulate: recover shared secret from ciphertext and private key
pub fn decapsulate(
    private_key: &MlKemPrivateKey,
    ciphertext: &MlKemCiphertext,
) -> Result<MlKemSharedSecret> {
    let sk = kyber768::SecretKey::from_bytes(private_key.as_bytes())
        .map_err(|e| anyhow::anyhow!("Invalid ML-KEM secret key: {:?}", e))?;

    let ct = kyber768::Ciphertext::from_bytes(ciphertext.as_bytes())
        .map_err(|e| anyhow::anyhow!("Invalid ML-KEM ciphertext: {:?}", e))?;

    let ss = kyber768::decapsulate(&ct, &sk);

    let mut ss_bytes = [0u8; 32];
    ss_bytes.copy_from_slice(ss.as_bytes());

    Ok(MlKemSharedSecret(ss_bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keygen() {
        let (pk, sk) = generate_keypair().unwrap();
        assert!(!pk.as_bytes().is_empty());
        assert!(!sk.as_bytes().is_empty());
    }

    #[test]
    fn test_encapsulate_decapsulate_round_trip() {
        let (pk, sk) = generate_keypair().unwrap();

        let (ss1, ct) = encapsulate(&pk).unwrap();
        let ss2 = decapsulate(&sk, &ct).unwrap();

        assert_eq!(ss1.as_bytes(), ss2.as_bytes());
    }

    #[test]
    fn test_different_keypairs_different_shared_secrets() {
        let (pk1, _sk1) = generate_keypair().unwrap();
        let (pk2, _sk2) = generate_keypair().unwrap();

        let (ss1, _ct1) = encapsulate(&pk1).unwrap();
        let (ss2, _ct2) = encapsulate(&pk2).unwrap();

        // Different encapsulations should produce different shared secrets
        assert_ne!(ss1.as_bytes(), ss2.as_bytes());
    }

    #[test]
    fn test_wrong_private_key_produces_different_shared_secret() {
        let (pk, _sk1) = generate_keypair().unwrap();
        let (_pk2, sk2) = generate_keypair().unwrap();

        let (ss1, ct) = encapsulate(&pk).unwrap();
        let ss2 = decapsulate(&sk2, &ct).unwrap();

        // Decapsulating with wrong key should produce different shared secret
        assert_ne!(ss1.as_bytes(), ss2.as_bytes());
    }

    #[test]
    fn test_from_bytes_shared_secret() {
        let ss = MlKemSharedSecret::from_bytes([0x3c; 32]);
        assert_eq!(ss.as_bytes(), &[0x3c; 32]);
    }

    #[test]
    fn test_public_key_rejects_wrong_length() {
        assert!(MlKemPublicKey::from_bytes(vec![0u8; 0]).is_err());
        assert!(MlKemPublicKey::from_bytes(vec![0u8; 1183]).is_err());
        assert!(MlKemPublicKey::from_bytes(vec![0u8; 1185]).is_err());
        assert!(MlKemPublicKey::from_bytes(vec![0u8; 1184]).is_ok());
    }

    #[test]
    fn test_private_key_rejects_wrong_length() {
        assert!(MlKemPrivateKey::from_bytes(vec![0u8; 0]).is_err());
        assert!(MlKemPrivateKey::from_bytes(vec![0u8; 2399]).is_err());
        assert!(MlKemPrivateKey::from_bytes(vec![0u8; 2401]).is_err());
        assert!(MlKemPrivateKey::from_bytes(vec![0u8; 2400]).is_ok());
    }

    #[test]
    fn test_ciphertext_rejects_wrong_length() {
        assert!(MlKemCiphertext::from_bytes(vec![0u8; 0]).is_err());
        assert!(MlKemCiphertext::from_bytes(vec![0u8; 1087]).is_err());
        assert!(MlKemCiphertext::from_bytes(vec![0u8; 1089]).is_err());
        assert!(MlKemCiphertext::from_bytes(vec![0u8; 1088]).is_ok());
    }
}
