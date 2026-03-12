//! Real ML-KEM-768 (FIPS 203) post-quantum key encapsulation mechanism.
//!
//! This module is the v6 implementation. Legacy Kyber compatibility for older
//! vaults lives in [`crate::crypto::legacy_kyber`].

use anyhow::{Context, Result};
#[allow(deprecated)]
use ml_kem::{
    ExpandedKeyEncoding as _, Kem as _, KeyExport as _, MlKem768,
    array::Array,
    kem::{Decapsulate as _, Encapsulate as _, Key},
    ml_kem_768::{
        Ciphertext as RawCiphertext, DecapsulationKey as RawDecapsulationKey,
        EncapsulationKey as RawEncapsulationKey,
    },
};
use zeroize::{Zeroize, ZeroizeOnDrop};

const MLKEM_PUBLIC_KEY_LEN: usize = 1184;
const MLKEM_PRIVATE_KEY_LEN: usize = 2400;
const MLKEM_CIPHERTEXT_LEN: usize = 1088;

type RawEncapsulationKeyBytes = Key<RawEncapsulationKey>;
#[allow(deprecated)]
type RawExpandedDecapsulationKeyBytes =
    Array<u8, <ml_kem::DecapsulationKey<MlKem768> as ml_kem::ExpandedKeyEncoding>::EncodedSize>;

/// ML-KEM-768 public key (encapsulation key)
#[derive(Clone)]
pub struct MlKemPublicKey(Vec<u8>);

/// ML-KEM-768 private key in expanded 2400-byte form, preserved to keep the
/// current vault byte contract stable until the v6 format migration lands.
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
            bytes.len() == MLKEM_PUBLIC_KEY_LEN,
            "Invalid ML-KEM public key length: {} (expected {})",
            bytes.len(),
            MLKEM_PUBLIC_KEY_LEN
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
            bytes.len() == MLKEM_PRIVATE_KEY_LEN,
            "Invalid ML-KEM private key length: {} (expected {})",
            bytes.len(),
            MLKEM_PRIVATE_KEY_LEN
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
            bytes.len() == MLKEM_CIPHERTEXT_LEN,
            "Invalid ML-KEM ciphertext length: {} (expected {})",
            bytes.len(),
            MLKEM_CIPHERTEXT_LEN
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

fn decode_public_key(public_key: &MlKemPublicKey) -> Result<RawEncapsulationKey> {
    let key_bytes: [u8; MLKEM_PUBLIC_KEY_LEN] = public_key
        .as_bytes()
        .try_into()
        .context("Invalid ML-KEM public key length")?;
    let key_bytes: RawEncapsulationKeyBytes = key_bytes.into();
    RawEncapsulationKey::new(&key_bytes)
        .map_err(|e| anyhow::anyhow!("Invalid ML-KEM public key: {:?}", e))
}

#[allow(deprecated)]
fn decode_private_key(private_key: &MlKemPrivateKey) -> Result<RawDecapsulationKey> {
    let key_bytes: [u8; MLKEM_PRIVATE_KEY_LEN] = private_key
        .as_bytes()
        .try_into()
        .context("Invalid ML-KEM private key length")?;
    let key_bytes: RawExpandedDecapsulationKeyBytes = key_bytes.into();
    RawDecapsulationKey::from_expanded_bytes(&key_bytes)
        .map_err(|e| anyhow::anyhow!("Invalid ML-KEM secret key: {:?}", e))
}

fn decode_ciphertext(ciphertext: &MlKemCiphertext) -> Result<RawCiphertext> {
    let ciphertext_bytes: [u8; MLKEM_CIPHERTEXT_LEN] = ciphertext
        .as_bytes()
        .try_into()
        .context("Invalid ML-KEM ciphertext length")?;
    Ok(ciphertext_bytes.into())
}

/// Generate ML-KEM-768 keypair
pub fn generate_keypair() -> Result<(MlKemPublicKey, MlKemPrivateKey)> {
    let (dk, ek): (RawDecapsulationKey, RawEncapsulationKey) = MlKem768::generate_keypair();

    #[allow(deprecated)]
    let dk_bytes = dk.to_expanded_bytes();
    let ek_bytes = ek.to_bytes();

    Ok((
        MlKemPublicKey(ek_bytes.as_slice().to_vec()),
        MlKemPrivateKey(dk_bytes.as_slice().to_vec()),
    ))
}

/// Encapsulate: generate shared secret and ciphertext from public key
pub fn encapsulate(public_key: &MlKemPublicKey) -> Result<(MlKemSharedSecret, MlKemCiphertext)> {
    let pk = decode_public_key(public_key)?;
    let (ct, ss) = pk.encapsulate();

    let mut ss_bytes = [0u8; 32];
    ss_bytes.copy_from_slice(ss.as_slice());

    Ok((
        MlKemSharedSecret(ss_bytes),
        MlKemCiphertext(ct.as_slice().to_vec()),
    ))
}

/// Decapsulate: recover shared secret from ciphertext and private key
pub fn decapsulate(
    private_key: &MlKemPrivateKey,
    ciphertext: &MlKemCiphertext,
) -> Result<MlKemSharedSecret> {
    let sk = decode_private_key(private_key)?;
    let ct = decode_ciphertext(ciphertext)?;
    let ss = sk.decapsulate(&ct);

    let mut ss_bytes = [0u8; 32];
    ss_bytes.copy_from_slice(ss.as_slice());

    Ok(MlKemSharedSecret(ss_bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keygen() {
        let (pk, sk) = generate_keypair().unwrap();
        assert_eq!(pk.as_bytes().len(), MLKEM_PUBLIC_KEY_LEN);
        assert_eq!(sk.as_bytes().len(), MLKEM_PRIVATE_KEY_LEN);
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

        assert_ne!(ss1.as_bytes(), ss2.as_bytes());
    }

    #[test]
    fn test_wrong_private_key_produces_different_shared_secret() {
        let (pk, _sk1) = generate_keypair().unwrap();
        let (_pk2, sk2) = generate_keypair().unwrap();

        let (ss1, ct) = encapsulate(&pk).unwrap();
        let ss2 = decapsulate(&sk2, &ct).unwrap();

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
