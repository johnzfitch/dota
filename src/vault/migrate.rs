//! Vault version migration framework.
//!
//! Supports **forward-only** migration (no downgrades). Each version step
//! has a dedicated migration function that re-wraps private keys under the
//! new version's HKDF labels. The chain is applied sequentially:
//! v3 → v4 → v5 → …
//!
//! Anti-rollback: the `min_version` field is set to `VAULT_VERSION` after
//! migration so older binaries refuse to open the vault even if they could
//! technically parse the JSON.

use super::format::{Vault, MIN_SUPPORTED_VERSION, VAULT_VERSION};
use crate::crypto::{AesKey, MasterKey, aes_decrypt, aes_encrypt};
use anyhow::{Context, Result};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::{Zeroize, ZeroizeOnDrop};

// ── Version-specific HKDF wrapping labels ──────────────────────────────

/// v4 wrapping labels (purpose-labeled HKDF-Expand)
const V4_WRAP_MLKEM: &[u8] = b"dota-v4-wrap-mlkem";
const V4_WRAP_X25519: &[u8] = b"dota-v4-wrap-x25519";

/// v5 wrapping labels (refreshed domain separation)
const V5_WRAP_MLKEM: &[u8] = b"dota-v5-wrap-mlkem";
const V5_WRAP_X25519: &[u8] = b"dota-v5-wrap-x25519";

// ── Public types ───────────────────────────────────────────────────────

/// Wrapping keys derived from the master key for encrypting vault private keys.
/// Derives `Zeroize` + `ZeroizeOnDrop` so wrapping key material is scrubbed
/// from memory when this struct is dropped.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct WrappingKeys {
    pub mlkem: AesKey,
    pub x25519: AesKey,
}

// ── Version validation ─────────────────────────────────────────────────

/// Validate that the vault version is within the range this binary supports.
///
/// Returns `Ok(())` when the vault can be opened (possibly after migration).
/// Returns an error with a human-readable message when the vault is
/// incompatible.
pub fn validate_version(vault: &Vault) -> Result<()> {
    // Anti-downgrade: vault was written by a newer binary
    if vault.version > VAULT_VERSION {
        anyhow::bail!(
            "Vault version {} is newer than this binary supports (max {}). \
             Please upgrade dota to open this vault.",
            vault.version,
            VAULT_VERSION,
        );
    }

    // Anti-rollback via explicit min_version field
    if vault.min_version > VAULT_VERSION {
        anyhow::bail!(
            "This vault requires dota v{} or later (anti-rollback). \
             Please upgrade dota.",
            vault.min_version,
        );
    }

    // Consistency check: min_version should never exceed version
    if vault.min_version > vault.version {
        anyhow::bail!(
            "Corrupt vault: min_version ({}) exceeds version ({})",
            vault.min_version,
            vault.version,
        );
    }

    // Too old to migrate
    if vault.version < MIN_SUPPORTED_VERSION {
        anyhow::bail!(
            "Vault version {} is too old to migrate directly (minimum {}). \
             Please use an intermediate dota release to upgrade first.",
            vault.version,
            MIN_SUPPORTED_VERSION,
        );
    }

    Ok(())
}

/// Returns `true` when the vault needs to be migrated to `VAULT_VERSION`.
pub fn needs_migration(vault: &Vault) -> bool {
    vault.version < VAULT_VERSION
}

// ── Migration chain ────────────────────────────────────────────────────

/// Migrate a vault from its current version to `VAULT_VERSION` by applying
/// each intermediate step in order.
///
/// The caller is responsible for creating a backup **before** calling this
/// function and for persisting the result afterwards.
pub fn migrate_vault(vault: &mut Vault, master_key: &MasterKey) -> Result<()> {
    while vault.version < VAULT_VERSION {
        match vault.version {
            3 => migrate_v3_to_v4(vault, master_key)?,
            4 => migrate_v4_to_v5(vault, master_key)?,
            v => anyhow::bail!(
                "No migration path from vault version {} (this is a bug)",
                v
            ),
        }
    }
    Ok(())
}

// ── Wrapping key derivation ────────────────────────────────────────────

/// Derive the wrapping keys appropriate for a given vault version.
///
/// - v3: master key used directly (no HKDF, same key for both slots).
/// - v4: HKDF-Expand with `dota-v4-wrap-*` labels.
/// - v5: HKDF-Expand with `dota-v5-wrap-*` labels.
pub fn derive_wrapping_keys(mk: &MasterKey, version: u32) -> Result<WrappingKeys> {
    match version {
        3 => {
            // v3 used the raw master key as the AES wrapping key for both slots.
            let key = AesKey::from_bytes(*mk.as_bytes());
            Ok(WrappingKeys {
                mlkem: key.clone(),
                x25519: key,
            })
        }
        4 => derive_hkdf_wrapping_keys(mk, V4_WRAP_MLKEM, V4_WRAP_X25519),
        5 => derive_hkdf_wrapping_keys(mk, V5_WRAP_MLKEM, V5_WRAP_X25519),
        _ => anyhow::bail!("Cannot derive wrapping keys for vault version {}", version),
    }
}

/// HKDF-Expand (no extract – Argon2id output is already a high-quality PRK)
/// with distinct purpose labels for ML-KEM and X25519 wrapping.
fn derive_hkdf_wrapping_keys(
    mk: &MasterKey,
    mlkem_label: &[u8],
    x25519_label: &[u8],
) -> Result<WrappingKeys> {
    let hk = Hkdf::<Sha256>::from_prk(mk.as_bytes())
        .map_err(|_| anyhow::anyhow!("master key too short for HKDF-Expand PRK"))?;

    let mut mlkem_key = [0u8; 32];
    hk.expand(mlkem_label, &mut mlkem_key)
        .map_err(|e| anyhow::anyhow!("HKDF expand for ML-KEM wrapping key failed: {}", e))?;

    let mut x25519_key = [0u8; 32];
    hk.expand(x25519_label, &mut x25519_key)
        .map_err(|e| anyhow::anyhow!("HKDF expand for X25519 wrapping key failed: {}", e))?;

    let keys = WrappingKeys {
        mlkem: AesKey::from_bytes(mlkem_key),
        x25519: AesKey::from_bytes(x25519_key),
    };

    // Scrub the intermediate stack buffers after copying into AesKey
    mlkem_key.zeroize();
    x25519_key.zeroize();

    Ok(keys)
}

// ── Individual version migration steps ─────────────────────────────────

/// v3 → v4: Re-wrap private keys with HKDF-derived purpose-labeled keys.
///
/// In v3, the raw master key was used as the AES wrapping key for both
/// ML-KEM and X25519 private keys (no domain separation).
fn migrate_v3_to_v4(vault: &mut Vault, master_key: &MasterKey) -> Result<()> {
    let old = derive_wrapping_keys(master_key, 3)?;
    let new = derive_wrapping_keys(master_key, 4)?;

    rewrap_private_keys(vault, &old, &new)
        .context("v3→v4 migration: failed to re-wrap private keys")?;

    vault.version = 4;
    Ok(())
}

/// v4 → v5: Refresh HKDF labels and add anti-rollback `min_version`.
fn migrate_v4_to_v5(vault: &mut Vault, master_key: &MasterKey) -> Result<()> {
    let old = derive_wrapping_keys(master_key, 4)?;
    let new = derive_wrapping_keys(master_key, 5)?;

    rewrap_private_keys(vault, &old, &new)
        .context("v4→v5 migration: failed to re-wrap private keys")?;

    vault.version = 5;
    vault.min_version = VAULT_VERSION;
    Ok(())
}

/// Decrypt both vault private keys with `old` wrapping keys and re-encrypt
/// them under `new` wrapping keys. Nonces are always freshly generated.
fn rewrap_private_keys(
    vault: &mut Vault,
    old: &WrappingKeys,
    new: &WrappingKeys,
) -> Result<()> {
    // ── ML-KEM private key ──
    let mlkem_nonce: [u8; 12] = vault
        .kem
        .private_key_nonce
        .as_slice()
        .try_into()
        .context("Invalid ML-KEM nonce length")?;
    let mut mlkem_sk = aes_decrypt(&old.mlkem, &vault.kem.encrypted_private_key, &mlkem_nonce)
        .context("Failed to decrypt ML-KEM private key during migration")?;

    // ── X25519 private key ──
    let x25519_nonce: [u8; 12] = vault
        .x25519
        .private_key_nonce
        .as_slice()
        .try_into()
        .context("Invalid X25519 nonce length")?;
    let mut x25519_sk = aes_decrypt(
        &old.x25519,
        &vault.x25519.encrypted_private_key,
        &x25519_nonce,
    )
    .context("Failed to decrypt X25519 private key during migration")?;

    // ── Re-encrypt under new wrapping keys with fresh nonces ──
    let (enc_mlkem, new_mlkem_nonce) = aes_encrypt(&new.mlkem, &mlkem_sk)?;
    let (enc_x25519, new_x25519_nonce) = aes_encrypt(&new.x25519, &x25519_sk)?;

    // Zeroize decrypted private key material before dropping
    mlkem_sk.zeroize();
    x25519_sk.zeroize();

    vault.kem.encrypted_private_key = enc_mlkem;
    vault.kem.private_key_nonce = new_mlkem_nonce.to_vec();
    vault.x25519.encrypted_private_key = enc_x25519;
    vault.x25519.private_key_nonce = new_x25519_nonce.to_vec();

    Ok(())
}

// ── Tests ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{
        KdfConfig, MlKemPrivateKey, aes_encrypt, derive_key, generate_salt,
        mlkem_generate_keypair, x25519_generate_keypair,
    };
    use crate::vault::format::{
        KdfParams, KemKeyPair, Vault, X25519KeyPair, MIN_SUPPORTED_VERSION, VAULT_VERSION,
    };
    use chrono::Utc;
    use std::collections::HashMap;

    /// Helper: create a v4 vault (using v4 wrapping labels) for migration tests.
    fn make_v4_vault(passphrase: &str) -> (Vault, MasterKey) {
        let salt = generate_salt();
        let kdf_config = KdfConfig {
            salt: salt.clone(),
            time_cost: 1,
            memory_cost: 8192,
            parallelism: 1,
        };
        let master_key = derive_key(passphrase, &kdf_config).unwrap();

        let (mlkem_pub, mlkem_priv) = mlkem_generate_keypair().unwrap();
        let (x25519_pub, x25519_priv) = x25519_generate_keypair();

        let wrapping = derive_wrapping_keys(&master_key, 4).unwrap();
        let (enc_mlkem, mlkem_nonce) =
            aes_encrypt(&wrapping.mlkem, mlkem_priv.as_bytes()).unwrap();
        let (enc_x25519, x25519_nonce) =
            aes_encrypt(&wrapping.x25519, x25519_priv.as_bytes()).unwrap();

        let vault = Vault {
            version: 4,
            min_version: 0,
            created: Utc::now(),
            kdf: KdfParams {
                algorithm: "argon2id".to_string(),
                salt,
                time_cost: kdf_config.time_cost,
                memory_cost: kdf_config.memory_cost,
                parallelism: kdf_config.parallelism,
            },
            kem: KemKeyPair {
                algorithm: "ML-KEM-768".to_string(),
                public_key: mlkem_pub.as_bytes().to_vec(),
                encrypted_private_key: enc_mlkem,
                private_key_nonce: mlkem_nonce.to_vec(),
            },
            x25519: X25519KeyPair {
                public_key: x25519_pub.as_bytes().to_vec(),
                encrypted_private_key: enc_x25519,
                private_key_nonce: x25519_nonce.to_vec(),
            },
            secrets: HashMap::new(),
        };

        (vault, master_key)
    }

    /// Helper: create a v3 vault (raw master key wrapping) for migration tests.
    fn make_v3_vault(passphrase: &str) -> (Vault, MasterKey) {
        let salt = generate_salt();
        let kdf_config = KdfConfig {
            salt: salt.clone(),
            time_cost: 1,
            memory_cost: 8192,
            parallelism: 1,
        };
        let master_key = derive_key(passphrase, &kdf_config).unwrap();

        let (mlkem_pub, mlkem_priv) = mlkem_generate_keypair().unwrap();
        let (x25519_pub, x25519_priv) = x25519_generate_keypair();

        // v3: raw master key as AES wrapping key
        let raw_key = AesKey::from_bytes(*master_key.as_bytes());
        let (enc_mlkem, mlkem_nonce) =
            aes_encrypt(&raw_key, mlkem_priv.as_bytes()).unwrap();
        let (enc_x25519, x25519_nonce) =
            aes_encrypt(&raw_key, x25519_priv.as_bytes()).unwrap();

        let vault = Vault {
            version: 3,
            min_version: 0,
            created: Utc::now(),
            kdf: KdfParams {
                algorithm: "argon2id".to_string(),
                salt,
                time_cost: kdf_config.time_cost,
                memory_cost: kdf_config.memory_cost,
                parallelism: kdf_config.parallelism,
            },
            kem: KemKeyPair {
                algorithm: "ML-KEM-768".to_string(),
                public_key: mlkem_pub.as_bytes().to_vec(),
                encrypted_private_key: enc_mlkem,
                private_key_nonce: mlkem_nonce.to_vec(),
            },
            x25519: X25519KeyPair {
                public_key: x25519_pub.as_bytes().to_vec(),
                encrypted_private_key: enc_x25519,
                private_key_nonce: x25519_nonce.to_vec(),
            },
            secrets: HashMap::new(),
        };

        (vault, master_key)
    }

    #[test]
    fn test_validate_version_current() {
        let vault = Vault {
            version: VAULT_VERSION,
            min_version: VAULT_VERSION,
            created: Utc::now(),
            kdf: KdfParams {
                algorithm: "argon2id".to_string(),
                salt: vec![0; 16],
                time_cost: 1,
                memory_cost: 8192,
                parallelism: 1,
            },
            kem: KemKeyPair {
                algorithm: "ML-KEM-768".to_string(),
                public_key: vec![0; 1184],
                encrypted_private_key: vec![0; 100],
                private_key_nonce: vec![0; 12],
            },
            x25519: X25519KeyPair {
                public_key: vec![0; 32],
                encrypted_private_key: vec![0; 48],
                private_key_nonce: vec![0; 12],
            },
            secrets: HashMap::new(),
        };
        assert!(validate_version(&vault).is_ok());
    }

    #[test]
    fn test_validate_version_rejects_future() {
        let vault = Vault {
            version: VAULT_VERSION + 1,
            min_version: 0,
            created: Utc::now(),
            kdf: KdfParams {
                algorithm: "argon2id".to_string(),
                salt: vec![0; 16],
                time_cost: 1,
                memory_cost: 8192,
                parallelism: 1,
            },
            kem: KemKeyPair {
                algorithm: "ML-KEM-768".to_string(),
                public_key: vec![],
                encrypted_private_key: vec![],
                private_key_nonce: vec![],
            },
            x25519: X25519KeyPair {
                public_key: vec![],
                encrypted_private_key: vec![],
                private_key_nonce: vec![],
            },
            secrets: HashMap::new(),
        };
        let err = validate_version(&vault).unwrap_err();
        assert!(err.to_string().contains("newer than this binary"));
    }

    #[test]
    fn test_validate_version_rejects_anti_rollback() {
        let vault = Vault {
            version: VAULT_VERSION,
            min_version: VAULT_VERSION + 1,
            created: Utc::now(),
            kdf: KdfParams {
                algorithm: "argon2id".to_string(),
                salt: vec![0; 16],
                time_cost: 1,
                memory_cost: 8192,
                parallelism: 1,
            },
            kem: KemKeyPair {
                algorithm: "ML-KEM-768".to_string(),
                public_key: vec![],
                encrypted_private_key: vec![],
                private_key_nonce: vec![],
            },
            x25519: X25519KeyPair {
                public_key: vec![],
                encrypted_private_key: vec![],
                private_key_nonce: vec![],
            },
            secrets: HashMap::new(),
        };
        let err = validate_version(&vault).unwrap_err();
        assert!(err.to_string().contains("anti-rollback"));
    }

    #[test]
    fn test_validate_version_rejects_too_old() {
        let vault = Vault {
            version: MIN_SUPPORTED_VERSION - 1,
            min_version: 0,
            created: Utc::now(),
            kdf: KdfParams {
                algorithm: "argon2id".to_string(),
                salt: vec![0; 16],
                time_cost: 1,
                memory_cost: 8192,
                parallelism: 1,
            },
            kem: KemKeyPair {
                algorithm: "ML-KEM-768".to_string(),
                public_key: vec![],
                encrypted_private_key: vec![],
                private_key_nonce: vec![],
            },
            x25519: X25519KeyPair {
                public_key: vec![],
                encrypted_private_key: vec![],
                private_key_nonce: vec![],
            },
            secrets: HashMap::new(),
        };
        let err = validate_version(&vault).unwrap_err();
        assert!(err.to_string().contains("too old"));
    }

    #[test]
    fn test_needs_migration_current_version() {
        let vault = Vault {
            version: VAULT_VERSION,
            min_version: VAULT_VERSION,
            created: Utc::now(),
            kdf: KdfParams {
                algorithm: "argon2id".to_string(),
                salt: vec![],
                time_cost: 1,
                memory_cost: 8192,
                parallelism: 1,
            },
            kem: KemKeyPair {
                algorithm: "ML-KEM-768".to_string(),
                public_key: vec![],
                encrypted_private_key: vec![],
                private_key_nonce: vec![],
            },
            x25519: X25519KeyPair {
                public_key: vec![],
                encrypted_private_key: vec![],
                private_key_nonce: vec![],
            },
            secrets: HashMap::new(),
        };
        assert!(!needs_migration(&vault));
    }

    #[test]
    fn test_needs_migration_old_version() {
        let vault = Vault {
            version: 4,
            min_version: 0,
            created: Utc::now(),
            kdf: KdfParams {
                algorithm: "argon2id".to_string(),
                salt: vec![],
                time_cost: 1,
                memory_cost: 8192,
                parallelism: 1,
            },
            kem: KemKeyPair {
                algorithm: "ML-KEM-768".to_string(),
                public_key: vec![],
                encrypted_private_key: vec![],
                private_key_nonce: vec![],
            },
            x25519: X25519KeyPair {
                public_key: vec![],
                encrypted_private_key: vec![],
                private_key_nonce: vec![],
            },
            secrets: HashMap::new(),
        };
        assert!(needs_migration(&vault));
    }

    #[test]
    fn test_migrate_v4_to_v5() {
        let (mut vault, master_key) = make_v4_vault("test-passphrase");
        assert_eq!(vault.version, 4);

        migrate_vault(&mut vault, &master_key).unwrap();

        assert_eq!(vault.version, VAULT_VERSION);
        assert_eq!(vault.min_version, VAULT_VERSION);

        // Verify we can decrypt private keys with v5 wrapping
        let wrapping = derive_wrapping_keys(&master_key, 5).unwrap();
        let mlkem_nonce: [u8; 12] = vault.kem.private_key_nonce.as_slice().try_into().unwrap();
        let mlkem_sk =
            aes_decrypt(&wrapping.mlkem, &vault.kem.encrypted_private_key, &mlkem_nonce).unwrap();
        let _ = MlKemPrivateKey::from_bytes(mlkem_sk).unwrap();

        let x25519_nonce: [u8; 12] =
            vault.x25519.private_key_nonce.as_slice().try_into().unwrap();
        let x25519_sk = aes_decrypt(
            &wrapping.x25519,
            &vault.x25519.encrypted_private_key,
            &x25519_nonce,
        )
        .unwrap();
        let _: [u8; 32] = x25519_sk.as_slice().try_into().unwrap();
    }

    #[test]
    fn test_migrate_v3_to_v5() {
        let (mut vault, master_key) = make_v3_vault("test-passphrase");
        assert_eq!(vault.version, 3);

        migrate_vault(&mut vault, &master_key).unwrap();

        assert_eq!(vault.version, VAULT_VERSION);
        assert_eq!(vault.min_version, VAULT_VERSION);

        // Verify we can decrypt with v5 wrapping
        let wrapping = derive_wrapping_keys(&master_key, 5).unwrap();
        let mlkem_nonce: [u8; 12] = vault.kem.private_key_nonce.as_slice().try_into().unwrap();
        let mlkem_sk =
            aes_decrypt(&wrapping.mlkem, &vault.kem.encrypted_private_key, &mlkem_nonce).unwrap();
        let _ = MlKemPrivateKey::from_bytes(mlkem_sk).unwrap();
    }

    #[test]
    fn test_migrate_v4_wrong_passphrase_fails() {
        let (mut vault, _master_key) = make_v4_vault("correct-passphrase");

        let bad_salt = vault.kdf.salt.clone();
        let bad_config = KdfConfig {
            salt: bad_salt,
            time_cost: vault.kdf.time_cost,
            memory_cost: vault.kdf.memory_cost,
            parallelism: vault.kdf.parallelism,
        };
        let bad_key = derive_key("wrong-passphrase", &bad_config).unwrap();

        let result = migrate_vault(&mut vault, &bad_key);
        assert!(result.is_err());
    }

    #[test]
    fn test_wrapping_keys_differ_across_versions() {
        let salt = b"fixed-salt-for-testing-12345".to_vec();
        let kdf_config = KdfConfig {
            salt,
            time_cost: 1,
            memory_cost: 8192,
            parallelism: 1,
        };
        let mk = derive_key("test", &kdf_config).unwrap();

        let v4 = derive_wrapping_keys(&mk, 4).unwrap();
        let v5 = derive_wrapping_keys(&mk, 5).unwrap();

        // v4 and v5 must produce different wrapping keys (domain separation)
        assert_ne!(v4.mlkem.as_bytes(), v5.mlkem.as_bytes());
        assert_ne!(v4.x25519.as_bytes(), v5.x25519.as_bytes());
    }

    #[test]
    fn test_v3_wrapping_uses_raw_master_key() {
        let salt = b"fixed-salt-for-testing-12345".to_vec();
        let kdf_config = KdfConfig {
            salt,
            time_cost: 1,
            memory_cost: 8192,
            parallelism: 1,
        };
        let mk = derive_key("test", &kdf_config).unwrap();

        let v3 = derive_wrapping_keys(&mk, 3).unwrap();

        // v3: both wrapping keys == raw master key
        assert_eq!(v3.mlkem.as_bytes(), mk.as_bytes());
        assert_eq!(v3.x25519.as_bytes(), mk.as_bytes());
        assert_eq!(v3.mlkem.as_bytes(), v3.x25519.as_bytes());
    }

    #[test]
    fn test_no_downgrade_after_migration() {
        let (mut vault, master_key) = make_v4_vault("test-passphrase");
        migrate_vault(&mut vault, &master_key).unwrap();

        // Simulate an older binary checking the vault
        assert!(vault.version > 4);
        assert!(vault.min_version > 4);

        // Old v4 wrapping keys must NOT decrypt the migrated private keys
        let old_wrapping = derive_wrapping_keys(&master_key, 4).unwrap();
        let mlkem_nonce: [u8; 12] = vault.kem.private_key_nonce.as_slice().try_into().unwrap();
        let result =
            aes_decrypt(&old_wrapping.mlkem, &vault.kem.encrypted_private_key, &mlkem_nonce);
        // AES-GCM decryption with wrong key should fail (auth tag mismatch)
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_version_rejects_corrupt_min_version() {
        let vault = Vault {
            version: 4,
            min_version: 5, // min_version > version = corrupt
            created: Utc::now(),
            kdf: KdfParams {
                algorithm: "argon2id".to_string(),
                salt: vec![0; 16],
                time_cost: 1,
                memory_cost: 8192,
                parallelism: 1,
            },
            kem: KemKeyPair {
                algorithm: "ML-KEM-768".to_string(),
                public_key: vec![],
                encrypted_private_key: vec![],
                private_key_nonce: vec![],
            },
            x25519: X25519KeyPair {
                public_key: vec![],
                encrypted_private_key: vec![],
                private_key_nonce: vec![],
            },
            secrets: HashMap::new(),
        };
        let err = validate_version(&vault).unwrap_err();
        assert!(err.to_string().contains("Corrupt vault"));
    }

    #[test]
    fn test_validate_version_rejects_version_zero() {
        let vault = Vault {
            version: 0,
            min_version: 0,
            created: Utc::now(),
            kdf: KdfParams {
                algorithm: "argon2id".to_string(),
                salt: vec![0; 16],
                time_cost: 1,
                memory_cost: 8192,
                parallelism: 1,
            },
            kem: KemKeyPair {
                algorithm: "ML-KEM-768".to_string(),
                public_key: vec![],
                encrypted_private_key: vec![],
                private_key_nonce: vec![],
            },
            x25519: X25519KeyPair {
                public_key: vec![],
                encrypted_private_key: vec![],
                private_key_nonce: vec![],
            },
            secrets: HashMap::new(),
        };
        let err = validate_version(&vault).unwrap_err();
        assert!(err.to_string().contains("too old"));
    }

    #[test]
    fn test_validate_version_rejects_u32_max() {
        let vault = Vault {
            version: u32::MAX,
            min_version: 0,
            created: Utc::now(),
            kdf: KdfParams {
                algorithm: "argon2id".to_string(),
                salt: vec![0; 16],
                time_cost: 1,
                memory_cost: 8192,
                parallelism: 1,
            },
            kem: KemKeyPair {
                algorithm: "ML-KEM-768".to_string(),
                public_key: vec![],
                encrypted_private_key: vec![],
                private_key_nonce: vec![],
            },
            x25519: X25519KeyPair {
                public_key: vec![],
                encrypted_private_key: vec![],
                private_key_nonce: vec![],
            },
            secrets: HashMap::new(),
        };
        let err = validate_version(&vault).unwrap_err();
        assert!(err.to_string().contains("newer than this binary"));
    }

    #[test]
    fn test_migrate_v4_already_at_target_is_noop() {
        let (mut vault, master_key) = make_v4_vault("test-passphrase");
        vault.version = VAULT_VERSION;
        vault.min_version = VAULT_VERSION;

        // Should not error — already at target
        assert!(!needs_migration(&vault));
    }

    #[test]
    fn test_migrate_preserves_vault_metadata() {
        let (mut vault, master_key) = make_v4_vault("test-passphrase");
        let original_created = vault.created;
        let original_algorithm = vault.kem.algorithm.clone();
        let original_public_key = vault.kem.public_key.clone();

        migrate_vault(&mut vault, &master_key).unwrap();

        // Migration should NOT change public keys, creation time, or algorithm
        assert_eq!(vault.created, original_created);
        assert_eq!(vault.kem.algorithm, original_algorithm);
        assert_eq!(vault.kem.public_key, original_public_key);
    }

    #[test]
    fn test_v4_wrapping_key_separation() {
        let salt = b"fixed-salt-for-testing-12345".to_vec();
        let kdf_config = KdfConfig {
            salt,
            time_cost: 1,
            memory_cost: 8192,
            parallelism: 1,
        };
        let mk = derive_key("test", &kdf_config).unwrap();

        let v4 = derive_wrapping_keys(&mk, 4).unwrap();

        // v4+ must produce distinct ML-KEM and X25519 wrapping keys
        assert_ne!(v4.mlkem.as_bytes(), v4.x25519.as_bytes());
    }

    #[test]
    fn test_v5_wrapping_key_separation() {
        let salt = b"fixed-salt-for-testing-12345".to_vec();
        let kdf_config = KdfConfig {
            salt,
            time_cost: 1,
            memory_cost: 8192,
            parallelism: 1,
        };
        let mk = derive_key("test", &kdf_config).unwrap();

        let v5 = derive_wrapping_keys(&mk, 5).unwrap();

        // v5 must also produce distinct ML-KEM and X25519 wrapping keys
        assert_ne!(v5.mlkem.as_bytes(), v5.x25519.as_bytes());
    }

    #[test]
    fn test_wrapping_keys_deterministic() {
        let salt = b"fixed-salt-for-testing-12345".to_vec();
        let kdf_config = KdfConfig {
            salt,
            time_cost: 1,
            memory_cost: 8192,
            parallelism: 1,
        };
        let mk = derive_key("test", &kdf_config).unwrap();

        let a = derive_wrapping_keys(&mk, 5).unwrap();
        let b = derive_wrapping_keys(&mk, 5).unwrap();

        assert_eq!(a.mlkem.as_bytes(), b.mlkem.as_bytes());
        assert_eq!(a.x25519.as_bytes(), b.x25519.as_bytes());
    }
}
