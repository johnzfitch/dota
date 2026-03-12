//! Vault migration engine ("upvault")
//!
//! Automatically upgrades vaults from any older version to the current version.
//! Each version step is handled by a single `upvault_vN` function that converts
//! version N to N+1. The engine chains these steps to reach the current version.
//!
//! Security invariants:
//! - Backup is created ONLY after successful in-memory migration (deferred backup)
//! - All decrypted key material is wrapped in `Zeroizing<T>` for RAII cleanup
//! - Wrong passphrase / corrupted data → error before any disk writes

use super::format::{
    EncryptedSecret, KemKeyPair, MigrationInfo, Vault, VAULT_VERSION, X25519KeyPair,
};
use super::legacy::{VaultV1, VaultV2, VaultV3, VaultVersionProbe};
use super::ops::{compute_key_commitment, derive_wrapping_keys, save_vault_file};
use crate::crypto::{
    AesKey, KdfConfig, MasterKey, aes_decrypt, aes_encrypt, derive_key, hybrid_encapsulate,
    mlkem_generate_keypair, MlKemPublicKey, X25519PrivateKey, X25519PublicKey,
};
use anyhow::{Context, Result, bail};
use chrono::Utc;
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use zeroize::Zeroizing;

const MAX_BACKUPS: usize = 5;

/// Migrate a vault from any older version to the current version.
///
/// All migration happens in memory first. Backup and disk write occur only
/// after the full migration chain succeeds. Returns the migrated Vault.
pub fn upvault(original_json: &str, passphrase: &str, vault_path: &str) -> Result<Vault> {
    let probe: VaultVersionProbe =
        serde_json::from_str(original_json).context("Failed to parse vault version")?;

    if probe.version > VAULT_VERSION {
        bail!(
            "Vault version {} is newer than supported (v{}). Please update dota.",
            probe.version,
            VAULT_VERSION
        );
    }

    if probe.version >= VAULT_VERSION {
        bail!(
            "Vault is already at v{} (current: v{})",
            probe.version,
            VAULT_VERSION
        );
    }

    if probe.version == 0 {
        bail!("Unknown vault version: 0");
    }

    // Derive master key once — shared across all migration steps
    let kdf_params = parse_kdf_params(original_json)?;
    let master_key = derive_key(passphrase, &kdf_params)?;

    // Build the migration path: [original_version, ..., VAULT_VERSION]
    let migration_path: Vec<u32> = (probe.version..=VAULT_VERSION).collect();

    // Run the stepwise upvault chain. Each step converts vN → vN+1 in memory.
    let vault = match probe.version {
        1 => {
            let v1: VaultV1 =
                serde_json::from_str(original_json).context("Failed to parse v1 vault")?;
            let v2 = upvault_v1(v1, &master_key)?;
            let v3 = upvault_v2(v2)?;
            let v4 = upvault_v3(v3, &master_key)?;
            upvault_v4(v4, probe.version, &migration_path, &master_key)?
        }
        2 => {
            let v2: VaultV2 =
                serde_json::from_str(original_json).context("Failed to parse v2 vault")?;
            let v3 = upvault_v2(v2)?;
            let v4 = upvault_v3(v3, &master_key)?;
            upvault_v4(v4, probe.version, &migration_path, &master_key)?
        }
        3 => {
            let v3: VaultV3 =
                serde_json::from_str(original_json).context("Failed to parse v3 vault")?;
            let v4 = upvault_v3(v3, &master_key)?;
            upvault_v4(v4, probe.version, &migration_path, &master_key)?
        }
        4 => {
            let v4: Vault =
                serde_json::from_str(original_json).context("Failed to parse v4 vault")?;
            upvault_v4(v4, probe.version, &migration_path, &master_key)?
        }
        _ => bail!("Unsupported vault version: {}", probe.version),
    };

    // === All in-memory migration succeeded — now persist ===
    create_backup(vault_path)?;
    save_vault_file(vault_path, &vault)?;

    eprintln!(
        "Migration complete: v{} → v{}",
        probe.version, VAULT_VERSION
    );

    Ok(vault)
}

// ---------------------------------------------------------------------------
// Step functions: each converts vN → vN+1
// ---------------------------------------------------------------------------

/// v1 → v2: Add ML-KEM-768, re-encrypt secrets with hybrid KEM
fn upvault_v1(v1: VaultV1, master_key: &MasterKey) -> Result<VaultV2> {
    // v1 uses master key directly as AES key for private key wrapping
    let wrapping_key = AesKey::from_bytes(*master_key.as_bytes());

    // Decrypt X25519 private key
    let x25519_sk_bytes = Zeroizing::new(
        aes_decrypt(
            &wrapping_key,
            &v1.encrypted_private_key,
            v1.private_key_nonce
                .as_slice()
                .try_into()
                .context("Invalid v1 nonce length")?,
        )
        .context("Failed to decrypt v1 X25519 private key (wrong passphrase?)")?,
    );
    let x25519_private = X25519PrivateKey::from_bytes(
        x25519_sk_bytes
            .as_slice()
            .try_into()
            .context("Invalid X25519 key length")?,
    );
    let x25519_public = X25519PublicKey::from_bytes(
        v1.x25519_public_key
            .as_slice()
            .try_into()
            .context("Invalid v1 X25519 public key length")?,
    );

    // Generate new ML-KEM keypair
    let (mlkem_public, mlkem_private) = mlkem_generate_keypair()?;

    // Encrypt both private keys using master key directly (v2 wrapping style)
    let (enc_mlkem_sk, mlkem_nonce) = aes_encrypt(&wrapping_key, mlkem_private.as_bytes())?;
    let (enc_x25519_sk, x25519_nonce) = aes_encrypt(&wrapping_key, x25519_private.as_bytes())?;

    // Re-encrypt all secrets from X25519-only to hybrid KEM
    let mut secrets = HashMap::new();
    for (name, secret_v1) in v1.secrets {
        // v1: decrypt secret using X25519 DH shared secret as AES key
        let eph_pk = X25519PublicKey::from_bytes(
            secret_v1
                .x25519_ephemeral_public
                .as_slice()
                .try_into()
                .context("Invalid v1 ephemeral public key")?,
        );
        let dh_ss = crate::crypto::x25519::diffie_hellman(&x25519_private, &eph_pk)?;
        let v1_aes_key = AesKey::from_bytes(*dh_ss.as_bytes());

        let plaintext = Zeroizing::new(aes_decrypt(
            &v1_aes_key,
            &secret_v1.ciphertext,
            secret_v1
                .nonce
                .as_slice()
                .try_into()
                .context("Invalid v1 secret nonce")?,
        )?);

        // Re-encrypt with hybrid KEM
        let encap = hybrid_encapsulate(
            &MlKemPublicKey::from_bytes(mlkem_public.as_bytes().to_vec())?,
            &x25519_public,
        )?;
        let (ciphertext, nonce) = aes_encrypt(&encap.derived_key, &plaintext)?;

        secrets.insert(
            name,
            EncryptedSecret {
                algorithm: "hybrid-mlkem768-x25519".to_string(),
                kem_ciphertext: encap.kem_ciphertext.as_bytes().to_vec(),
                x25519_ephemeral_public: encap.x25519_ephemeral_public.as_bytes().to_vec(),
                nonce: nonce.to_vec(),
                ciphertext,
                created: secret_v1.created,
                modified: secret_v1.modified,
            },
        );
    }

    Ok(VaultV2 {
        version: 2,
        created: v1.created,
        kdf: v1.kdf,
        mlkem_public_key: mlkem_public.as_bytes().to_vec(),
        encrypted_mlkem_private_key: enc_mlkem_sk,
        mlkem_private_key_nonce: mlkem_nonce.to_vec(),
        x25519_public_key: v1.x25519_public_key,
        encrypted_x25519_private_key: enc_x25519_sk,
        x25519_private_key_nonce: x25519_nonce.to_vec(),
        secrets,
    })
}

/// v2 → v3: Restructure flat fields into nested structs (no crypto changes)
fn upvault_v2(v2: VaultV2) -> Result<VaultV3> {
    Ok(VaultV3 {
        version: 3,
        created: v2.created,
        kdf: v2.kdf,
        kem: KemKeyPair {
            algorithm: "ML-KEM-768".to_string(),
            public_key: v2.mlkem_public_key,
            encrypted_private_key: v2.encrypted_mlkem_private_key,
            private_key_nonce: v2.mlkem_private_key_nonce,
        },
        x25519: X25519KeyPair {
            public_key: v2.x25519_public_key,
            encrypted_private_key: v2.encrypted_x25519_private_key,
            private_key_nonce: v2.x25519_private_key_nonce,
        },
        secrets: v2.secrets,
    })
}

/// v3 → v4: Re-wrap private keys with HKDF-derived wrapping keys (key separation)
fn upvault_v3(v3: VaultV3, master_key: &MasterKey) -> Result<Vault> {
    // v3 uses master key directly as AES key
    let direct_key = AesKey::from_bytes(*master_key.as_bytes());

    // Decrypt both private keys using direct master key
    let mlkem_sk_bytes = Zeroizing::new(
        aes_decrypt(
            &direct_key,
            &v3.kem.encrypted_private_key,
            v3.kem
                .private_key_nonce
                .as_slice()
                .try_into()
                .context("Invalid v3 ML-KEM nonce")?,
        )
        .context("Failed to decrypt v3 ML-KEM private key (wrong passphrase?)")?,
    );

    let x25519_sk_bytes = Zeroizing::new(
        aes_decrypt(
            &direct_key,
            &v3.x25519.encrypted_private_key,
            v3.x25519
                .private_key_nonce
                .as_slice()
                .try_into()
                .context("Invalid v3 X25519 nonce")?,
        )
        .context("Failed to decrypt v3 X25519 private key (wrong passphrase?)")?,
    );

    // Re-encrypt with HKDF-derived wrapping keys (v4 key separation)
    let wrapping = derive_wrapping_keys(master_key)?;
    let (enc_mlkem_sk, mlkem_nonce) = aes_encrypt(&wrapping.mlkem, &mlkem_sk_bytes)?;
    let (enc_x25519_sk, x25519_nonce) = aes_encrypt(&wrapping.x25519, &x25519_sk_bytes)?;

    Ok(Vault {
        version: 4,
        created: v3.created,
        kdf: v3.kdf,
        key_commitment: None, // Will be set by upvault_v4
        kem: KemKeyPair {
            algorithm: v3.kem.algorithm,
            public_key: v3.kem.public_key,
            encrypted_private_key: enc_mlkem_sk,
            private_key_nonce: mlkem_nonce.to_vec(),
        },
        x25519: X25519KeyPair {
            public_key: v3.x25519.public_key,
            encrypted_private_key: enc_x25519_sk,
            private_key_nonce: x25519_nonce.to_vec(),
        },
        secrets: v3.secrets,
        migrated_from: None, // Will be set by upvault_v4
        min_version: 0,      // Will be set by upvault_v4
    })
}

/// v4 → v5: Add key commitment, migration metadata, and anti-rollback
fn upvault_v4(
    mut v4: Vault,
    original_version: u32,
    migration_path: &[u32],
    master_key: &MasterKey,
) -> Result<Vault> {
    v4.version = 5;
    v4.key_commitment = Some(compute_key_commitment(
        master_key,
        &v4.kdf,
        &v4.kem.public_key,
        &v4.x25519.public_key,
    ));
    v4.min_version = VAULT_VERSION;
    v4.migrated_from = Some(MigrationInfo {
        original_version,
        migrated_at: Utc::now(),
        migration_path: migration_path.to_vec(),
    });
    Ok(v4)
}

// ---------------------------------------------------------------------------
// Backup management
// ---------------------------------------------------------------------------

/// Create a backup of the vault file before overwriting with migrated version.
///
/// Uses timestamped filenames with a cap of MAX_BACKUPS to prevent accumulation.
/// Only called after in-memory migration has fully succeeded.
fn create_backup(vault_path: &str) -> Result<()> {
    let path = Path::new(vault_path);
    if !path.exists() {
        return Ok(()); // Nothing to back up
    }

    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let stem = path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("vault");
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("json");

    // Clean up old backups if over limit
    let mut existing_backups = find_backups(parent, stem, ext)?;
    existing_backups.sort();
    while existing_backups.len() >= MAX_BACKUPS {
        if let Some(oldest) = existing_backups.first() {
            let _ = fs::remove_file(parent.join(oldest));
        }
        existing_backups.remove(0);
    }

    // Create new backup with timestamp
    let timestamp = Utc::now().format("%Y%m%d_%H%M%S");
    let backup_name = format!("{}.backup.{}.{}", stem, timestamp, ext);
    let backup_path = parent.join(&backup_name);

    // Symlink protection: refuse to write through a symlink
    if let Ok(meta) = fs::symlink_metadata(&backup_path)
        && meta.file_type().is_symlink()
    {
        bail!(
            "Refusing to write backup through symlink: {}",
            backup_path.display()
        );
    }

    fs::copy(vault_path, &backup_path)
        .with_context(|| format!("Failed to create vault backup at {}", backup_path.display()))?;

    eprintln!("Backup saved: {}", backup_path.display());
    Ok(())
}

/// Find existing backup files matching the pattern `{stem}.backup.*.{ext}`
fn find_backups(
    dir: &Path,
    stem: &str,
    ext: &str,
) -> Result<Vec<String>> {
    let prefix = format!("{}.backup.", stem);
    let suffix = format!(".{}", ext);

    let mut backups = Vec::new();
    if let Ok(entries) = fs::read_dir(dir) {
        for entry in entries.flatten() {
            if let Some(name) = entry.file_name().to_str()
                && name.starts_with(&prefix)
                && name.ends_with(&suffix)
            {
                backups.push(name.to_string());
            }
        }
    }
    Ok(backups)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Extract KDF parameters from vault JSON (shared across all versions).
fn parse_kdf_params(json: &str) -> Result<KdfConfig> {
    #[derive(serde::Deserialize)]
    struct KdfProbe {
        kdf: super::format::KdfParams,
    }
    let probe: KdfProbe = serde_json::from_str(json).context("Failed to parse KDF parameters")?;
    Ok(KdfConfig {
        salt: probe.kdf.salt,
        time_cost: probe.kdf.time_cost,
        memory_cost: probe.kdf.memory_cost,
        parallelism: probe.kdf.parallelism,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{
        aes_encrypt, derive_key, generate_salt, mlkem_generate_keypair,
        x25519_generate_keypair,
    };
    use tempfile::tempdir;

    /// Helper: build a v1 vault JSON for testing
    fn build_v1_vault(passphrase: &str) -> (String, KdfConfig) {
        let config = KdfConfig {
            salt: generate_salt(),
            time_cost: 1,
            memory_cost: 8192,
            parallelism: 1,
        };
        let master_key = derive_key(passphrase, &config).unwrap();
        let wrapping_key = AesKey::from_bytes(*master_key.as_bytes());

        let (x25519_pk, x25519_sk) = crate::crypto::x25519_generate_keypair();
        let (enc_sk, nonce) = aes_encrypt(&wrapping_key, x25519_sk.as_bytes()).unwrap();

        // Encrypt a test secret: X25519 DH with ephemeral key
        let (eph_pk, eph_sk) = crate::crypto::x25519_generate_keypair();
        let dh_ss = crate::crypto::x25519::diffie_hellman(&eph_sk, &x25519_pk).unwrap();
        let secret_key = AesKey::from_bytes(*dh_ss.as_bytes());
        let (secret_ct, secret_nonce) = aes_encrypt(&secret_key, b"my-secret-value").unwrap();

        use base64::{Engine, engine::general_purpose::STANDARD};
        let json = serde_json::json!({
            "version": 1,
            "created": "2025-01-01T00:00:00Z",
            "kdf": {
                "algorithm": "argon2id",
                "salt": STANDARD.encode(&config.salt),
                "time_cost": config.time_cost,
                "memory_cost": config.memory_cost,
                "parallelism": config.parallelism,
            },
            "x25519_public_key": STANDARD.encode(x25519_pk.as_bytes()),
            "encrypted_private_key": STANDARD.encode(&enc_sk),
            "private_key_nonce": STANDARD.encode(&nonce),
            "secrets": {
                "test-secret": {
                    "x25519_ephemeral_public": STANDARD.encode(eph_pk.as_bytes()),
                    "nonce": STANDARD.encode(&secret_nonce),
                    "ciphertext": STANDARD.encode(&secret_ct),
                    "created": "2025-01-01T00:00:00Z",
                    "modified": "2025-01-01T00:00:00Z",
                }
            }
        });
        (json.to_string(), config)
    }

    /// Helper: build a v3 vault JSON for testing
    fn build_v3_vault(passphrase: &str) -> String {
        let config = KdfConfig {
            salt: generate_salt(),
            time_cost: 1,
            memory_cost: 8192,
            parallelism: 1,
        };
        let master_key = derive_key(passphrase, &config).unwrap();
        let wrapping_key = AesKey::from_bytes(*master_key.as_bytes());

        let (mlkem_pk, mlkem_sk) = mlkem_generate_keypair().unwrap();
        let (x25519_pk, x25519_sk) = x25519_generate_keypair();

        let (enc_mlkem, mlkem_nonce) = aes_encrypt(&wrapping_key, mlkem_sk.as_bytes()).unwrap();
        let (enc_x25519, x25519_nonce) = aes_encrypt(&wrapping_key, x25519_sk.as_bytes()).unwrap();

        use base64::{Engine, engine::general_purpose::STANDARD};
        let json = serde_json::json!({
            "version": 3,
            "created": "2025-06-01T00:00:00Z",
            "kdf": {
                "algorithm": "argon2id",
                "salt": STANDARD.encode(&config.salt),
                "time_cost": config.time_cost,
                "memory_cost": config.memory_cost,
                "parallelism": config.parallelism,
            },
            "kem": {
                "algorithm": "ML-KEM-768",
                "public_key": STANDARD.encode(mlkem_pk.as_bytes()),
                "encrypted_private_key": STANDARD.encode(&enc_mlkem),
                "private_key_nonce": STANDARD.encode(&mlkem_nonce),
            },
            "x25519": {
                "public_key": STANDARD.encode(x25519_pk.as_bytes()),
                "encrypted_private_key": STANDARD.encode(&enc_x25519),
                "private_key_nonce": STANDARD.encode(&x25519_nonce),
            },
            "secrets": {}
        });
        json.to_string()
    }

    /// Helper: build a v4 vault JSON for testing
    fn build_v4_vault(passphrase: &str) -> String {
        let config = KdfConfig {
            salt: generate_salt(),
            time_cost: 1,
            memory_cost: 8192,
            parallelism: 1,
        };
        let master_key = derive_key(passphrase, &config).unwrap();
        let wrapping = derive_wrapping_keys(&master_key).unwrap();

        let (mlkem_pk, mlkem_sk) = mlkem_generate_keypair().unwrap();
        let (x25519_pk, x25519_sk) = x25519_generate_keypair();

        let (enc_mlkem, mlkem_nonce) = aes_encrypt(&wrapping.mlkem, mlkem_sk.as_bytes()).unwrap();
        let (enc_x25519, x25519_nonce) =
            aes_encrypt(&wrapping.x25519, x25519_sk.as_bytes()).unwrap();

        use base64::{Engine, engine::general_purpose::STANDARD};
        let json = serde_json::json!({
            "version": 4,
            "created": "2025-09-01T00:00:00Z",
            "kdf": {
                "algorithm": "argon2id",
                "salt": STANDARD.encode(&config.salt),
                "time_cost": config.time_cost,
                "memory_cost": config.memory_cost,
                "parallelism": config.parallelism,
            },
            "kem": {
                "algorithm": "ML-KEM-768",
                "public_key": STANDARD.encode(mlkem_pk.as_bytes()),
                "encrypted_private_key": STANDARD.encode(&enc_mlkem),
                "private_key_nonce": STANDARD.encode(&mlkem_nonce),
            },
            "x25519": {
                "public_key": STANDARD.encode(x25519_pk.as_bytes()),
                "encrypted_private_key": STANDARD.encode(&enc_x25519),
                "private_key_nonce": STANDARD.encode(&x25519_nonce),
            },
            "secrets": {}
        });
        json.to_string()
    }

    #[test]
    fn test_upvault_v4_to_v5_adds_metadata() {
        let dir = tempdir().unwrap();
        let vault_path = dir.path().join("vault.json");
        let json = build_v4_vault("test-passphrase");
        fs::write(&vault_path, &json).unwrap();

        let result = upvault(&json, "test-passphrase", vault_path.to_str().unwrap()).unwrap();
        assert_eq!(result.version, 5);
        let info = result.migrated_from.as_ref().unwrap();
        assert_eq!(info.original_version, 4);
        assert_eq!(info.migration_path, vec![4, 5]);
    }

    #[test]
    fn test_upvault_v3_to_v5_rewraps_keys() {
        let dir = tempdir().unwrap();
        let vault_path = dir.path().join("vault.json");
        let json = build_v3_vault("test-passphrase");
        fs::write(&vault_path, &json).unwrap();

        let result = upvault(&json, "test-passphrase", vault_path.to_str().unwrap()).unwrap();
        assert_eq!(result.version, 5);
        let info = result.migrated_from.as_ref().unwrap();
        assert_eq!(info.original_version, 3);
        assert_eq!(info.migration_path, vec![3, 4, 5]);

        // Verify the private keys can be decrypted with HKDF-derived wrapping keys
        let config = KdfConfig {
            salt: result.kdf.salt.clone(),
            time_cost: result.kdf.time_cost,
            memory_cost: result.kdf.memory_cost,
            parallelism: result.kdf.parallelism,
        };
        let mk = derive_key("test-passphrase", &config).unwrap();
        let wrapping = derive_wrapping_keys(&mk).unwrap();

        let mlkem_sk = aes_decrypt(
            &wrapping.mlkem,
            &result.kem.encrypted_private_key,
            result.kem.private_key_nonce.as_slice().try_into().unwrap(),
        );
        assert!(mlkem_sk.is_ok(), "ML-KEM private key should decrypt with HKDF wrapping key");

        let x25519_sk = aes_decrypt(
            &wrapping.x25519,
            &result.x25519.encrypted_private_key,
            result.x25519.private_key_nonce.as_slice().try_into().unwrap(),
        );
        assert!(x25519_sk.is_ok(), "X25519 private key should decrypt with HKDF wrapping key");
    }

    #[test]
    fn test_upvault_v1_to_v5_full_chain() {
        let dir = tempdir().unwrap();
        let vault_path = dir.path().join("vault.json");
        let (json, _config) = build_v1_vault("test-passphrase");
        fs::write(&vault_path, &json).unwrap();

        let result = upvault(&json, "test-passphrase", vault_path.to_str().unwrap()).unwrap();
        assert_eq!(result.version, 5);
        let info = result.migrated_from.as_ref().unwrap();
        assert_eq!(info.original_version, 1);
        assert_eq!(info.migration_path, vec![1, 2, 3, 4, 5]);
        assert!(result.secrets.contains_key("test-secret"));

        // Verify the migrated secret is decryptable
        let config = KdfConfig {
            salt: result.kdf.salt.clone(),
            time_cost: result.kdf.time_cost,
            memory_cost: result.kdf.memory_cost,
            parallelism: result.kdf.parallelism,
        };
        let mk = derive_key("test-passphrase", &config).unwrap();
        let wrapping = derive_wrapping_keys(&mk).unwrap();

        // Decrypt private keys
        let mlkem_sk_bytes = aes_decrypt(
            &wrapping.mlkem,
            &result.kem.encrypted_private_key,
            result.kem.private_key_nonce.as_slice().try_into().unwrap(),
        )
        .unwrap();
        let mlkem_sk = crate::crypto::MlKemPrivateKey::from_bytes(mlkem_sk_bytes).unwrap();

        let x25519_sk_bytes = aes_decrypt(
            &wrapping.x25519,
            &result.x25519.encrypted_private_key,
            result.x25519.private_key_nonce.as_slice().try_into().unwrap(),
        )
        .unwrap();
        let x25519_sk = X25519PrivateKey::from_bytes(
            x25519_sk_bytes.as_slice().try_into().unwrap(),
        );

        // Decrypt the secret using hybrid decapsulation
        let secret = &result.secrets["test-secret"];
        let kem_ct =
            crate::crypto::MlKemCiphertext::from_bytes(secret.kem_ciphertext.clone()).unwrap();
        let eph_pk = X25519PublicKey::from_bytes(
            secret.x25519_ephemeral_public.as_slice().try_into().unwrap(),
        );
        let aes_key =
            crate::crypto::hybrid_decapsulate(&mlkem_sk, &x25519_sk, &kem_ct, &eph_pk).unwrap();
        let nonce: [u8; 12] = secret.nonce.as_slice().try_into().unwrap();
        let plaintext = aes_decrypt(&aes_key, &secret.ciphertext, &nonce).unwrap();
        assert_eq!(String::from_utf8(plaintext).unwrap(), "my-secret-value");
    }

    #[test]
    fn test_wrong_passphrase_no_backup() {
        let dir = tempdir().unwrap();
        let vault_path = dir.path().join("vault.json");
        let json = build_v3_vault("correct-passphrase");
        fs::write(&vault_path, &json).unwrap();

        let result = upvault(&json, "wrong-passphrase", vault_path.to_str().unwrap());
        assert!(result.is_err());

        // No backup should have been created
        let backups = find_backups(dir.path(), "vault", "json").unwrap();
        assert!(backups.is_empty(), "No backup should exist after failed migration");
    }

    #[test]
    fn test_backup_created_on_success() {
        let dir = tempdir().unwrap();
        let vault_path = dir.path().join("vault.json");
        let json = build_v4_vault("test-passphrase");
        fs::write(&vault_path, &json).unwrap();

        upvault(&json, "test-passphrase", vault_path.to_str().unwrap()).unwrap();

        let backups = find_backups(dir.path(), "vault", "json").unwrap();
        assert_eq!(backups.len(), 1, "Exactly one backup should exist");
    }

    #[test]
    fn test_backup_limit_enforcement() {
        let dir = tempdir().unwrap();
        let vault_path = dir.path().join("vault.json");
        let json = build_v4_vault("test-passphrase");
        fs::write(&vault_path, &json).unwrap();

        // Create MAX_BACKUPS existing backup files
        for i in 0..MAX_BACKUPS {
            let name = format!("vault.backup.20250101_{:06}.json", i);
            fs::write(dir.path().join(&name), "old backup").unwrap();
        }

        upvault(&json, "test-passphrase", vault_path.to_str().unwrap()).unwrap();

        let backups = find_backups(dir.path(), "vault", "json").unwrap();
        assert!(
            backups.len() <= MAX_BACKUPS,
            "Should not exceed MAX_BACKUPS ({}), got {}",
            MAX_BACKUPS,
            backups.len()
        );
    }

    #[test]
    fn test_future_version_rejected() {
        let json = r#"{"version": 99}"#;
        let result = upvault(json, "pass", "/tmp/fake.json");
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("newer than supported") || err.contains("update dota"),
            "Expected future version rejection, got: {}",
            err
        );
    }

    #[test]
    fn test_current_version_rejected() {
        let json = format!(r#"{{"version": {}}}"#, VAULT_VERSION);
        let result = upvault(&json, "pass", "/tmp/fake.json");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("already at"));
    }

    #[test]
    fn test_version_zero_rejected() {
        let json = r#"{"version": 0}"#;
        let result = upvault(json, "pass", "/tmp/fake.json");
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_json_rejected() {
        let result = upvault("not json at all", "pass", "/tmp/fake.json");
        assert!(result.is_err());
    }

    #[test]
    fn test_v1_empty_secrets_migrates() {
        // v1 vault with no secrets should migrate cleanly
        let config = KdfConfig {
            salt: generate_salt(),
            time_cost: 1,
            memory_cost: 8192,
            parallelism: 1,
        };
        let master_key = derive_key("test-passphrase", &config).unwrap();
        let wrapping_key = AesKey::from_bytes(*master_key.as_bytes());

        let (x25519_pk, x25519_sk) = x25519_generate_keypair();
        let (enc_sk, nonce) = aes_encrypt(&wrapping_key, x25519_sk.as_bytes()).unwrap();

        use base64::{Engine, engine::general_purpose::STANDARD};
        let json = serde_json::json!({
            "version": 1,
            "created": "2025-01-01T00:00:00Z",
            "kdf": {
                "algorithm": "argon2id",
                "salt": STANDARD.encode(&config.salt),
                "time_cost": config.time_cost,
                "memory_cost": config.memory_cost,
                "parallelism": config.parallelism,
            },
            "x25519_public_key": STANDARD.encode(x25519_pk.as_bytes()),
            "encrypted_private_key": STANDARD.encode(&enc_sk),
            "private_key_nonce": STANDARD.encode(&nonce),
            "secrets": {}
        })
        .to_string();

        let dir = tempdir().unwrap();
        let vault_path = dir.path().join("vault.json");
        fs::write(&vault_path, &json).unwrap();

        let result = upvault(&json, "test-passphrase", vault_path.to_str().unwrap()).unwrap();
        assert_eq!(result.version, 5);
        assert!(result.secrets.is_empty());
    }

    #[test]
    fn test_v3_wrong_passphrase_fails_before_rewrap() {
        let dir = tempdir().unwrap();
        let vault_path = dir.path().join("vault.json");
        let json = build_v3_vault("correct-passphrase");
        fs::write(&vault_path, &json).unwrap();

        let err = upvault(&json, "wrong-passphrase", vault_path.to_str().unwrap()).unwrap_err();
        // Should mention passphrase/decryption failure
        let msg = err.to_string();
        assert!(
            msg.contains("passphrase") || msg.contains("decrypt") || msg.contains("AES-GCM"),
            "Expected passphrase-related error, got: {}",
            msg
        );
    }

    #[test]
    fn test_migrated_vault_file_is_valid_v5() {
        let dir = tempdir().unwrap();
        let vault_path = dir.path().join("vault.json");
        let json = build_v4_vault("test-passphrase");
        fs::write(&vault_path, &json).unwrap();

        upvault(&json, "test-passphrase", vault_path.to_str().unwrap()).unwrap();

        // Read the file back and verify it's valid v5
        let saved = fs::read_to_string(&vault_path).unwrap();
        let vault: Vault = serde_json::from_str(&saved).unwrap();
        assert_eq!(vault.version, 5);
        assert!(vault.migrated_from.is_some());
    }

    #[test]
    fn test_backup_preserves_original_content() {
        let dir = tempdir().unwrap();
        let vault_path = dir.path().join("vault.json");
        let json = build_v4_vault("test-passphrase");
        fs::write(&vault_path, &json).unwrap();

        upvault(&json, "test-passphrase", vault_path.to_str().unwrap()).unwrap();

        let backups = find_backups(dir.path(), "vault", "json").unwrap();
        assert_eq!(backups.len(), 1);
        let backup_content = fs::read_to_string(dir.path().join(&backups[0])).unwrap();
        assert_eq!(backup_content, json, "Backup should preserve original vault content");
    }

    #[test]
    fn test_v1_multiple_secrets_all_migrate() {
        let config = KdfConfig {
            salt: generate_salt(),
            time_cost: 1,
            memory_cost: 8192,
            parallelism: 1,
        };
        let master_key = derive_key("test-passphrase", &config).unwrap();
        let wrapping_key = AesKey::from_bytes(*master_key.as_bytes());

        let (x25519_pk, x25519_sk) = x25519_generate_keypair();
        let (enc_sk, nonce) = aes_encrypt(&wrapping_key, x25519_sk.as_bytes()).unwrap();

        use base64::{Engine, engine::general_purpose::STANDARD};

        let mut secrets = serde_json::Map::new();
        for i in 0..5 {
            let (eph_pk, eph_sk) = crate::crypto::x25519_generate_keypair();
            let dh_ss = crate::crypto::x25519::diffie_hellman(&eph_sk, &x25519_pk).unwrap();
            let secret_key = AesKey::from_bytes(*dh_ss.as_bytes());
            let value = format!("secret-value-{}", i);
            let (ct, sn) = aes_encrypt(&secret_key, value.as_bytes()).unwrap();

            secrets.insert(
                format!("key-{}", i),
                serde_json::json!({
                    "x25519_ephemeral_public": STANDARD.encode(eph_pk.as_bytes()),
                    "nonce": STANDARD.encode(&sn),
                    "ciphertext": STANDARD.encode(&ct),
                    "created": "2025-01-01T00:00:00Z",
                    "modified": "2025-01-01T00:00:00Z",
                }),
            );
        }

        let json = serde_json::json!({
            "version": 1,
            "created": "2025-01-01T00:00:00Z",
            "kdf": {
                "algorithm": "argon2id",
                "salt": STANDARD.encode(&config.salt),
                "time_cost": config.time_cost,
                "memory_cost": config.memory_cost,
                "parallelism": config.parallelism,
            },
            "x25519_public_key": STANDARD.encode(x25519_pk.as_bytes()),
            "encrypted_private_key": STANDARD.encode(&enc_sk),
            "private_key_nonce": STANDARD.encode(&nonce),
            "secrets": secrets
        })
        .to_string();

        let dir = tempdir().unwrap();
        let vault_path = dir.path().join("vault.json");
        fs::write(&vault_path, &json).unwrap();

        let result = upvault(&json, "test-passphrase", vault_path.to_str().unwrap()).unwrap();
        assert_eq!(result.secrets.len(), 5, "All 5 secrets should migrate");
        for i in 0..5 {
            assert!(
                result.secrets.contains_key(&format!("key-{}", i)),
                "Secret key-{} should exist",
                i
            );
        }
    }
}
