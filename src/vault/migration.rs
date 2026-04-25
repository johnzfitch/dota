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
    EncryptedSecret, KemKeyPair, MigrationInfo, V5_VAULT_VERSION, V6_KEM_ALGORITHM,
    V6_SECRET_ALGORITHM, V6_SUITE, V6_VAULT_VERSION, V6_X25519_ALGORITHM, V7_KEM_ALGORITHM,
    V7_SECRET_ALGORITHM, V7_SUITE, V7_VAULT_VERSION, V7_X25519_ALGORITHM, VAULT_VERSION, Vault,
    X25519KeyPair,
};
use super::legacy::{VaultV1, VaultV2, VaultV3, VaultVersionProbe};
use super::ops::{
    compute_key_commitment, derive_wrapping_keys, derive_wrapping_keys_v6, derive_wrapping_keys_v7,
    save_vault_file, verify_v5_key_commitment,
};
use crate::crypto::hybrid::{
    hybrid_decapsulate_legacy, hybrid_decapsulate_v6, hybrid_encapsulate_legacy,
    hybrid_encapsulate_v6, hybrid_encapsulate_v7,
};
use crate::crypto::legacy_kyber::{self, LegacyKyberCiphertext, LegacyKyberPrivateKey};
use crate::crypto::{
    AesKey, KdfConfig, MasterKey, X25519PrivateKey, X25519PublicKey, aes_decrypt, aes_encrypt,
    derive_key, mlkem_generate_keypair,
};
use anyhow::{Context, Result, bail};
use chrono::Utc;
use std::collections::HashMap;
use std::fs;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
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

    // Run the stepwise upvault chain. All paths terminate at v7.
    let vault = match probe.version {
        1 => {
            let v1: VaultV1 =
                serde_json::from_str(original_json).context("Failed to parse v1 vault")?;
            let v2 = upvault_v1(v1, &master_key)?;
            let v3 = upvault_v2(v2)?;
            let v4 = upvault_v3(v3, &master_key)?;
            let v5 = upvault_v4(v4, &master_key)?;
            let v6 = upvault_v5_to_v6(v5, probe.version, &migration_path, &master_key)?;
            upvault_v6_to_v7(v6, probe.version, &migration_path, &master_key)?
        }
        2 => {
            let v2: VaultV2 =
                serde_json::from_str(original_json).context("Failed to parse v2 vault")?;
            let v3 = upvault_v2(v2)?;
            let v4 = upvault_v3(v3, &master_key)?;
            let v5 = upvault_v4(v4, &master_key)?;
            let v6 = upvault_v5_to_v6(v5, probe.version, &migration_path, &master_key)?;
            upvault_v6_to_v7(v6, probe.version, &migration_path, &master_key)?
        }
        3 => {
            let v3: VaultV3 =
                serde_json::from_str(original_json).context("Failed to parse v3 vault")?;
            let v4 = upvault_v3(v3, &master_key)?;
            let v5 = upvault_v4(v4, &master_key)?;
            let v6 = upvault_v5_to_v6(v5, probe.version, &migration_path, &master_key)?;
            upvault_v6_to_v7(v6, probe.version, &migration_path, &master_key)?
        }
        4 => {
            let v4: Vault =
                serde_json::from_str(original_json).context("Failed to parse v4 vault")?;
            let v5 = upvault_v4(v4, &master_key)?;
            let v6 = upvault_v5_to_v6(v5, probe.version, &migration_path, &master_key)?;
            upvault_v6_to_v7(v6, probe.version, &migration_path, &master_key)?
        }
        5 => {
            let v5: Vault =
                serde_json::from_str(original_json).context("Failed to parse v5 vault")?;
            let v6 = upvault_v5_to_v6(v5, probe.version, &migration_path, &master_key)?;
            upvault_v6_to_v7(v6, probe.version, &migration_path, &master_key)?
        }
        6 => {
            let v6: Vault =
                serde_json::from_str(original_json).context("Failed to parse v6 vault")?;
            upvault_v6_to_v7(v6, probe.version, &migration_path, &master_key)?
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

    // Generate new legacy Kyber keypair for the in-memory v2-v5 compatibility chain.
    let (mlkem_public, mlkem_private) = legacy_kyber::generate_keypair()?;

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
        let (kem_ciphertext, x25519_ephemeral_public, derived_key) =
            hybrid_encapsulate_legacy(&mlkem_public, &x25519_public)?;
        let (ciphertext, nonce) = aes_encrypt(&derived_key, &plaintext)?;

        secrets.insert(
            name,
            EncryptedSecret {
                algorithm: "hybrid-mlkem768-x25519".to_string(),
                kem_ciphertext: kem_ciphertext.as_bytes().to_vec(),
                x25519_ephemeral_public: x25519_ephemeral_public.as_bytes().to_vec(),
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
            algorithm: String::new(),
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
            algorithm: String::new(),
            public_key: v3.x25519.public_key,
            encrypted_private_key: enc_x25519_sk,
            private_key_nonce: x25519_nonce.to_vec(),
        },
        secrets: v3.secrets,
        suite: String::new(),
        migrated_from: None, // Will be set by upvault_v4
        min_version: 0,      // Will be set by upvault_v4
    })
}

/// v4 → v5: Add the legacy key commitment and anti-rollback floor.
///
/// This is an internal staging step used only in memory before the final v6 re-key.
fn upvault_v4(mut v4: Vault, master_key: &MasterKey) -> Result<Vault> {
    v4.version = V5_VAULT_VERSION;
    v4.min_version = V5_VAULT_VERSION;
    v4.key_commitment = Some(compute_key_commitment(master_key, &v4)?);
    v4.migrated_from = None;
    Ok(v4)
}

/// v5 → v6: verify the legacy commitment, decrypt under legacy Kyber semantics,
/// rotate both asymmetric keypairs, and re-encrypt everything under real v6 semantics.
fn upvault_v5_to_v6(
    v5: Vault,
    original_version: u32,
    migration_path: &[u32],
    master_key: &MasterKey,
) -> Result<Vault> {
    verify_v5_key_commitment(&v5, master_key)?;

    let legacy_wrapping = derive_wrapping_keys(master_key)?;
    let legacy_mlkem_sk_bytes = Zeroizing::new(
        aes_decrypt(
            &legacy_wrapping.mlkem,
            &v5.kem.encrypted_private_key,
            v5.kem
                .private_key_nonce
                .as_slice()
                .try_into()
                .context("Invalid v5 ML-KEM nonce")?,
        )
        .context("Failed to decrypt v5 legacy Kyber private key (wrong passphrase?)")?,
    );
    let legacy_mlkem_private = LegacyKyberPrivateKey::from_bytes(legacy_mlkem_sk_bytes.to_vec())?;

    let legacy_x25519_sk_bytes = Zeroizing::new(
        aes_decrypt(
            &legacy_wrapping.x25519,
            &v5.x25519.encrypted_private_key,
            v5.x25519
                .private_key_nonce
                .as_slice()
                .try_into()
                .context("Invalid v5 X25519 nonce")?,
        )
        .context("Failed to decrypt v5 X25519 private key (wrong passphrase?)")?,
    );
    let legacy_x25519_private = X25519PrivateKey::from_bytes(
        legacy_x25519_sk_bytes
            .as_slice()
            .try_into()
            .context("Invalid X25519 key length")?,
    );

    let mut plaintext_secrets = Vec::with_capacity(v5.secrets.len());
    for (name, secret) in &v5.secrets {
        if secret.algorithm != "hybrid-mlkem768-x25519" {
            bail!(
                "Unsupported legacy secret algorithm for '{}': {}",
                name,
                secret.algorithm
            );
        }

        let legacy_kem_ciphertext = LegacyKyberCiphertext::from_bytes(
            secret.kem_ciphertext.clone(),
        )
        .with_context(|| {
            format!(
                "Invalid legacy Kyber ciphertext length for secret '{}'",
                name
            )
        })?;
        let x25519_ephemeral_public = X25519PublicKey::from_bytes(
            secret
                .x25519_ephemeral_public
                .as_slice()
                .try_into()
                .with_context(|| {
                    format!(
                        "Invalid X25519 ephemeral public key length for secret '{}'",
                        name
                    )
                })?,
        );
        let aes_key = hybrid_decapsulate_legacy(
            &legacy_mlkem_private,
            &legacy_x25519_private,
            &legacy_kem_ciphertext,
            &x25519_ephemeral_public,
        )?;
        let nonce: [u8; 12] = secret
            .nonce
            .as_slice()
            .try_into()
            .with_context(|| format!("Invalid nonce length for secret '{}'", name))?;
        let plaintext = Zeroizing::new(aes_decrypt(&aes_key, &secret.ciphertext, &nonce)?);
        plaintext_secrets.push((name.clone(), plaintext, secret.created, secret.modified));
    }

    let (mlkem_public, mlkem_private) = mlkem_generate_keypair()?;
    let (x25519_public, x25519_private) = crate::crypto::x25519_generate_keypair();
    let wrapping = derive_wrapping_keys_v6(master_key)?;
    let (encrypted_mlkem_sk, mlkem_nonce) = aes_encrypt(&wrapping.mlkem, mlkem_private.as_bytes())?;
    let (encrypted_x25519_sk, x25519_nonce) =
        aes_encrypt(&wrapping.x25519, x25519_private.as_bytes())?;

    let mut secrets = HashMap::with_capacity(plaintext_secrets.len());
    for (name, plaintext, created, modified) in &plaintext_secrets {
        let encap = hybrid_encapsulate_v6(&mlkem_public, &x25519_public)?;
        let (ciphertext, nonce) = aes_encrypt(&encap.derived_key, plaintext.as_ref())?;
        secrets.insert(
            name.clone(),
            EncryptedSecret {
                algorithm: V6_SECRET_ALGORITHM.to_string(),
                kem_ciphertext: encap.kem_ciphertext.as_bytes().to_vec(),
                x25519_ephemeral_public: encap.x25519_ephemeral_public.as_bytes().to_vec(),
                nonce: nonce.to_vec(),
                ciphertext,
                created: *created,
                modified: *modified,
            },
        );
    }

    let mut v6 = Vault {
        version: V6_VAULT_VERSION,
        created: v5.created,
        kdf: v5.kdf,
        key_commitment: None,
        kem: KemKeyPair {
            algorithm: V6_KEM_ALGORITHM.to_string(),
            public_key: mlkem_public.as_bytes().to_vec(),
            encrypted_private_key: encrypted_mlkem_sk,
            private_key_nonce: mlkem_nonce.to_vec(),
        },
        x25519: X25519KeyPair {
            algorithm: V6_X25519_ALGORITHM.to_string(),
            public_key: x25519_public.as_bytes().to_vec(),
            encrypted_private_key: encrypted_x25519_sk,
            private_key_nonce: x25519_nonce.to_vec(),
        },
        secrets,
        suite: V6_SUITE.to_string(),
        migrated_from: Some(MigrationInfo {
            original_version,
            migrated_at: Utc::now(),
            migration_path: migration_path.to_vec(),
        }),
        min_version: V6_VAULT_VERSION,
    };
    v6.key_commitment = Some(compute_key_commitment(master_key, &v6)?);
    Ok(v6)
}

/// v6 → v7: Re-key and re-encrypt under TC-HKEM (ciphertext-bound + mk-committed).
///
/// Decrypts all secrets under v6 hybrid semantics, generates fresh keypairs,
/// and re-encrypts under v7 TC-HKEM with passphrase commitment.
fn upvault_v6_to_v7(
    v6: Vault,
    original_version: u32,
    migration_path: &[u32],
    master_key: &MasterKey,
) -> Result<Vault> {
    // Verify the v6 key commitment before touching private keys
    super::ops::verify_v6_key_commitment(&v6, master_key)?;

    // Decrypt v6 private keys
    let v6_wrapping = derive_wrapping_keys_v6(master_key)?;
    let mlkem_sk_bytes = Zeroizing::new(
        aes_decrypt(
            &v6_wrapping.mlkem,
            &v6.kem.encrypted_private_key,
            v6.kem
                .private_key_nonce
                .as_slice()
                .try_into()
                .context("Invalid v6 ML-KEM nonce")?,
        )
        .context("Failed to decrypt v6 ML-KEM private key (wrong passphrase?)")?,
    );
    let v6_mlkem_private = crate::crypto::MlKemPrivateKey::from_bytes(mlkem_sk_bytes.to_vec())?;

    let x25519_sk_bytes = Zeroizing::new(
        aes_decrypt(
            &v6_wrapping.x25519,
            &v6.x25519.encrypted_private_key,
            v6.x25519
                .private_key_nonce
                .as_slice()
                .try_into()
                .context("Invalid v6 X25519 nonce")?,
        )
        .context("Failed to decrypt v6 X25519 private key (wrong passphrase?)")?,
    );
    let v6_x25519_private = X25519PrivateKey::from_bytes(
        x25519_sk_bytes
            .as_slice()
            .try_into()
            .context("Invalid X25519 key length")?,
    );

    // Decrypt all v6 secrets
    let mut plaintext_secrets = Vec::with_capacity(v6.secrets.len());
    for (name, secret) in &v6.secrets {
        if secret.algorithm != V6_SECRET_ALGORITHM {
            bail!(
                "Unsupported v6 secret algorithm for '{}': {}",
                name,
                secret.algorithm
            );
        }

        let kem_ct = crate::crypto::MlKemCiphertext::from_bytes(secret.kem_ciphertext.clone())
            .with_context(|| format!("Invalid ML-KEM ciphertext for secret '{}'", name))?;

        let x25519_eph_pk = X25519PublicKey::from_bytes(
            secret
                .x25519_ephemeral_public
                .as_slice()
                .try_into()
                .with_context(|| format!("Invalid X25519 ephemeral key for secret '{}'", name))?,
        );

        let aes_key = hybrid_decapsulate_v6(
            &v6_mlkem_private,
            &v6_x25519_private,
            &kem_ct,
            &x25519_eph_pk,
        )?;
        let nonce: [u8; 12] = secret
            .nonce
            .as_slice()
            .try_into()
            .with_context(|| format!("Invalid nonce for secret '{}'", name))?;
        let plaintext = Zeroizing::new(aes_decrypt(&aes_key, &secret.ciphertext, &nonce)?);
        plaintext_secrets.push((name.clone(), plaintext, secret.created, secret.modified));
    }

    // Generate fresh keypairs for v7
    let (mlkem_public, mlkem_private) = mlkem_generate_keypair()?;
    let (x25519_public, x25519_private) = crate::crypto::x25519_generate_keypair();

    // Wrap private keys under v7 wrapping labels
    let wrapping = derive_wrapping_keys_v7(master_key)?;
    let (encrypted_mlkem_sk, mlkem_nonce) = aes_encrypt(&wrapping.mlkem, mlkem_private.as_bytes())?;
    let (encrypted_x25519_sk, x25519_nonce) =
        aes_encrypt(&wrapping.x25519, x25519_private.as_bytes())?;

    // Re-encrypt all secrets under v7 TC-HKEM (with passphrase commitment)
    let mut secrets = HashMap::with_capacity(plaintext_secrets.len());
    for (name, plaintext, created, modified) in &plaintext_secrets {
        let encap = hybrid_encapsulate_v7(&mlkem_public, &x25519_public, master_key.as_bytes())?;
        let (ciphertext, nonce) = aes_encrypt(&encap.derived_key, plaintext.as_ref())?;
        secrets.insert(
            name.clone(),
            EncryptedSecret {
                algorithm: V7_SECRET_ALGORITHM.to_string(),
                kem_ciphertext: encap.kem_ciphertext.as_bytes().to_vec(),
                x25519_ephemeral_public: encap.x25519_ephemeral_public.as_bytes().to_vec(),
                nonce: nonce.to_vec(),
                ciphertext,
                created: *created,
                modified: *modified,
            },
        );
    }

    let mut v7 = Vault {
        version: V7_VAULT_VERSION,
        created: v6.created,
        kdf: v6.kdf,
        key_commitment: None,
        kem: KemKeyPair {
            algorithm: V7_KEM_ALGORITHM.to_string(),
            public_key: mlkem_public.as_bytes().to_vec(),
            encrypted_private_key: encrypted_mlkem_sk,
            private_key_nonce: mlkem_nonce.to_vec(),
        },
        x25519: X25519KeyPair {
            algorithm: V7_X25519_ALGORITHM.to_string(),
            public_key: x25519_public.as_bytes().to_vec(),
            encrypted_private_key: encrypted_x25519_sk,
            private_key_nonce: x25519_nonce.to_vec(),
        },
        secrets,
        suite: V7_SUITE.to_string(),
        migrated_from: Some(MigrationInfo {
            original_version,
            migrated_at: Utc::now(),
            migration_path: migration_path.to_vec(),
        }),
        min_version: V7_VAULT_VERSION,
    };
    v7.key_commitment = Some(compute_key_commitment(master_key, &v7)?);
    Ok(v7)
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
    let stem = path.file_stem().and_then(|s| s.to_str()).unwrap_or("vault");
    let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("json");

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

    // Backups contain wrapped private keys, KEM ciphertexts, and encrypted
    // secrets — every cryptographic byte the live vault holds. `fs::copy`
    // preserves the source mode on Unix, but lock the backup down to 0600
    // explicitly so a permissive source mode (e.g. on a vault written before
    // the chmod hardening landed) cannot bleed into the backup.
    #[cfg(unix)]
    {
        let mut perms = fs::metadata(&backup_path)
            .with_context(|| {
                format!(
                    "Failed to inspect backup permissions at {}",
                    backup_path.display()
                )
            })?
            .permissions();
        perms.set_mode(0o600);
        fs::set_permissions(&backup_path, perms).with_context(|| {
            format!(
                "Failed to secure backup file permissions at {}",
                backup_path.display()
            )
        })?;
    }

    eprintln!("Backup saved: {}", backup_path.display());
    Ok(())
}

/// Find existing backup files matching the pattern `{stem}.backup.*.{ext}`
fn find_backups(dir: &Path, stem: &str, ext: &str) -> Result<Vec<String>> {
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
    use crate::crypto::hybrid::hybrid_decapsulate_v7;
    use crate::crypto::legacy_kyber;
    use crate::crypto::{aes_encrypt, derive_key, generate_salt, x25519_generate_keypair};
    use crate::vault::format::{
        V7_SECRET_ALGORITHM, V7_SUITE, V7_VAULT_VERSION, V7_X25519_ALGORITHM,
    };
    use crate::vault::ops::compute_v5_key_commitment;
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
            "private_key_nonce": STANDARD.encode(nonce),
            "secrets": {
                "test-secret": {
                    "x25519_ephemeral_public": STANDARD.encode(eph_pk.as_bytes()),
                    "nonce": STANDARD.encode(secret_nonce),
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

        let (mlkem_pk, mlkem_sk) = legacy_kyber::generate_keypair().unwrap();
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
                "private_key_nonce": STANDARD.encode(mlkem_nonce),
            },
            "x25519": {
                "public_key": STANDARD.encode(x25519_pk.as_bytes()),
                "encrypted_private_key": STANDARD.encode(&enc_x25519),
                "private_key_nonce": STANDARD.encode(x25519_nonce),
            },
            "secrets": {}
        });
        json.to_string()
    }

    fn build_v3_vault_with_secret(passphrase: &str) -> String {
        let config = KdfConfig {
            salt: generate_salt(),
            time_cost: 1,
            memory_cost: 8192,
            parallelism: 1,
        };
        let master_key = derive_key(passphrase, &config).unwrap();
        let wrapping_key = AesKey::from_bytes(*master_key.as_bytes());

        let (mlkem_pk, mlkem_sk) = legacy_kyber::generate_keypair().unwrap();
        let (x25519_pk, x25519_sk) = x25519_generate_keypair();

        let (enc_mlkem, mlkem_nonce) = aes_encrypt(&wrapping_key, mlkem_sk.as_bytes()).unwrap();
        let (enc_x25519, x25519_nonce) = aes_encrypt(&wrapping_key, x25519_sk.as_bytes()).unwrap();
        let (kem_ct, eph_pk, aes_key) = hybrid_encapsulate_legacy(&mlkem_pk, &x25519_pk).unwrap();
        let (ciphertext, nonce) = aes_encrypt(&aes_key, b"v3-sample-secret").unwrap();

        use base64::{Engine, engine::general_purpose::STANDARD};
        serde_json::json!({
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
                "private_key_nonce": STANDARD.encode(mlkem_nonce),
            },
            "x25519": {
                "public_key": STANDARD.encode(x25519_pk.as_bytes()),
                "encrypted_private_key": STANDARD.encode(&enc_x25519),
                "private_key_nonce": STANDARD.encode(x25519_nonce),
            },
            "secrets": {
                "sample-secret": {
                    "algorithm": "hybrid-mlkem768-x25519",
                    "kem_ciphertext": STANDARD.encode(kem_ct.as_bytes()),
                    "x25519_ephemeral_public": STANDARD.encode(eph_pk.as_bytes()),
                    "nonce": STANDARD.encode(nonce),
                    "ciphertext": STANDARD.encode(&ciphertext),
                    "created": "2025-06-01T00:00:00Z",
                    "modified": "2025-06-01T00:00:00Z"
                }
            }
        })
        .to_string()
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

        let (mlkem_pk, mlkem_sk) = legacy_kyber::generate_keypair().unwrap();
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
                "private_key_nonce": STANDARD.encode(mlkem_nonce),
            },
            "x25519": {
                "public_key": STANDARD.encode(x25519_pk.as_bytes()),
                "encrypted_private_key": STANDARD.encode(&enc_x25519),
                "private_key_nonce": STANDARD.encode(x25519_nonce),
            },
            "secrets": {}
        });
        json.to_string()
    }

    fn build_v5_vault_with_secret(passphrase: &str) -> String {
        let config = KdfConfig {
            salt: generate_salt(),
            time_cost: 1,
            memory_cost: 8192,
            parallelism: 1,
        };
        let master_key = derive_key(passphrase, &config).unwrap();
        let wrapping = derive_wrapping_keys(&master_key).unwrap();

        let (mlkem_pk, mlkem_sk) = legacy_kyber::generate_keypair().unwrap();
        let (x25519_pk, x25519_sk) = x25519_generate_keypair();
        let (enc_mlkem, mlkem_nonce) = aes_encrypt(&wrapping.mlkem, mlkem_sk.as_bytes()).unwrap();
        let (enc_x25519, x25519_nonce) =
            aes_encrypt(&wrapping.x25519, x25519_sk.as_bytes()).unwrap();
        let (kem_ct, eph_pk, aes_key) = hybrid_encapsulate_legacy(&mlkem_pk, &x25519_pk).unwrap();
        let (ciphertext, nonce) = aes_encrypt(&aes_key, b"legacy-v5-secret").unwrap();

        let mut vault = Vault {
            version: V5_VAULT_VERSION,
            created: Utc::now(),
            kdf: super::super::format::KdfParams {
                algorithm: "argon2id".to_string(),
                salt: config.salt.clone(),
                time_cost: config.time_cost,
                memory_cost: config.memory_cost,
                parallelism: config.parallelism,
            },
            key_commitment: None,
            kem: KemKeyPair {
                algorithm: "ML-KEM-768".to_string(),
                public_key: mlkem_pk.as_bytes().to_vec(),
                encrypted_private_key: enc_mlkem,
                private_key_nonce: mlkem_nonce.to_vec(),
            },
            x25519: X25519KeyPair {
                algorithm: String::new(),
                public_key: x25519_pk.as_bytes().to_vec(),
                encrypted_private_key: enc_x25519,
                private_key_nonce: x25519_nonce.to_vec(),
            },
            secrets: HashMap::from([(
                "legacy-secret".to_string(),
                EncryptedSecret {
                    algorithm: "hybrid-mlkem768-x25519".to_string(),
                    kem_ciphertext: kem_ct.as_bytes().to_vec(),
                    x25519_ephemeral_public: eph_pk.as_bytes().to_vec(),
                    nonce: nonce.to_vec(),
                    ciphertext,
                    created: Utc::now(),
                    modified: Utc::now(),
                },
            )]),
            suite: String::new(),
            migrated_from: None,
            min_version: V5_VAULT_VERSION,
        };
        vault.key_commitment = Some(compute_v5_key_commitment(
            &master_key,
            &vault.kdf,
            &vault.kem.public_key,
            &vault.x25519.public_key,
        ));
        serde_json::to_string(&vault).unwrap()
    }

    #[test]
    fn test_upvault_v4_to_v6_adds_metadata() {
        let dir = tempdir().unwrap();
        let vault_path = dir.path().join("vault.json");
        let json = build_v4_vault("test-passphrase");
        fs::write(&vault_path, &json).unwrap();

        let result = upvault(&json, "test-passphrase", vault_path.to_str().unwrap()).unwrap();
        assert_eq!(result.version, V7_VAULT_VERSION);
        let info = result.migrated_from.as_ref().unwrap();
        assert_eq!(info.original_version, 4);
        assert_eq!(info.migration_path, vec![4, 5, 6, 7]);
        assert_eq!(result.suite, V7_SUITE);
        assert_eq!(result.x25519.algorithm, V7_X25519_ALGORITHM);
    }

    #[test]
    fn test_upvault_v3_to_v6_rekeys_keys() {
        let dir = tempdir().unwrap();
        let vault_path = dir.path().join("vault.json");
        let json = build_v3_vault("test-passphrase");
        fs::write(&vault_path, &json).unwrap();

        let result = upvault(&json, "test-passphrase", vault_path.to_str().unwrap()).unwrap();
        assert_eq!(result.version, V7_VAULT_VERSION);
        let info = result.migrated_from.as_ref().unwrap();
        assert_eq!(info.original_version, 3);
        assert_eq!(info.migration_path, vec![3, 4, 5, 6, 7]);

        // Verify the private keys are now wrapped with v6 wrapping labels.
        let config = KdfConfig {
            salt: result.kdf.salt.clone(),
            time_cost: result.kdf.time_cost,
            memory_cost: result.kdf.memory_cost,
            parallelism: result.kdf.parallelism,
        };
        let mk = derive_key("test-passphrase", &config).unwrap();
        let wrapping = derive_wrapping_keys_v7(&mk).unwrap();

        let mlkem_sk = aes_decrypt(
            &wrapping.mlkem,
            &result.kem.encrypted_private_key,
            result.kem.private_key_nonce.as_slice().try_into().unwrap(),
        );
        assert!(
            mlkem_sk.is_ok(),
            "ML-KEM private key should decrypt with v6 wrapping key"
        );

        let x25519_sk = aes_decrypt(
            &wrapping.x25519,
            &result.x25519.encrypted_private_key,
            result
                .x25519
                .private_key_nonce
                .as_slice()
                .try_into()
                .unwrap(),
        );
        assert!(
            x25519_sk.is_ok(),
            "X25519 private key should decrypt with v6 wrapping key"
        );
    }

    #[test]
    fn test_upvault_v1_to_v6_full_chain() {
        let dir = tempdir().unwrap();
        let vault_path = dir.path().join("vault.json");
        let (json, _config) = build_v1_vault("test-passphrase");
        fs::write(&vault_path, &json).unwrap();

        let result = upvault(&json, "test-passphrase", vault_path.to_str().unwrap()).unwrap();
        assert_eq!(result.version, V7_VAULT_VERSION);
        let info = result.migrated_from.as_ref().unwrap();
        assert_eq!(info.original_version, 1);
        assert_eq!(info.migration_path, vec![1, 2, 3, 4, 5, 6, 7]);
        assert!(result.secrets.contains_key("test-secret"));
        assert_eq!(result.secrets["test-secret"].algorithm, V7_SECRET_ALGORITHM);

        // Verify the migrated secret is decryptable under v6 semantics.
        let config = KdfConfig {
            salt: result.kdf.salt.clone(),
            time_cost: result.kdf.time_cost,
            memory_cost: result.kdf.memory_cost,
            parallelism: result.kdf.parallelism,
        };
        let mk = derive_key("test-passphrase", &config).unwrap();
        let wrapping = derive_wrapping_keys_v7(&mk).unwrap();

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
            result
                .x25519
                .private_key_nonce
                .as_slice()
                .try_into()
                .unwrap(),
        )
        .unwrap();
        let x25519_sk =
            X25519PrivateKey::from_bytes(x25519_sk_bytes.as_slice().try_into().unwrap());

        // Decrypt the secret using hybrid decapsulation
        let secret = &result.secrets["test-secret"];
        let kem_ct =
            crate::crypto::MlKemCiphertext::from_bytes(secret.kem_ciphertext.clone()).unwrap();
        let eph_pk = X25519PublicKey::from_bytes(
            secret
                .x25519_ephemeral_public
                .as_slice()
                .try_into()
                .unwrap(),
        );
        let aes_key =
            hybrid_decapsulate_v7(&mlkem_sk, &x25519_sk, &kem_ct, &eph_pk, mk.as_bytes()).unwrap();
        let nonce: [u8; 12] = secret.nonce.as_slice().try_into().unwrap();
        let plaintext = aes_decrypt(&aes_key, &secret.ciphertext, &nonce).unwrap();
        assert_eq!(String::from_utf8(plaintext).unwrap(), "my-secret-value");
    }

    #[test]
    fn test_upvault_v3_sample_secret_migrates_end_to_end_to_v6() {
        let dir = tempdir().unwrap();
        let vault_path = dir.path().join("vault.json");
        let json = build_v3_vault_with_secret("test-passphrase");
        fs::write(&vault_path, &json).unwrap();

        let result = upvault(&json, "test-passphrase", vault_path.to_str().unwrap()).unwrap();
        assert_eq!(result.version, V7_VAULT_VERSION);
        assert!(result.secrets.contains_key("sample-secret"));
        assert_eq!(
            result.secrets["sample-secret"].algorithm,
            V7_SECRET_ALGORITHM
        );

        let config = KdfConfig {
            salt: result.kdf.salt.clone(),
            time_cost: result.kdf.time_cost,
            memory_cost: result.kdf.memory_cost,
            parallelism: result.kdf.parallelism,
        };
        let mk = derive_key("test-passphrase", &config).unwrap();
        let wrapping = derive_wrapping_keys_v7(&mk).unwrap();
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
            result
                .x25519
                .private_key_nonce
                .as_slice()
                .try_into()
                .unwrap(),
        )
        .unwrap();
        let x25519_sk =
            X25519PrivateKey::from_bytes(x25519_sk_bytes.as_slice().try_into().unwrap());

        let secret = &result.secrets["sample-secret"];
        let kem_ct =
            crate::crypto::MlKemCiphertext::from_bytes(secret.kem_ciphertext.clone()).unwrap();
        let eph_pk = X25519PublicKey::from_bytes(
            secret
                .x25519_ephemeral_public
                .as_slice()
                .try_into()
                .unwrap(),
        );
        let aes_key =
            hybrid_decapsulate_v7(&mlkem_sk, &x25519_sk, &kem_ct, &eph_pk, mk.as_bytes()).unwrap();
        let nonce: [u8; 12] = secret.nonce.as_slice().try_into().unwrap();
        let plaintext = aes_decrypt(&aes_key, &secret.ciphertext, &nonce).unwrap();
        assert_eq!(String::from_utf8(plaintext).unwrap(), "v3-sample-secret");
    }

    #[test]
    fn test_upvault_v5_to_v6_preserves_secret_values() {
        let dir = tempdir().unwrap();
        let vault_path = dir.path().join("vault.json");
        let json = build_v5_vault_with_secret("test-passphrase");
        fs::write(&vault_path, &json).unwrap();

        let result = upvault(&json, "test-passphrase", vault_path.to_str().unwrap()).unwrap();
        assert_eq!(result.version, V7_VAULT_VERSION);
        let info = result.migrated_from.as_ref().unwrap();
        assert_eq!(info.original_version, 5);
        assert_eq!(info.migration_path, vec![5, 6, 7]);
        assert_eq!(
            result.secrets["legacy-secret"].algorithm,
            V7_SECRET_ALGORITHM
        );

        let config = KdfConfig {
            salt: result.kdf.salt.clone(),
            time_cost: result.kdf.time_cost,
            memory_cost: result.kdf.memory_cost,
            parallelism: result.kdf.parallelism,
        };
        let mk = derive_key("test-passphrase", &config).unwrap();
        let wrapping = derive_wrapping_keys_v7(&mk).unwrap();
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
            result
                .x25519
                .private_key_nonce
                .as_slice()
                .try_into()
                .unwrap(),
        )
        .unwrap();
        let x25519_sk =
            X25519PrivateKey::from_bytes(x25519_sk_bytes.as_slice().try_into().unwrap());

        let secret = &result.secrets["legacy-secret"];
        let kem_ct =
            crate::crypto::MlKemCiphertext::from_bytes(secret.kem_ciphertext.clone()).unwrap();
        let eph_pk = X25519PublicKey::from_bytes(
            secret
                .x25519_ephemeral_public
                .as_slice()
                .try_into()
                .unwrap(),
        );
        let aes_key =
            hybrid_decapsulate_v7(&mlkem_sk, &x25519_sk, &kem_ct, &eph_pk, mk.as_bytes()).unwrap();
        let nonce: [u8; 12] = secret.nonce.as_slice().try_into().unwrap();
        let plaintext = aes_decrypt(&aes_key, &secret.ciphertext, &nonce).unwrap();
        assert_eq!(String::from_utf8(plaintext).unwrap(), "legacy-v5-secret");
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
        assert!(
            backups.is_empty(),
            "No backup should exist after failed migration"
        );
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
            "private_key_nonce": STANDARD.encode(nonce),
            "secrets": {}
        })
        .to_string();

        let dir = tempdir().unwrap();
        let vault_path = dir.path().join("vault.json");
        fs::write(&vault_path, &json).unwrap();

        let result = upvault(&json, "test-passphrase", vault_path.to_str().unwrap()).unwrap();
        assert_eq!(result.version, V7_VAULT_VERSION);
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
    fn test_malformed_legacy_kyber_ciphertext_fails_cleanly() {
        use base64::Engine as _;

        let dir = tempdir().unwrap();
        let vault_path = dir.path().join("vault.json");
        let json = build_v5_vault_with_secret("test-passphrase");
        fs::write(&vault_path, &json).unwrap();

        let mut raw: serde_json::Value = serde_json::from_str(&json).unwrap();
        let secret = raw["secrets"]["legacy-secret"].as_object_mut().unwrap();
        let original = secret.get("kem_ciphertext").unwrap().as_str().unwrap();
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(original)
            .unwrap();
        let malformed = base64::engine::general_purpose::STANDARD.encode(&bytes[..1087]);
        secret.insert(
            "kem_ciphertext".to_string(),
            serde_json::Value::String(malformed),
        );
        let malformed_json = serde_json::to_string(&raw).unwrap();
        fs::write(&vault_path, &malformed_json).unwrap();

        let err = upvault(
            &malformed_json,
            "test-passphrase",
            vault_path.to_str().unwrap(),
        )
        .unwrap_err();
        assert!(
            err.to_string().contains("legacy Kyber ciphertext")
                || err.to_string().contains("ciphertext length"),
            "unexpected error: {}",
            err
        );
    }

    #[test]
    fn test_migrated_vault_file_is_valid_v6() {
        let dir = tempdir().unwrap();
        let vault_path = dir.path().join("vault.json");
        let json = build_v4_vault("test-passphrase");
        fs::write(&vault_path, &json).unwrap();

        upvault(&json, "test-passphrase", vault_path.to_str().unwrap()).unwrap();

        // Read the file back and verify it's valid v6
        let saved = fs::read_to_string(&vault_path).unwrap();
        let vault: Vault = serde_json::from_str(&saved).unwrap();
        assert_eq!(vault.version, VAULT_VERSION);
        assert!(vault.migrated_from.is_some());
        assert_eq!(vault.suite, V7_SUITE);
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
        assert_eq!(
            backup_content, json,
            "Backup should preserve original vault content"
        );
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
                    "nonce": STANDARD.encode(sn),
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
            "private_key_nonce": STANDARD.encode(nonce),
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
