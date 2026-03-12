//! Vault operations: create, unlock, add/get/remove secrets

use super::format::{EncryptedSecret, KdfParams, KemKeyPair, VAULT_VERSION, Vault, X25519KeyPair};
use crate::crypto::{
    AesKey, KdfConfig, MasterKey, MlKemCiphertext, MlKemPrivateKey, MlKemPublicKey,
    X25519PrivateKey, X25519PublicKey, aes_decrypt, aes_encrypt, derive_key, generate_salt,
    hybrid_decapsulate, hybrid_encapsulate, mlkem_generate_keypair, x25519_generate_keypair,
};
use crate::security::{self, SecretString, SecretVec};
use anyhow::{Context, Result};
use chrono::Utc;
use hkdf::Hkdf;
use sha2::Sha256;
use std::collections::HashMap;
use std::fs;
use std::io::Write;
use std::path::Path;
use zeroize::Zeroizing;

/// Default vault file path
pub fn default_vault_path() -> String {
    dirs::home_dir()
        .unwrap_or_else(|| std::path::PathBuf::from("."))
        .join(".dota")
        .join("vault.json")
        .to_string_lossy()
        .to_string()
}

/// Unlocked vault with decrypted keypairs
impl std::fmt::Debug for UnlockedVault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UnlockedVault")
            .field("vault_version", &self.vault.version)
            .field("path", &self.path)
            .finish_non_exhaustive()
    }
}

pub struct UnlockedVault {
    pub vault: Vault,
    pub mlkem_private: MlKemPrivateKey,
    pub x25519_private: X25519PrivateKey,
    pub path: String,
}

/// Create a new vault with a passphrase
pub fn create_vault(passphrase: &str, vault_path: &str) -> Result<()> {
    // Generate KDF salt
    let salt = generate_salt();

    let kdf_config = KdfConfig {
        salt: salt.clone(),
        time_cost: 3,
        memory_cost: 65536,
        parallelism: 4,
    };

    // Derive master key from passphrase
    let master_key = derive_key(passphrase, &kdf_config)?;

    // Generate ML-KEM keypair
    let (mlkem_public, mlkem_private) = mlkem_generate_keypair()?;

    // Generate X25519 keypair
    let (x25519_public, x25519_private) = x25519_generate_keypair();

    // Derive separate wrapping keys for each private key (key separation)
    let wrapping = derive_wrapping_keys(&master_key)?;
    let (encrypted_mlkem_sk, mlkem_nonce) = aes_encrypt(&wrapping.mlkem, mlkem_private.as_bytes())?;
    let (encrypted_x25519_sk, x25519_nonce) =
        aes_encrypt(&wrapping.x25519, x25519_private.as_bytes())?;

    // Build KDF params for commitment
    let kdf_params = KdfParams {
        algorithm: "argon2id".to_string(),
        salt,
        time_cost: kdf_config.time_cost,
        memory_cost: kdf_config.memory_cost,
        parallelism: kdf_config.parallelism,
    };

    // Compute key commitment
    let commitment = compute_key_commitment(
        &master_key,
        &kdf_params,
        mlkem_public.as_bytes(),
        x25519_public.as_bytes(),
    );

    // Create vault structure
    let vault = Vault {
        version: VAULT_VERSION,
        created: Utc::now(),
        kdf: kdf_params,
        key_commitment: Some(commitment),
        kem: KemKeyPair {
            algorithm: "ML-KEM-768".to_string(),
            public_key: mlkem_public.as_bytes().to_vec(),
            encrypted_private_key: encrypted_mlkem_sk,
            private_key_nonce: mlkem_nonce.to_vec(),
        },
        x25519: X25519KeyPair {
            public_key: x25519_public.as_bytes().to_vec(),
            encrypted_private_key: encrypted_x25519_sk,
            private_key_nonce: x25519_nonce.to_vec(),
        },
        secrets: HashMap::new(),
        migrated_from: None,
        min_version: VAULT_VERSION,
    };

    // Create parent directory if needed
    if let Some(parent) = Path::new(vault_path).parent() {
        fs::create_dir_all(parent).context("Failed to create vault directory")?;
    }

    // Write vault to file with atomic replace and restrictive permissions.
    save_vault_file(vault_path, &vault)?;

    Ok(())
}

/// Unlock a vault with a passphrase
pub fn unlock_vault(passphrase: &str, vault_path: &str) -> Result<UnlockedVault> {
    // Read and parse vault file, migrating if needed
    let json = fs::read_to_string(vault_path).context("Failed to read vault file")?;

    let probe: super::legacy::VaultVersionProbe =
        serde_json::from_str(&json).context("Failed to parse vault version")?;

    let vault: Vault = if probe.version == VAULT_VERSION {
        serde_json::from_str(&json).context("Failed to parse vault file")?
    } else if probe.version < VAULT_VERSION {
        eprintln!(
            "Migrating vault from v{} to v{}...",
            probe.version, VAULT_VERSION
        );
        super::migration::upvault(&json, passphrase, vault_path)?
    } else {
        anyhow::bail!(
            "Vault version {} is newer than supported (v{}). Please update dota.",
            probe.version,
            VAULT_VERSION
        );
    };

    // Derive master key from passphrase
    let kdf_config = KdfConfig {
        salt: vault.kdf.salt.clone(),
        time_cost: vault.kdf.time_cost,
        memory_cost: vault.kdf.memory_cost,
        parallelism: vault.kdf.parallelism,
    };
    let master_key = derive_key(passphrase, &kdf_config)?;

    // Verify key commitment (v5+). v4 vaults lack this field and are
    // accepted without verification — they get upgraded by the migration path.
    if let Some(ref stored_commitment) = vault.key_commitment {
        let expected = compute_key_commitment(
            &master_key,
            &vault.kdf,
            &vault.kem.public_key,
            &vault.x25519.public_key,
        );
        if !security::constant_time_eq(stored_commitment, &expected) {
            anyhow::bail!(
                "Key commitment mismatch — vault may have been tampered with \
                 (KDF parameters or public keys were modified), or wrong passphrase"
            );
        }
    } else if vault.version >= 5 {
        anyhow::bail!(
            "Vault version {} requires a key commitment, but none was found — \
             vault file may have been tampered with",
            vault.version
        );
    }

    // Derive separate wrapping keys and decrypt private keys
    let wrapping = derive_wrapping_keys(&master_key)?;
    let mlkem_sk_bytes = Zeroizing::new(
        aes_decrypt(
            &wrapping.mlkem,
            &vault.kem.encrypted_private_key,
            vault.kem.private_key_nonce.as_slice().try_into()?,
        )
        .context("Failed to decrypt ML-KEM private key (wrong passphrase?)")?,
    );
    let mlkem_private = MlKemPrivateKey::from_bytes(mlkem_sk_bytes.to_vec())?;

    let x25519_sk_bytes = Zeroizing::new(
        aes_decrypt(
            &wrapping.x25519,
            &vault.x25519.encrypted_private_key,
            vault.x25519.private_key_nonce.as_slice().try_into()?,
        )
        .context("Failed to decrypt X25519 private key (wrong passphrase?)")?,
    );
    let x25519_private = X25519PrivateKey::from_bytes(
        x25519_sk_bytes
            .as_ref()
            .try_into()
            .context("Invalid X25519 key length")?,
    );

    Ok(UnlockedVault {
        vault,
        mlkem_private,
        x25519_private,
        path: vault_path.to_string(),
    })
}

/// Add or update a secret in the vault
pub fn set_secret(unlocked: &mut UnlockedVault, name: &str, value: &str) -> Result<()> {
    // Parse public keys
    let mlkem_public = MlKemPublicKey::from_bytes(unlocked.vault.kem.public_key.clone())?;
    let x25519_public = X25519PublicKey::from_bytes(
        unlocked
            .vault
            .x25519
            .public_key
            .as_slice()
            .try_into()
            .context("Invalid X25519 public key length")?,
    );

    // Hybrid encapsulate to get per-secret AES key
    let encap = hybrid_encapsulate(&mlkem_public, &x25519_public)?;

    // Encrypt the secret value with derived AES key
    let (ciphertext, nonce) = aes_encrypt(&encap.derived_key, value.as_bytes())?;

    // Store encrypted secret
    let now = Utc::now();
    let is_new = !unlocked.vault.secrets.contains_key(name);

    unlocked.vault.secrets.insert(
        name.to_string(),
        EncryptedSecret {
            algorithm: "hybrid-mlkem768-x25519".to_string(),
            kem_ciphertext: encap.kem_ciphertext.as_bytes().to_vec(),
            x25519_ephemeral_public: encap.x25519_ephemeral_public.as_bytes().to_vec(),
            nonce: nonce.to_vec(),
            ciphertext,
            created: if is_new {
                now
            } else {
                unlocked.vault.secrets[name].created
            },
            modified: now,
        },
    );

    // Save vault
    save_vault(unlocked)?;

    Ok(())
}

/// Re-encrypt vault private keys with a new passphrase
pub fn change_passphrase(unlocked: &mut UnlockedVault, new_passphrase: &str) -> Result<()> {
    let kdf_config = KdfConfig {
        salt: generate_salt(),
        time_cost: unlocked.vault.kdf.time_cost,
        memory_cost: unlocked.vault.kdf.memory_cost,
        parallelism: unlocked.vault.kdf.parallelism,
    };

    let master_key = derive_key(new_passphrase, &kdf_config)?;
    let wrapping = derive_wrapping_keys(&master_key)?;

    let (encrypted_mlkem_sk, mlkem_nonce) =
        aes_encrypt(&wrapping.mlkem, unlocked.mlkem_private.as_bytes())?;
    let (encrypted_x25519_sk, x25519_nonce) =
        aes_encrypt(&wrapping.x25519, unlocked.x25519_private.as_bytes())?;

    unlocked.vault.kdf.salt = kdf_config.salt;
    unlocked.vault.kdf.time_cost = kdf_config.time_cost;
    unlocked.vault.kdf.memory_cost = kdf_config.memory_cost;
    unlocked.vault.kdf.parallelism = kdf_config.parallelism;

    unlocked.vault.kem.encrypted_private_key = encrypted_mlkem_sk;
    unlocked.vault.kem.private_key_nonce = mlkem_nonce.to_vec();
    unlocked.vault.x25519.encrypted_private_key = encrypted_x25519_sk;
    unlocked.vault.x25519.private_key_nonce = x25519_nonce.to_vec();

    // Recompute key commitment with new master key
    unlocked.vault.key_commitment = Some(compute_key_commitment(
        &master_key,
        &unlocked.vault.kdf,
        &unlocked.vault.kem.public_key,
        &unlocked.vault.x25519.public_key,
    ));
    unlocked.vault.version = VAULT_VERSION;
    unlocked.vault.min_version = VAULT_VERSION;

    save_vault(unlocked)?;

    Ok(())
}

/// Rotate vault key material and re-encrypt all secrets with the new keys
/// using the supplied passphrase for re-wrapping private key material.
pub fn rotate_keys(unlocked: &mut UnlockedVault, passphrase: &str) -> Result<()> {
    let kdf_config = KdfConfig {
        salt: generate_salt(),
        time_cost: unlocked.vault.kdf.time_cost,
        memory_cost: unlocked.vault.kdf.memory_cost,
        parallelism: unlocked.vault.kdf.parallelism,
    };

    let existing_names = list_secrets(unlocked);
    // Collect all plaintext secrets into SecretStrings for automatic zeroization.
    let mut secrets: Vec<(String, SecretString, chrono::DateTime<Utc>)> =
        Vec::with_capacity(existing_names.len());
    for name in &existing_names {
        let entry = unlocked
            .vault
            .secrets
            .get(name)
            .with_context(|| format!("Secret '{}' missing during rotation", name))?;
        let plaintext = get_secret(unlocked, name)?;
        secrets.push((name.clone(), plaintext, entry.created));
    }

    let (mlkem_public, mlkem_private) = mlkem_generate_keypair()?;
    let (x25519_public, x25519_private) = x25519_generate_keypair();

    unlocked.vault.kem.public_key = mlkem_public.as_bytes().to_vec();
    unlocked.mlkem_private = mlkem_private;
    unlocked.vault.x25519.public_key = x25519_public.as_bytes().to_vec();
    unlocked.x25519_private = x25519_private;

    let master_key = derive_key(passphrase, &kdf_config)?;
    let wrapping = derive_wrapping_keys(&master_key)?;
    let (encrypted_mlkem_sk, mlkem_nonce) =
        aes_encrypt(&wrapping.mlkem, unlocked.mlkem_private.as_bytes())?;
    let (encrypted_x25519_sk, x25519_nonce) =
        aes_encrypt(&wrapping.x25519, unlocked.x25519_private.as_bytes())?;

    unlocked.vault.kem.encrypted_private_key = encrypted_mlkem_sk;
    unlocked.vault.kem.private_key_nonce = mlkem_nonce.to_vec();
    unlocked.vault.x25519.encrypted_private_key = encrypted_x25519_sk;
    unlocked.vault.x25519.private_key_nonce = x25519_nonce.to_vec();
    unlocked.vault.kdf.salt = kdf_config.salt;

    // Recompute key commitment with new keys and master key
    unlocked.vault.key_commitment = Some(compute_key_commitment(
        &master_key,
        &unlocked.vault.kdf,
        &unlocked.vault.kem.public_key,
        &unlocked.vault.x25519.public_key,
    ));
    unlocked.vault.version = VAULT_VERSION;
    unlocked.vault.min_version = VAULT_VERSION;

    unlocked.vault.secrets.clear();
    let mlkem_public = MlKemPublicKey::from_bytes(unlocked.vault.kem.public_key.clone())?;
    let x25519_public = X25519PublicKey::from_bytes(
        unlocked
            .vault
            .x25519
            .public_key
            .as_slice()
            .try_into()
            .context("Invalid X25519 public key length")?,
    );

    for (name, plaintext, created) in &secrets {
        let encap = hybrid_encapsulate(&mlkem_public, &x25519_public)?;
        let (ciphertext, nonce) = aes_encrypt(&encap.derived_key, plaintext.expose().as_bytes())?;

        unlocked.vault.secrets.insert(
            name.clone(),
            EncryptedSecret {
                algorithm: "hybrid-mlkem768-x25519".to_string(),
                kem_ciphertext: encap.kem_ciphertext.as_bytes().to_vec(),
                x25519_ephemeral_public: encap.x25519_ephemeral_public.as_bytes().to_vec(),
                nonce: nonce.to_vec(),
                ciphertext,
                created: *created,
                modified: Utc::now(),
            },
        );
    }
    // `secrets` Vec<(String, SecretString, ...)> drops here — each
    // SecretString is zeroized via ZeroizeOnDrop.

    save_vault(unlocked)?;
    Ok(())
}

/// Get a secret from the vault.
///
/// Returns a `SecretString` that is automatically zeroized on drop,
/// preventing the plaintext from lingering on the heap.
pub fn get_secret(unlocked: &UnlockedVault, name: &str) -> Result<SecretString> {
    let encrypted = unlocked
        .vault
        .secrets
        .get(name)
        .with_context(|| format!("Secret '{}' not found", name))?;

    // Parse KEM ciphertext and X25519 ephemeral public key
    let kem_ct = MlKemCiphertext::from_bytes(encrypted.kem_ciphertext.clone())?;
    let x25519_eph_pk = X25519PublicKey::from_bytes(
        encrypted
            .x25519_ephemeral_public
            .as_slice()
            .try_into()
            .context("Invalid X25519 ephemeral public key length")?,
    );

    // Hybrid decapsulate to recover AES key
    let aes_key = hybrid_decapsulate(
        &unlocked.mlkem_private,
        &unlocked.x25519_private,
        &kem_ct,
        &x25519_eph_pk,
    )?;

    // Decrypt the secret value — wrap in SecretVec for zeroization
    let nonce: [u8; 12] = encrypted.nonce.as_slice().try_into()?;
    let plaintext = SecretVec::new(aes_decrypt(&aes_key, &encrypted.ciphertext, &nonce)?);

    // Convert to String, consuming the SecretVec (inner bytes zeroized on drop)
    let s = String::from_utf8(plaintext.into_inner()).context("Secret contains invalid UTF-8")?;
    Ok(SecretString::new(s))
}

/// Remove a secret from the vault
pub fn remove_secret(unlocked: &mut UnlockedVault, name: &str) -> Result<()> {
    if unlocked.vault.secrets.remove(name).is_none() {
        anyhow::bail!("Secret '{}' not found", name);
    }

    save_vault(unlocked)?;
    Ok(())
}

/// List all secret names
pub fn list_secrets(unlocked: &UnlockedVault) -> Vec<String> {
    let mut names: Vec<String> = unlocked.vault.secrets.keys().cloned().collect();
    names.sort();
    names
}

/// Save vault to disk
fn save_vault(unlocked: &UnlockedVault) -> Result<()> {
    save_vault_file(&unlocked.path, &unlocked.vault)?;

    Ok(())
}

/// Safely save vault JSON to disk with symlink protection and atomic replace.
pub(crate) fn save_vault_file(path: &str, vault: &Vault) -> Result<()> {
    let vault_path = Path::new(path);
    if let Ok(meta) = fs::symlink_metadata(vault_path)
        && meta.file_type().is_symlink()
    {
        anyhow::bail!("Refusing to write vault through symlink: {}", path);
    }

    let parent = vault_path.parent().unwrap_or_else(|| Path::new("."));
    let json = serde_json::to_string_pretty(vault).context("Failed to serialize vault")?;

    let mut tmp = tempfile::Builder::new()
        .prefix(".vault.tmp-")
        .tempfile_in(parent)
        .context("Failed to create temporary vault file")?;

    tmp.write_all(json.as_bytes())
        .context("Failed to write vault data")?;
    tmp.as_file()
        .sync_all()
        .context("Failed to sync vault data")?;

    tmp.persist(vault_path)
        .context("Failed to persist vault file")?;

    Ok(())
}

/// Wrapping keys derived from the master key via HKDF-Expand with purpose labels.
/// Provides cryptographic domain separation: each private key is encrypted under
/// a distinct wrapping key even though both are derived from the same master key.
pub(crate) struct WrappingKeys {
    pub(crate) mlkem: AesKey,
    pub(crate) x25519: AesKey,
}

/// Purpose labels for HKDF-Expand key derivation (domain separation)
const WRAP_LABEL_MLKEM: &[u8] = b"dota-v4-wrap-mlkem";
const WRAP_LABEL_X25519: &[u8] = b"dota-v4-wrap-x25519";

/// Derive separate wrapping keys for ML-KEM and X25519 private key encryption.
///
/// Uses HKDF-Expand (no extract step — the master key from Argon2id is already
/// a high-quality PRF output) with distinct purpose labels.
pub(crate) fn derive_wrapping_keys(mk: &MasterKey) -> Result<WrappingKeys> {
    let hk = Hkdf::<Sha256>::from_prk(mk.as_bytes())
        .map_err(|_| anyhow::anyhow!("master key too short for HKDF-Expand PRK"))?;

    let mut mlkem_key = Zeroizing::new([0u8; 32]);
    hk.expand(WRAP_LABEL_MLKEM, mlkem_key.as_mut())
        .map_err(|e| anyhow::anyhow!("HKDF expand for ML-KEM wrapping key failed: {}", e))?;

    let mut x25519_key = Zeroizing::new([0u8; 32]);
    hk.expand(WRAP_LABEL_X25519, x25519_key.as_mut())
        .map_err(|e| anyhow::anyhow!("HKDF expand for X25519 wrapping key failed: {}", e))?;

<<<<<<< HEAD
    let keys = WrappingKeys {
        mlkem: AesKey::from_bytes(mlkem_key),
        x25519: AesKey::from_bytes(x25519_key),
    };
    // Zeroize stack temporaries — data now lives inside AesKey (ZeroizeOnDrop)
    mlkem_key.zeroize();
    x25519_key.zeroize();
    std::hint::black_box(&mlkem_key);
    std::hint::black_box(&x25519_key);
    Ok(keys)
}

// ── Key commitment ──────────────────────────────────────────────────────────

/// Domain separator for key commitment
const KEY_COMMITMENT_LABEL: &[u8] = b"dota-v5-key-commitment";

/// Compute a 32-byte commitment over KDF params + public keys, keyed by
/// the master key. Uses HKDF-Expand (the master key is already a high-quality
/// PRF output from Argon2id) with the commitment data as the info string.
///
/// This binds the master key to the vault's public parameters, detecting any
/// tampering (KDF downgrade, key replacement) at unlock time before decryption.
fn compute_key_commitment(
    master_key: &MasterKey,
    kdf: &KdfParams,
    mlkem_pk: &[u8],
    x25519_pk: &[u8],
) -> Vec<u8> {
    // Build the commitment input: domain || kdf_canonical || public keys
    let mut info = Vec::new();
    info.extend_from_slice(KEY_COMMITMENT_LABEL);
    info.extend_from_slice(kdf.algorithm.as_bytes());
    info.extend_from_slice(&kdf.salt);
    info.extend_from_slice(&kdf.time_cost.to_be_bytes());
    info.extend_from_slice(&kdf.memory_cost.to_be_bytes());
    info.extend_from_slice(&kdf.parallelism.to_be_bytes());
    info.extend_from_slice(mlkem_pk);
    info.extend_from_slice(x25519_pk);

    let hk = Hkdf::<Sha256>::from_prk(master_key.as_bytes())
        .expect("master key is 32 bytes, valid HKDF PRK");
    let mut commitment = [0u8; 32];
    hk.expand(&info, &mut commitment)
        .expect("32-byte expand always succeeds");
    commitment.to_vec()
}

// ── Vault migration ─────────────────────────────────────────────────────────

/// Migrate a vault file to the current format version.
///
/// - Versions < 4 are rejected (no vaults in the wild).
/// - Version 4 → 5: adds key commitment, bumps version.
/// - Version 5: already current, no-op.
#[allow(dead_code)]
pub fn migrate_vault(passphrase: &str, vault_path: &str) -> Result<()> {
    let json = fs::read_to_string(vault_path).context("Failed to read vault file")?;
    let mut vault: Vault = serde_json::from_str(&json).context("Failed to parse vault file")?;

    if vault.version < MIN_VAULT_VERSION {
        anyhow::bail!(
            "Vault version {} is no longer supported. \
             Please re-initialize with 'dota init'.",
            vault.version
        );
    }
    if vault.version >= VAULT_VERSION {
        return Ok(()); // Already current
    }

    // v4 → v5: derive master key, compute commitment, save
    let kdf_config = KdfConfig {
        salt: vault.kdf.salt.clone(),
        time_cost: vault.kdf.time_cost,
        memory_cost: vault.kdf.memory_cost,
        parallelism: vault.kdf.parallelism,
    };
    let master_key = derive_key(passphrase, &kdf_config)?;

    vault.key_commitment = Some(compute_key_commitment(
        &master_key,
        &vault.kdf,
        &vault.kem.public_key,
        &vault.x25519.public_key,
    ));
    vault.version = VAULT_VERSION;
    save_vault_file(vault_path, &vault)?;

    Ok(())
}

// ── Key commitment ──────────────────────────────────────────────────────────

/// Domain separator for key commitment
const KEY_COMMITMENT_LABEL: &[u8] = b"dota-v5-key-commitment";

/// Compute a 32-byte commitment over KDF params + public keys, keyed by
/// the master key. Uses HKDF-Expand with the commitment data as the info string.
///
/// This binds the master key to the vault's public parameters, detecting any
/// tampering (KDF downgrade, key replacement) at unlock time before decryption.
pub(crate) fn compute_key_commitment(
    master_key: &MasterKey,
    kdf: &KdfParams,
    mlkem_pk: &[u8],
    x25519_pk: &[u8],
) -> Vec<u8> {
    // Build the commitment input: domain || kdf_canonical || public keys
    let mut info = Vec::new();
    info.extend_from_slice(KEY_COMMITMENT_LABEL);
    info.extend_from_slice(kdf.algorithm.as_bytes());
    info.extend_from_slice(&kdf.salt);
    info.extend_from_slice(&kdf.time_cost.to_be_bytes());
    info.extend_from_slice(&kdf.memory_cost.to_be_bytes());
    info.extend_from_slice(&kdf.parallelism.to_be_bytes());
    info.extend_from_slice(mlkem_pk);
    info.extend_from_slice(x25519_pk);

    let hk = Hkdf::<Sha256>::from_prk(master_key.as_bytes())
        .expect("master key is 32 bytes, valid HKDF PRK");
    let mut commitment = [0u8; 32];
    hk.expand(&info, &mut commitment)
        .expect("32-byte expand always succeeds");
    commitment.to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs as unix_fs;
    use tempfile::{NamedTempFile, tempdir};

    #[test]
    fn test_create_and_unlock_vault() {
        let tmp = NamedTempFile::new().unwrap();
        let vault_path = tmp.path().to_str().unwrap();

        create_vault("test-passphrase", vault_path).unwrap();
        let unlocked = unlock_vault("test-passphrase", vault_path).unwrap();

        assert_eq!(unlocked.vault.version, VAULT_VERSION);
        assert_eq!(unlocked.vault.secrets.len(), 0);
        assert!(unlocked.vault.key_commitment.is_some());
        assert_eq!(unlocked.vault.min_version, VAULT_VERSION);
    }

    #[test]
    fn test_wrong_passphrase_fails() {
        let tmp = NamedTempFile::new().unwrap();
        let vault_path = tmp.path().to_str().unwrap();

        create_vault("correct-passphrase", vault_path).unwrap();
        let result = unlock_vault("wrong-passphrase", vault_path);

        assert!(result.is_err());
    }

    #[test]
    fn test_set_and_get_secret() {
        let tmp = NamedTempFile::new().unwrap();
        let vault_path = tmp.path().to_str().unwrap();

        create_vault("test-pass", vault_path).unwrap();
        let mut unlocked = unlock_vault("test-pass", vault_path).unwrap();

        set_secret(&mut unlocked, "API_KEY", "sk-test-12345").unwrap();
        let value = get_secret(&unlocked, "API_KEY").unwrap();

        assert_eq!(value.expose(), "sk-test-12345");
    }

    #[test]
    fn test_remove_secret() {
        let tmp = NamedTempFile::new().unwrap();
        let vault_path = tmp.path().to_str().unwrap();

        create_vault("test-pass", vault_path).unwrap();
        let mut unlocked = unlock_vault("test-pass", vault_path).unwrap();

        set_secret(&mut unlocked, "SECRET", "value").unwrap();
        assert_eq!(list_secrets(&unlocked).len(), 1);

        remove_secret(&mut unlocked, "SECRET").unwrap();
        assert_eq!(list_secrets(&unlocked).len(), 0);
    }

    #[test]
    fn test_list_secrets() {
        let tmp = NamedTempFile::new().unwrap();
        let vault_path = tmp.path().to_str().unwrap();

        create_vault("test-pass", vault_path).unwrap();
        let mut unlocked = unlock_vault("test-pass", vault_path).unwrap();

        set_secret(&mut unlocked, "KEY1", "val1").unwrap();
        set_secret(&mut unlocked, "KEY2", "val2").unwrap();
        set_secret(&mut unlocked, "KEY3", "val3").unwrap();

        let names = list_secrets(&unlocked);
        assert_eq!(names, vec!["KEY1", "KEY2", "KEY3"]);
    }

    #[test]
    fn test_v5_vault_rejects_stripped_key_commitment() {
        let tmp = NamedTempFile::new().unwrap();
        let vault_path = tmp.path().to_str().unwrap();

        // Create a v5 vault with a valid key commitment
        create_vault("test-pass", vault_path).unwrap();

        // Tamper: strip the key_commitment field from the vault file
        let json = std::fs::read_to_string(vault_path).unwrap();
        let mut raw: serde_json::Value = serde_json::from_str(&json).unwrap();
        raw.as_object_mut().unwrap().remove("key_commitment");
        assert_eq!(raw["version"], 5);
        std::fs::write(vault_path, serde_json::to_string_pretty(&raw).unwrap()).unwrap();

        // Unlock must fail — missing commitment on a v5 vault is tamper evidence
        let err = unlock_vault("test-pass", vault_path).unwrap_err();
        assert!(
            err.to_string().contains("requires a key commitment"),
            "unexpected error: {}",
            err
        );
    }

    #[test]
    fn test_create_vault_rejects_symlink_path() {
        let dir = tempdir().unwrap();
        let target = dir.path().join("real-vault.json");
        let symlink = dir.path().join("vault.json");
        unix_fs::symlink(&target, &symlink).unwrap();

        let err = create_vault("test-passphrase", symlink.to_str().unwrap()).unwrap_err();
        assert!(err.to_string().contains("symlink"));
    }
}
