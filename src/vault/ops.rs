//! Vault operations: create, unlock, add/get/remove secrets

use super::format::{
    EncryptedSecret, KdfParams, KemKeyPair, MIN_VAULT_VERSION, V5_VAULT_VERSION,
    V6_SECRET_ALGORITHM, V6_VAULT_VERSION, V7_KEM_ALGORITHM, V7_SECRET_ALGORITHM, V7_SUITE,
    V7_VAULT_VERSION, V7_X25519_ALGORITHM, VAULT_VERSION, Vault, X25519KeyPair,
};
use crate::crypto::hybrid::{hybrid_decapsulate_v6, hybrid_decapsulate_v7, hybrid_encapsulate_v7};
use crate::crypto::{
    AesKey, KdfConfig, MasterKey, MlKemCiphertext, MlKemPrivateKey, MlKemPublicKey,
    X25519PrivateKey, X25519PublicKey, aes_decrypt, aes_encrypt, derive_key, generate_salt,
    hybrid_decapsulate, hybrid_encapsulate, mlkem_generate_keypair, x25519_generate_keypair,
};
use crate::security::{self, SecretString, SecretVec};
use anyhow::{Context, Result};
use chrono::Utc;
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::collections::HashMap;
use std::fs;
use std::io::ErrorKind;
use std::io::Write;
use std::path::Path;
use zeroize::{Zeroize, Zeroizing};

#[cfg(unix)]
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};

const KDF_ALGORITHM: &str = "argon2id";
const SECRET_ALGORITHM: &str = "hybrid-mlkem768-x25519";
const MIN_SALT_LEN: usize = 16;
const MAX_SALT_LEN: usize = 128;
const MIN_TIME_COST: u32 = 1;
const MAX_TIME_COST: u32 = 10;
const MIN_MEMORY_COST_KIB: u32 = 8 * 1024;
const MAX_MEMORY_COST_KIB: u32 = 256 * 1024;
const MIN_PARALLELISM: u32 = 1;
const MAX_PARALLELISM: u32 = 32;
const AES_GCM_NONCE_LEN: usize = 12;
const AES_GCM_TAG_LEN: usize = 16;
const WRAPPED_MLKEM_PRIVATE_KEY_LEN: usize = 2400 + AES_GCM_TAG_LEN;
const WRAPPED_X25519_PRIVATE_KEY_LEN: usize = 32 + AES_GCM_TAG_LEN;

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
    /// Retained for v7 TC-HKEM per-secret passphrase commitment.
    /// ZeroizeOnDrop ensures this is cleared when the vault is dropped.
    pub(crate) master_key: MasterKey,
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
    let wrapping = derive_wrapping_keys_v7(&master_key)?;
    let (encrypted_mlkem_sk, mlkem_nonce) = aes_encrypt(&wrapping.mlkem, mlkem_private.as_bytes())?;
    let (encrypted_x25519_sk, x25519_nonce) =
        aes_encrypt(&wrapping.x25519, x25519_private.as_bytes())?;

    // Build KDF params for commitment
    let kdf_params = KdfParams {
        algorithm: KDF_ALGORITHM.to_string(),
        salt,
        time_cost: kdf_config.time_cost,
        memory_cost: kdf_config.memory_cost,
        parallelism: kdf_config.parallelism,
    };

    // Create vault structure
    let mut vault = Vault {
        version: VAULT_VERSION,
        created: Utc::now(),
        kdf: kdf_params,
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
        secrets: HashMap::new(),
        suite: V7_SUITE.to_string(),
        migrated_from: None,
        min_version: VAULT_VERSION,
    };
    vault.key_commitment = Some(compute_key_commitment(&master_key, &vault)?);

    // `save_vault_file` will create and harden the parent directory as
    // part of the atomic-write path; no need to pre-create it here. Doing
    // a separate `fs::create_dir_all` first would briefly expose the
    // directory at the umask-default mode before it is chmod'd to 0700.

    // Write vault to file with atomic replace and restrictive permissions.
    save_vault_file(vault_path, &vault)?;

    Ok(())
}

/// Maximum vault file size accepted on disk.
///
/// A real-world vault — KEM public key + wrapped private keys + a few
/// thousand secrets — fits well under a megabyte. The cap exists to defeat
/// resource-exhaustion attacks where a hostile vault file (e.g. a vault
/// planted in a shared directory) tries to make `serde_json` allocate
/// unbounded memory before any cryptographic check has run.
pub(crate) const MAX_VAULT_FILE_BYTES: u64 = 16 * 1024 * 1024;

/// Refuse to operate on a path that resolves to a symlink. Centralized so
/// every read/write path enforces the same policy and error wording.
pub(crate) fn reject_symlink_path(path: &Path, action: &str) -> Result<()> {
    if let Ok(meta) = fs::symlink_metadata(path)
        && meta.file_type().is_symlink()
    {
        anyhow::bail!(
            "Refusing to {} vault through symlink: {}",
            action,
            path.display()
        );
    }
    Ok(())
}

/// Tighten an existing on-disk file to mode 0o600 (owner-only rw). No-op
/// on non-Unix.
#[cfg(unix)]
pub(crate) fn restrict_file_to_owner_rw(path: &Path) -> Result<()> {
    let mut perms = fs::metadata(path)
        .with_context(|| format!("Failed to inspect permissions for {}", path.display()))?
        .permissions();
    perms.set_mode(0o600);
    fs::set_permissions(path, perms)
        .with_context(|| format!("Failed to secure file permissions for {}", path.display()))
}

#[cfg(not(unix))]
pub(crate) fn restrict_file_to_owner_rw(_path: &Path) -> Result<()> {
    Ok(())
}

/// Open a vault file for reading. On Unix the open refuses to traverse a
/// final-component symlink at the syscall boundary; on other platforms it
/// falls through to the platform's default open and relies on the caller's
/// pre-check.
#[cfg(unix)]
fn open_vault_file_for_read(path: &Path) -> std::io::Result<fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
}

#[cfg(not(unix))]
fn open_vault_file_for_read(path: &Path) -> std::io::Result<fs::File> {
    fs::File::open(path)
}

/// Read a vault file from disk with defensive bounds in place. The pre-check
/// gives a clean error wording for the common case; the open enforces the
/// final-component check at the syscall boundary so the result cannot be
/// swapped between the two; the read is bounded so a file that grows after
/// the open cannot allocate past the cap.
pub(crate) fn read_vault_file(vault_path: &str) -> Result<String> {
    use std::io::Read;

    let path_ref = Path::new(vault_path);
    reject_symlink_path(path_ref, "read")?;

    let mut file = open_vault_file_for_read(path_ref).context("Failed to read vault file")?;

    if let Ok(metadata) = file.metadata()
        && metadata.len() > MAX_VAULT_FILE_BYTES
    {
        anyhow::bail!(
            "Vault file size {} bytes exceeds {}-byte sanity cap; refusing to load",
            metadata.len(),
            MAX_VAULT_FILE_BYTES
        );
    }

    let mut buf = String::new();
    let read = (&mut file)
        .take(MAX_VAULT_FILE_BYTES + 1)
        .read_to_string(&mut buf)
        .context("Failed to read vault file")?;
    if read as u64 > MAX_VAULT_FILE_BYTES {
        // Drop the partial read so it never appears in any later error context.
        buf.zeroize();
        anyhow::bail!(
            "Vault file exceeds {}-byte sanity cap; refusing to load",
            MAX_VAULT_FILE_BYTES
        );
    }

    Ok(buf)
}

/// Unlock a vault with a passphrase
pub fn unlock_vault(passphrase: &str, vault_path: &str) -> Result<UnlockedVault> {
    let json = read_vault_file(vault_path)?;

    let probe: super::legacy::VaultVersionProbe =
        serde_json::from_str(&json).context("Failed to parse vault version")?;

    match probe.version {
        version if version < MIN_VAULT_VERSION => anyhow::bail!(
            "Vault version {} is no longer supported. Please re-initialize with 'dota init'.",
            version
        ),
        version if version < VAULT_VERSION => {
            eprintln!(
                "Migrating vault from v{} to v{}...",
                probe.version, VAULT_VERSION
            );
            let vault = super::migration::upvault(&json, passphrase, vault_path)?;
            unlock_v7(vault, passphrase, vault_path)
        }
        V7_VAULT_VERSION => {
            let vault: Vault = serde_json::from_str(&json).context("Failed to parse vault file")?;
            unlock_v7(vault, passphrase, vault_path)
        }
        version => anyhow::bail!(
            "Vault version {} is newer than supported (v{}). Please update dota.",
            version,
            V7_VAULT_VERSION
        ),
    }
}

fn unlock_v7(vault: Vault, passphrase: &str, vault_path: &str) -> Result<UnlockedVault> {
    validate_v7_vault(&vault)?;
    let master_key = derive_master_key(passphrase, &vault)?;
    verify_v7_key_commitment(&vault, &master_key)?;
    build_unlocked_vault(vault, &master_key, vault_path)
}

fn derive_master_key(passphrase: &str, vault: &Vault) -> Result<MasterKey> {
    let kdf_config = KdfConfig {
        salt: vault.kdf.salt.clone(),
        time_cost: vault.kdf.time_cost,
        memory_cost: vault.kdf.memory_cost,
        parallelism: vault.kdf.parallelism,
    };
    derive_key(passphrase, &kdf_config)
}

pub(crate) fn verify_v5_key_commitment(vault: &Vault, master_key: &MasterKey) -> Result<()> {
    if let Some(ref stored_commitment) = vault.key_commitment {
        let expected = compute_v5_key_commitment(
            master_key,
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
    } else if vault.version >= V5_VAULT_VERSION {
        anyhow::bail!(
            "Vault version {} requires a key commitment, but none was found — \
             vault file may have been tampered with",
            vault.version
        );
    }

    Ok(())
}

pub(crate) fn verify_v6_key_commitment(vault: &Vault, master_key: &MasterKey) -> Result<()> {
    let stored_commitment = vault.key_commitment.as_ref().ok_or_else(|| {
        anyhow::anyhow!(
            "Vault version {} requires a key commitment, but none was found — \
             vault file may have been tampered with",
            vault.version
        )
    })?;
    let expected = compute_v6_key_commitment(master_key, vault)?;
    if !security::constant_time_eq(stored_commitment, &expected) {
        anyhow::bail!(
            "Key commitment mismatch — vault may have been tampered with \
             (KDF parameters, suite, or public keys were modified), or wrong passphrase"
        );
    }
    Ok(())
}

fn build_unlocked_vault(
    vault: Vault,
    master_key: &MasterKey,
    vault_path: &str,
) -> Result<UnlockedVault> {
    let (mlkem_private, x25519_private) = decrypt_vault_private_keys(&vault, master_key)?;
    Ok(UnlockedVault {
        vault,
        mlkem_private,
        x25519_private,
        master_key: master_key.clone(),
        path: vault_path.to_string(),
    })
}

fn decrypt_vault_private_keys(
    vault: &Vault,
    master_key: &MasterKey,
) -> Result<(MlKemPrivateKey, X25519PrivateKey)> {
    // Key commitment runs before this function, so a failure here means
    // vault corruption rather than wrong passphrase. Surface one uniform
    // error so an observer cannot tell which arm failed first or distinguish
    // wrong-passphrase from corruption.
    const VAULT_DECRYPT_ERROR: &str =
        "Vault decryption failed — vault file may be corrupted or tampered with";

    let wrapping = derive_wrapping_keys_for_vault_version(vault.version, master_key)?;
    let mlkem_nonce: [u8; AES_GCM_NONCE_LEN] = vault
        .kem
        .private_key_nonce
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!(VAULT_DECRYPT_ERROR))?;
    // Move the decrypted Vec straight into MlKemPrivateKey (ZeroizeOnDrop).
    // An intermediate Zeroizing<Vec<u8>> + .to_vec() would clone the secret
    // onto a second heap allocation that the wrapper does not cover.
    let mlkem_private = MlKemPrivateKey::from_bytes(
        aes_decrypt(
            &wrapping.mlkem,
            &vault.kem.encrypted_private_key,
            &mlkem_nonce,
        )
        .map_err(|_| anyhow::anyhow!(VAULT_DECRYPT_ERROR))?,
    )
    .map_err(|_| anyhow::anyhow!(VAULT_DECRYPT_ERROR))?;

    let x25519_nonce: [u8; AES_GCM_NONCE_LEN] = vault
        .x25519
        .private_key_nonce
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!(VAULT_DECRYPT_ERROR))?;
    let x25519_sk_bytes = Zeroizing::new(
        aes_decrypt(
            &wrapping.x25519,
            &vault.x25519.encrypted_private_key,
            &x25519_nonce,
        )
        .map_err(|_| anyhow::anyhow!(VAULT_DECRYPT_ERROR))?,
    );
    // try_into materializes a fresh [u8; 32]. Because [u8; 32] is Copy,
    // X25519PrivateKey::from_bytes copies the array; the caller's local
    // survives the call and must be wiped explicitly.
    let mut x25519_arr: [u8; 32] = x25519_sk_bytes
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!(VAULT_DECRYPT_ERROR))?;
    let x25519_private = X25519PrivateKey::from_bytes(x25519_arr);
    x25519_arr.zeroize();
    std::hint::black_box(&x25519_arr);

    Ok((mlkem_private, x25519_private))
}

/// Decrypt the v6 private keys held in a v6 vault. Used by the migration
/// engine to drive a v6 -> v7 step.
pub(crate) fn decrypt_v6_private_keys(
    v6: &Vault,
    master_key: &MasterKey,
) -> Result<(MlKemPrivateKey, X25519PrivateKey)> {
    let wrapping = derive_wrapping_keys_v6(master_key)?;

    let mlkem_nonce: [u8; AES_GCM_NONCE_LEN] = v6
        .kem
        .private_key_nonce
        .as_slice()
        .try_into()
        .context("Invalid v6 ML-KEM nonce length")?;
    let mlkem_private = MlKemPrivateKey::from_bytes(
        aes_decrypt(&wrapping.mlkem, &v6.kem.encrypted_private_key, &mlkem_nonce)
            .context("Failed to decrypt v6 ML-KEM private key (wrong passphrase?)")?,
    )
    .context("Invalid v6 ML-KEM private key length")?;

    let x25519_nonce: [u8; AES_GCM_NONCE_LEN] = v6
        .x25519
        .private_key_nonce
        .as_slice()
        .try_into()
        .context("Invalid v6 X25519 nonce length")?;
    let x25519_sk_bytes = Zeroizing::new(
        aes_decrypt(
            &wrapping.x25519,
            &v6.x25519.encrypted_private_key,
            &x25519_nonce,
        )
        .context("Failed to decrypt v6 X25519 private key (wrong passphrase?)")?,
    );
    let mut x25519_arr: [u8; 32] = x25519_sk_bytes
        .as_slice()
        .try_into()
        .context("Invalid v6 X25519 private key length")?;
    let x25519_private = X25519PrivateKey::from_bytes(x25519_arr);
    x25519_arr.zeroize();
    std::hint::black_box(&x25519_arr);

    Ok((mlkem_private, x25519_private))
}

/// Decrypt one v6 secret to its plaintext bytes. Returned `Zeroizing` wipes
/// the buffer when dropped.
pub(crate) fn decrypt_v6_secret(
    name: &str,
    secret: &EncryptedSecret,
    mlkem_priv: &MlKemPrivateKey,
    x25519_priv: &X25519PrivateKey,
) -> Result<Zeroizing<Vec<u8>>> {
    let kem_ct = MlKemCiphertext::from_bytes(secret.kem_ciphertext.clone())
        .with_context(|| format!("Invalid ML-KEM ciphertext for secret '{}'", name))?;
    let x25519_eph_pk = X25519PublicKey::from_bytes(
        secret
            .x25519_ephemeral_public
            .as_slice()
            .try_into()
            .with_context(|| format!("Invalid X25519 ephemeral key for secret '{}'", name))?,
    );
    let aes_key = hybrid_decapsulate_v6(mlkem_priv, x25519_priv, &kem_ct, &x25519_eph_pk)?;
    let nonce: [u8; AES_GCM_NONCE_LEN] = secret
        .nonce
        .as_slice()
        .try_into()
        .with_context(|| format!("Invalid nonce for secret '{}'", name))?;
    Ok(Zeroizing::new(aes_decrypt(
        &aes_key,
        &secret.ciphertext,
        &nonce,
    )?))
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
    let encap = match unlocked.vault.version {
        V7_VAULT_VERSION => hybrid_encapsulate_v7(
            &mlkem_public,
            &x25519_public,
            unlocked.master_key.as_bytes(),
        )?,
        _ => hybrid_encapsulate(&mlkem_public, &x25519_public)?,
    };

    // Encrypt the secret value with derived AES key
    let (ciphertext, nonce) = aes_encrypt(&encap.derived_key, value.as_bytes())?;

    // Store encrypted secret
    let now = Utc::now();
    let created = unlocked
        .vault
        .secrets
        .get(name)
        .map(|existing| existing.created)
        .unwrap_or(now);

    unlocked.vault.secrets.insert(
        name.to_string(),
        EncryptedSecret {
            algorithm: expected_secret_algorithm(&unlocked.vault)?.to_string(),
            kem_ciphertext: encap.kem_ciphertext.as_bytes().to_vec(),
            x25519_ephemeral_public: encap.x25519_ephemeral_public.as_bytes().to_vec(),
            nonce: nonce.to_vec(),
            ciphertext,
            created,
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
    let wrapping = derive_wrapping_keys_for_vault_version(unlocked.vault.version, &master_key)?;

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
    preserve_unlock_version_on_save(&mut unlocked.vault)?;
    unlocked.vault.key_commitment = Some(compute_key_commitment(&master_key, &unlocked.vault)?);

    // Update the stored master key for future TC-HKEM operations
    unlocked.master_key = master_key;

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
    let wrapping = derive_wrapping_keys_for_vault_version(unlocked.vault.version, &master_key)?;
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
    preserve_unlock_version_on_save(&mut unlocked.vault)?;
    unlocked.vault.key_commitment = Some(compute_key_commitment(&master_key, &unlocked.vault)?);

    // Update stored master key for TC-HKEM re-encryption below
    unlocked.master_key = master_key;

    unlocked.vault.secrets.clear();
    let secret_algorithm = expected_secret_algorithm(&unlocked.vault)?.to_string();
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
        let encap = match unlocked.vault.version {
            V7_VAULT_VERSION => hybrid_encapsulate_v7(
                &mlkem_public,
                &x25519_public,
                unlocked.master_key.as_bytes(),
            )?,
            _ => hybrid_encapsulate(&mlkem_public, &x25519_public)?,
        };
        let (ciphertext, nonce) = aes_encrypt(&encap.derived_key, plaintext.expose().as_bytes())?;

        unlocked.vault.secrets.insert(
            name.clone(),
            EncryptedSecret {
                algorithm: secret_algorithm.clone(),
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

    let expected_algorithm = expected_secret_algorithm(&unlocked.vault)?;
    if encrypted.algorithm != expected_algorithm {
        anyhow::bail!(
            "Unsupported secret algorithm: {} (expected {})",
            encrypted.algorithm,
            expected_algorithm
        );
    }

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
    let aes_key = match unlocked.vault.version {
        V7_VAULT_VERSION => hybrid_decapsulate_v7(
            &unlocked.mlkem_private,
            &unlocked.x25519_private,
            &kem_ct,
            &x25519_eph_pk,
            unlocked.master_key.as_bytes(),
        )?,
        _ => hybrid_decapsulate(
            &unlocked.mlkem_private,
            &unlocked.x25519_private,
            &kem_ct,
            &x25519_eph_pk,
        )?,
    };

    // Decrypt the secret value — wrap in SecretVec for zeroization
    let nonce: [u8; 12] = encrypted.nonce.as_slice().try_into()?;
    let plaintext = SecretVec::new(aes_decrypt(&aes_key, &encrypted.ciphertext, &nonce)?);

    // Convert to String. On UTF-8 failure, `String::from_utf8` returns a
    // `FromUtf8Error` that owns the original bytes — if we propagated that
    // error directly, the plaintext would survive (un-zeroized) inside the
    // anyhow chain. Catch the error, zeroize the recovered bytes, and surface
    // a content-free message instead.
    let s = match String::from_utf8(plaintext.into_inner()) {
        Ok(s) => s,
        Err(err) => {
            let mut leaked = err.into_bytes();
            leaked.zeroize();
            anyhow::bail!("Secret contains invalid UTF-8");
        }
    };
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
    reject_symlink_path(vault_path, "write")?;

    let parent = vault_path.parent().unwrap_or_else(|| Path::new("."));
    let parent_existed = parent.exists();
    if !parent_existed {
        create_vault_directory(parent)?;
    }

    #[cfg(unix)]
    secure_vault_directory(parent, parent_existed)?;

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

    restrict_file_to_owner_rw(vault_path)?;

    if let Ok(dir) = fs::File::open(parent) {
        let _ = dir.sync_all();
    }

    Ok(())
}

/// Create the vault parent directory with 0700 from inception on Unix to
/// avoid a TOCTOU window in which a freshly-created directory exists at
/// the umask default before it is chmod'd. On non-Unix platforms this is
/// equivalent to `fs::create_dir_all`.
fn create_vault_directory(parent: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        let mut builder = fs::DirBuilder::new();
        builder.recursive(true);
        builder.mode(0o700);
        builder
            .create(parent)
            .context("Failed to create vault directory")?;
    }
    #[cfg(not(unix))]
    {
        fs::create_dir_all(parent).context("Failed to create vault directory")?;
    }
    Ok(())
}

#[cfg(unix)]
fn secure_vault_directory(parent: &Path, parent_existed: bool) -> Result<()> {
    let mut perms = fs::metadata(parent)
        .context("Failed to inspect vault directory permissions")?
        .permissions();
    perms.set_mode(0o700);

    match fs::set_permissions(parent, perms) {
        Ok(()) => Ok(()),
        Err(err) if parent_existed && is_nonfatal_directory_permission_error(&err) => {
            // Existing directories may live under temp/system-managed paths that
            // reject chmod. Keep file hardening strict, but do not fail when we
            // cannot redefine policy for a directory we did not create.
            eprintln!(
                "Warning: unable to tighten existing vault directory permissions for {}: {}",
                parent.display(),
                err
            );
            Ok(())
        }
        Err(err) => Err(err).context("Failed to secure vault directory"),
    }
}

#[cfg(unix)]
fn is_nonfatal_directory_permission_error(err: &std::io::Error) -> bool {
    err.kind() == ErrorKind::PermissionDenied || matches!(err.raw_os_error(), Some(1 | 13))
}

/// Wrapping keys derived from the master key via HKDF-Expand with purpose labels.
/// Provides cryptographic domain separation: each private key is encrypted under
/// a distinct wrapping key even though both are derived from the same master key.
pub(crate) struct WrappingKeys {
    pub(crate) mlkem: AesKey,
    pub(crate) x25519: AesKey,
}

/// Purpose labels for HKDF-Expand key derivation (domain separation)
const WRAP_LABEL_MLKEM_V5: &[u8] = b"dota-v4-wrap-mlkem";
const WRAP_LABEL_X25519_V5: &[u8] = b"dota-v4-wrap-x25519";
const WRAP_LABEL_MLKEM_V6: &[u8] = b"dota-v6-wrap-mlkem";
const WRAP_LABEL_X25519_V6: &[u8] = b"dota-v6-wrap-x25519";
const WRAP_LABEL_MLKEM_V7: &[u8] = b"dota-v7-wrap-mlkem";
const WRAP_LABEL_X25519_V7: &[u8] = b"dota-v7-wrap-x25519";

/// Derive separate wrapping keys for ML-KEM and X25519 private key encryption.
///
/// Uses HKDF-Expand (no extract step — the master key from Argon2id is already
/// a high-quality PRF output) with distinct purpose labels.
fn derive_wrapping_keys_with_labels(
    mk: &MasterKey,
    mlkem_label: &[u8],
    x25519_label: &[u8],
) -> Result<WrappingKeys> {
    let hk = Hkdf::<Sha256>::from_prk(mk.as_bytes())
        .map_err(|_| anyhow::anyhow!("master key too short for HKDF-Expand PRK"))?;

    let mut mlkem_key = Zeroizing::new([0u8; 32]);
    hk.expand(mlkem_label, mlkem_key.as_mut())
        .map_err(|e| anyhow::anyhow!("HKDF expand for ML-KEM wrapping key failed: {}", e))?;

    let mut x25519_key = Zeroizing::new([0u8; 32]);
    hk.expand(x25519_label, x25519_key.as_mut())
        .map_err(|e| anyhow::anyhow!("HKDF expand for X25519 wrapping key failed: {}", e))?;

    let keys = WrappingKeys {
        mlkem: AesKey::from_bytes(*mlkem_key),
        x25519: AesKey::from_bytes(*x25519_key),
    };
    // Zeroize stack temporaries — data now lives inside AesKey (ZeroizeOnDrop)
    mlkem_key.zeroize();
    x25519_key.zeroize();
    std::hint::black_box(&mlkem_key);
    std::hint::black_box(&x25519_key);
    Ok(keys)
}

pub(crate) fn derive_wrapping_keys(mk: &MasterKey) -> Result<WrappingKeys> {
    derive_wrapping_keys_v5(mk)
}

pub(crate) fn derive_wrapping_keys_v5(mk: &MasterKey) -> Result<WrappingKeys> {
    derive_wrapping_keys_with_labels(mk, WRAP_LABEL_MLKEM_V5, WRAP_LABEL_X25519_V5)
}

pub(crate) fn derive_wrapping_keys_v6(mk: &MasterKey) -> Result<WrappingKeys> {
    derive_wrapping_keys_with_labels(mk, WRAP_LABEL_MLKEM_V6, WRAP_LABEL_X25519_V6)
}

pub(crate) fn derive_wrapping_keys_v7(mk: &MasterKey) -> Result<WrappingKeys> {
    derive_wrapping_keys_with_labels(mk, WRAP_LABEL_MLKEM_V7, WRAP_LABEL_X25519_V7)
}

pub(crate) fn derive_wrapping_keys_for_vault_version(
    version: u32,
    mk: &MasterKey,
) -> Result<WrappingKeys> {
    match version {
        0..=V5_VAULT_VERSION => derive_wrapping_keys_v5(mk),
        V6_VAULT_VERSION => derive_wrapping_keys_v6(mk),
        V7_VAULT_VERSION => derive_wrapping_keys_v7(mk),
        other => anyhow::bail!("Unsupported vault version {} for wrapping keys", other),
    }
}

// ── Key commitment ──────────────────────────────────────────────────────────

/// Domain separator for the legacy v5 key commitment.
const KEY_COMMITMENT_LABEL_V5: &[u8] = b"dota-v5-key-commitment";
/// Domain separator for the v6 canonical-header commitment.
const KEY_COMMITMENT_LABEL_V6: &[u8] = b"dota-v6-key-commitment\0";
/// Domain separator for the v7 TC-HKEM canonical-header commitment.
const KEY_COMMITMENT_LABEL_V7: &[u8] = b"dota-v7-tchkem-key-commitment\0";

type HmacSha256 = Hmac<Sha256>;

/// Compute the legacy v5 key commitment.
///
/// This preserves the existing HKDF-based behavior exactly so that current v5
/// vaults continue to verify byte-for-byte during the transition to v6.
pub(crate) fn compute_v5_key_commitment(
    master_key: &MasterKey,
    kdf: &KdfParams,
    mlkem_pk: &[u8],
    x25519_pk: &[u8],
) -> Vec<u8> {
    let mut info = Vec::new();
    info.extend_from_slice(KEY_COMMITMENT_LABEL_V5);
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

fn append_u32_be(buf: &mut Vec<u8>, value: u32) {
    buf.extend_from_slice(&value.to_be_bytes());
}

fn append_len_prefixed(buf: &mut Vec<u8>, bytes: &[u8]) -> Result<()> {
    let len = u32::try_from(bytes.len()).context("commitment field too large to encode")?;
    append_u32_be(buf, len);
    buf.extend_from_slice(bytes);
    Ok(())
}

/// Canonical header encoding for the v6 key commitment.
pub(crate) fn encode_v6_commitment_header(vault: &Vault) -> Result<Vec<u8>> {
    let mut header = Vec::new();
    header.extend_from_slice(KEY_COMMITMENT_LABEL_V6);
    append_u32_be(&mut header, vault.version);
    append_u32_be(&mut header, vault.min_version);
    append_len_prefixed(&mut header, vault.kdf.algorithm.as_bytes())?;
    append_len_prefixed(&mut header, &vault.kdf.salt)?;
    append_u32_be(&mut header, vault.kdf.time_cost);
    append_u32_be(&mut header, vault.kdf.memory_cost);
    append_u32_be(&mut header, vault.kdf.parallelism);
    append_len_prefixed(&mut header, vault.kem.algorithm.as_bytes())?;
    append_len_prefixed(&mut header, &vault.kem.public_key)?;
    append_len_prefixed(&mut header, vault.x25519.algorithm.as_bytes())?;
    append_len_prefixed(&mut header, &vault.x25519.public_key)?;
    append_len_prefixed(&mut header, vault.suite.as_bytes())?;
    Ok(header)
}

/// Compute the v6 HMAC-SHA256 key commitment over the canonical header.
pub(crate) fn compute_v6_key_commitment(master_key: &MasterKey, vault: &Vault) -> Result<Vec<u8>> {
    let header = encode_v6_commitment_header(vault)?;
    let mut mac = HmacSha256::new_from_slice(master_key.as_bytes())
        .expect("HMAC accepts arbitrary key lengths");
    mac.update(&header);
    Ok(mac.finalize().into_bytes().to_vec())
}

/// Canonical header encoding for the v7 TC-HKEM key commitment.
/// Identical structure to v6 but with a distinct domain separator.
pub(crate) fn encode_v7_commitment_header(vault: &Vault) -> Result<Vec<u8>> {
    let mut header = Vec::new();
    header.extend_from_slice(KEY_COMMITMENT_LABEL_V7);
    append_u32_be(&mut header, vault.version);
    append_u32_be(&mut header, vault.min_version);
    append_len_prefixed(&mut header, vault.kdf.algorithm.as_bytes())?;
    append_len_prefixed(&mut header, &vault.kdf.salt)?;
    append_u32_be(&mut header, vault.kdf.time_cost);
    append_u32_be(&mut header, vault.kdf.memory_cost);
    append_u32_be(&mut header, vault.kdf.parallelism);
    append_len_prefixed(&mut header, vault.kem.algorithm.as_bytes())?;
    append_len_prefixed(&mut header, &vault.kem.public_key)?;
    append_len_prefixed(&mut header, vault.x25519.algorithm.as_bytes())?;
    append_len_prefixed(&mut header, &vault.x25519.public_key)?;
    append_len_prefixed(&mut header, vault.suite.as_bytes())?;
    Ok(header)
}

/// Compute the v7 HMAC-SHA256 key commitment over the TC-HKEM canonical header.
pub(crate) fn compute_v7_key_commitment(master_key: &MasterKey, vault: &Vault) -> Result<Vec<u8>> {
    let header = encode_v7_commitment_header(vault)?;
    let mut mac = HmacSha256::new_from_slice(master_key.as_bytes())
        .expect("HMAC accepts arbitrary key lengths");
    mac.update(&header);
    Ok(mac.finalize().into_bytes().to_vec())
}

fn verify_v7_key_commitment(vault: &Vault, master_key: &MasterKey) -> Result<()> {
    let stored_commitment = vault.key_commitment.as_ref().ok_or_else(|| {
        anyhow::anyhow!(
            "Vault version {} requires a key commitment, but none was found — \
             vault file may have been tampered with",
            vault.version
        )
    })?;
    let expected = compute_v7_key_commitment(master_key, vault)?;
    if !security::constant_time_eq(stored_commitment, &expected) {
        anyhow::bail!(
            "Key commitment mismatch — vault may have been tampered with \
             (KDF parameters, suite, or public keys were modified), or wrong passphrase"
        );
    }
    Ok(())
}

/// Compute the version-appropriate key commitment for a vault.
pub(crate) fn compute_key_commitment(master_key: &MasterKey, vault: &Vault) -> Result<Vec<u8>> {
    match vault.version {
        0..=V5_VAULT_VERSION => Ok(compute_v5_key_commitment(
            master_key,
            &vault.kdf,
            &vault.kem.public_key,
            &vault.x25519.public_key,
        )),
        V6_VAULT_VERSION => compute_v6_key_commitment(master_key, vault),
        V7_VAULT_VERSION => compute_v7_key_commitment(master_key, vault),
        version => anyhow::bail!(
            "Unsupported vault version {} for key commitment computation",
            version
        ),
    }
}

// ── Vault migration ─────────────────────────────────────────────────────────

/// Migrate a vault file to the current format version.
///
/// - Versions < 4 are rejected (no vaults in the wild).
/// - Version 4 to 5: adds key commitment, bumps version.
/// - Version 5: already current, no-op.
#[allow(dead_code)]
pub fn migrate_vault(passphrase: &str, vault_path: &str) -> Result<()> {
    let json = read_vault_file(vault_path)?;
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

    // v4 to v5: derive master key, compute commitment, save
    let kdf_config = KdfConfig {
        salt: vault.kdf.salt.clone(),
        time_cost: vault.kdf.time_cost,
        memory_cost: vault.kdf.memory_cost,
        parallelism: vault.kdf.parallelism,
    };
    let master_key = derive_key(passphrase, &kdf_config)?;

    vault.version = VAULT_VERSION;
    vault.key_commitment = Some(compute_key_commitment(&master_key, &vault)?);
    save_vault_file(vault_path, &vault)?;

    Ok(())
}

/// Validate a secret name against the project-wide rules.
///
/// Used at every point a secret name enters the system — direct CLI/TUI
/// input *and* names parsed out of a vault file on unlock — so that no
/// downstream caller (including `list` rendering, shell-export naming,
/// and informational output) ever sees a name carrying ASCII control
/// characters, terminal escape sequences, bidi overrides, zero-width or
/// BOM characters, or Unicode line/paragraph separators.
///
/// Without this check, a name like `API\u{202E}KEY` could spoof an
/// existing entry in `list`/TUI output, and a name embedding ESC could
/// rewrite the operator's terminal during a benign `list`.
pub(crate) fn validate_secret_name(name: &str) -> Result<()> {
    const MAX_SECRET_NAME_BYTES: usize = 256;

    if name.is_empty() {
        anyhow::bail!("secret name must not be empty");
    }
    if name.len() > MAX_SECRET_NAME_BYTES {
        anyhow::bail!("secret name exceeds {} bytes", MAX_SECRET_NAME_BYTES);
    }
    if name.trim() != name {
        anyhow::bail!("secret name must not have leading or trailing whitespace");
    }
    for ch in name.chars() {
        if ch.is_control() {
            anyhow::bail!(
                "secret name contains a control character (U+{:04X})",
                ch as u32
            );
        }
        // Bidi controls, zero-width, BOM, and Unicode line/paragraph
        // separators allow visually identical names to differ in bytes.
        if matches!(
            ch as u32,
            0x200B..=0x200F
                | 0x202A..=0x202E
                | 0x2066..=0x2069
                | 0xFEFF
                | 0x2028
                | 0x2029
        ) {
            anyhow::bail!(
                "secret name contains a disallowed format character (U+{:04X})",
                ch as u32
            );
        }
    }
    Ok(())
}

fn validate_vault_kdf(vault: &Vault) -> Result<()> {
    if vault.kdf.algorithm != KDF_ALGORITHM {
        anyhow::bail!(
            "Unsupported KDF algorithm: {} (expected {})",
            vault.kdf.algorithm,
            KDF_ALGORITHM
        );
    }

    if vault.kdf.salt.len() < MIN_SALT_LEN || vault.kdf.salt.len() > MAX_SALT_LEN {
        anyhow::bail!(
            "Invalid KDF salt length: {} (expected {}..={})",
            vault.kdf.salt.len(),
            MIN_SALT_LEN,
            MAX_SALT_LEN
        );
    }

    if !(MIN_TIME_COST..=MAX_TIME_COST).contains(&vault.kdf.time_cost) {
        anyhow::bail!(
            "Invalid Argon2 time cost: {} (expected {}..={})",
            vault.kdf.time_cost,
            MIN_TIME_COST,
            MAX_TIME_COST
        );
    }

    if !(MIN_MEMORY_COST_KIB..=MAX_MEMORY_COST_KIB).contains(&vault.kdf.memory_cost) {
        anyhow::bail!(
            "Invalid Argon2 memory cost: {} KiB (expected {}..={} KiB)",
            vault.kdf.memory_cost,
            MIN_MEMORY_COST_KIB,
            MAX_MEMORY_COST_KIB
        );
    }

    if !(MIN_PARALLELISM..=MAX_PARALLELISM).contains(&vault.kdf.parallelism) {
        anyhow::bail!(
            "Invalid Argon2 parallelism: {} (expected {}..={})",
            vault.kdf.parallelism,
            MIN_PARALLELISM,
            MAX_PARALLELISM
        );
    }

    Ok(())
}

fn validate_v7_vault(vault: &Vault) -> Result<()> {
    validate_vault_kdf(vault)?;

    if vault.version != V7_VAULT_VERSION {
        anyhow::bail!("Invalid v7 unlock path for vault version {}", vault.version);
    }

    if vault.kem.algorithm != V7_KEM_ALGORITHM {
        anyhow::bail!(
            "Unsupported ML-KEM algorithm: {} (expected {})",
            vault.kem.algorithm,
            V7_KEM_ALGORITHM
        );
    }

    if vault.x25519.algorithm != V7_X25519_ALGORITHM {
        anyhow::bail!(
            "Unsupported X25519 algorithm: {} (expected {})",
            vault.x25519.algorithm,
            V7_X25519_ALGORITHM
        );
    }

    if vault.suite != V7_SUITE {
        anyhow::bail!(
            "Unsupported vault suite: {} (expected {})",
            vault.suite,
            V7_SUITE
        );
    }

    if vault.min_version > V7_VAULT_VERSION {
        anyhow::bail!(
            "Vault requires newer dota version: min_version {} exceeds supported v{}",
            vault.min_version,
            V7_VAULT_VERSION
        );
    }

    MlKemPublicKey::from_bytes(vault.kem.public_key.clone())
        .context("Invalid v7 ML-KEM public key length")?;

    if vault.kem.encrypted_private_key.len() != WRAPPED_MLKEM_PRIVATE_KEY_LEN {
        anyhow::bail!(
            "Invalid wrapped ML-KEM private key length: {} (expected {})",
            vault.kem.encrypted_private_key.len(),
            WRAPPED_MLKEM_PRIVATE_KEY_LEN
        );
    }

    if vault.kem.private_key_nonce.len() != AES_GCM_NONCE_LEN {
        anyhow::bail!(
            "Invalid ML-KEM private key nonce length: {} (expected {})",
            vault.kem.private_key_nonce.len(),
            AES_GCM_NONCE_LEN
        );
    }

    <&[u8] as TryInto<[u8; 32]>>::try_into(vault.x25519.public_key.as_slice())
        .context("Invalid v7 X25519 public key length")?;

    if vault.x25519.encrypted_private_key.len() != WRAPPED_X25519_PRIVATE_KEY_LEN {
        anyhow::bail!(
            "Invalid wrapped X25519 private key length: {} (expected {})",
            vault.x25519.encrypted_private_key.len(),
            WRAPPED_X25519_PRIVATE_KEY_LEN
        );
    }

    if vault.x25519.private_key_nonce.len() != AES_GCM_NONCE_LEN {
        anyhow::bail!(
            "Invalid X25519 private key nonce length: {} (expected {})",
            vault.x25519.private_key_nonce.len(),
            AES_GCM_NONCE_LEN
        );
    }

    for (name, secret) in &vault.secrets {
        validate_secret_name(name).with_context(|| {
            // Names from a hostile or tampered vault file go through this
            // path before they ever reach `list`/TUI rendering. Catching
            // them here means an attacker cannot smuggle terminal escape
            // sequences or bidi-override confusables into operator output
            // by handing the user a poisoned vault.
            format!("Invalid secret name in vault file: {:?}", name)
        })?;

        if secret.algorithm != V7_SECRET_ALGORITHM {
            anyhow::bail!(
                "Unsupported secret algorithm for '{}': {} (expected {})",
                name,
                secret.algorithm,
                V7_SECRET_ALGORITHM
            );
        }

        MlKemCiphertext::from_bytes(secret.kem_ciphertext.clone())
            .with_context(|| format!("Invalid ML-KEM ciphertext length for secret '{}'", name))?;

        let ephemeral_public_key: [u8; 32] =
            <&[u8] as TryInto<[u8; 32]>>::try_into(secret.x25519_ephemeral_public.as_slice())
                .with_context(|| {
                    format!(
                        "Invalid X25519 ephemeral public key length for secret '{}'",
                        name
                    )
                })?;
        if ephemeral_public_key.iter().all(|&byte| byte == 0) {
            anyhow::bail!(
                "Invalid X25519 ephemeral public key for secret '{}': all-zero public key",
                name
            );
        }

        let _: [u8; AES_GCM_NONCE_LEN] =
            <&[u8] as TryInto<[u8; AES_GCM_NONCE_LEN]>>::try_into(secret.nonce.as_slice())
                .with_context(|| format!("Invalid nonce length for secret '{}'", name))?;
    }

    Ok(())
}

fn expected_secret_algorithm(vault: &Vault) -> Result<&'static str> {
    match vault.version {
        0..=V5_VAULT_VERSION => Ok(SECRET_ALGORITHM),
        V6_VAULT_VERSION => Ok(V6_SECRET_ALGORITHM),
        V7_VAULT_VERSION => Ok(V7_SECRET_ALGORITHM),
        version => anyhow::bail!(
            "Unsupported vault version {} for secret operations",
            version
        ),
    }
}

fn preserve_unlock_version_on_save(vault: &mut Vault) -> Result<()> {
    match vault.version {
        0..=V5_VAULT_VERSION => {
            vault.version = V5_VAULT_VERSION;
            vault.min_version = V5_VAULT_VERSION;
        }
        V6_VAULT_VERSION => {
            vault.min_version = V6_VAULT_VERSION;
        }
        V7_VAULT_VERSION => {
            vault.min_version = V7_VAULT_VERSION;
        }
        version => anyhow::bail!("Unsupported vault version {} for save", version),
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::format::{
        V6_KEM_ALGORITHM, V6_SECRET_ALGORITHM, V6_SUITE, V6_VAULT_VERSION, V6_X25519_ALGORITHM,
        V7_SECRET_ALGORITHM, V7_SUITE, V7_VAULT_VERSION, V7_X25519_ALGORITHM,
    };
    use std::collections::HashMap;
    use std::os::unix::fs as unix_fs;
    use tempfile::{NamedTempFile, tempdir};

    fn build_v6_commitment_test_vault() -> Vault {
        Vault {
            version: V6_VAULT_VERSION,
            created: chrono::Utc::now(),
            kdf: KdfParams {
                algorithm: KDF_ALGORITHM.to_string(),
                salt: b"fixed-v6-commitment-salt".to_vec(),
                time_cost: 3,
                memory_cost: 65536,
                parallelism: 4,
            },
            key_commitment: None,
            kem: KemKeyPair {
                algorithm: V6_KEM_ALGORITHM.to_string(),
                public_key: vec![0x41; 1184],
                encrypted_private_key: vec![0x42; 2400],
                private_key_nonce: vec![0x43; 12],
            },
            x25519: X25519KeyPair {
                algorithm: V6_X25519_ALGORITHM.to_string(),
                public_key: vec![0x44; 32],
                encrypted_private_key: vec![0x45; 32],
                private_key_nonce: vec![0x46; 12],
            },
            secrets: {
                let mut secrets = HashMap::new();
                secrets.insert(
                    "API_KEY".to_string(),
                    EncryptedSecret {
                        algorithm: V6_SECRET_ALGORITHM.to_string(),
                        kem_ciphertext: vec![0x47; 1088],
                        x25519_ephemeral_public: vec![0x48; 32],
                        nonce: vec![0x49; 12],
                        ciphertext: vec![0x4A; 24],
                        created: chrono::Utc::now(),
                        modified: chrono::Utc::now(),
                    },
                );
                secrets
            },
            suite: V6_SUITE.to_string(),
            migrated_from: None,
            min_version: V6_VAULT_VERSION,
        }
    }

    /// Helper: create a v7 vault and return the parsed Vault struct.
    fn write_v7_vault(vault_path: &str, passphrase: &str) -> Vault {
        create_vault(passphrase, vault_path).unwrap();
        serde_json::from_str(&fs::read_to_string(vault_path).unwrap()).unwrap()
    }

    #[test]
    fn test_v5_key_commitment_matches_legacy_hkdf_construction() {
        let master_key = MasterKey::from_bytes([0x11; 32]);
        let kdf = KdfParams {
            algorithm: KDF_ALGORITHM.to_string(),
            salt: b"fixed-v5-commitment-salt".to_vec(),
            time_cost: 3,
            memory_cost: 65536,
            parallelism: 4,
        };
        let mlkem_pk = vec![0x21; 1184];
        let x25519_pk = vec![0x31; 32];

        let computed = compute_v5_key_commitment(&master_key, &kdf, &mlkem_pk, &x25519_pk);

        let mut info = Vec::new();
        info.extend_from_slice(KEY_COMMITMENT_LABEL_V5);
        info.extend_from_slice(kdf.algorithm.as_bytes());
        info.extend_from_slice(&kdf.salt);
        info.extend_from_slice(&kdf.time_cost.to_be_bytes());
        info.extend_from_slice(&kdf.memory_cost.to_be_bytes());
        info.extend_from_slice(&kdf.parallelism.to_be_bytes());
        info.extend_from_slice(&mlkem_pk);
        info.extend_from_slice(&x25519_pk);

        let hk = Hkdf::<Sha256>::from_prk(master_key.as_bytes()).unwrap();
        let mut expected = [0u8; 32];
        hk.expand(&info, &mut expected).unwrap();

        assert_eq!(computed, expected.to_vec());
    }

    #[test]
    fn test_v6_key_commitment_changes_when_authenticated_header_fields_change() {
        let master_key = MasterKey::from_bytes([0x5a; 32]);
        let base = build_v6_commitment_test_vault();
        let original = compute_v6_key_commitment(&master_key, &base).unwrap();

        let mut changed_min_version = base.clone();
        changed_min_version.min_version += 1;
        let min_version_commitment =
            compute_v6_key_commitment(&master_key, &changed_min_version).unwrap();
        assert_ne!(original, min_version_commitment);

        let mut changed_suite = base.clone();
        changed_suite.suite = "dota-v6-hybrid-mlkem768-x25519-aes256gcm-alt".to_string();
        let suite_commitment = compute_v6_key_commitment(&master_key, &changed_suite).unwrap();
        assert_ne!(original, suite_commitment);

        let mut changed_x25519_algorithm = base.clone();
        changed_x25519_algorithm.x25519.algorithm = "X25519-alt".to_string();
        let x25519_algorithm_commitment =
            compute_v6_key_commitment(&master_key, &changed_x25519_algorithm).unwrap();
        assert_ne!(original, x25519_algorithm_commitment);
    }

    #[test]
    fn test_versioned_key_commitment_dispatch_uses_v6_hmac() {
        let master_key = MasterKey::from_bytes([0x7b; 32]);
        let v6_vault = build_v6_commitment_test_vault();

        let dispatched = compute_key_commitment(&master_key, &v6_vault).unwrap();
        let v6 = compute_v6_key_commitment(&master_key, &v6_vault).unwrap();
        let legacy = compute_v5_key_commitment(
            &master_key,
            &v6_vault.kdf,
            &v6_vault.kem.public_key,
            &v6_vault.x25519.public_key,
        );

        assert_eq!(dispatched, v6);
        assert_ne!(dispatched, legacy);
    }

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
    fn test_unlock_staged_v6_vault() {
        let tmp = NamedTempFile::new().unwrap();
        let vault_path = tmp.path().to_str().unwrap();

        write_v7_vault(vault_path, "test-passphrase");
        let unlocked = unlock_vault("test-passphrase", vault_path).unwrap();

        assert_eq!(unlocked.vault.version, V7_VAULT_VERSION);
        assert_eq!(unlocked.vault.min_version, V7_VAULT_VERSION);
        assert_eq!(unlocked.vault.x25519.algorithm, V7_X25519_ALGORITHM);
        assert_eq!(unlocked.vault.suite, V7_SUITE);
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
    fn test_unlock_v6_rejects_future_min_version() {
        let tmp = NamedTempFile::new().unwrap();
        let vault_path = tmp.path().to_str().unwrap();

        let mut vault = write_v7_vault(vault_path, "test-passphrase");
        vault.min_version = V7_VAULT_VERSION + 1;
        let kdf_config = KdfConfig {
            salt: vault.kdf.salt.clone(),
            time_cost: vault.kdf.time_cost,
            memory_cost: vault.kdf.memory_cost,
            parallelism: vault.kdf.parallelism,
        };
        let master_key = derive_key("test-passphrase", &kdf_config).unwrap();
        vault.key_commitment = Some(compute_v7_key_commitment(&master_key, &vault).unwrap());
        fs::write(vault_path, serde_json::to_string_pretty(&vault).unwrap()).unwrap();

        let err = unlock_vault("test-passphrase", vault_path).unwrap_err();
        assert!(err.to_string().contains("min_version"));
    }

    #[test]
    fn test_unlock_v6_rejects_invalid_suite() {
        let tmp = NamedTempFile::new().unwrap();
        let vault_path = tmp.path().to_str().unwrap();

        let mut vault = write_v7_vault(vault_path, "test-passphrase");
        vault.suite = "dota-v6-invalid-suite".to_string();
        let kdf_config = KdfConfig {
            salt: vault.kdf.salt.clone(),
            time_cost: vault.kdf.time_cost,
            memory_cost: vault.kdf.memory_cost,
            parallelism: vault.kdf.parallelism,
        };
        let master_key = derive_key("test-passphrase", &kdf_config).unwrap();
        vault.key_commitment = Some(compute_v7_key_commitment(&master_key, &vault).unwrap());
        fs::write(vault_path, serde_json::to_string_pretty(&vault).unwrap()).unwrap();

        let err = unlock_vault("test-passphrase", vault_path).unwrap_err();
        assert!(err.to_string().contains("Unsupported vault suite"));
    }

    #[test]
    fn test_unlock_v6_rejects_invalid_kem_algorithm() {
        let tmp = NamedTempFile::new().unwrap();
        let vault_path = tmp.path().to_str().unwrap();

        let mut vault = write_v7_vault(vault_path, "test-passphrase");
        vault.kem.algorithm = "ML-KEM-768-legacy".to_string();
        let kdf_config = KdfConfig {
            salt: vault.kdf.salt.clone(),
            time_cost: vault.kdf.time_cost,
            memory_cost: vault.kdf.memory_cost,
            parallelism: vault.kdf.parallelism,
        };
        let master_key = derive_key("test-passphrase", &kdf_config).unwrap();
        vault.key_commitment = Some(compute_v7_key_commitment(&master_key, &vault).unwrap());
        fs::write(vault_path, serde_json::to_string_pretty(&vault).unwrap()).unwrap();

        let err = unlock_vault("test-passphrase", vault_path).unwrap_err();
        assert!(err.to_string().contains("Unsupported ML-KEM algorithm"));
    }

    #[test]
    fn test_unlock_v6_rejects_invalid_x25519_algorithm() {
        let tmp = NamedTempFile::new().unwrap();
        let vault_path = tmp.path().to_str().unwrap();

        let mut vault = write_v7_vault(vault_path, "test-passphrase");
        vault.x25519.algorithm = "curve25519".to_string();
        let kdf_config = KdfConfig {
            salt: vault.kdf.salt.clone(),
            time_cost: vault.kdf.time_cost,
            memory_cost: vault.kdf.memory_cost,
            parallelism: vault.kdf.parallelism,
        };
        let master_key = derive_key("test-passphrase", &kdf_config).unwrap();
        vault.key_commitment = Some(compute_v7_key_commitment(&master_key, &vault).unwrap());
        fs::write(vault_path, serde_json::to_string_pretty(&vault).unwrap()).unwrap();

        let err = unlock_vault("test-passphrase", vault_path).unwrap_err();
        assert!(err.to_string().contains("Unsupported X25519 algorithm"));
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
    fn test_set_and_get_secret_on_staged_v6_vault_uses_v6_algorithm() {
        let tmp = NamedTempFile::new().unwrap();
        let vault_path = tmp.path().to_str().unwrap();

        write_v7_vault(vault_path, "test-pass");
        let mut unlocked = unlock_vault("test-pass", vault_path).unwrap();

        set_secret(&mut unlocked, "API_KEY", "sk-v6-12345").unwrap();
        assert_eq!(
            unlocked.vault.secrets.get("API_KEY").unwrap().algorithm,
            V7_SECRET_ALGORITHM
        );

        let value = get_secret(&unlocked, "API_KEY").unwrap();
        assert_eq!(value.expose(), "sk-v6-12345");
    }

    #[test]
    fn test_unlock_v6_rejects_tampered_public_key_via_commitment() {
        let tmp = NamedTempFile::new().unwrap();
        let vault_path = tmp.path().to_str().unwrap();

        let mut vault = write_v7_vault(vault_path, "test-passphrase");
        vault.kem.public_key[0] ^= 0x01;
        fs::write(vault_path, serde_json::to_string_pretty(&vault).unwrap()).unwrap();

        let err = unlock_vault("test-passphrase", vault_path).unwrap_err();
        assert!(err.to_string().contains("Key commitment mismatch"));
    }

    #[test]
    fn test_unlock_v6_rejects_legacy_secret_algorithm_string() {
        let tmp = NamedTempFile::new().unwrap();
        let vault_path = tmp.path().to_str().unwrap();

        write_v7_vault(vault_path, "test-pass");
        let mut unlocked = unlock_vault("test-pass", vault_path).unwrap();
        set_secret(&mut unlocked, "API_KEY", "sk-v6-12345").unwrap();

        let mut vault: Vault =
            serde_json::from_str(&fs::read_to_string(vault_path).unwrap()).unwrap();
        vault.secrets.get_mut("API_KEY").unwrap().algorithm = SECRET_ALGORITHM.to_string();
        fs::write(vault_path, serde_json::to_string_pretty(&vault).unwrap()).unwrap();

        let err = unlock_vault("test-pass", vault_path).unwrap_err();
        assert!(err.to_string().contains("Unsupported secret algorithm"));
    }

    #[test]
    fn test_unlock_v6_rejects_malformed_secret_ephemeral_public_key_length() {
        let tmp = NamedTempFile::new().unwrap();
        let vault_path = tmp.path().to_str().unwrap();

        write_v7_vault(vault_path, "test-pass");
        let mut unlocked = unlock_vault("test-pass", vault_path).unwrap();
        set_secret(&mut unlocked, "API_KEY", "sk-v6-12345").unwrap();

        let mut vault: Vault =
            serde_json::from_str(&fs::read_to_string(vault_path).unwrap()).unwrap();
        vault
            .secrets
            .get_mut("API_KEY")
            .unwrap()
            .x25519_ephemeral_public
            .truncate(31);
        fs::write(vault_path, serde_json::to_string_pretty(&vault).unwrap()).unwrap();

        let err = unlock_vault("test-pass", vault_path).unwrap_err();
        assert!(
            err.to_string()
                .contains("Invalid X25519 ephemeral public key length")
        );
    }

    #[test]
    fn test_unlock_v6_rejects_all_zero_secret_ephemeral_public_key() {
        let tmp = NamedTempFile::new().unwrap();
        let vault_path = tmp.path().to_str().unwrap();

        write_v7_vault(vault_path, "test-pass");
        let mut unlocked = unlock_vault("test-pass", vault_path).unwrap();
        set_secret(&mut unlocked, "API_KEY", "sk-v6-12345").unwrap();

        let mut vault: Vault =
            serde_json::from_str(&fs::read_to_string(vault_path).unwrap()).unwrap();
        vault
            .secrets
            .get_mut("API_KEY")
            .unwrap()
            .x25519_ephemeral_public = vec![0u8; 32];
        fs::write(vault_path, serde_json::to_string_pretty(&vault).unwrap()).unwrap();

        let err = unlock_vault("test-pass", vault_path).unwrap_err();
        assert!(err.to_string().contains("all-zero public key"));
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

        // Create a staged legacy v5 vault with a valid key commitment.
        create_vault("test-pass", vault_path).unwrap();
        let mut vault: Vault =
            serde_json::from_str(&fs::read_to_string(vault_path).unwrap()).unwrap();
        vault.version = V5_VAULT_VERSION;
        vault.min_version = V5_VAULT_VERSION;
        vault.kem.algorithm = "ML-KEM-768".to_string();
        vault.x25519.algorithm.clear();
        vault.suite.clear();
        let kdf_config = KdfConfig {
            salt: vault.kdf.salt.clone(),
            time_cost: vault.kdf.time_cost,
            memory_cost: vault.kdf.memory_cost,
            parallelism: vault.kdf.parallelism,
        };
        let master_key = derive_key("test-pass", &kdf_config).unwrap();
        vault.key_commitment = Some(compute_v5_key_commitment(
            &master_key,
            &vault.kdf,
            &vault.kem.public_key,
            &vault.x25519.public_key,
        ));
        fs::write(vault_path, serde_json::to_string_pretty(&vault).unwrap()).unwrap();

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
    fn test_unlock_v6_checks_commitment_before_private_key_decrypt() {
        let tmp = NamedTempFile::new().unwrap();
        let vault_path = tmp.path().to_str().unwrap();

        let mut vault = write_v7_vault(vault_path, "test-pass");
        vault.key_commitment = Some(vec![0x00; 32]);
        vault.kem.encrypted_private_key[0] ^= 0x55;
        fs::write(vault_path, serde_json::to_string_pretty(&vault).unwrap()).unwrap();

        let err = unlock_vault("test-pass", vault_path).unwrap_err();
        assert!(
            err.to_string().contains("Key commitment mismatch"),
            "unexpected error: {}",
            err
        );
    }

    #[test]
    fn test_change_passphrase_preserves_staged_v6_metadata() {
        let tmp = NamedTempFile::new().unwrap();
        let vault_path = tmp.path().to_str().unwrap();

        write_v7_vault(vault_path, "old-pass");
        let mut unlocked = unlock_vault("old-pass", vault_path).unwrap();
        change_passphrase(&mut unlocked, "new-pass").unwrap();

        let updated: Vault =
            serde_json::from_str(&fs::read_to_string(vault_path).unwrap()).unwrap();
        assert_eq!(updated.version, V7_VAULT_VERSION);
        assert_eq!(updated.min_version, V7_VAULT_VERSION);
        assert_eq!(updated.x25519.algorithm, V7_X25519_ALGORITHM);
        assert_eq!(updated.suite, V7_SUITE);

        let reopened = unlock_vault("new-pass", vault_path).unwrap();
        assert_eq!(reopened.vault.version, V7_VAULT_VERSION);
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

    #[test]
    fn test_unlock_rejects_oversized_kdf_memory() {
        let tmp = NamedTempFile::new().unwrap();
        let vault_path = tmp.path().to_str().unwrap();

        create_vault("test-passphrase", vault_path).unwrap();

        let mut vault: Vault =
            serde_json::from_str(&fs::read_to_string(vault_path).unwrap()).unwrap();
        vault.kdf.memory_cost = MAX_MEMORY_COST_KIB + 1;
        fs::write(vault_path, serde_json::to_string_pretty(&vault).unwrap()).unwrap();

        let err = match unlock_vault("test-passphrase", vault_path) {
            Ok(_) => panic!("unlock_vault unexpectedly succeeded"),
            Err(err) => err,
        };
        assert!(err.to_string().contains("Invalid Argon2 memory cost"));
    }

    #[test]
    fn test_get_secret_rejects_unknown_algorithm() {
        let tmp = NamedTempFile::new().unwrap();
        let vault_path = tmp.path().to_str().unwrap();

        create_vault("test-pass", vault_path).unwrap();
        let mut unlocked = unlock_vault("test-pass", vault_path).unwrap();
        set_secret(&mut unlocked, "API_KEY", "sk-test-12345").unwrap();

        unlocked.vault.secrets.get_mut("API_KEY").unwrap().algorithm = "legacy-algo".to_string();

        let err = get_secret(&unlocked, "API_KEY").unwrap_err();
        assert!(err.to_string().contains("Unsupported secret algorithm"));
    }

    #[test]
    fn test_unlock_vault_rejects_symlink_path() {
        let dir = tempdir().unwrap();
        let target = dir.path().join("real-vault.json");
        let symlink = dir.path().join("vault.json");

        create_vault("test-passphrase", target.to_str().unwrap()).unwrap();
        unix_fs::symlink(&target, &symlink).unwrap();

        let result = unlock_vault("test-passphrase", symlink.to_str().unwrap());
        assert!(result.is_err());
        assert!(result.err().unwrap().to_string().contains("symlink"));
    }

    #[test]
    fn test_create_vault_sets_restrictive_permissions() {
        let tmp = NamedTempFile::new().unwrap();
        let vault_path = tmp.path().to_str().unwrap();

        create_vault("test-passphrase", vault_path).unwrap();

        #[cfg(unix)]
        {
            let mode = fs::metadata(vault_path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
    }

    #[test]
    fn test_unlock_rejects_oversized_vault_file() {
        let tmp = NamedTempFile::new().unwrap();
        let vault_path = tmp.path().to_str().unwrap();

        // Plant a JSON-shaped file that comfortably exceeds the cap. We do
        // not need it to be a valid vault — the size check runs before any
        // parsing.
        let oversized = vec![b'A'; (MAX_VAULT_FILE_BYTES + 1) as usize];
        fs::write(vault_path, oversized).unwrap();

        let err = unlock_vault("test-passphrase", vault_path).unwrap_err();
        assert!(
            err.to_string().contains("exceeds"),
            "unexpected error: {}",
            err
        );
    }

    #[test]
    fn test_unlock_rejects_vault_with_malicious_secret_name() {
        let tmp = NamedTempFile::new().unwrap();
        let vault_path = tmp.path().to_str().unwrap();

        // Build a normal v7 vault, then rewrite the secret map under a name
        // carrying a bidi override. This is the "poisoned vault" case the
        // reviewer flagged: a hostile vault file presenting confusable
        // entries to operator output.
        create_vault("test-pass", vault_path).unwrap();
        let mut unlocked = unlock_vault("test-pass", vault_path).unwrap();
        set_secret(&mut unlocked, "API_KEY", "sk-12345").unwrap();

        let mut vault: Vault =
            serde_json::from_str(&fs::read_to_string(vault_path).unwrap()).unwrap();
        let secret = vault.secrets.remove("API_KEY").unwrap();
        vault.secrets.insert("API\u{202E}KEY".to_string(), secret);
        fs::write(vault_path, serde_json::to_string_pretty(&vault).unwrap()).unwrap();

        let err = unlock_vault("test-pass", vault_path).unwrap_err();
        assert!(
            err.to_string().contains("Invalid secret name"),
            "unexpected error: {}",
            err
        );
    }

    #[test]
    fn validate_secret_name_accepts_typical_identifiers() {
        validate_secret_name("API_KEY").unwrap();
        validate_secret_name("aws/prod/access-token").unwrap();
        validate_secret_name("user@example.com").unwrap();
        validate_secret_name("π-token").unwrap();
    }

    #[test]
    fn validate_secret_name_rejects_empty() {
        assert!(validate_secret_name("").is_err());
    }

    #[test]
    fn validate_secret_name_rejects_whitespace_padding() {
        assert!(validate_secret_name(" API_KEY").is_err());
        assert!(validate_secret_name("API_KEY ").is_err());
        assert!(validate_secret_name("\tAPI_KEY").is_err());
    }

    #[test]
    fn validate_secret_name_rejects_control_characters() {
        assert!(validate_secret_name("API\nKEY").is_err());
        assert!(validate_secret_name("API\rKEY").is_err());
        assert!(validate_secret_name("API\x00KEY").is_err());
        assert!(validate_secret_name("API\x1bKEY").is_err()); // ESC — terminal escape
        assert!(validate_secret_name("API\x7fKEY").is_err()); // DEL
    }

    #[test]
    fn validate_secret_name_rejects_bidi_and_format_overrides() {
        // Right-to-Left Override — classic confusable-name attack.
        assert!(validate_secret_name("API\u{202E}KEY").is_err());
        // Left-to-Right Override.
        assert!(validate_secret_name("API\u{202D}KEY").is_err());
        // Zero-Width Space — invisible in `list` output.
        assert!(validate_secret_name("API\u{200B}KEY").is_err());
        // Byte Order Mark / ZWNBSP.
        assert!(validate_secret_name("\u{FEFF}API_KEY").is_err());
        // Unicode line separator.
        assert!(validate_secret_name("API\u{2028}KEY").is_err());
    }

    #[test]
    fn validate_secret_name_rejects_oversized() {
        let huge = "A".repeat(257);
        assert!(validate_secret_name(&huge).is_err());
    }
}
