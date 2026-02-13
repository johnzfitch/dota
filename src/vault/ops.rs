//! Vault operations: create, unlock, add/get/remove secrets

use super::format::{EncryptedSecret, KdfParams, KemKeyPair, VAULT_VERSION, Vault, X25519KeyPair};
use crate::crypto::{
    KdfConfig, MasterKey, MlKemCiphertext, MlKemPrivateKey, MlKemPublicKey, X25519PrivateKey,
    X25519PublicKey, aes_decrypt, aes_encrypt, derive_key, generate_salt, hybrid_decapsulate,
    hybrid_encapsulate, mlkem_generate_keypair, x25519_generate_keypair,
};
use anyhow::{Context, Result};
use chrono::Utc;
use std::collections::HashMap;
use std::fs;
use std::io::Write;
use std::path::Path;

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

    // Encrypt private keys with master key
    let aes_key = master_key_to_aes_key(&master_key);
    let (encrypted_mlkem_sk, mlkem_nonce) = aes_encrypt(&aes_key, mlkem_private.as_bytes())?;
    let (encrypted_x25519_sk, x25519_nonce) = aes_encrypt(&aes_key, x25519_private.as_bytes())?;

    // Create vault structure
    let vault = Vault {
        version: VAULT_VERSION,
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
    // Read and parse vault file
    let json = fs::read_to_string(vault_path).context("Failed to read vault file")?;
    let vault: Vault = serde_json::from_str(&json).context("Failed to parse vault file")?;

    // Check version
    if vault.version != VAULT_VERSION {
        anyhow::bail!(
            "Unsupported vault version: {} (expected {})",
            vault.version,
            VAULT_VERSION
        );
    }

    // Derive master key from passphrase
    let kdf_config = KdfConfig {
        salt: vault.kdf.salt.clone(),
        time_cost: vault.kdf.time_cost,
        memory_cost: vault.kdf.memory_cost,
        parallelism: vault.kdf.parallelism,
    };
    let master_key = derive_key(passphrase, &kdf_config)?;

    // Decrypt ML-KEM private key
    let aes_key = master_key_to_aes_key(&master_key);
    let mlkem_sk_bytes = aes_decrypt(
        &aes_key,
        &vault.kem.encrypted_private_key,
        vault.kem.private_key_nonce.as_slice().try_into()?,
    )
    .context("Failed to decrypt ML-KEM private key (wrong passphrase?)")?;
    let mlkem_private = MlKemPrivateKey::from_bytes(mlkem_sk_bytes)?;

    // Decrypt X25519 private key
    let x25519_sk_bytes = aes_decrypt(
        &aes_key,
        &vault.x25519.encrypted_private_key,
        vault.x25519.private_key_nonce.as_slice().try_into()?,
    )
    .context("Failed to decrypt X25519 private key (wrong passphrase?)")?;
    let x25519_private = X25519PrivateKey::from_bytes(
        x25519_sk_bytes
            .as_slice()
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
    let aes_key = master_key_to_aes_key(&master_key);

    let (encrypted_mlkem_sk, mlkem_nonce) =
        aes_encrypt(&aes_key, unlocked.mlkem_private.as_bytes())?;
    let (encrypted_x25519_sk, x25519_nonce) =
        aes_encrypt(&aes_key, unlocked.x25519_private.as_bytes())?;

    unlocked.vault.kdf.salt = kdf_config.salt;
    unlocked.vault.kdf.time_cost = kdf_config.time_cost;
    unlocked.vault.kdf.memory_cost = kdf_config.memory_cost;
    unlocked.vault.kdf.parallelism = kdf_config.parallelism;

    unlocked.vault.kem.encrypted_private_key = encrypted_mlkem_sk;
    unlocked.vault.kem.private_key_nonce = mlkem_nonce.to_vec();
    unlocked.vault.x25519.encrypted_private_key = encrypted_x25519_sk;
    unlocked.vault.x25519.private_key_nonce = x25519_nonce.to_vec();

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
    let mut secrets: Vec<(String, String, chrono::DateTime<Utc>)> =
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
    let aes_key = master_key_to_aes_key(&master_key);
    let (encrypted_mlkem_sk, mlkem_nonce) =
        aes_encrypt(&aes_key, unlocked.mlkem_private.as_bytes())?;
    let (encrypted_x25519_sk, x25519_nonce) =
        aes_encrypt(&aes_key, unlocked.x25519_private.as_bytes())?;

    unlocked.vault.kem.encrypted_private_key = encrypted_mlkem_sk;
    unlocked.vault.kem.private_key_nonce = mlkem_nonce.to_vec();
    unlocked.vault.x25519.encrypted_private_key = encrypted_x25519_sk;
    unlocked.vault.x25519.private_key_nonce = x25519_nonce.to_vec();
    unlocked.vault.kdf.salt = kdf_config.salt;

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

    for (name, plaintext, created) in secrets {
        let encap = hybrid_encapsulate(&mlkem_public, &x25519_public)?;
        let (ciphertext, nonce) = aes_encrypt(&encap.derived_key, plaintext.as_bytes())?;

        unlocked.vault.secrets.insert(
            name,
            EncryptedSecret {
                algorithm: "hybrid-mlkem768-x25519".to_string(),
                kem_ciphertext: encap.kem_ciphertext.as_bytes().to_vec(),
                x25519_ephemeral_public: encap.x25519_ephemeral_public.as_bytes().to_vec(),
                nonce: nonce.to_vec(),
                ciphertext,
                created,
                modified: Utc::now(),
            },
        );
    }

    save_vault(unlocked)?;
    Ok(())
}

/// Get a secret from the vault
pub fn get_secret(unlocked: &UnlockedVault, name: &str) -> Result<String> {
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

    // Decrypt the secret value
    let nonce: [u8; 12] = encrypted.nonce.as_slice().try_into()?;
    let plaintext = aes_decrypt(&aes_key, &encrypted.ciphertext, &nonce)?;

    String::from_utf8(plaintext).context("Secret contains invalid UTF-8")
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
fn save_vault_file(path: &str, vault: &Vault) -> Result<()> {
    let vault_path = Path::new(path);
    if let Ok(meta) = fs::symlink_metadata(vault_path) {
        if meta.file_type().is_symlink() {
            anyhow::bail!("Refusing to write vault through symlink: {}", path);
        }
    }

    let parent = vault_path.parent().unwrap_or_else(|| Path::new("."));
    let json = serde_json::to_string_pretty(vault).context("Failed to serialize vault")?;

    let mut tmp = tempfile::Builder::new()
        .prefix(".vault.tmp-")
        .tempfile_in(parent)
        .context("Failed to create temporary vault file")?;

    tmp.write_all(json.as_bytes())
        .context("Failed to write vault data")?;
    tmp.as_file().sync_all()
        .context("Failed to sync vault data")?;

    tmp.persist(vault_path)
        .context("Failed to persist vault file")?;

    Ok(())
}

/// Convert MasterKey to AesKey (helper for type conversion)
fn master_key_to_aes_key(mk: &MasterKey) -> crate::crypto::AesKey {
    crate::crypto::AesKey::from_bytes(*mk.as_bytes())
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

        assert_eq!(value, "sk-test-12345");
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
    fn test_create_vault_rejects_symlink_path() {
        let dir = tempdir().unwrap();
        let target = dir.path().join("real-vault.json");
        let symlink = dir.path().join("vault.json");
        unix_fs::symlink(&target, &symlink).unwrap();

        let err = create_vault("test-passphrase", symlink.to_str().unwrap()).unwrap_err();
        assert!(err.to_string().contains("symlink"));
    }
}
