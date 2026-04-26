//! CLI command handlers

use crate::security::SecretString;
use crate::vault::ops::{
    change_passphrase, create_vault, default_vault_path, get_secret, list_secrets, remove_secret,
    rotate_keys, set_secret, unlock_vault, validate_secret_name,
};
use anyhow::{Context, Result};
use rpassword::prompt_password;
use zeroize::Zeroize;

fn describe_key_commitment(vault: &crate::vault::format::Vault) -> &'static str {
    match (vault.version, vault.key_commitment.is_some()) {
        (6.., true) => "HMAC-SHA256 (present)",
        (6.., false) => "HMAC-SHA256 (absent)",
        (5, true) => "legacy HKDF-based v5 commitment (present)",
        (5, false) => "legacy HKDF-based v5 commitment (absent)",
        (_, true) => "present",
        (_, false) => "absent",
    }
}

/// Read passphrase from `DOTA_PASSPHRASE` if set and non-empty, otherwise
/// from an interactive non-echoing prompt. Returns a `SecretString`.
fn read_passphrase(prompt: &str) -> Result<SecretString> {
    if let Ok(p) = std::env::var("DOTA_PASSPHRASE")
        && !p.is_empty()
    {
        return Ok(SecretString::new(p));
    }
    Ok(SecretString::new(prompt_password(prompt)?))
}

/// Handle 'init' command
pub fn handle_init(vault_path: Option<String>) -> Result<()> {
    let vault_path = vault_path.unwrap_or_else(default_vault_path);

    // Check if vault already exists
    if std::path::Path::new(&vault_path).exists() {
        anyhow::bail!("Vault already exists at: {}", vault_path);
    }

    println!("Creating new vault at: {}", vault_path);
    println!();

    let passphrase = SecretString::new(prompt_password("Enter passphrase: ")?);
    let confirm = SecretString::new(prompt_password("Confirm passphrase: ")?);

    if passphrase.expose() != confirm.expose() {
        anyhow::bail!("Passphrases do not match");
    }

    if passphrase.expose().len() < 8 {
        anyhow::bail!("Passphrase must be at least 8 characters");
    }

    // Create vault
    create_vault(passphrase.expose(), &vault_path)?;

    println!();
    println!("Vault created successfully!");
    println!("Location: {}", vault_path);
    println!();
    println!(
        "Use 'dota set <name>' to add secrets (the value is read from a non-echoing prompt or stdin)"
    );
    println!("Use 'dota unlock' to enter interactive TUI mode");

    Ok(())
}

/// Handle 'set' command
pub fn handle_set(vault_path: Option<String>, name: String) -> Result<()> {
    let vault_path = vault_path.unwrap_or_else(default_vault_path);

    validate_secret_name(&name)?;

    let secret_value = read_secret_value(&name)?;

    let passphrase = read_passphrase("Vault passphrase: ")?;
    let mut unlocked = unlock_vault(passphrase.expose(), &vault_path)?;

    set_secret(&mut unlocked, &name, secret_value.expose())?;

    println!("Secret '{}' saved", name);

    Ok(())
}

/// Read a value from stdin (when piped) or from a non-echoing prompt. The
/// stdin path reads at most `MAX_STDIN_SECRET_BYTES` and trims a trailing
/// CR/LF in place.
fn read_secret_value(name: &str) -> Result<SecretString> {
    use std::io::{IsTerminal, Read};

    const MAX_STDIN_SECRET_BYTES: usize = 1024 * 1024;

    if std::io::stdin().is_terminal() {
        return Ok(SecretString::new(prompt_password(format!(
            "Enter value for '{}': ",
            name
        ))?));
    }

    let mut buf = String::new();
    let n = std::io::stdin()
        .take(MAX_STDIN_SECRET_BYTES as u64 + 1)
        .read_to_string(&mut buf)?;
    if n > MAX_STDIN_SECRET_BYTES {
        buf.zeroize();
        anyhow::bail!(
            "value exceeds {} bytes; refusing to read further",
            MAX_STDIN_SECRET_BYTES
        );
    }
    let trimmed_len = buf.trim_end_matches(['\r', '\n']).len();
    buf.truncate(trimmed_len);
    if buf.is_empty() {
        anyhow::bail!(
            "empty value from stdin; provide the value via the interactive prompt or pipe non-empty input"
        );
    }
    Ok(SecretString::new(buf))
}

/// Handle 'get' command
pub fn handle_get(vault_path: Option<String>, name: String) -> Result<()> {
    let vault_path = vault_path.unwrap_or_else(default_vault_path);

    validate_secret_name(&name)?;

    let passphrase = read_passphrase("Vault passphrase: ")?;
    let unlocked = unlock_vault(passphrase.expose(), &vault_path)?;

    let value = get_secret(&unlocked, &name)?;
    println!("{}", value.expose());

    Ok(())
}

/// Handle 'list' command
pub fn handle_list(vault_path: Option<String>) -> Result<()> {
    let vault_path = vault_path.unwrap_or_else(default_vault_path);

    let passphrase = read_passphrase("Vault passphrase: ")?;
    let unlocked = unlock_vault(passphrase.expose(), &vault_path)?;

    let names = list_secrets(&unlocked);

    if names.is_empty() {
        println!("No secrets in vault");
    } else {
        println!("Secrets ({}):", names.len());
        for name in names {
            let secret = &unlocked.vault.secrets[&name];
            println!(
                "  {} (modified: {})",
                name,
                secret.modified.format("%Y-%m-%d %H:%M:%S")
            );
        }
    }

    Ok(())
}

/// Handle 'rm' command
pub fn handle_rm(vault_path: Option<String>, name: String) -> Result<()> {
    let vault_path = vault_path.unwrap_or_else(default_vault_path);

    validate_secret_name(&name)?;

    // Unlock vault
    let passphrase = SecretString::new(prompt_password("Vault passphrase: ")?);
    let mut unlocked = unlock_vault(passphrase.expose(), &vault_path)?;

    // Remove secret
    remove_secret(&mut unlocked, &name)?;

    println!("Secret '{}' removed", name);

    Ok(())
}

/// Handle 'info' command
pub fn handle_info(vault_path: Option<String>) -> Result<()> {
    let vault_path = vault_path.unwrap_or_else(default_vault_path);

    // Unlock vault
    let passphrase = SecretString::new(prompt_password("Vault passphrase: ")?);
    let unlocked = unlock_vault(passphrase.expose(), &vault_path)?;

    // Display info
    println!("Vault Information");
    println!("─────────────────");
    println!("Location:      {}", vault_path);
    println!("Version:       {}", unlocked.vault.version);
    println!(
        "Created:       {}",
        unlocked.vault.created.format("%Y-%m-%d %H:%M:%S")
    );
    println!("Secrets:       {}", unlocked.vault.secrets.len());
    println!("Min version:   {}", unlocked.vault.min_version);
    println!("Suite:         {}", unlocked.vault.suite);
    println!(
        "Header auth:   {}",
        describe_key_commitment(&unlocked.vault)
    );
    println!();
    println!("Cryptography");
    println!("─────────────────");
    println!("KEM:           {}", unlocked.vault.kem.algorithm);
    println!("X25519:        {}", unlocked.vault.x25519.algorithm);
    println!(
        "KDF:           {} (t={}, m={}, p={})",
        unlocked.vault.kdf.algorithm,
        unlocked.vault.kdf.time_cost,
        unlocked.vault.kdf.memory_cost,
        unlocked.vault.kdf.parallelism,
    );
    println!("Encryption:    AES-256-GCM");
    println!("Hybrid KDF:    HKDF-SHA256");

    if let Some(ref info) = unlocked.vault.migrated_from {
        println!();
        println!("Migration");
        println!("─────────────────");
        println!("Original version: v{}", info.original_version);
        println!(
            "Migrated at:      {}",
            info.migrated_at.format("%Y-%m-%d %H:%M:%S")
        );
        println!(
            "Migration path:   {}",
            info.migration_path
                .iter()
                .map(|v| format!("v{}", v))
                .collect::<Vec<_>>()
                .join(" -> ")
        );
    }

    Ok(())
}

/// Handle 'change-passphrase' command
pub fn handle_change_passphrase(vault_path: Option<String>) -> Result<()> {
    let vault_path = vault_path.unwrap_or_else(default_vault_path);

    // Unlock with current passphrase
    let current_passphrase = SecretString::new(prompt_password("Current passphrase: ")?);
    let mut unlocked = unlock_vault(current_passphrase.expose(), &vault_path)?;

    // Prompt for new passphrase
    let new_passphrase = SecretString::new(prompt_password("New passphrase: ")?);
    let confirm = SecretString::new(prompt_password("Confirm new passphrase: ")?);

    if new_passphrase.expose() != confirm.expose() {
        anyhow::bail!("Passphrases do not match");
    }

    if new_passphrase.expose().len() < 8 {
        anyhow::bail!("Passphrase must be at least 8 characters");
    }

    if new_passphrase.expose() == current_passphrase.expose() {
        anyhow::bail!("New passphrase must be different from current passphrase");
    }

    // Perform passphrase change
    change_passphrase(&mut unlocked, new_passphrase.expose())?;
    println!("Passphrase changed successfully");

    Ok(())
}

/// Handle 'rotate-keys' command
pub fn handle_rotate_keys(vault_path: Option<String>) -> Result<()> {
    let vault_path = vault_path.unwrap_or_else(default_vault_path);

    // Unlock vault
    let passphrase = SecretString::new(prompt_password("Vault passphrase: ")?);
    let mut unlocked = unlock_vault(passphrase.expose(), &vault_path)?;

    // Perform key rotation
    rotate_keys(&mut unlocked, passphrase.expose())?;
    println!("Vault keys rotated successfully");

    Ok(())
}

/// Handle 'upgrade' command — explicitly upgrade vault to latest format
pub fn handle_upgrade(vault_path: Option<String>) -> Result<()> {
    let vault_path = vault_path.unwrap_or_else(default_vault_path);

    if !std::path::Path::new(&vault_path).exists() {
        anyhow::bail!("No vault found at: {}", vault_path);
    }

    // Read once via the bounded helper so we honour the same size cap as
    // the unlock path before parsing.
    let json = crate::vault::ops::read_vault_file(&vault_path)?;
    let probe: serde_json::Value =
        serde_json::from_str(&json).context("Failed to parse vault file")?;
    let version = probe["version"].as_u64().context("Missing version field")?;

    use crate::vault::format::VAULT_VERSION;
    if version >= VAULT_VERSION as u64 {
        println!(
            "Vault is already at v{} (current: v{}). No upgrade needed.",
            version, VAULT_VERSION
        );
        return Ok(());
    }

    println!("Upgrading vault from v{} to v{}...", version, VAULT_VERSION);
    let passphrase = SecretString::new(prompt_password("Vault passphrase: ")?);

    // unlock_vault handles migration automatically
    let _unlocked = unlock_vault(passphrase.expose(), &vault_path)?;

    println!("Vault upgraded successfully to v{}.", VAULT_VERSION);
    Ok(())
}
