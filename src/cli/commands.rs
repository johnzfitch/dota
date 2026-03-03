//! CLI command handlers

use crate::security::SecretString;
use crate::vault::ops::{
    change_passphrase, create_vault, default_vault_path, get_secret, list_secrets, remove_secret,
    rotate_keys, set_secret, unlock_vault,
};
use anyhow::Result;
use rpassword::prompt_password;
use zeroize::Zeroize;

/// Read passphrase from DOTA_PASSPHRASE env var, falling back to interactive prompt.
/// Returns a `SecretString` that is zeroized on drop.
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

    // Prompt for passphrase — wrap in SecretString immediately
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
    println!("Use 'dota set <name> <value>' to add secrets");
    println!("Use 'dota unlock' to enter interactive TUI mode");

    Ok(())
}

/// Handle 'set' command
pub fn handle_set(vault_path: Option<String>, name: String, value: Option<String>) -> Result<()> {
    let vault_path = vault_path.unwrap_or_else(default_vault_path);

    // Get value from args, stdin (if piped), or interactive prompt.
    // Wrap in SecretString for automatic zeroization.
    let secret_value = SecretString::new(match value {
        Some(v) => v,
        None => {
            use std::io::{IsTerminal, Read};
            if std::io::stdin().is_terminal() {
                prompt_password(format!("Enter value for '{}': ", name))?
            } else {
                let mut buf = String::new();
                std::io::stdin()
                    .take(1024 * 1024)
                    .read_to_string(&mut buf)?;
                let trimmed = buf.trim_end().to_string();
                // Zeroize the original buffer containing the raw stdin read
                buf.zeroize();
                if trimmed.is_empty() {
                    anyhow::bail!(
                        "empty value from stdin; pass a value as an argument or use an interactive terminal"
                    );
                }
                trimmed
            }
        }
    });

    // Unlock vault (accepts DOTA_PASSPHRASE env var for programmatic use)
    let passphrase = read_passphrase("Vault passphrase: ")?;
    let mut unlocked = unlock_vault(passphrase.expose(), &vault_path)?;

    // Set secret
    set_secret(&mut unlocked, &name, secret_value.expose())?;

    println!("Secret '{}' saved", name);

    Ok(())
}

/// Handle 'get' command
pub fn handle_get(vault_path: Option<String>, name: String) -> Result<()> {
    let vault_path = vault_path.unwrap_or_else(default_vault_path);

    // Unlock vault (accepts DOTA_PASSPHRASE env var for non-interactive/daemon use)
    let passphrase = read_passphrase("Vault passphrase: ")?;
    let unlocked = unlock_vault(passphrase.expose(), &vault_path)?;

    // Get and print secret (SecretString zeroized after printing)
    let value = get_secret(&unlocked, &name)?;
    println!("{}", value.expose());

    Ok(())
}

/// Handle 'list' command
pub fn handle_list(vault_path: Option<String>) -> Result<()> {
    let vault_path = vault_path.unwrap_or_else(default_vault_path);

    // Unlock vault (accepts DOTA_PASSPHRASE env var for programmatic use)
    let passphrase = read_passphrase("Vault passphrase: ")?;
    let unlocked = unlock_vault(passphrase.expose(), &vault_path)?;

    // List secrets
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
    println!();
    println!("Cryptography");
    println!("─────────────────");
    println!("KEM:           {}", unlocked.vault.kem.algorithm);
    println!(
        "KDF:           {} (t={}, m={}, p={})",
        unlocked.vault.kdf.algorithm,
        unlocked.vault.kdf.time_cost,
        unlocked.vault.kdf.memory_cost,
        unlocked.vault.kdf.parallelism,
    );
    println!("Encryption:    AES-256-GCM");
    println!("Key Derivation: HKDF-SHA256");

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
