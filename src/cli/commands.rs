//! CLI command handlers

use crate::vault::ops::{
    change_passphrase, create_vault, default_vault_path, get_secret, list_secrets, remove_secret,
    rotate_keys, set_secret, unlock_vault,
};
use anyhow::Result;
use rpassword::prompt_password;

/// Handle 'init' command
pub fn handle_init(vault_path: Option<String>) -> Result<()> {
    let vault_path = vault_path.unwrap_or_else(default_vault_path);

    // Check if vault already exists
    if std::path::Path::new(&vault_path).exists() {
        anyhow::bail!("Vault already exists at: {}", vault_path);
    }

    println!("Creating new vault at: {}", vault_path);
    println!();

    // Prompt for passphrase
    let passphrase = prompt_password("Enter passphrase: ")?;
    let confirm = prompt_password("Confirm passphrase: ")?;

    if passphrase != confirm {
        anyhow::bail!("Passphrases do not match");
    }

    if passphrase.len() < 8 {
        anyhow::bail!("Passphrase must be at least 8 characters");
    }

    // Create vault
    create_vault(&passphrase, &vault_path)?;

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

    // Get value from args or prompt
    let secret_value = match value {
        Some(v) => v,
        None => prompt_password(&format!("Enter value for '{}': ", name))?,
    };

    // Unlock vault
    let passphrase = prompt_password("Vault passphrase: ")?;
    let mut unlocked = unlock_vault(&passphrase, &vault_path)?;

    // Set secret
    set_secret(&mut unlocked, &name, &secret_value)?;

    println!("Secret '{}' saved", name);

    Ok(())
}

/// Handle 'get' command
pub fn handle_get(vault_path: Option<String>, name: String) -> Result<()> {
    let vault_path = vault_path.unwrap_or_else(default_vault_path);

    // Unlock vault
    let passphrase = prompt_password("Vault passphrase: ")?;
    let unlocked = unlock_vault(&passphrase, &vault_path)?;

    // Get and print secret
    let value = get_secret(&unlocked, &name)?;
    println!("{}", value);

    Ok(())
}

/// Handle 'list' command
pub fn handle_list(vault_path: Option<String>) -> Result<()> {
    let vault_path = vault_path.unwrap_or_else(default_vault_path);

    // Unlock vault
    let passphrase = prompt_password("Vault passphrase: ")?;
    let unlocked = unlock_vault(&passphrase, &vault_path)?;

    // List secrets
    let names = list_secrets(&unlocked);

    if names.is_empty() {
        println!("No secrets in vault");
    } else {
        println!("Secrets ({}):", names.len());
        for name in names {
            let secret = &unlocked.vault.secrets[&name];
            println!("  {} (modified: {})", name, secret.modified.format("%Y-%m-%d %H:%M:%S"));
        }
    }

    Ok(())
}

/// Handle 'rm' command
pub fn handle_rm(vault_path: Option<String>, name: String) -> Result<()> {
    let vault_path = vault_path.unwrap_or_else(default_vault_path);

    // Unlock vault
    let passphrase = prompt_password("Vault passphrase: ")?;
    let mut unlocked = unlock_vault(&passphrase, &vault_path)?;

    // Remove secret
    remove_secret(&mut unlocked, &name)?;

    println!("Secret '{}' removed", name);

    Ok(())
}

/// Handle 'info' command
pub fn handle_info(vault_path: Option<String>) -> Result<()> {
    let vault_path = vault_path.unwrap_or_else(default_vault_path);

    // Unlock vault
    let passphrase = prompt_password("Vault passphrase: ")?;
    let unlocked = unlock_vault(&passphrase, &vault_path)?;

    // Display info
    println!("Vault Information");
    println!("─────────────────");
    println!("Location:      {}", vault_path);
    println!("Version:       {}", unlocked.vault.version);
    println!("Created:       {}", unlocked.vault.created.format("%Y-%m-%d %H:%M:%S"));
    println!("Secrets:       {}", unlocked.vault.secrets.len());
    println!();
    println!("Cryptography");
    println!("─────────────────");
    println!("KEM:           {}", unlocked.vault.kem.algorithm);
    println!("KDF:           {} (t={}, m={}, p={})",
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
    let current_passphrase = prompt_password("Current passphrase: ")?;
    let mut unlocked = unlock_vault(&current_passphrase, &vault_path)?;

    // Prompt for new passphrase
    let new_passphrase = prompt_password("New passphrase: ")?;
    let confirm = prompt_password("Confirm new passphrase: ")?;

    if new_passphrase != confirm {
        anyhow::bail!("Passphrases do not match");
    }

    if new_passphrase.len() < 8 {
        anyhow::bail!("Passphrase must be at least 8 characters");
    }

    if new_passphrase == current_passphrase {
        anyhow::bail!("New passphrase must be different from current passphrase");
    }

    // Perform passphrase change
    change_passphrase(&mut unlocked, &new_passphrase)?;
    println!("Passphrase changed successfully");

    Ok(())
}

/// Handle 'rotate-keys' command
pub fn handle_rotate_keys(vault_path: Option<String>) -> Result<()> {
    let vault_path = vault_path.unwrap_or_else(default_vault_path);

    // Unlock vault
    let passphrase = prompt_password("Vault passphrase: ")?;
    let mut unlocked = unlock_vault(&passphrase, &vault_path)?;

    // Perform key rotation
    rotate_keys(&mut unlocked, &passphrase)?;
    println!("Vault keys rotated successfully");

    Ok(())
}
