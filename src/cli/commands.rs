//! CLI command handlers

use crate::security::SecretString;
use crate::vault::ops::{
    change_passphrase, create_vault, default_vault_path, get_secret, list_secrets, remove_secret,
    rotate_keys, set_secret, unlock_vault,
};
use anyhow::Result;
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

/// Read passphrase from DOTA_PASSPHRASE env var, falling back to interactive prompt.
/// Returns a SecretString for automatic zeroization on drop.
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

    // Prompt for passphrase (wrapped in SecretString for zeroization)
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
pub fn handle_set(vault_path: Option<String>, name: String) -> Result<()> {
    let vault_path = vault_path.unwrap_or_else(default_vault_path);

    validate_secret_name(&name)?;

    // The value is read from stdin if piped, otherwise from an interactive
    // prompt. We never accept the value on argv: argv is observable to other
    // processes via /proc/<pid>/cmdline, ps(1), audit logs, and is recorded
    // in shell history.
    let secret_value = read_secret_value(&name)?;

    // Unlock vault (accepts DOTA_PASSPHRASE env var for programmatic use)
    let passphrase = read_passphrase("Vault passphrase: ")?;
    let mut unlocked = unlock_vault(passphrase.expose(), &vault_path)?;

    // Set secret
    set_secret(&mut unlocked, &name, secret_value.expose())?;

    println!("Secret '{}' saved", name);

    Ok(())
}

/// Read a secret value from stdin (when piped) or an interactive password
/// prompt (when stdin is a TTY). Stdin reads are capped to defend against
/// a malicious pipe trying to exhaust process memory.
fn read_secret_value(name: &str) -> Result<SecretString> {
    use std::io::{IsTerminal, Read};

    /// Maximum accepted size for a single secret read from stdin.
    /// Comfortably fits real-world tokens, certificates, and SSH keys
    /// while bounding peak memory.
    const MAX_STDIN_SECRET_BYTES: u64 = 1024 * 1024;

    if std::io::stdin().is_terminal() {
        return Ok(SecretString::new(prompt_password(format!(
            "Enter value for '{}': ",
            name
        ))?));
    }

    let mut buf = String::new();
    let n = std::io::stdin()
        .take(MAX_STDIN_SECRET_BYTES + 1)
        .read_to_string(&mut buf)?;
    if n as u64 > MAX_STDIN_SECRET_BYTES {
        buf.zeroize();
        anyhow::bail!(
            "secret value exceeds {} bytes; refusing to read further",
            MAX_STDIN_SECRET_BYTES
        );
    }
    let trimmed = buf.trim_end_matches(['\r', '\n']).to_string();
    buf.zeroize();
    if trimmed.is_empty() {
        anyhow::bail!(
            "empty value from stdin; provide the value via the interactive prompt or pipe non-empty input"
        );
    }
    Ok(SecretString::new(trimmed))
}

/// Validate a secret name supplied on the user-input boundary.
///
/// Rejects names that could be used to spoof other entries in `list`/TUI
/// output, that would break shell-export safety, or that would let
/// printable-looking strings carry hidden control / bidi-override characters
/// (a class of "unicode confusable" attack against the operator).
pub(crate) fn validate_secret_name(name: &str) -> Result<()> {
    const MAX_SECRET_NAME_BYTES: usize = 256;

    if name.is_empty() {
        anyhow::bail!("secret name must not be empty");
    }
    if name.len() > MAX_SECRET_NAME_BYTES {
        anyhow::bail!(
            "secret name exceeds {} bytes",
            MAX_SECRET_NAME_BYTES
        );
    }
    if name.trim() != name {
        anyhow::bail!("secret name must not have leading or trailing whitespace");
    }
    for ch in name.chars() {
        // ASCII control chars (incl. NUL, LF, CR, ESC, DEL) are never legitimate
        // in a secret identifier and let attacker-controlled names corrupt
        // terminal output or `list` rendering.
        if ch.is_control() {
            anyhow::bail!(
                "secret name contains a control character (U+{:04X})",
                ch as u32
            );
        }
        // Bidi controls and zero-width / formatting characters allow visually
        // identical names to differ in bytes, enabling spoofing of an existing
        // entry in TUI/list output.
        match ch as u32 {
            0x200B..=0x200F   // zero-width + LRM/RLM
            | 0x202A..=0x202E // LRE/RLE/PDF/LRO/RLO
            | 0x2066..=0x2069 // LRI/RLI/FSI/PDI
            | 0xFEFF          // BOM / ZWNBSP
            | 0x2028 | 0x2029 // LINE / PARAGRAPH SEPARATOR
            => anyhow::bail!(
                "secret name contains a disallowed format character (U+{:04X})",
                ch as u32
            ),
            _ => {}
        }
    }
    Ok(())
}

/// Handle 'get' command
pub fn handle_get(vault_path: Option<String>, name: String) -> Result<()> {
    let vault_path = vault_path.unwrap_or_else(default_vault_path);

    validate_secret_name(&name)?;

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
                .join(" → ")
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

    // Read vault to check version before prompting for passphrase. Honour
    // the same size cap the unlock path enforces — refuse to feed a
    // multi-gigabyte planted vault into serde_json before any crypto runs.
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

use anyhow::Context;

#[cfg(test)]
mod tests {
    use super::*;

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
