//! Export secrets as shell environment variables

use crate::vault::ops::{default_vault_path, get_secret, list_secrets, unlock_vault};
use anyhow::Result;
use rpassword::prompt_password;

/// Handle 'export-env' command
pub fn handle_export_env(vault_path: Option<String>, names: Vec<String>) -> Result<()> {
    let vault_path = vault_path.unwrap_or_else(default_vault_path);

    // Unlock vault
    let passphrase = prompt_password("Vault passphrase: ")?;
    let unlocked = unlock_vault(&passphrase, &vault_path)?;

    // Determine which secrets to export
    let export_names = if names.is_empty() {
        list_secrets(&unlocked)
    } else {
        names
    };

    // Export each secret
    for name in export_names {
        if !is_shell_var_name(&name) {
            eprintln!(
                "# Warning: Skipping secret with invalid shell name '{}': must match [A-Za-z_][A-Za-z0-9_]*",
                name
            );
            continue;
        }

        match get_secret(&unlocked, &name) {
            Ok(value) => {
                // Shell-escape the value
                let escaped = shell_escape(&value);
                // Note: name is already validated by is_shell_var_name to contain only
                // [A-Za-z_][A-Za-z0-9_]*, so it's safe to use directly without quoting
                println!("export {}={}", name, escaped);
            }
            Err(e) => {
                eprintln!("# Warning: Failed to get secret '{}': {}", name, e);
            }
        }
    }

    Ok(())
}

fn is_shell_var_name(name: &str) -> bool {
    let mut chars = name.chars();
    match chars.next() {
        Some(first) if first == '_' || first.is_ascii_alphabetic() => {}
        _ => return false,
    }

    chars.all(|c| c == '_' || c.is_ascii_alphanumeric())
}

/// Escape a string for safe use in shell
fn shell_escape(s: &str) -> String {
    // Simple approach: single-quote and escape existing single quotes
    format!("'{}'", s.replace('\'', r"'\''"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shell_escape() {
        assert_eq!(shell_escape("simple"), "'simple'");
        assert_eq!(shell_escape("with spaces"), "'with spaces'");
        assert_eq!(shell_escape("with'quote"), "'with'\\''quote'");
        assert_eq!(shell_escape("special!@#$%"), "'special!@#$%'");
    }

    #[test]
    fn test_is_shell_var_name_valid() {
        // Valid names
        assert!(is_shell_var_name("FOO"));
        assert!(is_shell_var_name("_BAR"));
        assert!(is_shell_var_name("API_KEY_123"));
        assert!(is_shell_var_name("DB_PASSWORD"));
    }

    #[test]
    fn test_is_shell_var_name_rejects_injection() {
        // Reject shell metacharacters that could enable injection
        assert!(!is_shell_var_name("FOO; rm -rf /")); // Command injection
        assert!(!is_shell_var_name("FOO$(whoami)")); // Command substitution
        assert!(!is_shell_var_name("FOO`whoami`")); // Backtick command substitution
        assert!(!is_shell_var_name("FOO|bar")); // Pipe
        assert!(!is_shell_var_name("FOO&bar")); // Background
        assert!(!is_shell_var_name("FOO>file")); // Redirect
        assert!(!is_shell_var_name("FOO-BAR")); // Hyphen (invalid in shell var)
        assert!(!is_shell_var_name("123FOO")); // Cannot start with digit
        assert!(!is_shell_var_name("FOO BAR")); // No spaces
    }
}
