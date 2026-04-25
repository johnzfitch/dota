//! Minimal interactive vault shell used as the default unlock mode.
//! The ratatui module remains in-tree, but the shipped unlock path currently
//! enters this text-mode shell.

pub mod app;

use crate::cli::commands::validate_secret_name;
use crate::security::{SecretString, shutdown_requested};
use crate::vault::ops::{get_secret, list_secrets, remove_secret, set_secret, unlock_vault};
use anyhow::Result;
use rpassword::prompt_password;
use std::collections::VecDeque;
use std::io::{self, Write};
use zeroize::Zeroize;

/// Launch the TUI application
pub fn launch_tui(vault_path: String) -> Result<()> {
    // Wrap passphrase in SecretString — persists for session lifetime but
    // will be zeroized when this function returns (including on signal exit).
    let passphrase = SecretString::new(prompt_password("Vault passphrase: ")?);
    let mut unlocked = unlock_vault(passphrase.expose(), &vault_path)?;

    println!("dota interactive mode");
    println!("Type 'help' for available commands.");

    let stdin = io::stdin();
    let mut buffer = String::new();
    loop {
        // Check for graceful shutdown (SIGTERM/SIGINT/SIGHUP)
        if shutdown_requested() {
            break;
        }

        print!("dota> ");
        io::stdout().flush()?;

        // Zeroize the buffer properly: clear() only resets length, not memory.
        // We zeroize the underlying bytes first, then clear.
        buffer.zeroize();
        if stdin.read_line(&mut buffer).is_err() {
            break; // EOF or read error (e.g. EINTR from signal)
        }
        let line = buffer.trim();

        if line.is_empty() {
            continue;
        }

        let mut parts: VecDeque<&str> = line.split_whitespace().collect();
        let command = parts.pop_front().unwrap_or("");

        match command {
            "help" => {
                println!("Commands:");
                println!("  help                          Show this help");
                println!("  list                          List secret names");
                println!("  get <name>                    Show secret value");
                println!(
                    "  set <name>                    Set/update secret (value prompted, never echoed)"
                );
                println!("  rm <name>                     Remove secret");
                println!("  info                          Vault metadata");
                println!("  refresh                       Reload vault from disk");
                println!("  export                        Export all secrets (shell format)");
                println!("  quit / exit                   Exit");
            }
            "list" => {
                for name in list_secrets(&unlocked) {
                    let secret = &unlocked.vault.secrets[&name];
                    println!(
                        "{} (modified: {})",
                        name,
                        secret.modified.format("%Y-%m-%d %H:%M:%S")
                    );
                }
            }
            "get" => match parts.pop_front() {
                Some(name) => match validate_secret_name(name) {
                    Ok(()) => match get_secret(&unlocked, name) {
                        Ok(value) => println!("{}", value.expose()),
                        Err(e) => println!("error: {}", e),
                    },
                    Err(e) => println!("error: {}", e),
                },
                None => println!("error: usage: get <name>"),
            },
            "set" => match parts.pop_front() {
                Some(name) => {
                    if let Err(e) = validate_secret_name(name) {
                        println!("error: {}", e);
                    } else if !parts.is_empty() {
                        // Refuse to accept the value from the inline command
                        // line. Anything typed here would land in the shell
                        // history of any line-buffered terminal we're attached
                        // to and would also live in the in-memory `buffer`
                        // until the next read overwrites it. Forcing the
                        // password prompt keeps the value out of both.
                        println!(
                            "error: 'set' does not accept the value inline; \
                             call 'set <name>' and enter the value at the \
                             non-echoing prompt"
                        );
                    } else {
                        let value = SecretString::new(prompt_password(format!(
                            "Enter value for '{}': ",
                            name
                        ))?);
                        match set_secret(&mut unlocked, name, value.expose()) {
                            Ok(_) => println!("Secret '{}' saved", name),
                            Err(e) => println!("error: {}", e),
                        }
                    }
                }
                None => println!("error: usage: set <name>"),
            },
            "rm" => match parts.pop_front() {
                Some(name) => match validate_secret_name(name) {
                    Ok(()) => match remove_secret(&mut unlocked, name) {
                        Ok(_) => println!("Secret '{}' removed", name),
                        Err(e) => println!("error: {}", e),
                    },
                    Err(e) => println!("error: {}", e),
                },
                None => println!("error: usage: rm <name>"),
            },
            "info" => {
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
                    unlocked.vault.kdf.parallelism
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
            }
            "export" => {
                for name in list_secrets(&unlocked) {
                    if let Ok(value) = get_secret(&unlocked, &name) {
                        let mut escaped = shell_escape(value.expose());
                        println!("export {}={}", name, escaped);
                        escaped.zeroize();
                    }
                }
            }
            "refresh" => match unlock_vault(passphrase.expose(), &vault_path) {
                Ok(fresh) => {
                    unlocked = fresh;
                    println!("Refreshed vault from disk");
                }
                Err(e) => println!("error: {}", e),
            },
            "quit" | "exit" => {
                break;
            }
            _ => {
                println!("unknown command: {}", command);
            }
        }
    }
    // Zeroize the input buffer on exit
    buffer.zeroize();

    // All SecretStrings (passphrase, values) are zeroized here via drop.
    Ok(())
}

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

fn shell_escape(s: &str) -> String {
    format!("'{}'", s.replace('\'', r"'\''"))
}
