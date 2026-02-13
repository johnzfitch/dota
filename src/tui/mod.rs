//! Minimal interactive vault shell used as the default unlock mode.
//! The Phase 6 ratatui implementation will replace this text mode flow.

pub mod app;

use anyhow::Result;
use crate::vault::ops::{
    get_secret, list_secrets, remove_secret, set_secret, unlock_vault,
};
use rpassword::prompt_password;
use std::collections::VecDeque;
use std::io::{self, Write};

/// Launch the TUI application
pub fn launch_tui(vault_path: String) -> Result<()> {
    let passphrase = prompt_password("Vault passphrase: ")?;
    let mut unlocked = unlock_vault(&passphrase, &vault_path)?;

    println!("dota interactive mode");
    println!("Type 'help' for available commands.");

    let stdin = io::stdin();
    let mut buffer = String::new();
    loop {
        print!("dota> ");
        io::stdout().flush()?;
        buffer.clear();
        stdin.read_line(&mut buffer)?;
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
                println!("  set <name> <value...>         Set/update secret");
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
            "get" => {
                let name = parts.pop_front();
                if let Some(name) = name {
                    match get_secret(&unlocked, name) {
                        Ok(value) => println!("{}", value),
                        Err(e) => println!("error: {}", e),
                    }
                } else {
                    println!("error: usage: get <name>");
                }
            }
            "set" => {
                let name = parts.pop_front();
                if let Some(name) = name {
                    let value = if let Some(v) = parts.pop_front() {
                        let mut merged = v.to_string();
                        while let Some(part) = parts.pop_front() {
                            merged.push(' ');
                            merged.push_str(part);
                        }
                        merged
                    } else {
                        prompt_password(&format!("Enter value for '{}': ", name))?
                    };

                    match set_secret(&mut unlocked, name, &value) {
                        Ok(_) => println!("Secret '{}' saved", name),
                        Err(e) => println!("error: {}", e),
                    }
                } else {
                    println!("error: usage: set <name> [value]");
                }
            }
            "rm" => {
                let name = parts.pop_front();
                if let Some(name) = name {
                    match remove_secret(&mut unlocked, name) {
                        Ok(_) => println!("Secret '{}' removed", name),
                        Err(e) => println!("error: {}", e),
                    }
                } else {
                    println!("error: usage: rm <name>");
                }
            }
            "info" => {
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
                println!("KDF:           {} (t={}, m={}, p={})", unlocked.vault.kdf.algorithm, unlocked.vault.kdf.time_cost, unlocked.vault.kdf.memory_cost, unlocked.vault.kdf.parallelism);
                println!("Encryption:    AES-256-GCM");
                println!("Key Derivation: HKDF-SHA256");
            }
            "export" => {
                for name in list_secrets(&unlocked) {
                    if let Ok(value) = get_secret(&unlocked, &name) {
                        println!("export {}={}", name, shell_escape(&value));
                    }
                }
            }
            "refresh" => {
                match unlock_vault(&passphrase, &vault_path) {
                    Ok(fresh) => {
                        unlocked = fresh;
                        println!("Refreshed vault from disk");
                    }
                    Err(e) => println!("error: {}", e),
                }
            }
            "quit" | "exit" => {
                break;
            }
            _ => {
                println!("unknown command: {}", command);
            }
        }
    }

    Ok(())
}

fn shell_escape(s: &str) -> String {
    format!("'{}'", s.replace('\'', r"'\''"))
}
