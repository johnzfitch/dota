//! Defense of the Artifacts (dota)
//!
//! Post-quantum secure secrets manager with hybrid ML-KEM-768 + X25519 encryption

mod cli;
mod crypto;
mod tui;
mod vault;

use anyhow::Result;
use clap::Parser;
use cli::{Cli, Commands};

fn main() -> Result<()> {
    let args = Cli::parse();

    match args.command {
        Some(Commands::Init) => {
            cli::commands::handle_init(args.vault)?;
        }
        Some(Commands::Unlock) => {
            let vault_path = args.vault.unwrap_or_else(vault::ops::default_vault_path);
            tui::launch_tui(vault_path)?;
        }
        Some(Commands::Set { name, value }) => {
            cli::commands::handle_set(args.vault, name, value)?;
        }
        Some(Commands::Get { name }) => {
            cli::commands::handle_get(args.vault, name)?;
        }
        Some(Commands::List) => {
            cli::commands::handle_list(args.vault)?;
        }
        Some(Commands::Rm { name }) => {
            cli::commands::handle_rm(args.vault, name)?;
        }
        Some(Commands::ExportEnv { names }) => {
            cli::export::handle_export_env(args.vault, names)?;
        }
        Some(Commands::ChangePassphrase) => {
            cli::commands::handle_change_passphrase(args.vault)?;
        }
        Some(Commands::RotateKeys) => {
            cli::commands::handle_rotate_keys(args.vault)?;
        }
        Some(Commands::Info) => {
            cli::commands::handle_info(args.vault)?;
        }
        None => {
            // Default: launch TUI
            let vault_path = args.vault.unwrap_or_else(vault::ops::default_vault_path);
            tui::launch_tui(vault_path)?;
        }
    }

    Ok(())
}
