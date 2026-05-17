//! Defense of the Artifacts (dota)
//!
//! Post-quantum secure secrets manager that writes `v7` TC-HKEM vaults under
//! real FIPS 203 ML-KEM-768 + X25519 encryption with ciphertext binding and
//! passphrase commitment, and migrates legacy vaults forward on unlock.

use anyhow::Result;
use clap::Parser;
use dota::cli::{self, Cli, Commands};
use dota::{security, tui, vault};

fn main() -> Result<()> {
    // OS-level hardening: disable core dumps, ptrace, lock memory
    security::harden_process();
    // Signal handlers: graceful shutdown to ensure ZeroizeOnDrop fires
    security::install_signal_handlers();

    // M7: harden_process is Linux-only. On other platforms we run with OS
    // defaults — make that visible to the operator so the README's
    // hardening claims do not mislead.
    #[cfg(not(target_os = "linux"))]
    eprintln!(
        "Note: OS-level hardening (mlockall, PR_SET_DUMPABLE=0, RLIMIT_CORE=0) is \
         available only on Linux; relying on default protections on {}.",
        std::env::consts::OS
    );

    let args = Cli::parse();

    match args.command {
        Some(Commands::Init) => {
            cli::commands::handle_init(args.vault)?;
        }
        Some(Commands::Unlock) => {
            let vault_path = args.vault.unwrap_or_else(vault::ops::default_vault_path);
            tui::launch_tui(vault_path)?;
        }
        Some(Commands::Set { name }) => {
            cli::commands::handle_set(args.vault, name)?;
        }
        Some(Commands::Get { name, copy }) => {
            cli::commands::handle_get(args.vault, name, copy)?;
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
        Some(Commands::Upgrade) => {
            cli::commands::handle_upgrade(args.vault)?;
        }
        None => {
            // Default: launch TUI
            let vault_path = args.vault.unwrap_or_else(vault::ops::default_vault_path);
            tui::launch_tui(vault_path)?;
        }
    }

    Ok(())
}
