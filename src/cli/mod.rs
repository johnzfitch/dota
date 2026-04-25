//! CLI interface and command handling

pub mod commands;
pub mod export;

use clap::{Parser, Subcommand};

/// Defense of the Artifacts - Post-quantum secure secrets manager with `v6`
/// ML-KEM-768 + X25519 vaults
#[derive(Parser, Debug)]
#[command(name = "dota")]
#[command(
    version,
    about = "Defense of the Artifacts - Post-quantum secure secrets manager with v6 ML-KEM-768 + X25519 vaults",
    long_about = None
)]
pub struct Cli {
    /// Path to vault file
    #[arg(short, long, global = true)]
    pub vault: Option<String>,

    #[command(subcommand)]
    pub command: Option<Commands>,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Initialize a new vault
    Init,

    /// Unlock vault and enter TUI (default)
    Unlock,

    /// Set a secret (add or update). The value is read from stdin when
    /// piped, otherwise from an interactive prompt. The value is never
    /// accepted on the command line — argv is visible to other local
    /// processes via /proc and is recorded in shell history.
    Set {
        /// Secret name
        name: String,
    },

    /// Get a secret value
    Get {
        /// Secret name
        name: String,
    },

    /// List all secrets
    List,

    /// Remove a secret
    Rm {
        /// Secret name
        name: String,
    },

    /// Export secrets as environment variables
    ExportEnv {
        /// Secret names to export (if empty, exports all)
        names: Vec<String>,
    },

    /// Change vault passphrase
    ChangePassphrase,

    /// Rotate encryption keys (re-encrypt all secrets)
    RotateKeys,

    /// Show vault information
    Info,

    /// Upgrade vault to latest format version
    Upgrade,
}
