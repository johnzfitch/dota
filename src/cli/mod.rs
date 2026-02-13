//! CLI interface and command handling

pub mod commands;
pub mod export;

use clap::{Parser, Subcommand};

/// Defense of the Artifacts - Post-quantum secure secrets manager
#[derive(Parser, Debug)]
#[command(name = "dota")]
#[command(version, about, long_about = None)]
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

    /// Set a secret (add or update)
    Set {
        /// Secret name
        name: String,
        /// Secret value (if omitted, will prompt)
        value: Option<String>,
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
}
