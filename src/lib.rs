//! Defense of the Artifacts (dota) — library crate.
//!
//! Post-quantum secure secrets manager that writes `v7` TC-HKEM vaults under
//! real FIPS 203 ML-KEM-768 + X25519 encryption with ciphertext binding and
//! passphrase commitment, and migrates legacy vaults forward on unlock.
//!
//! The binary entry point in `main.rs` is a thin wrapper over these modules.
//! Exposing them as a library lets the integration tests under `tests/`
//! exercise vault operations (`dota::vault::ops`) directly rather than only
//! through the CLI surface.

pub mod cli;
pub mod crypto;
pub mod security;
pub mod tui;
pub mod vault;
