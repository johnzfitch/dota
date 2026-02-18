//! Helper binary that creates a test vault for the Python red team script.
//! Usage: cargo test --test create_test_vault -- --nocapture
//! Outputs: vault path, passphrase, and secret names/values to stdout.

use dota::vault::ops::{create_vault, set_secret, unlock_vault};
use std::env;

#[test]
fn create_vault_for_python_red_team() {
    let vault_path = env::var("RED_TEAM_VAULT_PATH")
        .unwrap_or_else(|_| "/tmp/red_team_test_vault.json".to_string());

    // Remove if exists
    let _ = std::fs::remove_file(&vault_path);

    let passphrase = "red-team-test-P@ss!2026";

    create_vault(passphrase, &vault_path).unwrap();

    let mut v = unlock_vault(passphrase, &vault_path).unwrap();
    set_secret(&mut v, "AWS_SECRET_KEY", "AKIAIOSFODNN7EXAMPLE-secret").unwrap();
    set_secret(&mut v, "DATABASE_URL", "postgres://admin:s3cret@db.internal:5432/prod").unwrap();
    set_secret(&mut v, "API_TOKEN", "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx").unwrap();

    println!("VAULT_PATH={vault_path}");
    println!("PASSPHRASE={passphrase}");
    println!("SECRETS=AWS_SECRET_KEY,DATABASE_URL,API_TOKEN");
}
