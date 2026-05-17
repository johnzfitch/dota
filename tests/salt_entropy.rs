//! M6 regression: fresh vaults must use a salt with >= 32 bytes of entropy.
//! Legacy vaults can still load with the 16-byte floor, but anything
//! `dota` writes in v1.1+ uses a strictly larger salt.

use dota::vault::ops::{create_vault, unlock_vault};
use serde_json::Value;
use tempfile::tempdir;

#[test]
fn dota_init_produces_salt_at_least_32_bytes() {
    let dir = tempdir().unwrap();
    let vault_path = dir.path().join("vault.json");

    create_vault("salt-entropy-test-pass", vault_path.to_str().unwrap()).expect("create_vault");

    let bytes = std::fs::read(&vault_path).unwrap();
    let parsed: Value = serde_json::from_slice(&bytes).unwrap();
    let salt_b64 = parsed["kdf"]["salt"]
        .as_str()
        .expect("kdf.salt is base64 string");

    // Vault stores raw bytes base64-encoded — decode and assert length.
    use base64::Engine;
    let salt = base64::engine::general_purpose::STANDARD
        .decode(salt_b64)
        .expect("salt is valid base64");
    assert!(
        salt.len() >= 32,
        "new vault must use >= 32 byte salt, got {} bytes",
        salt.len()
    );
}

#[test]
fn change_passphrase_upgrades_salt_to_32_bytes() {
    let dir = tempdir().unwrap();
    let vault_path = dir.path().join("vault.json");

    create_vault("initial", vault_path.to_str().unwrap()).unwrap();
    let mut unlocked = unlock_vault("initial", vault_path.to_str().unwrap()).unwrap();
    dota::vault::ops::change_passphrase(&mut unlocked, "rotated").unwrap();

    let bytes = std::fs::read(&vault_path).unwrap();
    let parsed: Value = serde_json::from_slice(&bytes).unwrap();
    use base64::Engine;
    let salt = base64::engine::general_purpose::STANDARD
        .decode(parsed["kdf"]["salt"].as_str().unwrap())
        .unwrap();
    assert!(salt.len() >= 32);
}
