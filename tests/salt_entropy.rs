//! M6 regression: newly generated vaults use a 32-byte salt drawn from the OS
//! CSPRNG, and re-keying operations regenerate at the same strength.

use std::fs;

use dota::vault::format::Vault;
use dota::vault::ops::{change_passphrase, create_vault, rotate_keys, unlock_vault};

fn read_salt_len(path: &str) -> usize {
    let body = fs::read_to_string(path).unwrap();
    let vault: Vault = serde_json::from_str(&body).unwrap();
    vault.kdf.salt.len()
}

#[test]
fn new_vault_uses_32_byte_salt() {
    let dir = tempfile::tempdir().unwrap();
    let vp = dir.path().join("vault.json");
    let vps = vp.to_str().unwrap();

    create_vault("passphrase", vps).unwrap();
    assert_eq!(read_salt_len(vps), 32, "init must use a 32-byte salt");
}

#[test]
fn change_passphrase_regenerates_32_byte_salt() {
    let dir = tempfile::tempdir().unwrap();
    let vp = dir.path().join("vault.json");
    let vps = vp.to_str().unwrap();

    create_vault("old", vps).unwrap();
    let before = {
        let body = fs::read_to_string(vps).unwrap();
        serde_json::from_str::<Vault>(&body).unwrap().kdf.salt
    };

    let mut unlocked = unlock_vault("old", vps).unwrap();
    change_passphrase(&mut unlocked, "newpass1").unwrap();

    let after = {
        let body = fs::read_to_string(vps).unwrap();
        serde_json::from_str::<Vault>(&body).unwrap().kdf.salt
    };
    assert_eq!(after.len(), 32);
    assert_ne!(
        before, after,
        "salt must be freshly drawn on passphrase change"
    );
}

#[test]
fn rotate_keys_regenerates_32_byte_salt() {
    let dir = tempfile::tempdir().unwrap();
    let vp = dir.path().join("vault.json");
    let vps = vp.to_str().unwrap();

    create_vault("pw", vps).unwrap();
    let mut unlocked = unlock_vault("pw", vps).unwrap();
    rotate_keys(&mut unlocked, "pw").unwrap();

    assert_eq!(read_salt_len(vps), 32);
}
