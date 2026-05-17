//! Symlink-rejection invariant: every operation that touches the live
//! vault file or its directory must reject paths whose final component
//! is a symlink (existing audit covered `create_vault`; this test
//! confirms `unlock_vault`, `change_passphrase`, and `rotate_keys`
//! inherit the same rejection through `save_vault_file`).

#![cfg(unix)]

use std::os::unix::fs::symlink;

use dota::vault::ops::{change_passphrase, create_vault, rotate_keys, set_secret, unlock_vault};
use tempfile::tempdir;

#[test]
fn unlock_through_symlink_is_rejected() {
    let dir = tempdir().unwrap();
    let real = dir.path().join("real_vault.json");
    let link = dir.path().join("link_vault.json");

    create_vault("pass", real.to_str().unwrap()).unwrap();
    symlink(&real, &link).unwrap();

    let err = unlock_vault("pass", link.to_str().unwrap())
        .expect_err("symlinked vault path must be rejected");
    let msg = format!("{:#}", err);
    assert!(
        msg.to_lowercase().contains("symlink") || msg.to_lowercase().contains("link"),
        "expected symlink rejection, got: {}",
        msg
    );
}

#[test]
fn change_passphrase_does_not_save_through_a_symlinked_replacement() {
    // Scenario: vault opens normally, but between unlock and save, an
    // attacker replaces the vault file with a symlink. The save path
    // must refuse to follow the symlink. We simulate by replacing the
    // live file with a symlink in-process.
    let dir = tempdir().unwrap();
    let real = dir.path().join("vault.json");
    let attacker_target = dir.path().join("attacker_target.json");
    std::fs::write(&attacker_target, b"{}").unwrap();

    create_vault("pass", real.to_str().unwrap()).unwrap();
    let mut unlocked = unlock_vault("pass", real.to_str().unwrap()).unwrap();
    set_secret(&mut unlocked, "TOK", "value").unwrap();

    // Replace the live file with a symlink while we hold an unlocked handle.
    std::fs::remove_file(&real).unwrap();
    symlink(&attacker_target, &real).unwrap();

    let err = change_passphrase(&mut unlocked, "new-pass")
        .expect_err("change_passphrase must refuse to save through a symlink");
    let msg = format!("{:#}", err);
    assert!(
        msg.to_lowercase().contains("symlink") || msg.to_lowercase().contains("link"),
        "expected symlink rejection, got: {}",
        msg
    );

    // attacker_target must not have been overwritten with vault content.
    let attacker_body = std::fs::read_to_string(&attacker_target).unwrap();
    assert_eq!(attacker_body, "{}");
}

#[test]
fn rotate_keys_does_not_save_through_a_symlinked_replacement() {
    let dir = tempdir().unwrap();
    let real = dir.path().join("vault.json");
    let attacker_target = dir.path().join("attacker_target.json");
    std::fs::write(&attacker_target, b"{}").unwrap();

    create_vault("pass", real.to_str().unwrap()).unwrap();
    let mut unlocked = unlock_vault("pass", real.to_str().unwrap()).unwrap();
    set_secret(&mut unlocked, "TOK", "value").unwrap();

    std::fs::remove_file(&real).unwrap();
    symlink(&attacker_target, &real).unwrap();

    let err = rotate_keys(&mut unlocked, "pass")
        .expect_err("rotate_keys must refuse to save through a symlink");
    let msg = format!("{:#}", err);
    assert!(
        msg.to_lowercase().contains("symlink") || msg.to_lowercase().contains("link"),
        "expected symlink rejection, got: {}",
        msg
    );

    let attacker_body = std::fs::read_to_string(&attacker_target).unwrap();
    assert_eq!(attacker_body, "{}");
}
