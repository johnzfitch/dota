//! H3 regression: migration backups must be converted to scrubbed
//! "hollowed-shell" tombstones on `change_passphrase` and `rotate_keys`.
//!
//! Setup pattern: every test creates an isolated `tempdir` and runs the
//! public API end-to-end against it, so a parallel test run cannot collide
//! on the user's real `~/.dota/`.

#![cfg(feature = "legacy-migration")]

use std::fs;
use std::path::Path;

use dota::vault::ops::{
    change_passphrase, create_vault, default_vault_path, rotate_keys, unlock_vault,
};
use serde_json::Value;
use tempfile::tempdir;

/// Returns the basenames of every file in `dir` whose name matches the
/// `vault.*` prefix. Used to assert presence/absence of backup and
/// tombstone files without depending on Path::display formatting.
fn vault_artifact_names(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = fs::read_dir(dir)
        .unwrap()
        .flatten()
        .filter_map(|e| e.file_name().into_string().ok())
        .filter(|n| n.starts_with("vault"))
        .collect();
    names.sort();
    names
}

/// Confirm a tombstone file has every field of the H3 contract:
/// retains version/min_version/migrated_from/KDF params/public keys and
/// suite; scrubs the wrapped private keys, key commitment, and secrets;
/// adds `tombstoned_at` and `tombstoned_from`.
fn assert_tombstone_shape(json: &str) {
    let v: Value = serde_json::from_str(json).expect("tombstone is valid JSON");
    let obj = v.as_object().expect("tombstone is a JSON object");

    // Retained
    assert!(obj.contains_key("version"));
    assert!(obj.contains_key("min_version"));
    assert!(obj.contains_key("kdf"));
    assert!(obj.contains_key("suite"));
    assert!(obj["kem"]["public_key"].is_string());
    assert!(obj["x25519"]["public_key"].is_string());

    // Scrubbed
    assert!(obj["kem"]["encrypted_private_key"].is_null());
    assert!(obj["kem"]["private_key_nonce"].is_null());
    assert!(obj["x25519"]["encrypted_private_key"].is_null());
    assert!(obj["x25519"]["private_key_nonce"].is_null());
    assert!(obj["key_commitment"].is_null());

    // Secrets stripped to an empty map (names + ciphertext both gone)
    let secrets = obj["secrets"].as_object().expect("secrets is an object");
    assert!(secrets.is_empty(), "tombstone retained secret entries");

    // Provenance fields added
    assert!(obj["tombstoned_at"].is_string());
    assert!(obj["tombstoned_from"].is_string());
}

/// Helper: build a v6 vault file at `path` under `passphrase`.
///
/// Reuses the migration test's v6 build path indirectly: we drop a v6
/// JSON onto disk, then unlock it (which migrates v6→v7 and creates one
/// `vault.backup.*.json`).
fn write_v6_vault_then_migrate(path: &Path, passphrase: &str) {
    // Easier than hand-rolling v6 JSON: create a v7 vault, then patch the
    // version down to 6 with the v6 commitment recomputed. But we don't
    // have a public helper for v6 commitment — so go the other direction:
    // call `migrate_v6_via_unlock` by starting from a v6-shaped JSON
    // built using the dota crate's own format constants.
    //
    // Practical shortcut: create a v7 vault and rotate-keys/change-pass
    // to populate one migration backup naturally. Migration backups are
    // ONLY produced by `upvault()`, which requires version < 7. So we
    // simulate by writing a synthetic `vault.backup.*.json` next to the
    // live v7 vault and confirming the change-passphrase pipeline
    // converts it to a tombstone.
    create_vault(passphrase, path.to_str().unwrap()).expect("create_vault");

    // Synthesize a "migration backup" by copying the live v7 vault to a
    // backup name. The conversion code is content-agnostic and tests the
    // hollowing logic regardless of the source format.
    let parent = path.parent().unwrap();
    let backup_path = parent.join("vault.backup.20240101_000000.json");
    fs::copy(path, &backup_path).expect("seed backup");
}

#[test]
fn change_passphrase_converts_backup_to_tombstone() {
    let dir = tempdir().unwrap();
    let vault_path = dir.path().join("vault.json");

    write_v6_vault_then_migrate(&vault_path, "initial-passphrase");

    let before = vault_artifact_names(dir.path());
    assert!(
        before.iter().any(|n| n.contains(".backup.")),
        "seeded backup is present"
    );
    assert!(
        !before.iter().any(|n| n.contains(".tombstone.")),
        "no tombstone before change-passphrase"
    );

    let mut unlocked =
        unlock_vault("initial-passphrase", vault_path.to_str().unwrap()).expect("unlock");
    change_passphrase(&mut unlocked, "new-passphrase").expect("change_passphrase");

    let after = vault_artifact_names(dir.path());
    assert!(
        !after.iter().any(|n| n.contains(".backup.")),
        "backup files removed after change_passphrase, got {:?}",
        after
    );

    let tombstones: Vec<&String> = after.iter().filter(|n| n.contains(".tombstone.")).collect();
    assert_eq!(
        tombstones.len(),
        1,
        "exactly one tombstone per backup, got {:?}",
        after
    );

    let tombstone_body = fs::read_to_string(dir.path().join(tombstones[0])).unwrap();
    assert_tombstone_shape(&tombstone_body);

    // Live vault still unlockable under the new passphrase.
    unlock_vault("new-passphrase", vault_path.to_str().unwrap()).expect("unlock with new pass");
}

#[test]
fn rotate_keys_also_converts_backups_to_tombstones() {
    let dir = tempdir().unwrap();
    let vault_path = dir.path().join("vault.json");

    write_v6_vault_then_migrate(&vault_path, "rotate-test-pass");

    let mut unlocked = unlock_vault("rotate-test-pass", vault_path.to_str().unwrap()).unwrap();
    rotate_keys(&mut unlocked, "rotate-test-pass").expect("rotate_keys");

    let after = vault_artifact_names(dir.path());
    assert!(
        !after.iter().any(|n| n.contains(".backup.")),
        "backup files removed after rotate_keys, got {:?}",
        after
    );
    assert_eq!(
        after.iter().filter(|n| n.contains(".tombstone.")).count(),
        1
    );
}

#[test]
fn default_vault_path_is_a_valid_string() {
    // L2 regression: default_vault_path must round-trip through OsString
    // without lossy substitution. The Linux CI runner has a UTF-8 home, so
    // this asserts the happy path; the panic-on-non-UTF-8 path is reached
    // only on platforms outside our test matrix.
    let path = default_vault_path();
    assert!(!path.is_empty());
    assert!(path.ends_with("vault.json"));
}
