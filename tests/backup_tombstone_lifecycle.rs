//! H3 regression: re-keying operations scrub migration backups into hollowed
//! tombstones so stale wrapped key material does not linger next to the vault.
//!
//! Exercises the library surface (`dota::vault::ops`) directly via the new
//! `src/lib.rs`.

use std::fs;

use dota::vault::ops::{change_passphrase, create_vault, rotate_keys, unlock_vault};

/// Drop a `vault.backup.<ts>.json` next to the live vault, mimicking what the
/// migration engine leaves behind, and return its path.
fn plant_backup(dir: &std::path::Path, contents: &str, ts: &str) -> std::path::PathBuf {
    let p = dir.join(format!("vault.backup.{ts}.json"));
    fs::write(&p, contents).unwrap();
    p
}

fn list(dir: &std::path::Path, needle: &str) -> Vec<String> {
    let mut v: Vec<String> = fs::read_dir(dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().to_string())
        .filter(|n| n.contains(needle))
        .collect();
    v.sort();
    v
}

#[test]
fn change_passphrase_tombstones_backups() {
    let dir = tempfile::tempdir().unwrap();
    let vault_path = dir.path().join("vault.json");
    let vp = vault_path.to_str().unwrap();

    create_vault("old-passphrase", vp).unwrap();
    let live = fs::read_to_string(&vault_path).unwrap();

    // Two stale backups carrying live key material.
    plant_backup(dir.path(), &live, "20260101_000000");
    plant_backup(dir.path(), &live, "20260102_000000");
    assert_eq!(list(dir.path(), ".backup.").len(), 2);

    let mut unlocked = unlock_vault("old-passphrase", vp).unwrap();
    change_passphrase(&mut unlocked, "new-passphrase").unwrap();

    // Backups are gone; tombstones took their place.
    assert!(
        list(dir.path(), ".backup.").is_empty(),
        "backups must be removed after change-passphrase"
    );
    let tombstones = list(dir.path(), ".tombstone.");
    assert_eq!(tombstones.len(), 2, "each backup becomes one tombstone");

    // Tombstones retain metadata but null out every secret-bearing field.
    for name in tombstones {
        let body = fs::read_to_string(dir.path().join(&name)).unwrap();
        let doc: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(doc["tombstone"], serde_json::Value::Bool(true));
        assert!(doc["kdf"].is_object(), "non-secret metadata is retained");
        assert!(
            doc["kem"]["public_key"].is_string(),
            "public keys are retained for correlation"
        );
        assert!(
            doc["kem"]["encrypted_private_key"].is_null(),
            "wrapped ML-KEM private key must be nulled"
        );
        assert!(
            doc["x25519"]["encrypted_private_key"].is_null(),
            "wrapped X25519 private key must be nulled"
        );
        assert!(
            doc["key_commitment"].is_null(),
            "key commitment must be nulled"
        );
        assert_eq!(
            doc["secrets"],
            serde_json::json!({}),
            "secrets map must be emptied"
        );
    }

    // The live vault still opens under the new passphrase.
    unlock_vault("new-passphrase", vp).unwrap();
}

#[test]
fn rotate_keys_tombstones_backups() {
    let dir = tempfile::tempdir().unwrap();
    let vault_path = dir.path().join("vault.json");
    let vp = vault_path.to_str().unwrap();

    create_vault("passphrase-1", vp).unwrap();
    let live = fs::read_to_string(&vault_path).unwrap();
    plant_backup(dir.path(), &live, "20260103_000000");

    let mut unlocked = unlock_vault("passphrase-1", vp).unwrap();
    rotate_keys(&mut unlocked, "passphrase-1").unwrap();

    assert!(list(dir.path(), ".backup.").is_empty());
    assert_eq!(list(dir.path(), ".tombstone.").len(), 1);
}

#[test]
fn tombstone_is_not_unlockable_as_a_vault() {
    // A hollowed tombstone must never masquerade as a working vault: its
    // private-key material and commitment are gone, so unlock must fail rather
    // than silently producing an empty vault.
    let dir = tempfile::tempdir().unwrap();
    let vault_path = dir.path().join("vault.json");
    let vp = vault_path.to_str().unwrap();

    create_vault("pw", vp).unwrap();
    let live = fs::read_to_string(&vault_path).unwrap();
    plant_backup(dir.path(), &live, "20260104_000000");

    let mut unlocked = unlock_vault("pw", vp).unwrap();
    change_passphrase(&mut unlocked, "pw-rotated").unwrap();

    let tombstones = list(dir.path(), ".tombstone.");
    assert_eq!(tombstones.len(), 1);
    let tombstone_path = dir.path().join(&tombstones[0]);

    // It is still parseable as JSON and retains forensic metadata (version,
    // KDF params) — but the nulled byte fields mean it no longer deserializes as
    // a full `Vault`, and unlocking it fails rather than yielding a usable vault.
    let body = fs::read_to_string(&tombstone_path).unwrap();
    let doc: serde_json::Value =
        serde_json::from_str(&body).expect("tombstone remains valid JSON for forensics");
    assert_eq!(doc["tombstone"], serde_json::Value::Bool(true));
    assert!(doc["version"].is_number(), "version metadata is retained");
    assert!(
        unlock_vault("pw-rotated", tombstone_path.to_str().unwrap()).is_err(),
        "a hollowed tombstone must not unlock"
    );
}
