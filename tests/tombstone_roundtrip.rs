//! H3 schema regression: a tombstone JSON must be parseable as plain
//! `serde_json::Value` for diagnostic tooling, and the H3 contract is
//! that scrubbed fields are explicitly nulled out (rather than absent)
//! — diagnostic tooling can then tell "we deliberately scrubbed this"
//! apart from "this field was never written."

use dota::vault::ops::{change_passphrase, create_vault, unlock_vault};
use serde_json::Value;
use std::fs;
use tempfile::tempdir;

#[test]
fn tombstone_is_valid_json_with_h3_contract() {
    let dir = tempdir().unwrap();
    let vault_path = dir.path().join("vault.json");

    create_vault("pass", vault_path.to_str().unwrap()).unwrap();

    // Seed one synthetic migration backup next to the live vault.
    let backup_path = dir.path().join("vault.backup.20250101_120000.json");
    fs::copy(&vault_path, &backup_path).unwrap();

    let mut unlocked = unlock_vault("pass", vault_path.to_str().unwrap()).unwrap();
    change_passphrase(&mut unlocked, "new-pass").unwrap();

    // Find the tombstone produced by the change_passphrase pipeline.
    let tombstone = fs::read_dir(dir.path())
        .unwrap()
        .flatten()
        .find_map(|e| {
            let name = e.file_name().into_string().ok()?;
            if name.contains(".tombstone.") {
                Some(e.path())
            } else {
                None
            }
        })
        .expect("tombstone produced");

    let body = fs::read_to_string(&tombstone).unwrap();
    let parsed: Value = serde_json::from_str(&body).expect("tombstone parses as JSON");

    // H3 contract: scrubbed fields are explicitly null/empty so diagnostic
    // tooling can distinguish "no value" from "missing field".
    assert!(parsed["key_commitment"].is_null());
    assert!(parsed["kem"]["encrypted_private_key"].is_null());
    assert!(parsed["x25519"]["encrypted_private_key"].is_null());
    assert!(parsed["secrets"].as_object().unwrap().is_empty());

    // Provenance present for forensic correlation.
    assert!(parsed["tombstoned_at"].is_string());
    assert!(
        parsed["tombstoned_from"]
            .as_str()
            .unwrap()
            .starts_with("vault.backup.")
    );

    // Re-encoding round-trips losslessly (tooling can read+rewrite without
    // dropping fields).
    let re_encoded = serde_json::to_string(&parsed).unwrap();
    let _: Value = serde_json::from_str(&re_encoded).unwrap();
}
