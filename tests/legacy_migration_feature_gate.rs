//! H4 regression: when the `legacy-migration` feature is OFF, attempting
//! to unlock a pre-v6 vault must bail with a clear message instead of
//! a confusing crypto-layer error.
//!
//! The test is only compiled in the `--no-default-features` configuration.
//! When `legacy-migration` is enabled, the symmetric coverage lives in
//! `src/vault/migration.rs#[cfg(test)] mod tests`.

#![cfg(not(feature = "legacy-migration"))]

use dota::vault::ops::unlock_vault;
use std::fs;
use tempfile::tempdir;

#[test]
fn pre_v6_vault_bails_with_actionable_message_when_legacy_off() {
    let dir = tempdir().unwrap();
    let vault_path = dir.path().join("vault.json");

    // The migration probe only reads `version` before dispatching, so any
    // JSON object with "version": 3 is enough to take the legacy code path.
    // We never reach the crypto layer in this configuration.
    let v3_shaped_json = r#"{
        "version": 3,
        "created": "2024-01-01T00:00:00Z",
        "kdf": {
            "algorithm": "argon2id",
            "salt": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "time_cost": 1,
            "memory_cost": 8192,
            "parallelism": 1
        },
        "kem": {
            "algorithm": "ML-KEM-768",
            "public_key": "AA==",
            "encrypted_private_key": "AA==",
            "private_key_nonce": "AAAAAAAAAAAAAAAA"
        },
        "x25519": {
            "public_key": "AA==",
            "encrypted_private_key": "AA==",
            "private_key_nonce": "AAAAAAAAAAAAAAAA"
        },
        "secrets": {}
    }"#;
    fs::write(&vault_path, v3_shaped_json).unwrap();

    let err = unlock_vault("anything", vault_path.to_str().unwrap())
        .expect_err("v3 vault must fail to unlock without legacy-migration");
    let msg = format!("{:#}", err);
    assert!(
        msg.contains("legacy-migration"),
        "error message must mention the feature flag, got: {}",
        msg
    );
    assert!(
        msg.contains("Vault v3") || msg.contains("v3"),
        "error message must name the source version, got: {}",
        msg
    );
}
