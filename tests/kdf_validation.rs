//! L7 regression: `validate_kdf_params` rejection branches for `algorithm`
//! and `parallelism` were not covered by the v1.0.x test suite (PR #15
//! Copilot review). The legacy migration path is the easiest way to drive
//! these arms -- `upvault()` runs `validate_kdf_params` on the inbound
//! KDF block before any crypto.

#![cfg(feature = "legacy-migration")]

use dota::vault::ops::unlock_vault;
use std::fs;
use tempfile::tempdir;

/// Hand-built v3 JSON shape with a knob for tweaking individual KDF
/// fields. The crypto layer is not exercised -- the test asserts only
/// the validate_kdf_params bail message.
fn write_v3_with_kdf(dir_path: &std::path::Path, algorithm: &str, parallelism: u32) -> String {
    let json = format!(
        r#"{{
            "version": 3,
            "created": "2024-01-01T00:00:00Z",
            "kdf": {{
                "algorithm": "{}",
                "salt": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                "time_cost": 1,
                "memory_cost": 8192,
                "parallelism": {}
            }},
            "kem": {{
                "algorithm": "ML-KEM-768",
                "public_key": "AA==",
                "encrypted_private_key": "AA==",
                "private_key_nonce": "AAAAAAAAAAAAAAAA"
            }},
            "x25519": {{
                "public_key": "AA==",
                "encrypted_private_key": "AA==",
                "private_key_nonce": "AAAAAAAAAAAAAAAA"
            }},
            "secrets": {{}}
        }}"#,
        algorithm, parallelism
    );

    let vault_path = dir_path.join("vault.json");
    fs::write(&vault_path, &json).unwrap();
    vault_path.to_str().unwrap().to_string()
}

#[test]
fn rejects_argon2d_algorithm_on_legacy_path() {
    let dir = tempdir().unwrap();
    let vault_path = write_v3_with_kdf(dir.path(), "argon2d", 1);

    let err = unlock_vault("pass", &vault_path).expect_err("argon2d must be rejected");
    let msg = format!("{:#}", err);
    assert!(
        msg.contains("Unsupported KDF algorithm") || msg.contains("argon2d"),
        "expected algorithm rejection, got: {}",
        msg
    );
}

#[test]
fn rejects_excessive_parallelism_on_legacy_path() {
    let dir = tempdir().unwrap();
    let vault_path = write_v3_with_kdf(dir.path(), "argon2id", 100);

    let err = unlock_vault("pass", &vault_path).expect_err("parallelism=100 must be rejected");
    let msg = format!("{:#}", err);
    assert!(
        msg.contains("parallelism"),
        "expected parallelism rejection, got: {}",
        msg
    );
}

#[test]
fn accepts_argon2id_within_bounds() {
    // Confirm the rejection tests above are tight -- a vault with valid
    // KDF params should advance past validate_kdf_params and only fail
    // later (on crypto / passphrase decryption). We don't have a real
    // v3 fixture handy, so we just assert the failure is NOT a KDF
    // validation error.
    let dir = tempdir().unwrap();
    let vault_path = write_v3_with_kdf(dir.path(), "argon2id", 4);

    let err = unlock_vault("pass", &vault_path).expect_err("placeholder vault must still fail");
    let msg = format!("{:#}", err);
    assert!(
        !msg.contains("Unsupported KDF algorithm"),
        "valid algorithm should not trip the validate gate, got: {}",
        msg
    );
    assert!(
        !msg.contains("Invalid Argon2 parallelism"),
        "valid parallelism should not trip the validate gate, got: {}",
        msg
    );
}
