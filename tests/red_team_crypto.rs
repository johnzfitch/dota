//! Red Team Security Tests for dota's Cryptographic Implementation
//!
//! These tests attack the actual crypto primitives and vault operations
//! from every angle: ciphertext tampering, key confusion, nonce reuse,
//! parameter downgrade, malformed inputs, and more.

use dota::crypto::{
    self, AesKey, KdfConfig, MlKemCiphertext, MlKemPrivateKey, MlKemPublicKey, X25519PublicKey,
};
use dota::vault::ops::{
    create_vault, get_secret, list_secrets, remove_secret, set_secret, unlock_vault,
};
use std::collections::HashSet;
use tempfile::NamedTempFile;

// ================================================================
//  ATTACK 1: AES-GCM CIPHERTEXT TAMPERING
//  GCM should reject ANY modification to ciphertext, nonce, or tag.
// ================================================================

#[test]
fn attack_aes_gcm_bit_flip_ciphertext() {
    let key = AesKey::from_bytes([0xAA; 32]);
    let plaintext = b"TOP_SECRET_VALUE_12345";

    let (mut ciphertext, nonce) = crypto::aes_encrypt(&key, plaintext).unwrap();

    // Flip one bit in the ciphertext
    ciphertext[0] ^= 0x01;

    // GCM MUST reject this — no silent decryption of tampered data
    let result = crypto::aes_decrypt(&key, &ciphertext, &nonce);
    assert!(
        result.is_err(),
        "CRITICAL: AES-GCM accepted tampered ciphertext! No authentication."
    );
}

#[test]
fn attack_aes_gcm_bit_flip_every_byte() {
    let key = AesKey::from_bytes([0x42; 32]);
    let plaintext = b"sensitive data here";
    let (ciphertext, nonce) = crypto::aes_encrypt(&key, plaintext).unwrap();

    // Flip one bit in EVERY byte position of the ciphertext
    for i in 0..ciphertext.len() {
        let mut tampered = ciphertext.clone();
        tampered[i] ^= 0x01;
        let result = crypto::aes_decrypt(&key, &tampered, &nonce);
        assert!(
            result.is_err(),
            "AES-GCM accepted tampered ciphertext at byte {i}"
        );
    }
}

#[test]
fn attack_aes_gcm_wrong_nonce() {
    let key = AesKey::from_bytes([0xBB; 32]);
    let plaintext = b"secret";
    let (ciphertext, _correct_nonce) = crypto::aes_encrypt(&key, plaintext).unwrap();

    // Try decryption with a different nonce
    let wrong_nonce = [0xFF; 12];
    let result = crypto::aes_decrypt(&key, &ciphertext, &wrong_nonce);
    assert!(
        result.is_err(),
        "AES-GCM decrypted with wrong nonce — nonce isn't authenticated"
    );
}

#[test]
fn attack_aes_gcm_truncated_ciphertext() {
    let key = AesKey::from_bytes([0xCC; 32]);
    let plaintext = b"data that should be protected";
    let (ciphertext, nonce) = crypto::aes_encrypt(&key, plaintext).unwrap();

    // Try truncated ciphertext (strips part of the GCM tag)
    for truncate_to in [0, 1, 8, ciphertext.len() - 1] {
        let truncated = &ciphertext[..truncate_to];
        let result = crypto::aes_decrypt(&key, truncated, &nonce);
        assert!(
            result.is_err(),
            "AES-GCM accepted truncated ciphertext (len {truncate_to})"
        );
    }
}

#[test]
fn attack_aes_gcm_appended_data() {
    let key = AesKey::from_bytes([0xDD; 32]);
    let plaintext = b"original";
    let (mut ciphertext, nonce) = crypto::aes_encrypt(&key, plaintext).unwrap();

    // Append extra bytes after the GCM tag
    ciphertext.extend_from_slice(b"INJECTED");
    let result = crypto::aes_decrypt(&key, &ciphertext, &nonce);
    assert!(
        result.is_err(),
        "AES-GCM accepted ciphertext with appended data"
    );
}

#[test]
fn attack_aes_gcm_empty_ciphertext() {
    let key = AesKey::from_bytes([0xEE; 32]);
    let nonce = [0x11; 12];

    let result = crypto::aes_decrypt(&key, &[], &nonce);
    assert!(
        result.is_err(),
        "AES-GCM should reject empty ciphertext"
    );
}

// ================================================================
//  ATTACK 2: NONCE UNIQUENESS VERIFICATION
//  Each encryption MUST produce a unique random nonce.
// ================================================================

#[test]
fn attack_nonce_reuse_detection() {
    let key = AesKey::from_bytes([0x55; 32]);
    let plaintext = b"same plaintext encrypted many times";

    let mut nonces = HashSet::new();
    let num_encryptions = 100;

    for _ in 0..num_encryptions {
        let (_ct, nonce) = crypto::aes_encrypt(&key, plaintext).unwrap();
        let was_new = nonces.insert(nonce);
        assert!(
            was_new,
            "CRITICAL: Nonce reuse detected! GCM security is catastrophically broken with nonce reuse."
        );
    }

    assert_eq!(nonces.len(), num_encryptions);
}

#[test]
fn attack_same_plaintext_different_ciphertext() {
    let key = AesKey::from_bytes([0x66; 32]);
    let plaintext = b"identical plaintext";

    let (ct1, _) = crypto::aes_encrypt(&key, plaintext).unwrap();
    let (ct2, _) = crypto::aes_encrypt(&key, plaintext).unwrap();

    // Identical plaintexts MUST produce different ciphertexts (semantic security)
    assert_ne!(
        ct1, ct2,
        "Same plaintext produced identical ciphertext — nonce is likely static"
    );
}

// ================================================================
//  ATTACK 3: KEY DERIVATION ATTACKS (Argon2id)
// ================================================================

#[test]
fn attack_kdf_wrong_password_always_fails() {
    let config = KdfConfig {
        salt: b"test-salt-for-red-team-1234".to_vec(),
        time_cost: 1,
        memory_cost: 8192,
        parallelism: 1,
    };

    let correct_key = crypto::derive_key("correct-password", &config).unwrap();

    // Try 20 wrong passwords — all must produce different keys
    let wrong_passwords = [
        "wrong", "correct-passwor", "correct-password1", "Correct-password",
        "CORRECT-PASSWORD", "", " correct-password", "correct-password ",
        "correct password", "c0rrect-password", "correct-passw0rd",
        "\x00correct-password", "correct-password\x00", "correct-passwore",
        "correct-passworc", "borrect-password", "dorrect-password",
        "correctpassword", "correct_password", "correct.password",
    ];

    for wrong_pw in &wrong_passwords {
        let wrong_key = crypto::derive_key(wrong_pw, &config).unwrap();
        assert_ne!(
            correct_key.as_bytes(),
            wrong_key.as_bytes(),
            "KDF collision: '{wrong_pw}' produced the same key as 'correct-password'"
        );
    }
}

#[test]
fn attack_kdf_different_salts_different_keys() {
    let password = "same-password";
    let mut keys = HashSet::new();

    for i in 0..10 {
        let config = KdfConfig {
            salt: format!("unique-salt-number-{i:04}----").into_bytes(),
            time_cost: 1,
            memory_cost: 8192,
            parallelism: 1,
        };
        let key = crypto::derive_key(password, &config).unwrap();
        keys.insert(*key.as_bytes());
    }

    assert_eq!(
        keys.len(),
        10,
        "Different salts should always produce different keys"
    );
}

#[test]
fn attack_kdf_salt_uniqueness() {
    let mut salts = HashSet::new();
    for _ in 0..50 {
        let salt = crypto::generate_salt();
        let was_new = salts.insert(salt);
        assert!(was_new, "Salt collision detected! Salts must be unique.");
    }
}

// ================================================================
//  ATTACK 4: ML-KEM MALFORMED INPUT ATTACKS
// ================================================================

#[test]
fn attack_mlkem_malformed_public_key_lengths() {
    // Wrong lengths must be rejected
    for len in [0, 1, 1183, 1185, 2400, 4096] {
        let result = MlKemPublicKey::from_bytes(vec![0u8; len]);
        assert!(
            result.is_err(),
            "ML-KEM accepted public key of wrong length {len}"
        );
    }
}

#[test]
fn attack_mlkem_malformed_private_key_lengths() {
    for len in [0, 1, 2399, 2401, 1184, 4096] {
        let result = MlKemPrivateKey::from_bytes(vec![0u8; len]);
        assert!(
            result.is_err(),
            "ML-KEM accepted private key of wrong length {len}"
        );
    }
}

#[test]
fn attack_mlkem_malformed_ciphertext_lengths() {
    for len in [0, 1, 1087, 1089, 2048, 4096] {
        let result = MlKemCiphertext::from_bytes(vec![0u8; len]);
        assert!(
            result.is_err(),
            "ML-KEM accepted ciphertext of wrong length {len}"
        );
    }
}

#[test]
fn attack_mlkem_wrong_key_decapsulation() {
    // Encapsulate with one keypair, try to decapsulate with another
    let (pk1, _sk1) = crypto::mlkem_generate_keypair().unwrap();
    let (_pk2, sk2) = crypto::mlkem_generate_keypair().unwrap();

    let _encap = crypto::hybrid_encapsulate(
        &pk1,
        &X25519PublicKey::from_bytes({
            let (pk, _) = crypto::x25519_generate_keypair();
            *pk.as_bytes()
        }),
    )
    .unwrap();

    // Wrong ML-KEM key should produce a DIFFERENT shared secret (not crash)
    let (correct_pk, _correct_sk) = crypto::mlkem_generate_keypair().unwrap();
    let (ss1, ct) = crypto::mlkem::encapsulate(&correct_pk).unwrap();
    let ss2 = crypto::mlkem::decapsulate(&sk2, &ct).unwrap();

    assert_ne!(
        ss1.as_bytes(),
        ss2.as_bytes(),
        "Wrong ML-KEM key produced the same shared secret — KEM is broken"
    );
}

// ================================================================
//  ATTACK 5: X25519 SMALL SUBGROUP / SPECIAL POINT ATTACKS
// ================================================================

#[test]
fn attack_x25519_zero_public_key() {
    let (_, sk) = crypto::x25519_generate_keypair();
    let zero_pk = X25519PublicKey::from_bytes([0u8; 32]);

    let result = crypto::x25519::diffie_hellman(&sk, &zero_pk);
    assert!(
        result.is_err(),
        "X25519 accepted all-zero public key (order-1 point)"
    );
}

#[test]
fn attack_x25519_low_order_points() {
    // Known small-subgroup points on Curve25519
    // These have orders 1, 2, 4, or 8 and produce predictable DH results
    let low_order_points: [[u8; 32]; 4] = [
        // Order 1: the identity point (all zeros)
        [0; 32],
        // Order 2: (0, -1) = point of order 2
        {
            let mut p = [0u8; 32];
            p[0] = 1;
            p
        },
        // Order 4 point
        {
            let mut p = [0u8; 32];
            // e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800
            let bytes = [
                0xe0, 0xeb, 0x7a, 0x7c, 0x3b, 0x41, 0xb8, 0xae, 0x16, 0x56, 0xe3, 0xfa, 0xf1,
                0x9f, 0xc4, 0x6a, 0xda, 0x09, 0x8d, 0xeb, 0x9c, 0x32, 0xb1, 0xfd, 0x86, 0x62,
                0x05, 0x16, 0x5f, 0x49, 0xb8, 0x00,
            ];
            p.copy_from_slice(&bytes);
            p
        },
        // Order 8 point
        {
            let mut p = [0u8; 32];
            // 5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157
            let bytes = [
                0x5f, 0x9c, 0x95, 0xbc, 0xa3, 0x50, 0x8c, 0x24, 0xb1, 0xd0, 0xb1, 0x55, 0x9c,
                0x83, 0xef, 0x5b, 0x04, 0x44, 0x5c, 0xc4, 0x58, 0x1c, 0x8e, 0x86, 0xd8, 0x22,
                0x4e, 0xdd, 0xd0, 0x9f, 0x11, 0x57,
            ];
            p.copy_from_slice(&bytes);
            p
        },
    ];

    let (_, sk) = crypto::x25519_generate_keypair();

    for (i, point) in low_order_points.iter().enumerate() {
        let pk = X25519PublicKey::from_bytes(*point);
        let result = crypto::x25519::diffie_hellman(&sk, &pk);

        // Either error OR the shared secret must not be all zeros
        match result {
            Err(_) => {} // Good: rejected
            Ok(ss) => {
                assert_ne!(
                    ss.as_bytes(),
                    &[0u8; 32],
                    "X25519 DH with low-order point {i} produced all-zero shared secret"
                );
            }
        }
    }
}

// ================================================================
//  ATTACK 6: HYBRID KEM — BOTH KEYS MUST MATTER
// ================================================================

#[test]
fn attack_hybrid_wrong_mlkem_key_different_result() {
    let (mlkem_pk, _mlkem_sk1) = crypto::mlkem_generate_keypair().unwrap();
    let (_mlkem_pk2, mlkem_sk2) = crypto::mlkem_generate_keypair().unwrap();
    let (x25519_pk, x25519_sk) = crypto::x25519_generate_keypair();

    let encap = crypto::hybrid_encapsulate(&mlkem_pk, &x25519_pk).unwrap();

    let decap_key = crypto::hybrid_decapsulate(
        &mlkem_sk2, // WRONG ML-KEM key
        &x25519_sk,
        &encap.kem_ciphertext,
        &encap.x25519_ephemeral_public,
    )
    .unwrap();

    assert_ne!(
        encap.derived_key.as_bytes(),
        decap_key.as_bytes(),
        "Hybrid KEM ignores ML-KEM component — X25519 alone determines the key"
    );
}

#[test]
fn attack_hybrid_wrong_x25519_key_different_result() {
    let (mlkem_pk, mlkem_sk) = crypto::mlkem_generate_keypair().unwrap();
    let (x25519_pk, _x25519_sk1) = crypto::x25519_generate_keypair();
    let (_x25519_pk2, x25519_sk2) = crypto::x25519_generate_keypair();

    let encap = crypto::hybrid_encapsulate(&mlkem_pk, &x25519_pk).unwrap();

    let decap_key = crypto::hybrid_decapsulate(
        &mlkem_sk,
        &x25519_sk2, // WRONG X25519 key
        &encap.kem_ciphertext,
        &encap.x25519_ephemeral_public,
    )
    .unwrap();

    assert_ne!(
        encap.derived_key.as_bytes(),
        decap_key.as_bytes(),
        "Hybrid KEM ignores X25519 component — ML-KEM alone determines the key"
    );
}

#[test]
fn attack_hybrid_both_keys_wrong() {
    let (mlkem_pk, _) = crypto::mlkem_generate_keypair().unwrap();
    let (x25519_pk, _) = crypto::x25519_generate_keypair();
    let (_, mlkem_sk_wrong) = crypto::mlkem_generate_keypair().unwrap();
    let (_, x25519_sk_wrong) = crypto::x25519_generate_keypair();

    let encap = crypto::hybrid_encapsulate(&mlkem_pk, &x25519_pk).unwrap();

    let decap_key = crypto::hybrid_decapsulate(
        &mlkem_sk_wrong,
        &x25519_sk_wrong,
        &encap.kem_ciphertext,
        &encap.x25519_ephemeral_public,
    )
    .unwrap();

    assert_ne!(
        encap.derived_key.as_bytes(),
        decap_key.as_bytes(),
        "Both keys wrong but same derived key — hybrid KEM is completely broken"
    );
}

#[test]
fn attack_hybrid_each_encapsulation_unique() {
    let (mlkem_pk, _) = crypto::mlkem_generate_keypair().unwrap();
    let (x25519_pk, _) = crypto::x25519_generate_keypair();

    let mut keys = HashSet::new();
    for _ in 0..20 {
        let encap = crypto::hybrid_encapsulate(&mlkem_pk, &x25519_pk).unwrap();
        keys.insert(*encap.derived_key.as_bytes());
    }

    assert_eq!(
        keys.len(),
        20,
        "Multiple encapsulations to same public key produced duplicate derived keys"
    );
}

// ================================================================
//  ATTACK 7: VAULT-LEVEL ATTACKS
// ================================================================

#[test]
fn attack_vault_wrong_passphrase_rejected() {
    let tmp = NamedTempFile::new().unwrap();
    let path = tmp.path().to_str().unwrap();

    create_vault("correct-passphrase-!@#$", path).unwrap();

    let wrong_passphrases = [
        "",
        " ",
        "correct-passphrase-!@#",
        "correct-passphrase-!@#$%",
        "Correct-passphrase-!@#$",
        "CORRECT-PASSPHRASE-!@#$",
        "wrong",
        "correct-passphrase-!@#$\x00",
    ];

    for wrong in &wrong_passphrases {
        let result = unlock_vault(wrong, path);
        assert!(
            result.is_err(),
            "Vault unlocked with wrong passphrase: '{wrong}'"
        );
    }
}

#[test]
fn attack_vault_secret_isolation() {
    // Create two vaults with different passphrases
    let tmp1 = NamedTempFile::new().unwrap();
    let tmp2 = NamedTempFile::new().unwrap();
    let path1 = tmp1.path().to_str().unwrap();
    let path2 = tmp2.path().to_str().unwrap();

    create_vault("pass1", path1).unwrap();
    create_vault("pass2", path2).unwrap();

    let mut v1 = unlock_vault("pass1", path1).unwrap();
    set_secret(&mut v1, "SECRET", "value-in-vault-1").unwrap();

    let v2 = unlock_vault("pass2", path2).unwrap();

    // Vault 2 should NOT have vault 1's secrets
    assert!(
        get_secret(&v2, "SECRET").is_err(),
        "Secret leaked between vaults"
    );
    assert_eq!(list_secrets(&v2).len(), 0);
}

#[test]
fn attack_vault_per_secret_unique_encryption() {
    // Each secret must use unique KEM encapsulation (per-secret keys)
    let tmp = NamedTempFile::new().unwrap();
    let path = tmp.path().to_str().unwrap();

    create_vault("test-pass", path).unwrap();
    let mut v = unlock_vault("test-pass", path).unwrap();

    // Store same value under different names
    set_secret(&mut v, "KEY1", "identical-value").unwrap();
    set_secret(&mut v, "KEY2", "identical-value").unwrap();

    // The encrypted representations must differ (different KEM encapsulations)
    let s1 = &v.vault.secrets["KEY1"];
    let s2 = &v.vault.secrets["KEY2"];

    assert_ne!(
        s1.ciphertext, s2.ciphertext,
        "Identical values produced identical ciphertext — per-secret keys not working"
    );
    assert_ne!(
        s1.kem_ciphertext, s2.kem_ciphertext,
        "Same KEM ciphertext for different secrets — key reuse"
    );
    assert_ne!(
        s1.x25519_ephemeral_public, s2.x25519_ephemeral_public,
        "Same ephemeral X25519 key for different secrets — nonce reuse"
    );
}

#[test]
fn attack_vault_secret_round_trip_integrity() {
    let tmp = NamedTempFile::new().unwrap();
    let path = tmp.path().to_str().unwrap();

    create_vault("test", path).unwrap();
    let mut v = unlock_vault("test", path).unwrap();

    // Test various edge-case secret values
    let test_values = [
        ("empty", ""),
        ("unicode", "\u{1F512}\u{1F510}\u{1F511}"),
        ("long", &"A".repeat(10000)),
        ("null_bytes", "before\x00after"),
        ("newlines", "line1\nline2\r\nline3"),
        ("json", r#"{"key": "value", "nested": [1,2,3]}"#),
        ("special", "!@#$%^&*()_+-=[]{}|;':\",./<>?"),
    ];

    for (name, value) in &test_values {
        set_secret(&mut v, name, value).unwrap();
        let recovered = get_secret(&v, name).unwrap();
        assert_eq!(
            &recovered, value,
            "Secret '{name}' corrupted during encrypt/decrypt"
        );
    }
}

#[test]
fn attack_vault_overwrite_secret() {
    let tmp = NamedTempFile::new().unwrap();
    let path = tmp.path().to_str().unwrap();

    create_vault("pass", path).unwrap();
    let mut v = unlock_vault("pass", path).unwrap();

    set_secret(&mut v, "KEY", "original").unwrap();
    let orig_ct = v.vault.secrets["KEY"].ciphertext.clone();

    set_secret(&mut v, "KEY", "updated").unwrap();

    // Verify: new value is returned and ciphertext changed
    let value = get_secret(&v, "KEY").unwrap();
    assert_eq!(value, "updated");
    assert_ne!(
        v.vault.secrets["KEY"].ciphertext, orig_ct,
        "Ciphertext didn't change after secret update"
    );
}

#[test]
fn attack_vault_remove_then_access() {
    let tmp = NamedTempFile::new().unwrap();
    let path = tmp.path().to_str().unwrap();

    create_vault("pass", path).unwrap();
    let mut v = unlock_vault("pass", path).unwrap();

    set_secret(&mut v, "TEMP", "temporary").unwrap();
    remove_secret(&mut v, "TEMP").unwrap();

    // Must not be recoverable after removal
    assert!(
        get_secret(&v, "TEMP").is_err(),
        "Removed secret still accessible"
    );
}

// ================================================================
//  ATTACK 8: VAULT FILE TAMPERING (simulate external attacker)
// ================================================================

#[test]
fn attack_vault_file_tampered_ciphertext() {
    let tmp = NamedTempFile::new().unwrap();
    let path = tmp.path().to_str().unwrap();

    create_vault("pass", path).unwrap();
    let mut v = unlock_vault("pass", path).unwrap();
    set_secret(&mut v, "SECRET", "my-api-key").unwrap();
    drop(v);

    // Read the vault file and tamper with the secret's ciphertext
    let json = std::fs::read_to_string(path).unwrap();
    let mut vault: serde_json::Value = serde_json::from_str(&json).unwrap();

    if let Some(secrets) = vault["secrets"].as_object_mut() {
        if let Some(secret) = secrets.get_mut("SECRET") {
            if let Some(ct) = secret["ciphertext"].as_str() {
                // Decode, tamper, re-encode
                let mut ct_bytes = base64::Engine::decode(
                    &base64::engine::general_purpose::STANDARD,
                    ct,
                )
                .unwrap();
                ct_bytes[0] ^= 0xFF;
                let tampered = base64::Engine::encode(
                    &base64::engine::general_purpose::STANDARD,
                    &ct_bytes,
                );
                secret["ciphertext"] = serde_json::Value::String(tampered);
            }
        }
    }

    std::fs::write(path, serde_json::to_string_pretty(&vault).unwrap()).unwrap();

    // Try to unlock and read the tampered secret
    let v = unlock_vault("pass", path).unwrap();
    let result = get_secret(&v, "SECRET");
    assert!(
        result.is_err(),
        "CRITICAL: Tampered ciphertext decrypted successfully — no integrity check"
    );
}

#[test]
fn attack_vault_file_tampered_nonce() {
    let tmp = NamedTempFile::new().unwrap();
    let path = tmp.path().to_str().unwrap();

    create_vault("pass", path).unwrap();
    let mut v = unlock_vault("pass", path).unwrap();
    set_secret(&mut v, "KEY", "value123").unwrap();
    drop(v);

    // Tamper with the nonce
    let json = std::fs::read_to_string(path).unwrap();
    let mut vault: serde_json::Value = serde_json::from_str(&json).unwrap();

    if let Some(secrets) = vault["secrets"].as_object_mut() {
        if let Some(secret) = secrets.get_mut("KEY") {
            if let Some(nonce) = secret["nonce"].as_str() {
                let mut nonce_bytes = base64::Engine::decode(
                    &base64::engine::general_purpose::STANDARD,
                    nonce,
                )
                .unwrap();
                nonce_bytes[0] ^= 0xFF;
                let tampered = base64::Engine::encode(
                    &base64::engine::general_purpose::STANDARD,
                    &nonce_bytes,
                );
                secret["nonce"] = serde_json::Value::String(tampered);
            }
        }
    }

    std::fs::write(path, serde_json::to_string_pretty(&vault).unwrap()).unwrap();

    let v = unlock_vault("pass", path).unwrap();
    let result = get_secret(&v, "KEY");
    assert!(
        result.is_err(),
        "Tampered nonce still allowed decryption"
    );
}

#[test]
fn attack_vault_version_downgrade() {
    let tmp = NamedTempFile::new().unwrap();
    let path = tmp.path().to_str().unwrap();

    create_vault("pass", path).unwrap();

    // Change the vault version to 0 (downgrade)
    let json = std::fs::read_to_string(path).unwrap();
    let mut vault: serde_json::Value = serde_json::from_str(&json).unwrap();
    vault["version"] = serde_json::Value::Number(0.into());
    std::fs::write(path, serde_json::to_string_pretty(&vault).unwrap()).unwrap();

    let result = unlock_vault("pass", path);
    assert!(
        result.is_err(),
        "Vault accepted downgraded version — version check missing"
    );
}

#[test]
fn attack_vault_symlink_write() {
    use std::os::unix::fs as unix_fs;

    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("real-vault.json");
    let symlink = dir.path().join("vault.json");
    unix_fs::symlink(&target, &symlink).unwrap();

    let result = create_vault("pass", symlink.to_str().unwrap());
    assert!(
        result.is_err(),
        "Vault wrote through symlink — symlink attack possible"
    );
}

// ================================================================
//  ATTACK 9: PASSPHRASE CHANGE / KEY ROTATION ATTACKS
// ================================================================

#[test]
fn attack_old_passphrase_rejected_after_change() {
    let tmp = NamedTempFile::new().unwrap();
    let path = tmp.path().to_str().unwrap();

    create_vault("old-pass", path).unwrap();
    let mut v = unlock_vault("old-pass", path).unwrap();
    set_secret(&mut v, "KEY", "secret-value").unwrap();

    // Change passphrase
    dota::vault::ops::change_passphrase(&mut v, "new-pass").unwrap();
    drop(v);

    // Old passphrase must fail
    let result = unlock_vault("old-pass", path);
    assert!(
        result.is_err(),
        "Old passphrase still works after passphrase change"
    );

    // New passphrase must work and secrets must be preserved
    let v = unlock_vault("new-pass", path).unwrap();
    let value = get_secret(&v, "KEY").unwrap();
    assert_eq!(value, "secret-value");
}

#[test]
fn attack_key_rotation_preserves_secrets() {
    let tmp = NamedTempFile::new().unwrap();
    let path = tmp.path().to_str().unwrap();

    create_vault("pass", path).unwrap();
    let mut v = unlock_vault("pass", path).unwrap();

    set_secret(&mut v, "KEY1", "value1").unwrap();
    set_secret(&mut v, "KEY2", "value2").unwrap();

    let old_kem_pk = v.vault.kem.public_key.clone();
    let old_x25519_pk = v.vault.x25519.public_key.clone();

    // Rotate keys
    dota::vault::ops::rotate_keys(&mut v, "pass").unwrap();

    // Keys must have changed
    assert_ne!(
        v.vault.kem.public_key, old_kem_pk,
        "ML-KEM public key unchanged after rotation"
    );
    assert_ne!(
        v.vault.x25519.public_key, old_x25519_pk,
        "X25519 public key unchanged after rotation"
    );

    // Secrets must still be accessible
    assert_eq!(get_secret(&v, "KEY1").unwrap(), "value1");
    assert_eq!(get_secret(&v, "KEY2").unwrap(), "value2");
}
