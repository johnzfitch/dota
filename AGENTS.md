# AGENTS.md

Agent instructions for working with the dota codebase.

## Commands

```bash
# Build and test
cargo build
cargo test
cargo clippy

# Run locally
cargo run -- init
cargo run -- set TEST_KEY "test-value"
cargo run -- get TEST_KEY

# Format code
cargo fmt

# Run with debug logging
RUST_LOG=debug cargo run
```

## Boundaries

**Always safe:**
- Read any source file
- Run `cargo test` and `cargo clippy`
- Add/modify tests in `tests/` directory
- Update documentation in comments and markdown files

**Ask first:**
- Modify cryptographic implementations in `src/crypto/`
- Change vault format in `src/vault/format.rs`
- Alter Argon2 parameters or key derivation
- Add new dependencies (especially crypto libraries)
- Change memory zeroization logic

**Never:**
- Commit secrets, API keys, or vault files
- Weaken security parameters (Argon2 memory, iterations, key sizes)
- Remove zeroization of sensitive data
- Add network functionality without explicit approval
- Disable constant-time operations in crypto code

## Key files

| Path | Purpose |
|------|---------|
| `src/main.rs` | CLI entry point and command routing |
| `src/crypto/hybrid.rs` | TC-HKEM (ML-KEM-768 + X25519 with ciphertext binding + passphrase commitment) |
| `src/crypto/mlkem.rs` | ML-KEM-768 wrapper (post-quantum) |
| `src/crypto/legacy_kyber.rs` | Read-only legacy Kyber compatibility for `v2-v5` migration |
| `src/crypto/x25519.rs` | X25519 ECDH wrapper (classical) |
| `src/crypto/kdf.rs` | Argon2 key derivation and HKDF |
| `src/crypto/aes_gcm.rs` | AES-256-GCM symmetric encryption |
| `src/vault/format.rs` | Vault file structure and versioning |
| `src/vault/ops.rs` | Vault operations (load, save, add, get, rotate) |
| `src/tui/app.rs` | Ratatui terminal UI |
| `src/cli/commands.rs` | CLI command implementations |
| `tests/` | Integration tests for vault and crypto |

## Architecture

```
┌─────────────────┐
│ CLI / TUI       │  User interface layer
└────────┬────────┘
         │
┌────────▼────────┐
│ vault::ops      │  Vault operations (load, save, CRUD)
└────────┬────────┘
         │
┌────────▼────────┐
│ crypto::hybrid  │  TC-HKEM (combines ML-KEM + X25519 + mk binding)
└───┬─────────┬───┘
    │         │
┌───▼───┐ ┌──▼────┐
│ mlkem │ │x25519 │  Individual KEMs
└───┬───┘ └──┬────┘
    │        │
┌───▼────────▼───┐
│ aes_gcm + kdf  │  Symmetric encryption and key derivation
└────────────────┘
```

## Testing

Run full test suite:
```bash
cargo test --all
```

Test specific module:
```bash
cargo test --test vault_tests
cargo test crypto::hybrid
```

## Security notes

- All crypto types implement `Zeroize` and `Drop` for memory safety
- Vault files are JSON but contain base64-encoded binary data
- Test vectors use fixed seeds; production uses `OsRng`
- The current on-disk format is `v7`; legacy `v1-v6` vaults are migration-only inputs and are rewritten to `v7` on unlock
- `v7` authenticates `version`, `min_version`, KDF params, both algorithm ids, both public keys, and `suite` with an HMAC-SHA256 header commitment before any private-key decryption
- `v7` TC-HKEM binds ciphertexts and the passphrase-derived master key into every per-secret key derivation (best-of-both-worlds IND-CCA + passphrase commitment)
