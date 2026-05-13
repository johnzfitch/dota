# Security Audit — First Pass

Scope: `dota` v1.0.0 commit on branch `claude/plan-security-audit-e11PJ`. Methodology and checklist live in the audit plan; this document records concrete findings.

Severity rubric:

- **Critical**: key/plaintext disclosure, auth bypass, or downgrade with known threat model.
- **High**: silent corruption, partial zeroize, or material gap from a documented security claim.
- **Medium**: defense-in-depth gap, side channel, or hardening shortfall.
- **Low**: doc/comment drift, dead code, or style risk.

Per-finding format: `[Severity] Title — file:line` + Description, Impact, Suggested fix.

---

## Critical

_None identified in first pass._ The TC-HKEM v7 path validates the header HMAC under the master key before decapsulating private keys (`vault/ops.rs:278-283`), bounds KDF parameters before invoking Argon2 (`ops.rs:1091-1137`), uses `constant_time_eq` for every commitment compare (`ops.rs:303,329,974`), enforces `min_version` rollback floor (`ops.rs:1174`), rejects all-zero X25519 ephemeral keys (`ops.rs:1250`), and writes vaults atomically through `tempfile::persist` with a directory `sync_all` (`ops.rs:709-727`). Symlink traversal is rejected at the syscall boundary with `O_NOFOLLOW` on Unix (`ops.rs:192-199`). The dangerous shapes that would have lived here (HMAC `==` compares, attacker-controllable Argon2 memory, plaintext-on-stdin overflow, MAC-on-bare-bytes) are all absent.

## High

### H1 — README and README diagram describe a clipboard / ratatui TUI that does not exist

- `Cargo.toml:40` declares `arboard = "3.4"` and `ratatui = "0.30"`, `crossterm = "0.28"`.
- `src/tui/app.rs:1-3` is a 3-line placeholder file ("Placeholder for TUI app implementation").
- `src/tui/mod.rs:79` and `:170-174` print the secret value with `println!("{}", value.expose())` — there is no clipboard call site anywhere (`grep -RIn 'arboard\|Clipboard' src/` returns nothing; `Cargo.toml` is the only hit).
- `README.md:225` ("Enter — Copy the selected secret value to the clipboard"), the readme's TUI keyboard table, and the project description ("plus a terminal UI") all describe behavior the binary does not implement.

**Impact**: Users who follow the README will believe the secret is loaded into the OS clipboard with an auto-clear (`tokio` is even pulled in for "time"); in reality the secret is written to stdout and is now in the terminal scrollback, the user's `script(1)` log, the IDE terminal buffer, and any pty multiplexer history. This is a real exposure caused by documentation, not by code.

**Fix**: Pick one — either implement the clipboard path with `arboard` + a `tokio` timer to clear after N seconds, or update the README + remove the dead `arboard`/`ratatui`/`crossterm`/`tokio` dependencies. Removing dead deps also shrinks the supply-chain surface (H4).

### H2 — `panic = "abort"` defeated `ZeroizeOnDrop`; four `.expect` panic surfaces in commitment helpers — **addressed in this PR**

Original finding:

- `Cargo.toml:63` set `panic = "abort"` for the release profile.
- `README.md:67-68` states "Memory safety: Rust with `ZeroizeOnDrop` for all sensitive types — passphrases, shared secrets, and AES keys are wiped from memory on drop."
- With `panic = "abort"`, the runtime calls `abort()` and **does not run destructors**. Any panic between secret creation and the natural end of scope leaves the bytes resident in pages the kernel later reclaims. The protective measures from `security::harden_process` (no core dumps, `mlockall`, `PR_SET_DUMPABLE = 0`) reduce but do not eliminate this gap.
- Actual panicking call sites in the runtime path: `vault/ops.rs:890,893` (`compute_v5_key_commitment` `.expect`s) and `:931,960` (HMAC init `.expect`s). Reachable only on impossible state (32-byte master key, HMAC accepting any key length), but still panic surfaces.

**Resolution (in this PR, commits `ca00718` + `db57912`)**:

- `Cargo.toml:63` switched to `panic = "unwind"`. Destructors now run on panic paths, restoring the README guarantee.
- Four `.expect` calls in `compute_v5_key_commitment`, `compute_v6_key_commitment`, and `compute_v7_key_commitment` replaced with `?`-propagating `Result` returns. The HKDF / HMAC errors are wrapped with `anyhow::Error::new(e).context(...)` so the underlying `hkdf::InvalidPrkLength` / `hmac::digest::InvalidLength` is preserved as a `source()` in the error chain.
- `compute_v5_key_commitment` now returns `Result<Vec<u8>>`; callers were updated. `compute_key_commitment` dispatch arm for `0..=V5_VAULT_VERSION` removed the wrapping `Ok(...)` since the inner call already returns `Result`.

**Residual risk**: `panic = "unwind"` increases binary size and means panics during `unsafe` blocks in `security.rs` could theoretically unwind through FFI boundaries. The four `unsafe` blocks in `security.rs` (`harden_linux`, `install_signal_handlers`, the signal handler itself) do not call any code that can panic, so this is safe in practice — but worth a regression test if more `unsafe` is added.

### H3 — Migration backups retain old key material indefinitely; never re-encrypted across passphrase change or rotation

- `vault/migration.rs:39 MAX_BACKUPS: usize = 5` and `:636-672 create_backup` writes `vault.backup.<timestamp>.json` next to the live vault on every migration.
- After `dota change-passphrase` or `dota rotate-keys`, **the backups are not touched**. They keep the old wrapped private keys, old key commitment, and (for pre-v7 paths) potentially weaker construction (v1 used master-key-as-AES-key directly: `migration.rs:154`).
- Backups are only locked to 0o600 *after* `fs::copy` (`migration.rs:663-669`). `fs::copy` is not atomic; a partial write that surfaces to a same-UID observer between the copy and the chmod inherits the source mode briefly.

**Impact**: A vault that was migrated v3→v7 with passphrase A, then had its passphrase rotated to B, leaves an encrypted-under-A copy in the directory for up to 5 migrations. An attacker who later compromises passphrase A (e.g., from a password leak) can decrypt the backup. This contradicts the operator's mental model of "I rotated the passphrase, so old credentials no longer help."

**Fix**: Three options, in order of preference:
1. Delete migration backups on the next successful unlock-and-save under a new passphrase (i.e., `change_passphrase` and `rotate_keys` purge `*.backup.*.json` matching the live vault stem).
2. Default to `MAX_BACKUPS = 1` and add a CLI flag `--keep-backups N` for users who want disaster recovery.
3. Document explicitly that backups carry old credential state and recommend `shred(1)` after migration.
   Tighten `create_backup` to write to a 0600 tempfile via `tempfile_in(parent)` + `persist`, the same pattern `save_vault_file` already uses.

### H4 — `ml-kem = 0.3.0-rc.0` and other dead crypto-adjacent dependencies in production crate

- `Cargo.toml:11`: `ml-kem = "0.3.0-rc.0"` — pre-release (release candidate) version of the FIPS 203 implementation. RC versions can change behavior between point releases and are not generally suitable for a security-critical build.
- `Cargo.toml:12`: `pqcrypto-kyber = "0.8"` — pulled in for read-only legacy migration (`legacy_kyber.rs`). This is fine but should be feature-gated behind `legacy-migration` so security-conscious downstreams can opt out once their vaults are all v7.
- `Cargo.toml:25-27,40-41`: `ratatui`, `crossterm`, `arboard`, `tokio` are all declared but unused (see H1). Dead deps inflate the supply-chain surface for a security-critical tool.
- No `cargo deny` / `deny.toml` / `cargo vet` config in repo. CI runs `rustsec/audit-check@v2` (`.github/workflows/ci.yml:54`) but does not enforce a license/source allowlist or pin crypto-crate origins.

**Impact**: An RC-quality dependency in the cryptographic core is acceptable for development but not for the v1.0.0 declared in `Cargo.toml:3`. Each unused dep is a free-of-charge attack surface (typosquat, malicious dependency update during `cargo update`).

**Fix**:
- Pin `ml-kem` to a non-RC release once available; until then, document the version explicitly in the README and gate it behind a CI matrix that fails if the version regresses.
- Feature-gate `pqcrypto-kyber` and `legacy_kyber.rs` behind `migrate-legacy`.
- Remove `arboard`, `tokio`, `ratatui`, `crossterm` until they have a call site (or implement H1).
- Add `deny.toml` enforcing: no duplicate crypto crates, allowed licenses, allowed registries; wire `cargo deny check` into CI alongside the existing audit step.

## Medium

### M1 — `DOTA_PASSPHRASE` env var is read inconsistently and is observable to same-UID processes

- `cli/commands.rs:25-32 read_passphrase` reads `DOTA_PASSPHRASE` and falls back to `prompt_password`.
- Used by `handle_set` (`:84`), `handle_get` (`:139`), `handle_list` (`:154`).
- **Not** used by `handle_init` (`:47`), `handle_rm` (`:184`), `handle_info` (`:200`), `handle_change_passphrase` (`:261`), `handle_rotate_keys` (`:292`), `handle_upgrade` (`:328`), `cli/export.rs:14`, `tui/mod.rs:21`.

**Impact**: Inconsistent UX (CI scripts mixing `set` and `change-passphrase` will silently break). Security-wise, env vars are visible via `/proc/<pid>/environ` to same-UID processes and to anything with `CAP_SYS_PTRACE`. The README does not document the env var at all (`grep DOTA_PASSPHRASE README.md` is empty). This is dual-use: scripted CI use is convenient, but it is also footgun-grade.

**Fix**:
- Either route every command through `read_passphrase`, or remove the env var entirely.
- If kept, document explicitly in `README.md` and `cli/mod.rs` that env-var passphrase is opt-in for non-interactive use and exposes the secret to same-UID observers, and unset it in the parent shell after use.
- Add a `--passphrase-fd N` style flag (read passphrase from a specified file descriptor) as the recommended scripted-use alternative; fd transfer is not visible in `/proc/.../environ`.

### M2 — Defense-in-depth: `okm` not zeroized on HKDF-expand error in hybrid combiners

- `crypto/hybrid.rs:243-254 (combine_shared_secrets_v7)`: `let result = hk.expand(...).map_err(...); ikm.zeroize(); result?; let key = AesKey::from_bytes(okm); okm.zeroize();` — on `result?` early return, `okm` is **not** zeroized. The same shape lives in `combine_shared_secrets_with_labels:288-302`.
- In practice `expand` on a 32-byte output cannot fail (HKDF-SHA256 supports up to 8160 bytes), so `okm` will always be either uninitialized zeros or a valid key here. But the pattern is fragile.

**Impact**: Low real-world risk today; high risk of regression if a future change increases the output length or swaps the HKDF backend.

**Fix**: Wrap `okm` in `Zeroizing::<[u8; 32]>` (the same pattern `derive_wrapping_keys_with_labels:810,814` already uses), then construct `AesKey` from `*okm` and let `Zeroizing` clean up on every path.

### M3 — `derive_wrapping_keys_with_labels` zeroizes after copying out of `Zeroizing`

- `vault/ops.rs:810-826`: `let mut mlkem_key = Zeroizing::new([0u8; 32]); ...; let keys = WrappingKeys { mlkem: AesKey::from_bytes(*mlkem_key), ... }; mlkem_key.zeroize(); ...`
- `*mlkem_key` dereferences and **copies** the `[u8; 32]` (it's `Copy`) into `AesKey::from_bytes` by value. The original lives inside the `Zeroizing` wrapper, which would have zeroized it on drop anyway. The explicit `.zeroize()` afterwards is redundant but not wrong.
- The follow-up `std::hint::black_box(&mlkem_key)` after `zeroize()` keeps the compiler from eliding the wipe; this is the right pattern.

**Impact**: None — the code is correct. Listed here for the next reviewer so the redundancy is not "fixed" by deleting the explicit zeroize and relying on the wrapper drop alone. The redundancy is the safe direction.

**Fix**: Add a one-line comment explaining that the explicit zeroize is intentional belt-and-suspenders next to the drop guard.

### M4 — Secret name is a metadata leak by design; not documented in threat model

- `vault/format.rs:55`: `pub secrets: HashMap<String, EncryptedSecret>` — names are stored as plaintext JSON keys.
- `validate_secret_name (ops.rs:1052-1089)` rejects control chars and bidi confusables on input, but the names themselves are never encrypted.

**Impact**: Anyone who can read the vault file (including a stolen backup, a B-tree of `~/.dota/vault.json` discovered in a forensic image, or a mis-permissioned cloud sync) sees the names of all stored secrets even without the passphrase. This is by design (HashMap-based file format) but is not in `README.md` "Security assumptions."

**Fix**: Add an explicit bullet to `README.md` under "Security assumptions" or "Design constraints":
> **Metadata exposure**: Secret *names* are stored in plaintext inside the vault. The vault file should be treated as confidential at-rest; full-disk encryption is the recommended container.

If the team wants to fix this rather than document it, the format change is large (secrets become an opaque encrypted blob keyed by an HMAC of the name; lookups become HMAC-then-search) — schedule for v8.

### M5 — `set` / TUI `set` rejects inline values, but `dota get` still echoes secrets to stdout (and into terminal scrollback)

- `cli/commands.rs:144`: `println!("{}", value.expose())` for `dota get NAME`.
- `tui/mod.rs:79`: same shape inside the interactive shell.
- README documents `dota get NAME` as the canonical retrieval path.

**Impact**: Once a secret is in stdout, it's also in the user's tmux scrollback, IDE terminal history, `script(1)` capture, ssh-session record, etc. This is the inverse of the careful argv-avoidance done for `set` (commands.rs:79 comment).

**Fix**: Add a `dota get --no-stdout` mode that copies to clipboard (paired with H1) and clears after N seconds, and document it as the recommended interactive retrieval path. Keep raw `dota get` for piped use (`dota get TOKEN | ssh-agent`-style).

### M6 — Argon2 parameter validation is bounded, but salt lower bound (16 bytes) is below modern recommendations on `change_passphrase` regen path

- `vault/ops.rs:32 MIN_SALT_LEN: usize = 16` — used in `validate_kdf_params:1100`.
- `change_passphrase:470` regenerates salt via `generate_salt()` (`crypto/kdf.rs:50`) which uses `SaltString::generate` from the `argon2` crate — that produces a 22-byte base64 string (16 bytes of entropy). Acceptable today, but RFC 9106 recommends 16 bytes minimum and ≥ 32 bytes for archival contexts.

**Impact**: Negligible today. Defense-in-depth gap if a future post-quantum salt-collision attack on Argon2 emerges (currently unknown).

**Fix**: Raise `MIN_SALT_LEN` to 32 bytes for new vaults (keep 16 as the floor for legacy validation). Use `OsRng.fill_bytes(&mut [0u8; 32])` directly instead of `SaltString::generate` to avoid the base64 round-trip.

### M7 — Process hardening is Linux-only; macOS and Windows users get no `mlockall`, no core-dump suppression, no ptrace block

- `security.rs:109-114 harden_process` is `#[cfg(target_os = "linux")]` only.
- `security.rs:154-164 install_signal_handlers` is also Linux-only.
- README does not state that `dota` on macOS or Windows runs with default OS security only.

**Impact**: An operator on macOS or Windows reading the README believes core dumps and ptrace are blocked. They are not.

**Fix**: Add macOS equivalents (`PT_DENY_ATTACH`, `RLIMIT_CORE = 0`, `mlock` per-allocation rather than `mlockall`) and Windows equivalents (`SetProcessMitigationPolicy`, `CryptProtectMemory`). Until then, log a one-line warning at startup on non-Linux platforms ("Process hardening unavailable on this OS") and document the limitation in README.

### M8 — `secure_vault_directory` silently degrades to a warning on existing-directory chmod failures

- `vault/ops.rs:760-774`: if `set_permissions(parent, 0o700)` fails AND `parent_existed`, log a warning and continue.
- The vault FILE itself is still 0600 (`restrict_file_to_owner_rw:174-181`), so secrets stay unreadable. But the parent dir might be world-readable (e.g., `/tmp`), allowing an observer to enumerate filenames including the backup pattern from H3.

**Impact**: An attacker who can `ls /tmp` enumerates the backup files and can poll for new ones (e.g., during a migration). Combined with H3 they can also race the partial-copy window.

**Fix**: Return an error instead of warning when running with a non-default `--vault PATH` whose parent is world-readable. For the default `~/.dota/`, the existing behavior is correct.

### M9 — `eprintln!` at vault-load time prints uncontrolled diagnostic strings; can corrupt a TUI

- `vault/ops.rs:259-262`: `eprintln!("Migrating vault from v{} to v{}...", probe.version, VAULT_VERSION);` runs unconditionally when the on-disk version is older than current.
- `vault/migration.rs:139-142,671`: more `eprintln!` with the migration result and backup path.

**Impact**: Cosmetic — the migration banner can be smuggled into a piped consumer (`dota get TOKEN | ssh-agent`) and confuse downstream parsers. Not a security issue per se, but if a future hostile vault includes attacker-controlled fields in a `Migrating from v{}…` payload, this could become one.

**Fix**: Route migration progress through a dedicated logger (or `eprint`-only when stderr is a tty), and never include attacker-controlled fields in the format string. The current code already only prints version numbers (u32), so it is safe today.

## Low

### L1 — Misleading variable name in X25519 zero-check

- `crypto/x25519.rs:84`: `let is_nonzero = shared_bytes.iter().fold(0u8, |acc, &b| acc | b);` — `is_nonzero` holds the bitwise-OR of all bytes, which is **non-zero** iff any byte is non-zero. The `if is_nonzero == 0` check at line 85 then catches all-zero. The logic is correct; the name reads as a boolean even though it is a `u8` accumulator.

**Fix**: Rename to `acc` or `nonzero_or` and add a comment that `acc != 0` ⇔ at least one input byte was non-zero.

### L2 — `to_string_lossy()` on the default vault path can silently drop UTF-8 errors

- `vault/ops.rs:46-53 default_vault_path` uses `to_string_lossy().to_string()`. On a system with a non-UTF-8 home directory path (rare but possible), substitutions are silent.

**Fix**: Either return a `PathBuf` from `default_vault_path` and propagate `Path` through the API, or fail loudly when the path is not valid UTF-8.

### L3 — `ml-kem` private key stored expanded (2400 bytes) per legacy compat

- `crypto/mlkem.rs:33-35` comment: "preserved to keep the current vault byte contract stable until the v6 format migration lands." v7 is current; this comment is stale.

**Fix**: Update the comment or shrink to seed-form (which is what FIPS 203 actually standardizes). A separate change because it changes vault layout (would require a v8 bump).

### L4 — Tests use `.unwrap()`; not a security issue but worth noting in the audit completeness check

- All `.unwrap()` matches in `grep` were inside `#[cfg(test)]` modules, except the four `.expect` calls in `vault/ops.rs:890,893,931,960` flagged in H2.

**Fix**: H2 covers the production-path subset.

### L5 — `chrono = "0.4"` for `DateTime<Utc>` serialization is fine, but `created`/`modified` timestamps in `EncryptedSecret` are user-observable inside the vault file even when names are not — operators may not realize last-modified time leaks usage patterns

**Fix**: Document in the threat-model section.

### L6 — `ratatui = "0.30"` is a higher version than upstream's published latest (`0.28.x` at audit time); double-check the version exists or this is a typo

**Fix**: Verify against `crates.io`. If it does not exist, the build is currently broken on a fresh checkout — but H1 says we should be removing this dep anyway.

---

## Tests to add (regressions for the above)

1. `tests/no_clipboard.rs` — assert `arboard` is never linked; if H1 path A is chosen, the inverse test (clipboard called and cleared after timer).
2. `tests/migration_backup_lifecycle.rs` — exercise: migrate, change passphrase, assert backup is gone OR assert the backup is encrypted under the *new* passphrase (depending on which fix from H3 ships).
3. `tests/header_tamper_v7.rs` — flip every byte in the canonical header (kdf params, suite, public keys, min_version) and confirm `verify_v7_key_commitment` rejects each.
4. `tests/downgrade_rejected.rs` — write a v7 header that claims `version = 6`; confirm unlock rejects.
5. `tests/argon2_dos.rs` — write a vault with `memory_cost = 1_000_000` (1 GiB); confirm `validate_kdf_params` rejects before Argon2 runs.
6. `tests/export_env_quoting.rs` — fuzz secret values containing `'`, `\n`, `;`, `$( )`, NUL, and confirm `eval $(dota export-env)` is byte-identical to `dota get NAME` for each.
7. `tests/stdin_overflow.rs` — pipe `MAX_STDIN_SECRET_BYTES + 1` bytes into `dota set`; confirm refusal and confirm the buffer is zeroized (peek at /proc/self/maps not feasible, so verify via the error path only).
8. `tests/symlink_rejected_e2e.rs` — extends the existing `test_create_vault_rejects_symlink_path` to also cover `change_passphrase`, `rotate_keys`, and `upgrade`.

## Sweep results summary

| Sweep                                  | Hits | Triage |
| -------------------------------------- | ---- | ------ |
| `unwrap()`/`expect()` outside `#[cfg(test)]` | 4 | H2 |
| `println!`/`eprintln!` in non-test src | 100+ | M5, M9 |
| Non-CT compares on auth bytes          | 0 | ✓ |
| Non-`OsRng` RNG in production          | 0 | ✓ |
| `unsafe` blocks                        | 4 (all in `security.rs`) | acceptable; reviewed |
| Domain-separation labels (inventory)   | 12 distinct strings | ✓ all distinct, version-tagged |
| `clone()` of sensitive types           | 27 | reviewed; all appropriate (immutable salts, bounded `master_key.clone()` for unlocked-vault retention) |
| `arboard` / `Clipboard` call sites     | 0 (only `Cargo.toml`) | H1 |
| `ratatui` / `crossterm` call sites     | 0 in `src/` | H1 |
| Symlink protection sites               | 3 (read, write, write-backup) | ✓ |
| File permission enforcement (0o600/0o700) | 4 sites | ✓ |
| `min_version` enforcement              | `ops.rs:1174` | ✓ |
| Backup retention policy                | `MAX_BACKUPS = 5` | H3 |

## Suggested PR ordering

1. **H1** — pick clipboard-or-strip; lowest blast radius, immediately reduces docs/code drift.
2. **H4** — drop dead deps, add `deny.toml`, gate legacy Kyber.
3. **H3** — backup lifecycle fix + 0o600-from-creation. Touches `migration.rs`; ask first per `AGENTS.md` rules.
4. **H2** — replace four `.expect` calls; revisit `panic = "abort"` decision and update README.
5. **M1, M2, M3, M5, M6, M7, M8, M9** — small focused PRs, in any order. Most touch `cli/` or `vault/ops.rs` only.
6. **L1–L6** — bundled doc/style PR.

## Out of scope for this pass (deferred)

- Side-channel review of the underlying `aes-gcm`, `ml-kem`, and `x25519-dalek` crates (relies on upstream constant-time guarantees).
- Formal verification of the GHP18 reduction claim in `README.md` Theorem 1.
- Cryptographic review of the v1→v2→v3→v4→v5→v6 step functions in `migration.rs:152–600` beyond the v6→v7 step (they are read-only legacy paths but should still get a structured trace pass).
- macOS/Windows hardening implementations (M7).
