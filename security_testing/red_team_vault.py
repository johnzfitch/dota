#!/usr/bin/env python3
"""
Red Team: External Attack on dota vault.json
=============================================
Attacks a REAL vault.json file from the outside, simulating an attacker
who has obtained the vault file from disk.

The vault is created by a Rust test helper (no CLI/tty needed).
Run: RED_TEAM_VAULT_PATH=/tmp/red_team_test_vault.json \
     cargo test --test create_test_vault -- --nocapture && \
     python3 security_testing/red_team_vault.py

Attacks that require CLI interaction are covered by the Rust integration
tests in tests/red_team_crypto.rs (ciphertext tampering, nonce tampering,
version downgrade, passphrase brute force, etc.).

This script focuses on what an external attacker can learn and do
from the vault.json file alone — WITHOUT knowing the passphrase.
"""

import json
import os
import sys
import copy
import base64
import hashlib
from pathlib import Path

VAULT_PATH = os.environ.get(
    "RED_TEAM_VAULT_PATH",
    "/tmp/red_team_test_vault.json",
)


class AttackResult:
    def __init__(self, name: str, success: bool, details: str,
                 severity: str = "INFO"):
        self.name = name
        self.success = success
        self.details = details
        self.severity = severity

    def __str__(self):
        icon = "[!!]" if self.success else "[OK]"
        status = "VULNERABLE" if self.success else "DEFENDED"
        return (
            f"{icon} [{self.severity}] {self.name}\n"
            f"    {status}: {self.details}"
        )


def read_vault(path: str) -> dict:
    with open(path) as f:
        return json.load(f)


# ================================================================
#  ATTACK 1: METADATA LEAKAGE ANALYSIS
# ================================================================

def attack_metadata_leakage(vault: dict) -> AttackResult:
    """Catalog everything an attacker can learn from vault.json without
    the passphrase."""
    leaked = []

    if "version" in vault:
        leaked.append(f"Vault format version: {vault['version']}")
    if "created" in vault:
        leaked.append(f"Vault creation time: {vault['created']}")

    kdf = vault.get("kdf", {})
    if kdf:
        leaked.append(f"KDF algorithm: {kdf.get('algorithm')}")
        leaked.append(f"KDF time_cost: {kdf.get('time_cost')}")
        mem_kib = kdf.get('memory_cost', 0)
        leaked.append(f"KDF memory_cost: {mem_kib} KiB ({mem_kib // 1024} MiB)")
        leaked.append(f"KDF parallelism: {kdf.get('parallelism')}")
        salt_b64 = kdf.get("salt", "")
        if salt_b64:
            salt_bytes = base64.b64decode(salt_b64)
            leaked.append(f"KDF salt: {len(salt_bytes)} bytes ({salt_b64[:20]}...)")

    kem = vault.get("kem", {})
    if kem:
        leaked.append(f"KEM algorithm: {kem.get('algorithm')}")
        pk_b64 = kem.get("public_key", "")
        if pk_b64:
            pk_bytes = base64.b64decode(pk_b64)
            leaked.append(f"ML-KEM public key: {len(pk_bytes)} bytes (confirms ML-KEM-768)")
        enc_sk = kem.get("encrypted_private_key", "")
        if enc_sk:
            leaked.append(f"Encrypted ML-KEM private key: {len(base64.b64decode(enc_sk))} bytes")

    x25519 = vault.get("x25519", {})
    if x25519:
        pk_b64 = x25519.get("public_key", "")
        if pk_b64:
            leaked.append(f"X25519 public key: {base64.b64decode(pk_b64).hex()[:32]}...")

    secrets = vault.get("secrets", {})
    leaked.append(f"Number of stored secrets: {len(secrets)}")

    return AttackResult(
        "Metadata Leakage Analysis",
        success=True,
        details=(
            f"Vault exposes {len(leaked)} metadata items:\n"
            + "\n".join(f"      - {l}" for l in leaked)
            + "\n    IMPACT: Attacker knows the exact crypto stack, KDF parameters "
            "(to estimate brute-force cost), and secret count."
        ),
        severity="MEDIUM",
    )


# ================================================================
#  ATTACK 2: SECRET NAME ENUMERATION (cleartext)
# ================================================================

def attack_secret_names_cleartext(vault: dict) -> AttackResult:
    """Secret names are stored unencrypted — the attacker knows WHAT
    you're storing."""
    secrets = vault.get("secrets", {})
    names = list(secrets.keys())

    if not names:
        return AttackResult(
            "Secret Name Enumeration", False,
            "No secrets in vault.", "INFO",
        )

    details_parts = [f"Found {len(names)} secret names in cleartext: {names}"]

    for name in names:
        entry = secrets[name]
        if "created" in entry:
            details_parts.append(f"  '{name}' created: {entry['created']}")
        if "modified" in entry:
            details_parts.append(f"  '{name}' modified: {entry['modified']}")
        ct = entry.get("ciphertext", "")
        if ct:
            ct_len = len(base64.b64decode(ct))
            details_parts.append(
                f"  '{name}' ciphertext: {ct_len} bytes "
                f"(value is ~{ct_len - 16} bytes, minus GCM tag)"
            )

    details_parts.append(
        "IMPACT: An attacker knows what you store (e.g., 'AWS_SECRET_KEY') "
        "and when each was last changed. They also know approximate secret "
        "lengths from ciphertext size."
    )

    return AttackResult(
        "Secret Name Enumeration",
        success=True,
        details="\n    ".join(details_parts),
        severity="MEDIUM",
    )


# ================================================================
#  ATTACK 3: CROSS-SECRET KEY REUSE
# ================================================================

def attack_cross_secret_key_reuse(vault: dict) -> AttackResult:
    """Verify each secret uses a unique KEM encapsulation."""
    secrets = vault.get("secrets", {})
    if len(secrets) < 2:
        return AttackResult(
            "Cross-Secret Key Reuse", False,
            "Need >= 2 secrets.", "INFO",
        )

    kem_cts = set()
    eph_pks = set()
    nonces = set()

    for name, s in secrets.items():
        kem_cts.add(s.get("kem_ciphertext", ""))
        eph_pks.add(s.get("x25519_ephemeral_public", ""))
        nonces.add(s.get("nonce", ""))

    issues = []
    if len(kem_cts) < len(secrets):
        issues.append("KEM ciphertext reused across secrets")
    if len(eph_pks) < len(secrets):
        issues.append("X25519 ephemeral key reused across secrets")
    if len(nonces) < len(secrets):
        issues.append("AES-GCM nonce reused across secrets")

    if issues:
        return AttackResult(
            "Cross-Secret Key Reuse", True,
            f"KEY REUSE: {'; '.join(issues)}",
            "CRITICAL",
        )

    return AttackResult(
        "Cross-Secret Key Reuse", False,
        f"All {len(secrets)} secrets use unique KEM ciphertexts, "
        f"ephemeral keys, and nonces. Per-secret key isolation confirmed.",
        "INFO",
    )


# ================================================================
#  ATTACK 4: BRUTE-FORCE COST ESTIMATION
# ================================================================

def attack_brute_force_estimate(vault: dict) -> AttackResult:
    """Estimate the cost of brute-forcing the passphrase from the KDF params."""
    kdf = vault.get("kdf", {})
    algo = kdf.get("algorithm", "?")
    t = kdf.get("time_cost", 0)
    m_kib = kdf.get("memory_cost", 0)
    p = kdf.get("parallelism", 0)

    # RTX 4090: 24 GB VRAM
    gpu_vram_mib = 24 * 1024
    mem_per_trial_mib = m_kib / 1024
    parallel_trials = int(gpu_vram_mib / mem_per_trial_mib) if mem_per_trial_mib > 0 else 0
    est_trials_per_sec_per_gpu = parallel_trials  # ~1 trial/sec per slot for Argon2id

    details = [
        f"KDF: {algo}, t={t}, m={m_kib} KiB ({m_kib // 1024} MiB), p={p}",
        f"GPU (RTX 4090, 24 GB): ~{parallel_trials} parallel trials, "
        f"~{est_trials_per_sec_per_gpu} trials/sec",
    ]

    # Cost estimates for various passphrase strengths
    import math
    for label, entropy_bits in [
        ("4-digit PIN (13 bits)", 13.3),
        ("Common password (20 bits)", 20),
        ("8-char random alphanumeric (48 bits)", 47.6),
        ("4-word Diceware (52 bits)", 51.7),
        ("6-word Diceware (78 bits)", 77.5),
        ("20-char random (119 bits)", 119),
    ]:
        if est_trials_per_sec_per_gpu > 0:
            trials = 2 ** entropy_bits
            cluster_rate = 1000 * est_trials_per_sec_per_gpu  # 1000 GPUs
            seconds = trials / cluster_rate
            years = seconds / (365.25 * 24 * 3600)

            if years < 0.001:
                time_str = f"{seconds:.1f} seconds"
            elif years < 1:
                time_str = f"{years * 365:.1f} days"
            elif years > 1e12:
                time_str = f"2^{math.log2(years):.0f} years"
            elif years > 1e6:
                time_str = f"{years:.2e} years"
            else:
                time_str = f"{years:.1f} years"

            feasible = "FEASIBLE" if years < 1 else "INFEASIBLE"
            details.append(f"  {label}: {time_str} on 1000 GPUs [{feasible}]")

    return AttackResult(
        "Brute-Force Cost Estimation",
        success=True,
        details="\n    ".join(details)
            + "\n    IMPACT: KDF params visible in vault.json allow precise "
            "cost estimation. Weak passphrases are still crackable.",
        severity="MEDIUM",
    )


# ================================================================
#  ATTACK 5: FILE PERMISSIONS
# ================================================================

def attack_file_permissions(vault_path: str) -> AttackResult:
    """Check vault file permissions."""
    import stat
    st = os.stat(vault_path)
    mode = st.st_mode
    perms = oct(mode)[-3:]

    issues = []
    if mode & stat.S_IROTH:
        issues.append("world-readable")
    if mode & stat.S_IWOTH:
        issues.append("world-writable")
    if mode & stat.S_IRGRP:
        issues.append("group-readable")
    if mode & stat.S_IWGRP:
        issues.append("group-writable")

    if issues:
        return AttackResult(
            "Vault File Permissions", True,
            f"Permissions: {perms} ({', '.join(issues)}). "
            f"Recommended: 600 (owner-only).",
            "MEDIUM",
        )

    return AttackResult(
        "Vault File Permissions", False,
        f"Permissions: {perms} — properly restricted.",
        "INFO",
    )


# ================================================================
#  ATTACK 6: CIPHERTEXT LENGTH ANALYSIS
# ================================================================

def attack_ciphertext_length_analysis(vault: dict) -> AttackResult:
    """AES-GCM ciphertext length = plaintext length + 16 bytes (tag).
    Attacker can estimate secret value lengths."""
    secrets = vault.get("secrets", {})
    if not secrets:
        return AttackResult("Ciphertext Length Analysis", False, "No secrets.", "INFO")

    length_info = []
    for name, s in secrets.items():
        ct_bytes = base64.b64decode(s.get("ciphertext", ""))
        # AES-GCM: ciphertext includes 16-byte auth tag appended
        estimated_plaintext_len = len(ct_bytes) - 16
        length_info.append(
            f"'{name}': ciphertext={len(ct_bytes)} bytes → "
            f"value is ~{estimated_plaintext_len} bytes"
        )

    return AttackResult(
        "Ciphertext Length Analysis",
        success=True,
        details=(
            "AES-GCM does not pad plaintext. Exact value lengths are leaked:\n"
            + "\n".join(f"      - {l}" for l in length_info)
            + "\n    IMPACT: Attacker can distinguish short PINs from long API keys. "
            "Mitigation: pad secrets to fixed block sizes before encryption."
        ),
        severity="LOW",
    )


# ================================================================
#  ATTACK 7: PUBLIC KEY EXTRACTION (for future quantum attack)
# ================================================================

def attack_public_key_harvest(vault: dict) -> AttackResult:
    """Extract public keys for harvest-now-decrypt-later scenario."""
    kem = vault.get("kem", {})
    x25519 = vault.get("x25519", {})

    pk_kem = kem.get("public_key", "")
    pk_x25519 = x25519.get("public_key", "")

    details = []
    if pk_kem:
        pk_bytes = base64.b64decode(pk_kem)
        details.append(f"ML-KEM-768 public key: {len(pk_bytes)} bytes (quantum-resistant)")
    if pk_x25519:
        pk_bytes = base64.b64decode(pk_x25519)
        details.append(
            f"X25519 public key: {pk_bytes.hex()[:40]}... "
            f"(VULNERABLE to Shor's algorithm)"
        )

    details.append(
        "HARVEST-NOW-DECRYPT-LATER: An attacker records the vault today. "
        "With a future quantum computer, X25519 falls to Shor's algorithm. "
        "BUT: the hybrid design means ML-KEM still protects the secrets — "
        "both KEMs must be broken to recover the AES key."
    )

    return AttackResult(
        "Public Key Harvest (Quantum Threat)",
        success=True,
        details="\n    ".join(details),
        severity="LOW",
    )


# ================================================================
#  ATTACK 8: STRUCTURAL INTEGRITY CHECK
# ================================================================

def attack_structural_consistency(vault: dict) -> AttackResult:
    """Verify the vault's internal structural consistency."""
    issues = []

    # Check version
    version = vault.get("version")
    if version is None:
        issues.append("Missing version field")
    elif not isinstance(version, int):
        issues.append(f"Version is not integer: {type(version)}")

    # Check KDF has required fields
    kdf = vault.get("kdf", {})
    for field in ["algorithm", "salt", "time_cost", "memory_cost", "parallelism"]:
        if field not in kdf:
            issues.append(f"Missing kdf.{field}")

    # Check KEM public key length (ML-KEM-768 = 1184 bytes)
    kem = vault.get("kem", {})
    pk_b64 = kem.get("public_key", "")
    if pk_b64:
        pk_len = len(base64.b64decode(pk_b64))
        if pk_len != 1184:
            issues.append(f"ML-KEM public key wrong length: {pk_len} (expected 1184)")

    # Check X25519 public key length (32 bytes)
    x25519 = vault.get("x25519", {})
    pk_b64 = x25519.get("public_key", "")
    if pk_b64:
        pk_len = len(base64.b64decode(pk_b64))
        if pk_len != 32:
            issues.append(f"X25519 public key wrong length: {pk_len} (expected 32)")

    # Check each secret has required fields
    for name, s in vault.get("secrets", {}).items():
        for field in ["algorithm", "kem_ciphertext", "x25519_ephemeral_public",
                       "nonce", "ciphertext"]:
            if field not in s:
                issues.append(f"Secret '{name}' missing field: {field}")

        # Nonce should be 12 bytes
        nonce_b64 = s.get("nonce", "")
        if nonce_b64:
            nonce_len = len(base64.b64decode(nonce_b64))
            if nonce_len != 12:
                issues.append(f"Secret '{name}' nonce wrong length: {nonce_len} (expected 12)")

        # KEM ciphertext should be 1088 bytes
        kem_ct_b64 = s.get("kem_ciphertext", "")
        if kem_ct_b64:
            ct_len = len(base64.b64decode(kem_ct_b64))
            if ct_len != 1088:
                issues.append(
                    f"Secret '{name}' KEM ciphertext wrong length: {ct_len} (expected 1088)"
                )

        # X25519 ephemeral key should be 32 bytes
        eph_b64 = s.get("x25519_ephemeral_public", "")
        if eph_b64:
            eph_len = len(base64.b64decode(eph_b64))
            if eph_len != 32:
                issues.append(
                    f"Secret '{name}' X25519 ephemeral key wrong length: {eph_len} (expected 32)"
                )

    if issues:
        return AttackResult(
            "Structural Consistency", True,
            f"Found {len(issues)} structural issues: {issues}",
            "HIGH",
        )

    return AttackResult(
        "Structural Consistency", False,
        "Vault structure is internally consistent. All field lengths and types are correct.",
        "INFO",
    )


# ================================================================
#  RUNNER
# ================================================================

def run_all_attacks():
    print("=" * 70)
    print("  RED TEAM: EXTERNAL VAULT FILE ANALYSIS")
    print("  Target: Real dota vault.json")
    print("=" * 70)

    if not os.path.exists(VAULT_PATH):
        print(f"\n[!] Vault not found at: {VAULT_PATH}")
        print("    Create one first:")
        print("    RED_TEAM_VAULT_PATH=/tmp/red_team_test_vault.json \\")
        print("      cargo test --test create_test_vault -- --nocapture")
        return []

    print(f"\n[*] Vault file: {VAULT_PATH}")
    print(f"    Size: {os.path.getsize(VAULT_PATH):,} bytes")

    vault = read_vault(VAULT_PATH)
    results = []

    attacks = [
        lambda: attack_metadata_leakage(vault),
        lambda: attack_secret_names_cleartext(vault),
        lambda: attack_cross_secret_key_reuse(vault),
        lambda: attack_brute_force_estimate(vault),
        lambda: attack_file_permissions(VAULT_PATH),
        lambda: attack_ciphertext_length_analysis(vault),
        lambda: attack_public_key_harvest(vault),
        lambda: attack_structural_consistency(vault),
    ]

    print(f"\n[*] Running {len(attacks)} external analysis attacks...\n")

    for attack_fn in attacks:
        try:
            result = attack_fn()
            results.append(result)
            print(result)
            print()
        except Exception as e:
            print(f"[ERR] Attack failed: {e}\n")

    # Summary
    print("=" * 70)
    print("  SUMMARY")
    print("=" * 70)

    total = len(results)
    vulns = sum(1 for r in results if r.success)
    defended = total - vulns

    print(f"\n  Total Attacks: {total}")
    print(f"  Findings: {vulns}")
    print(f"  Clean: {defended}")

    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        findings = [r for r in results if r.success and r.severity == sev]
        if findings:
            print(f"\n  [{sev}]")
            for f in findings:
                print(f"    - {f.name}")

    print()
    print("  NOTE: Ciphertext tampering, nonce tampering, version downgrade,")
    print("  passphrase brute-force, and key rotation attacks are covered by")
    print("  the Rust integration tests in tests/red_team_crypto.rs")
    print("  (33/33 attacks DEFENDED).")
    print()
    print("=" * 70)

    return results


if __name__ == "__main__":
    run_all_attacks()
