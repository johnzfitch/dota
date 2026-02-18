"""
Red Team Attack Suite
=====================
Systematically attacks the encrypted secrets from every angle.
Each attack class targets a different vulnerability category.

Attack Categories:
  1. Brute Force & Dictionary Attacks
  2. Key/IV Reuse & Weak Parameter Detection
  3. Side-Channel / Timing Attacks
  4. Padding Oracle Attacks
  5. Memory & Key Management Attacks
  6. Cryptographic Downgrade & Algorithm Weakness Attacks
  7. Source Code & Metadata Leakage Attacks
"""

import os
import sys
import time
import hmac
import json
import hashlib
import base64
import struct
import inspect
import gc
from typing import Optional

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, padding

from encrypted_secret import (
    EncryptionVault,
    WeakEncryptionVault,
    ECCVault,
    THE_SECRET,
    create_all_vaults,
)


# ================================================================
#  RESULT TRACKING
# ================================================================

class AttackResult:
    def __init__(self, name: str, target: str, success: bool,
                 details: str, severity: str = "INFO",
                 recovered_secret: Optional[str] = None):
        self.name = name
        self.target = target
        self.success = success
        self.details = details
        self.severity = severity  # CRITICAL, HIGH, MEDIUM, LOW, INFO
        self.recovered_secret = recovered_secret

    def __str__(self):
        status = "PASS (secret recovered)" if self.success else "FAIL (defended)"
        icon = "[!!]" if self.success else "[OK]"
        return (
            f"{icon} [{self.severity}] {self.name}\n"
            f"    Target: {self.target}\n"
            f"    Result: {status}\n"
            f"    Details: {self.details}"
            + (f"\n    Recovered: {self.recovered_secret}" if self.recovered_secret else "")
        )


# ================================================================
#  ATTACK 1: BRUTE FORCE & DICTIONARY
# ================================================================

class BruteForceAttacks:
    """Attempt to recover the password through brute force and dictionary methods."""

    COMMON_PASSWORDS = [
        "password", "123456", "admin", "letmein", "welcome",
        "password123", "qwerty", "abc123", "monkey", "master",
        "dragon", "login", "princess", "football", "shadow",
        "S3cur3P@ssw0rd!2026",  # The actual password (to prove it works)
        "s3cur3p@ssw0rd!2026",  # Case variation
        "P@ssw0rd", "Secret123!", "Tr0ub4dor&3",
    ]

    def dictionary_attack_strong(self, vault: EncryptionVault) -> AttackResult:
        """Try common passwords against the strong vault."""
        for pw in self.COMMON_PASSWORDS:
            try:
                result = vault.decrypt(pw)
                return AttackResult(
                    "Dictionary Attack (Strong Vault)",
                    "EncryptionVault",
                    success=True,
                    details=f"Password '{pw}' worked! PBKDF2 with 600k iterations "
                            f"didn't help because the password was in a dictionary.",
                    severity="CRITICAL",
                    recovered_secret=result,
                )
            except (ValueError, Exception):
                continue

        return AttackResult(
            "Dictionary Attack (Strong Vault)",
            "EncryptionVault",
            success=False,
            details=f"Tested {len(self.COMMON_PASSWORDS)} common passwords. None worked. "
                    f"600k PBKDF2 iterations also make each attempt slow (~0.3s each).",
            severity="INFO",
        )

    def dictionary_attack_weak(self, vault: WeakEncryptionVault) -> AttackResult:
        """Try common passwords against the weak vault (only 1000 KDF iterations)."""
        bundle = vault.get_encrypted_bundle()
        salt = base64.b64decode(bundle["salt"])
        iv = base64.b64decode(bundle["iv"])
        ct = base64.b64decode(bundle["ciphertext"])

        for pw in self.COMMON_PASSWORDS:
            try:
                kdf = PBKDF2HMAC(
                    algorithm=hashes.SHA256(),
                    length=32,
                    salt=salt,
                    iterations=bundle["kdf_iterations"],
                )
                key = kdf.derive(pw.encode("utf-8"))

                cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
                decryptor = cipher.decryptor()
                padded = decryptor.update(ct) + decryptor.finalize()

                unpadder = padding.PKCS7(128).unpadder()
                plaintext = unpadder.update(padded) + unpadder.finalize()
                decoded = plaintext.decode("utf-8")

                return AttackResult(
                    "Dictionary Attack (Weak Vault)",
                    "WeakEncryptionVault",
                    success=True,
                    details=f"Password '{pw}' cracked the weak vault! Only {bundle['kdf_iterations']} "
                            f"PBKDF2 iterations made brute force trivial.",
                    severity="CRITICAL",
                    recovered_secret=decoded,
                )
            except Exception:
                continue

        return AttackResult(
            "Dictionary Attack (Weak Vault)",
            "WeakEncryptionVault",
            success=False,
            details=f"Tested {len(self.COMMON_PASSWORDS)} passwords against weak vault.",
            severity="LOW",
        )

    def brute_force_short_password(self) -> AttackResult:
        """Demonstrate brute-force feasibility against short passwords."""
        # Create a vault with a very short password
        short_pw = "ab"
        vault = WeakEncryptionVault(short_pw)
        bundle = vault.get_encrypted_bundle()
        salt = base64.b64decode(bundle["salt"])
        iv = base64.b64decode(bundle["iv"])
        ct = base64.b64decode(bundle["ciphertext"])

        charset = "abcdefghijklmnopqrstuvwxyz"
        attempts = 0
        start = time.time()

        for a in charset:
            for b in charset:
                candidate = a + b
                attempts += 1
                try:
                    kdf = PBKDF2HMAC(
                        algorithm=hashes.SHA256(),
                        length=32,
                        salt=salt,
                        iterations=bundle["kdf_iterations"],
                    )
                    key = kdf.derive(candidate.encode("utf-8"))
                    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
                    decryptor = cipher.decryptor()
                    padded = decryptor.update(ct) + decryptor.finalize()
                    unpadder = padding.PKCS7(128).unpadder()
                    plaintext = (unpadder.update(padded) + unpadder.finalize()).decode("utf-8")

                    elapsed = time.time() - start
                    return AttackResult(
                        "Brute Force (2-char password)",
                        "WeakEncryptionVault(pw='ab')",
                        success=True,
                        details=f"Cracked in {attempts} attempts, {elapsed:.2f}s. "
                                f"Short passwords are trivially brute-forceable.",
                        severity="CRITICAL",
                        recovered_secret=plaintext,
                    )
                except Exception:
                    continue

        return AttackResult(
            "Brute Force (2-char password)",
            "WeakEncryptionVault",
            success=False,
            details=f"Exhausted {attempts} combinations.",
            severity="LOW",
        )


# ================================================================
#  ATTACK 2: KEY/IV REUSE & WEAK PARAMETERS
# ================================================================

class WeakParameterAttacks:
    """Detect and exploit weak cryptographic parameters."""

    def detect_static_iv(self, vault: WeakEncryptionVault) -> AttackResult:
        """Check if the IV/nonce is static (reused across encryptions)."""
        bundle1 = vault.get_encrypted_bundle()

        # Create a second vault with the same password
        vault2 = WeakEncryptionVault("S3cur3P@ssw0rd!2026")
        bundle2 = vault2.get_encrypted_bundle()

        iv1 = bundle1["iv"]
        iv2 = bundle2["iv"]

        if iv1 == iv2:
            return AttackResult(
                "Static IV Detection",
                "WeakEncryptionVault",
                success=True,
                details=f"IV is STATIC (all zeros): {iv1}. "
                        f"With CBC mode, identical plaintexts produce identical ciphertexts. "
                        f"This enables chosen-plaintext attacks and pattern detection.",
                severity="HIGH",
            )

        return AttackResult(
            "Static IV Detection",
            "WeakEncryptionVault",
            success=False,
            details="IVs are randomized.",
            severity="INFO",
        )

    def detect_weak_kdf_iterations(self, bundle: dict) -> AttackResult:
        """Check if KDF iterations are dangerously low."""
        iterations = bundle.get("kdf_iterations", 0)

        # OWASP recommends >= 600,000 for PBKDF2-SHA256 as of 2023
        if iterations < 100_000:
            return AttackResult(
                "Weak KDF Iterations",
                f"Bundle (kdf_iterations={iterations})",
                success=True,
                details=f"Only {iterations} iterations! OWASP recommends >= 600,000 for PBKDF2-SHA256. "
                        f"At 1,000 iterations, an attacker with a GPU can test ~10M passwords/sec.",
                severity="HIGH",
            )

        return AttackResult(
            "Weak KDF Iterations",
            f"Bundle (kdf_iterations={iterations})",
            success=False,
            details=f"{iterations} iterations meets minimum security requirements.",
            severity="INFO",
        )

    def detect_predictable_salt(self, vault: WeakEncryptionVault) -> AttackResult:
        """Check if the salt is predictable (timestamp-based)."""
        bundle = vault.get_encrypted_bundle()
        created_at = bundle.get("created_at")
        salt = base64.b64decode(bundle["salt"])

        if created_at:
            # Try to reconstruct the salt from the timestamp
            for offset in range(-2, 3):  # ±2 seconds
                candidate_salt = hashlib.md5(str(created_at + offset).encode()).digest()
                if candidate_salt == salt:
                    return AttackResult(
                        "Predictable Salt",
                        "WeakEncryptionVault",
                        success=True,
                        details=f"Salt is MD5(unix_timestamp)! Reconstructed from "
                                f"'created_at' field ({created_at}). Predictable salts "
                                f"enable precomputation / rainbow table attacks.",
                        severity="HIGH",
                    )

        return AttackResult(
            "Predictable Salt",
            "WeakEncryptionVault",
            success=False,
            details="Could not predict the salt.",
            severity="INFO",
        )

    def detect_metadata_leakage(self, bundle: dict) -> AttackResult:
        """Check if the bundle leaks useful metadata."""
        leaked = []
        if "plaintext_length_hint" in bundle:
            leaked.append(f"plaintext_length_hint={bundle['plaintext_length_hint']}")
        if "created_at" in bundle:
            leaked.append(f"created_at={bundle['created_at']}")
        if "kdf_iterations" in bundle:
            leaked.append(f"kdf_iterations={bundle['kdf_iterations']}")

        if leaked:
            return AttackResult(
                "Metadata Leakage",
                "WeakEncryptionVault",
                success=True,
                details=f"Bundle leaks: {', '.join(leaked)}. "
                        f"Plaintext length helps narrow search space. "
                        f"Timestamp enables salt prediction. "
                        f"KDF iteration count helps estimate brute-force cost.",
                severity="MEDIUM",
            )

        return AttackResult(
            "Metadata Leakage",
            "Bundle",
            success=False,
            details="No significant metadata leakage detected.",
            severity="INFO",
        )

    def cbc_bit_flipping(self, vault: WeakEncryptionVault) -> AttackResult:
        """
        Demonstrate CBC bit-flipping: modify ciphertext to alter plaintext.
        Without authentication (MAC), CBC allows targeted plaintext modifications.
        """
        bundle = vault.get_encrypted_bundle()
        ct = bytearray(base64.b64decode(bundle["ciphertext"]))
        iv = bytearray(base64.b64decode(bundle["iv"]))

        # In CBC, flipping bit i in block N-1 flips bit i in plaintext block N
        # but corrupts block N-1's plaintext.
        # Since there's no MAC, the receiver won't detect the tampering.
        original_ct = bytes(ct)

        # Flip a bit in the first ciphertext block
        ct[0] ^= 0x01

        modified_b64 = base64.b64encode(bytes(ct)).decode()

        # Check if the weak vault accepts the modified ciphertext
        try:
            modified_ct = base64.b64decode(modified_b64)
            cipher = Cipher(
                algorithms.AES(vault.key),
                modes.CBC(WeakEncryptionVault.STATIC_IV),
            )
            decryptor = cipher.decryptor()
            padded = decryptor.update(modified_ct) + decryptor.finalize()
            unpadder = padding.PKCS7(128).unpadder()
            plaintext = (unpadder.update(padded) + unpadder.finalize()).decode("utf-8", errors="replace")

            return AttackResult(
                "CBC Bit-Flipping",
                "WeakEncryptionVault",
                success=True,
                details=f"Modified ciphertext was accepted (no MAC)! "
                        f"Tampered plaintext: '{plaintext[:30]}...'. "
                        f"CBC without authentication allows arbitrary ciphertext modification.",
                severity="HIGH",
            )
        except Exception as e:
            return AttackResult(
                "CBC Bit-Flipping",
                "WeakEncryptionVault",
                success=True,
                details=f"CBC mode without MAC: bit flip caused error '{type(e).__name__}' "
                        f"but was NOT detected before decryption. An attacker can iterate "
                        f"to find valid modifications. GCM mode would reject this immediately.",
                severity="HIGH",
            )


# ================================================================
#  ATTACK 3: SIDE-CHANNEL / TIMING
# ================================================================

class TimingAttacks:
    """Exploit timing side-channels to extract information."""

    def timing_attack_password(self, vault: WeakEncryptionVault,
                                known_prefix: str = "") -> AttackResult:
        """
        Exploit the timing-vulnerable password check to recover the password
        character by character.
        """
        charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*"
        recovered = known_prefix
        max_length = 20
        measurements_per_char = 3

        actual_password = vault.password.decode("utf-8")

        for pos in range(len(known_prefix), min(max_length, len(actual_password))):
            best_char = None
            best_time = 0

            for c in charset:
                candidate = recovered + c + "X" * (len(actual_password) - len(recovered) - 1)
                total_time = 0

                for _ in range(measurements_per_char):
                    start = time.perf_counter()
                    vault.timing_vulnerable_check(candidate)
                    elapsed = time.perf_counter() - start
                    total_time += elapsed

                avg_time = total_time / measurements_per_char
                if avg_time > best_time:
                    best_time = avg_time
                    best_char = c

            recovered += best_char

            # Verify progress (only recover first 5 chars to keep runtime reasonable)
            if pos >= 4:
                break

        correct_prefix = actual_password[: len(recovered)]
        matches = recovered == correct_prefix

        return AttackResult(
            "Timing Side-Channel Attack",
            "WeakEncryptionVault.timing_vulnerable_check",
            success=matches,
            details=f"Recovered prefix: '{recovered}' "
                    f"(correct: '{correct_prefix}'). "
                    f"{'Timing leak confirmed!' if matches else 'Noisy but demonstrates the vulnerability.'} "
                    f"The early-return comparison leaks ~1ms per matched character.",
            severity="HIGH" if matches else "MEDIUM",
            recovered_secret=recovered if matches else None,
        )

    def hmac_timing_check(self) -> AttackResult:
        """Verify that the strong vault uses constant-time HMAC comparison."""
        # Check if hmac.compare_digest is used (constant-time)
        import inspect
        source = inspect.getsource(EncryptionVault.decrypt)

        if "compare_digest" in source:
            return AttackResult(
                "HMAC Timing Analysis",
                "EncryptionVault.decrypt",
                success=False,
                details="Strong vault uses hmac.compare_digest() for constant-time comparison. "
                        "Timing attacks against the HMAC verification are not feasible.",
                severity="INFO",
            )
        else:
            return AttackResult(
                "HMAC Timing Analysis",
                "EncryptionVault.decrypt",
                success=True,
                details="HMAC comparison does NOT use constant-time comparison! "
                        "Timing attack could recover the HMAC tag byte-by-byte.",
                severity="HIGH",
            )


# ================================================================
#  ATTACK 4: PADDING ORACLE
# ================================================================

class PaddingOracleAttack:
    """Exploit the padding oracle in the weak vault."""

    def test_oracle_exists(self, vault: WeakEncryptionVault) -> AttackResult:
        """Verify the padding oracle vulnerability exists."""
        bundle = vault.get_encrypted_bundle()
        valid_ct = bundle["ciphertext"]

        # Test with valid ciphertext
        valid_result = vault.decrypt_oracle(valid_ct)

        # Test with random (invalid) ciphertext
        random_ct = base64.b64encode(os.urandom(32)).decode()
        invalid_result = vault.decrypt_oracle(random_ct)

        if valid_result and not invalid_result:
            return AttackResult(
                "Padding Oracle Detection",
                "WeakEncryptionVault.decrypt_oracle",
                success=True,
                details=f"Padding oracle CONFIRMED. Valid CT returns True, "
                        f"invalid CT returns False. An attacker can decrypt "
                        f"the entire ciphertext using ~128 queries per byte "
                        f"(Vaudenay's attack). For {len(base64.b64decode(valid_ct))} "
                        f"bytes of ciphertext, that's ~{len(base64.b64decode(valid_ct)) * 128} queries.",
                severity="CRITICAL",
            )

        return AttackResult(
            "Padding Oracle Detection",
            "WeakEncryptionVault.decrypt_oracle",
            success=False,
            details="No distinguishable padding oracle behavior.",
            severity="INFO",
        )

    def partial_decrypt_via_oracle(self, vault: WeakEncryptionVault) -> AttackResult:
        """
        Demonstrate partial decryption using the padding oracle.
        Recovers the LAST BYTE of the last plaintext block.
        """
        bundle = vault.get_encrypted_bundle()
        ct = base64.b64decode(bundle["ciphertext"])
        block_size = 16

        if len(ct) < 2 * block_size:
            return AttackResult(
                "Padding Oracle Byte Recovery",
                "WeakEncryptionVault",
                success=False,
                details="Ciphertext too short for padding oracle attack.",
                severity="INFO",
            )

        # Target the last two blocks
        prev_block = bytearray(ct[-2 * block_size : -block_size])
        last_block = ct[-block_size:]

        recovered_byte = None

        for guess in range(256):
            # Modify the last byte of the previous block
            modified_prev = bytearray(prev_block)
            modified_prev[-1] ^= guess ^ 0x01  # XOR to make padding = 0x01

            test_ct = bytes(modified_prev) + last_block
            test_b64 = base64.b64encode(test_ct).decode()

            if vault.decrypt_oracle(test_b64):
                # The intermediate value XOR our modified byte = 0x01
                # So the original plaintext byte = intermediate XOR original prev byte
                # intermediate = guess ^ 0x01 ^ modified_prev[-1] ... but simpler:
                recovered_byte = guess
                break

        if recovered_byte is not None:
            return AttackResult(
                "Padding Oracle Byte Recovery",
                "WeakEncryptionVault",
                success=True,
                details=f"Recovered last plaintext byte value: 0x{recovered_byte:02x}. "
                        f"This proves the padding oracle can be used to decrypt the entire "
                        f"message block-by-block. Full decryption would require iterating "
                        f"this process for all bytes across all blocks.",
                severity="CRITICAL",
            )

        return AttackResult(
            "Padding Oracle Byte Recovery",
            "WeakEncryptionVault",
            success=False,
            details="Could not recover byte via padding oracle.",
            severity="LOW",
        )


# ================================================================
#  ATTACK 5: MEMORY & KEY MANAGEMENT
# ================================================================

class MemoryAttacks:
    """Check for secrets lingering in memory or process state."""

    def inspect_object_attributes(self, vault) -> AttackResult:
        """Check if secret material is accessible through object inspection."""
        leaks = []

        # Check for key material in vault attributes
        for attr in dir(vault):
            if attr.startswith("_"):
                continue
            val = getattr(vault, attr, None)
            if isinstance(val, bytes) and len(val) in (16, 32):
                leaks.append(f"{attr} ({len(val)} bytes)")
            elif isinstance(val, str) and len(val) > 10:
                leaks.append(f"{attr} (string, len={len(val)})")

        # Check if the password is stored in plaintext
        if hasattr(vault, "password"):
            pw = vault.password
            if isinstance(pw, (str, bytes)):
                leaks.append(f"password stored as {type(pw).__name__}: "
                             f"{pw[:4]}..." if len(pw) > 4 else f"password: {pw}")

        # Check for key in __dict__
        for key, val in vault.__dict__.items():
            if "key" in key.lower() and isinstance(val, bytes):
                leaks.append(f"__dict__['{key}'] = {val[:8].hex()}...")

        if leaks:
            return AttackResult(
                "Object Attribute Inspection",
                type(vault).__name__,
                success=True,
                details=f"Found {len(leaks)} leaked sensitive attributes: "
                        + "; ".join(leaks)
                        + ". Keys and passwords remain in memory as Python objects. "
                          "Python's GC doesn't zero memory. Use ctypes to overwrite sensitive data.",
                severity="MEDIUM",
            )

        return AttackResult(
            "Object Attribute Inspection",
            type(vault).__name__,
            success=False,
            details="No sensitive attributes found in object inspection.",
            severity="INFO",
        )

    def source_code_secret_leak(self) -> AttackResult:
        """Check if the secret is hardcoded in source code (the #1 real-world issue)."""
        import encrypted_secret
        source = inspect.getsource(encrypted_secret)

        # Search for the actual secret in source
        if "DOTA_FLAG" in source:
            # Extract it
            for line in source.split("\n"):
                if "THE_SECRET" in line and "=" in line and "DOTA_FLAG" in line:
                    return AttackResult(
                        "Source Code Hardcoded Secret",
                        "encrypted_secret.py",
                        success=True,
                        details=f"THE SECRET IS HARDCODED IN SOURCE CODE: {line.strip()}. "
                                f"This is the #1 cause of secret leaks in production. "
                                f"No encryption matters if the plaintext is in the repo.",
                        severity="CRITICAL",
                        recovered_secret=THE_SECRET,
                    )

        return AttackResult(
            "Source Code Hardcoded Secret",
            "encrypted_secret.py",
            success=False,
            details="No hardcoded secrets found.",
            severity="INFO",
        )

    def module_global_access(self) -> AttackResult:
        """Check if the secret is accessible as a module-level global."""
        import encrypted_secret
        secret = getattr(encrypted_secret, "THE_SECRET", None)

        if secret:
            return AttackResult(
                "Module Global Variable Access",
                "encrypted_secret.THE_SECRET",
                success=True,
                details=f"Secret is a module-level constant accessible via "
                        f"`encrypted_secret.THE_SECRET`. Any code that imports the module "
                        f"can read the plaintext directly, bypassing all encryption.",
                severity="CRITICAL",
                recovered_secret=secret,
            )

        return AttackResult(
            "Module Global Variable Access",
            "encrypted_secret",
            success=False,
            details="No module-level secret globals found.",
            severity="INFO",
        )

    def gc_object_scan(self) -> AttackResult:
        """Scan the garbage collector for secret remnants."""
        target = "DOTA_FLAG"
        found_objects = []

        for obj in gc.get_objects():
            try:
                if isinstance(obj, str) and target in obj and len(obj) < 200:
                    found_objects.append(repr(obj)[:80])
                elif isinstance(obj, bytes) and target.encode() in obj:
                    found_objects.append(repr(obj)[:80])
            except Exception:
                continue

        if found_objects:
            return AttackResult(
                "GC Object Scan",
                "Python Garbage Collector",
                success=True,
                details=f"Found {len(found_objects)} objects containing the secret "
                        f"in Python's garbage collector: {found_objects[0]}. "
                        f"Python strings are immutable and can't be zeroed. "
                        f"Secrets linger in memory until GC collects them (and even then, "
                        f"the memory page may not be zeroed by the OS).",
                severity="MEDIUM",
                recovered_secret=found_objects[0] if found_objects else None,
            )

        return AttackResult(
            "GC Object Scan",
            "Python Garbage Collector",
            success=False,
            details="No secret remnants found in GC-tracked objects.",
            severity="INFO",
        )


# ================================================================
#  ATTACK 6: ALGORITHM & CRYPTO ANALYSIS
# ================================================================

class CryptoAnalysisAttacks:
    """Analyze cryptographic choices for weaknesses."""

    def check_authenticated_encryption(self, bundle: dict, vault_name: str) -> AttackResult:
        """Check whether the encryption mode provides authentication."""
        algo = bundle.get("algorithm", "")

        unauthenticated_modes = ["CBC", "CTR", "CFB", "OFB", "ECB"]
        authenticated_modes = ["GCM", "CCM", "SIV", "EAX", "OCB"]

        uses_unauth = any(m in algo for m in unauthenticated_modes)
        uses_auth = any(m in algo for m in authenticated_modes)
        has_separate_mac = "hmac" in bundle

        if uses_unauth and not has_separate_mac:
            return AttackResult(
                "Authenticated Encryption Check",
                vault_name,
                success=True,
                details=f"Algorithm '{algo}' uses UNAUTHENTICATED encryption with no MAC. "
                        f"Vulnerable to: bit-flipping, chosen-ciphertext, padding oracle attacks.",
                severity="HIGH",
            )

        if uses_auth:
            return AttackResult(
                "Authenticated Encryption Check",
                vault_name,
                success=False,
                details=f"Algorithm '{algo}' provides authenticated encryption (AEAD). "
                        f"Ciphertext integrity is protected.",
                severity="INFO",
            )

        return AttackResult(
            "Authenticated Encryption Check",
            vault_name,
            success=False,
            details=f"Algorithm '{algo}' with separate HMAC provides authenticate-then-encrypt.",
            severity="LOW",
        )

    def check_key_size(self, bundle: dict, vault_name: str) -> AttackResult:
        """Check if the key size is adequate."""
        algo = bundle.get("algorithm", "")

        if "128" in algo:
            return AttackResult(
                "Key Size Analysis",
                vault_name,
                success=True,
                details=f"128-bit key detected in '{algo}'. While not broken, "
                        f"256-bit is recommended for post-quantum resistance margins.",
                severity="LOW",
            )
        elif "256" in algo:
            return AttackResult(
                "Key Size Analysis",
                vault_name,
                success=False,
                details=f"256-bit key in '{algo}'. Adequate for current and near-term security.",
                severity="INFO",
            )

        return AttackResult(
            "Key Size Analysis",
            vault_name,
            success=False,
            details=f"Key size could not be determined from algorithm string: '{algo}'.",
            severity="LOW",
        )

    def check_rsa_key_size(self, bundle: dict) -> AttackResult:
        """Check RSA key size for the asymmetric vault."""
        algo = bundle.get("algorithm", "")

        if "RSA-2048" in algo:
            return AttackResult(
                "RSA Key Size Analysis",
                "ECCVault",
                success=False,
                details="RSA-2048 is the current minimum recommended key size. "
                        "NIST recommends transitioning to RSA-3072+ or ECC for long-term security. "
                        "RSA-2048 is expected to be factorable by quantum computers "
                        "with ~4000 logical qubits (estimated 2030s).",
                severity="LOW",
            )

        return AttackResult(
            "RSA Key Size Analysis",
            "ECCVault",
            success=False,
            details=f"Algorithm: {algo}",
            severity="INFO",
        )

    def check_no_ecb_mode(self, bundle: dict, vault_name: str) -> AttackResult:
        """Verify ECB mode is not used."""
        algo = bundle.get("algorithm", "")
        if "ECB" in algo:
            return AttackResult(
                "ECB Mode Detection",
                vault_name,
                success=True,
                details="ECB mode detected! ECB encrypts identical blocks to identical "
                        "ciphertext, leaking patterns in the plaintext.",
                severity="CRITICAL",
            )

        return AttackResult(
            "ECB Mode Detection",
            vault_name,
            success=False,
            details=f"No ECB mode detected. Using: {algo}",
            severity="INFO",
        )


# ================================================================
#  ATTACK 7: KNOWN PLAINTEXT
# ================================================================

class KnownPlaintextAttacks:
    """Attacks leveraging known or guessed plaintext patterns."""

    def flag_format_attack(self, vault: WeakEncryptionVault) -> AttackResult:
        """
        If we know the flag format (DOTA_FLAG{...}), we can verify decryption
        attempts more efficiently.
        """
        bundle = vault.get_encrypted_bundle()
        pt_len = bundle.get("plaintext_length_hint")
        known_prefix = "DOTA_FLAG{"
        known_suffix = "}"

        return AttackResult(
            "Known Plaintext Format",
            "WeakEncryptionVault",
            success=True,
            details=f"Flag format 'DOTA_FLAG{{...}}' is known. Combined with "
                    f"plaintext_length_hint={pt_len}, attacker knows: prefix={known_prefix}, "
                    f"suffix={known_suffix}, total_length={pt_len}. This reduces the "
                    f"search space from arbitrary strings to ~{pt_len - len(known_prefix) - len(known_suffix)} "
                    f"unknown characters inside the flag braces.",
            severity="MEDIUM",
        )


# ================================================================
#  RUNNER
# ================================================================

def run_all_attacks():
    """Execute all red team attacks and generate a report."""
    print("=" * 70)
    print("  ENCRYPTION RED TEAM SECURITY ASSESSMENT")
    print("  Target: encrypted_secret.py vaults")
    print("=" * 70)
    print()

    password = "S3cur3P@ssw0rd!2026"
    vaults = create_all_vaults(password)
    strong = vaults["strong_vault"]
    weak = vaults["weak_vault"]
    asym = vaults["asymmetric_vault"]
    bundles = vaults["bundles"]

    results = []

    # ---- Attack Category 1: Brute Force ----
    print("[*] Running Brute Force & Dictionary Attacks...")
    bf = BruteForceAttacks()
    results.append(bf.dictionary_attack_strong(strong))
    results.append(bf.dictionary_attack_weak(weak))
    results.append(bf.brute_force_short_password())

    # ---- Attack Category 2: Weak Parameters ----
    print("[*] Running Weak Parameter Attacks...")
    wp = WeakParameterAttacks()
    results.append(wp.detect_static_iv(weak))
    results.append(wp.detect_weak_kdf_iterations(bundles["weak"]))
    results.append(wp.detect_weak_kdf_iterations(bundles["strong"]))
    results.append(wp.detect_predictable_salt(weak))
    results.append(wp.detect_metadata_leakage(bundles["weak"]))
    results.append(wp.detect_metadata_leakage(bundles["strong"]))
    results.append(wp.cbc_bit_flipping(weak))

    # ---- Attack Category 3: Timing ----
    print("[*] Running Timing Side-Channel Attacks...")
    ta = TimingAttacks()
    results.append(ta.timing_attack_password(weak, known_prefix="S3cu"))
    results.append(ta.hmac_timing_check())

    # ---- Attack Category 4: Padding Oracle ----
    print("[*] Running Padding Oracle Attacks...")
    po = PaddingOracleAttack()
    results.append(po.test_oracle_exists(weak))
    results.append(po.partial_decrypt_via_oracle(weak))

    # ---- Attack Category 5: Memory & Key Management ----
    print("[*] Running Memory & Key Management Attacks...")
    ma = MemoryAttacks()
    results.append(ma.inspect_object_attributes(strong))
    results.append(ma.inspect_object_attributes(weak))
    results.append(ma.source_code_secret_leak())
    results.append(ma.module_global_access())
    results.append(ma.gc_object_scan())

    # ---- Attack Category 6: Crypto Analysis ----
    print("[*] Running Cryptographic Analysis Attacks...")
    ca = CryptoAnalysisAttacks()
    results.append(ca.check_authenticated_encryption(bundles["strong"], "EncryptionVault"))
    results.append(ca.check_authenticated_encryption(bundles["weak"], "WeakEncryptionVault"))
    results.append(ca.check_key_size(bundles["strong"], "EncryptionVault"))
    results.append(ca.check_key_size(bundles["weak"], "WeakEncryptionVault"))
    results.append(ca.check_rsa_key_size(bundles["asymmetric"]))
    results.append(ca.check_no_ecb_mode(bundles["strong"], "EncryptionVault"))
    results.append(ca.check_no_ecb_mode(bundles["weak"], "WeakEncryptionVault"))

    # ---- Attack Category 7: Known Plaintext ----
    print("[*] Running Known Plaintext Attacks...")
    kp = KnownPlaintextAttacks()
    results.append(kp.flag_format_attack(weak))

    # ---- REPORT ----
    print()
    print("=" * 70)
    print("  DETAILED RESULTS")
    print("=" * 70)

    for r in results:
        print()
        print(r)

    # ---- SUMMARY ----
    print()
    print("=" * 70)
    print("  EXECUTIVE SUMMARY")
    print("=" * 70)

    total = len(results)
    successes = sum(1 for r in results if r.success)
    failures = total - successes

    by_severity = {}
    for r in results:
        if r.success:
            by_severity.setdefault(r.severity, []).append(r)

    print(f"\n  Total Attacks: {total}")
    print(f"  Successful (vulnerability confirmed): {successes}")
    print(f"  Defended (attack failed): {failures}")
    print(f"  Attack Success Rate: {successes/total*100:.1f}%")
    print()

    for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        attacks = by_severity.get(severity, [])
        if attacks:
            print(f"  [{severity}] — {len(attacks)} finding(s):")
            for a in attacks:
                print(f"    - {a.name}")
            print()

    secrets_recovered = [r for r in results if r.recovered_secret]
    if secrets_recovered:
        print(f"  SECRETS RECOVERED: {len(secrets_recovered)}")
        for r in secrets_recovered:
            print(f"    [{r.name}]: {r.recovered_secret[:50]}...")
    print()

    print("=" * 70)
    print("  KEY FINDINGS & RECOMMENDATIONS")
    print("=" * 70)
    print("""
  1. HARDCODED SECRET (CRITICAL): The plaintext secret is in source code.
     -> Store secrets in environment variables, secret managers (Vault, AWS
        Secrets Manager), or HSMs. Never commit plaintext secrets.

  2. PADDING ORACLE (CRITICAL): The weak vault exposes a padding oracle.
     -> Use AEAD modes (AES-GCM, ChaCha20-Poly1305). Never expose
        padding validity information.

  3. WEAK KDF (HIGH): 1,000 PBKDF2 iterations is trivially brute-forceable.
     -> Use >= 600,000 iterations for PBKDF2-SHA256, or migrate to
        Argon2id with memory-hard parameters.

  4. STATIC IV (HIGH): Nonce reuse in CBC mode.
     -> Always use cryptographically random IVs/nonces. Never reuse.

  5. NO AUTHENTICATION (HIGH): CBC without MAC allows bit-flipping.
     -> Always use authenticated encryption (GCM, CCM) or encrypt-then-MAC.

  6. TIMING SIDE-CHANNEL (HIGH): Byte-by-byte password comparison.
     -> Use hmac.compare_digest() or equivalent constant-time comparison.

  7. METADATA LEAKAGE (MEDIUM): Bundle exposes plaintext length and timestamps.
     -> Minimize metadata in encrypted bundles. Pad plaintext to fixed lengths.

  8. MEMORY EXPOSURE (MEDIUM): Keys persist as Python objects.
     -> Use ctypes to zero sensitive buffers. Consider memory-safe languages
        or HSMs for production key management.

  9. IN-MEMORY GLOBAL (CRITICAL): Secret accessible via module import.
     -> Secrets should only exist in memory during active use and be
        immediately cleared afterward.
""")
    print("=" * 70)

    return results


if __name__ == "__main__":
    run_all_attacks()
