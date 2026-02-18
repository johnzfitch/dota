"""
Encrypted Secret Module
=======================
Creates an encrypted secret using multiple layers and techniques.
This is the TARGET that the red team tests will attempt to break.
"""

import os
import json
import time
import hmac
import hashlib
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives import hashes, padding, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding as asym_padding
from cryptography.hazmat.backends import default_backend


# ============================================================
# THE SECRET — this is what red teamers are trying to recover
# ============================================================
THE_SECRET = "DOTA_FLAG{cr0wn_0f_th3_sh4d0w_k1ng_2026}"


class EncryptionVault:
    """Production-grade encryption vault protecting a secret."""

    def __init__(self, password: str):
        self.password = password.encode("utf-8")
        self._setup_keys()
        self._encrypt_secret()

    def _setup_keys(self):
        """Derive encryption keys from password using PBKDF2."""
        self.salt = os.urandom(16)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self.salt,
            iterations=600_000,
        )
        self.master_key = kdf.derive(self.password)

        # Derive sub-keys for different purposes
        self.encryption_key = hashlib.sha256(self.master_key + b"encrypt").digest()
        self.hmac_key = hashlib.sha256(self.master_key + b"hmac").digest()

    def _encrypt_secret(self):
        """Encrypt the secret with AES-256-GCM."""
        self.nonce = os.urandom(12)
        cipher = Cipher(
            algorithms.AES(self.encryption_key),
            modes.GCM(self.nonce),
        )
        encryptor = cipher.encryptor()
        self.ciphertext = encryptor.update(THE_SECRET.encode("utf-8")) + encryptor.finalize()
        self.tag = encryptor.tag

        # Also compute HMAC over the ciphertext for integrity
        self.hmac_tag = hmac.new(
            self.hmac_key, self.ciphertext, hashlib.sha256
        ).digest()

    def get_encrypted_bundle(self) -> dict:
        """Return the encrypted bundle (what an attacker would see)."""
        return {
            "salt": base64.b64encode(self.salt).decode(),
            "nonce": base64.b64encode(self.nonce).decode(),
            "ciphertext": base64.b64encode(self.ciphertext).decode(),
            "gcm_tag": base64.b64encode(self.tag).decode(),
            "hmac": base64.b64encode(self.hmac_tag).decode(),
            "algorithm": "AES-256-GCM",
            "kdf": "PBKDF2-HMAC-SHA256",
            "kdf_iterations": 600_000,
        }

    def decrypt(self, password: str) -> str:
        """Decrypt with the correct password."""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self.salt,
            iterations=600_000,
        )
        master_key = kdf.derive(password.encode("utf-8"))
        enc_key = hashlib.sha256(master_key + b"encrypt").digest()
        hmac_key = hashlib.sha256(master_key + b"hmac").digest()

        # Verify HMAC first
        expected_hmac = hmac.new(hmac_key, self.ciphertext, hashlib.sha256).digest()
        if not hmac.compare_digest(expected_hmac, self.hmac_tag):
            raise ValueError("HMAC verification failed — wrong password or tampered data")

        cipher = Cipher(algorithms.AES(enc_key), modes.GCM(self.nonce, self.tag))
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(self.ciphertext) + decryptor.finalize()
        return plaintext.decode("utf-8")


class WeakEncryptionVault:
    """
    INTENTIONALLY WEAK encryption vault for red team testing.
    Contains multiple deliberate vulnerabilities.
    """

    # Vulnerability 1: Hardcoded IV (nonce reuse)
    STATIC_IV = b"\x00" * 16

    # Vulnerability 2: Weak key derivation (only 1000 iterations)
    KDF_ITERATIONS = 1000

    def __init__(self, password: str):
        self.password = password.encode("utf-8")
        # Vulnerability 3: Predictable salt (timestamp-based)
        self.salt = hashlib.md5(str(int(time.time())).encode()).digest()
        self._derive_key()
        self._encrypt()

    def _derive_key(self):
        """Weak key derivation."""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self.salt,
            iterations=self.KDF_ITERATIONS,  # Way too low
        )
        self.key = kdf.derive(self.password)

    def _encrypt(self):
        """Encrypt using AES-CBC with PKCS7 padding (no authentication)."""
        padder = padding.PKCS7(128).padder()
        padded = padder.update(THE_SECRET.encode("utf-8")) + padder.finalize()

        cipher = Cipher(algorithms.AES(self.key), modes.CBC(self.STATIC_IV))
        encryptor = cipher.encryptor()
        self.ciphertext = encryptor.update(padded) + encryptor.finalize()

    def get_encrypted_bundle(self) -> dict:
        """Return the weak encrypted bundle."""
        return {
            "salt": base64.b64encode(self.salt).decode(),
            "iv": base64.b64encode(self.STATIC_IV).decode(),
            "ciphertext": base64.b64encode(self.ciphertext).decode(),
            "algorithm": "AES-256-CBC",
            "kdf": "PBKDF2-HMAC-SHA256",
            "kdf_iterations": self.KDF_ITERATIONS,
            # Vulnerability 4: Leaking metadata
            "plaintext_length_hint": len(THE_SECRET),
            "created_at": int(time.time()),
        }

    def decrypt_oracle(self, ciphertext_b64: str) -> bool:
        """
        Vulnerability 5: Padding oracle — returns whether padding is valid.
        This leaks information about the plaintext one byte at a time.
        """
        try:
            ct = base64.b64decode(ciphertext_b64)
            cipher = Cipher(algorithms.AES(self.key), modes.CBC(self.STATIC_IV))
            decryptor = cipher.decryptor()
            padded = decryptor.update(ct) + decryptor.finalize()
            unpadder = padding.PKCS7(128).unpadder()
            unpadder.update(padded) + unpadder.finalize()
            return True  # Valid padding
        except Exception:
            return False  # Invalid padding

    def timing_vulnerable_check(self, candidate_password: str) -> bool:
        """
        Vulnerability 6: Timing side-channel in password comparison.
        Uses byte-by-byte comparison instead of constant-time.
        """
        correct = self.password
        candidate = candidate_password.encode("utf-8")
        if len(correct) != len(candidate):
            return False
        for a, b in zip(correct, candidate):
            if a != b:
                return False  # Early return leaks position info
            time.sleep(0.001)  # Amplify timing difference
        return True


class ECCVault:
    """Asymmetric encryption vault using Elliptic Curve Cryptography."""

    def __init__(self):
        self.private_key = ec.generate_private_key(ec.SECP256R1())
        self.public_key = self.private_key.public_key()

        # Encrypt with RSA hybrid approach
        self.rsa_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        self.rsa_public = self.rsa_key.public_key()
        self._encrypt()

    def _encrypt(self):
        """Hybrid encryption: RSA encrypts the AES key, AES encrypts the secret."""
        self.aes_key = os.urandom(32)
        self.nonce = os.urandom(12)

        # RSA-encrypt the AES key
        self.encrypted_aes_key = self.rsa_public.encrypt(
            self.aes_key,
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )

        # AES-GCM encrypt the secret
        cipher = Cipher(algorithms.AES(self.aes_key), modes.GCM(self.nonce))
        encryptor = cipher.encryptor()
        self.ciphertext = encryptor.update(THE_SECRET.encode("utf-8")) + encryptor.finalize()
        self.tag = encryptor.tag

    def get_encrypted_bundle(self) -> dict:
        return {
            "encrypted_aes_key": base64.b64encode(self.encrypted_aes_key).decode(),
            "nonce": base64.b64encode(self.nonce).decode(),
            "ciphertext": base64.b64encode(self.ciphertext).decode(),
            "gcm_tag": base64.b64encode(self.tag).decode(),
            "rsa_public_key": self.rsa_public.public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            ).decode(),
            "algorithm": "RSA-2048-OAEP + AES-256-GCM",
        }


def create_all_vaults(password: str = "S3cur3P@ssw0rd!2026") -> dict:
    """Create all three vault types and return their bundles."""
    strong = EncryptionVault(password)
    weak = WeakEncryptionVault(password)
    asymmetric = ECCVault()

    return {
        "strong_vault": strong,
        "weak_vault": weak,
        "asymmetric_vault": asymmetric,
        "bundles": {
            "strong": strong.get_encrypted_bundle(),
            "weak": weak.get_encrypted_bundle(),
            "asymmetric": asymmetric.get_encrypted_bundle(),
        },
    }


if __name__ == "__main__":
    vaults = create_all_vaults()
    print("=== Encrypted Bundles (what an attacker sees) ===\n")
    for name, bundle in vaults["bundles"].items():
        print(f"--- {name.upper()} ---")
        print(json.dumps(bundle, indent=2))
        print()
