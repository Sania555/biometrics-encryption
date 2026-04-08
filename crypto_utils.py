"""
AES-256 encryption utilities with face-embedding-based key derivation.
Key derivation: PBKDF2-HMAC-SHA256 over the face embedding bytes.
"""

import os
import hashlib
import numpy as np
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

# Fixed salt stored alongside encrypted data (not secret, but unique per enrollment)
PBKDF2_ITERATIONS = 600_000  # OWASP 2023 recommendation


def embedding_to_key(embedding: np.ndarray, salt: bytes) -> bytes:
    """Derive a 256-bit AES key from a 128-d face embedding using PBKDF2."""
    # Quantize embedding to bytes: round to 2 decimal places for stability across captures,
    # then encode as float32 bytes. Facenet embeddings are L2-normalized floats.
    rounded = np.round(embedding.astype(np.float32), decimals=2)
    embedding_bytes = rounded.tobytes()

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # 256-bit key
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )
    return kdf.derive(embedding_bytes)


def encrypt_data(plaintext: bytes, key: bytes) -> tuple[bytes, bytes]:
    """
    AES-256-GCM encryption.
    Returns (nonce, ciphertext+tag). GCM provides both confidentiality and integrity.
    """
    nonce = os.urandom(12)  # 96-bit nonce, standard for GCM
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    return nonce, ciphertext


def decrypt_data(nonce: bytes, ciphertext: bytes, key: bytes) -> bytes:
    """
    AES-256-GCM decryption. Raises InvalidTag if key is wrong or data tampered.
    """
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, None)


def generate_salt() -> bytes:
    return os.urandom(16)
