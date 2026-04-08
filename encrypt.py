"""
Encrypt a file or text using the AES key derived from the enrolled face embedding.
Output: .enc file containing salt + nonce + ciphertext (all hex-encoded JSON).
"""

import json
import numpy as np
from enroll import load_profile
from crypto_utils import embedding_to_key, encrypt_data


def encrypt_for_user(username: str, plaintext: bytes, output_path: str) -> bool:
    """
    Encrypt plaintext using the AES key derived from the enrolled face embedding.
    No live face capture needed here — uses stored enrollment embedding.
    """
    profile = load_profile(username)
    if not profile:
        return False

    salt = bytes.fromhex(profile["salt"])
    enrolled_embedding = np.array(profile["enrolled_embedding"])

    # Derive AES key from enrolled embedding
    key = embedding_to_key(enrolled_embedding, salt)

    nonce, ciphertext = encrypt_data(plaintext, key)

    payload = {
        "username": username,
        "salt": salt.hex(),
        "nonce": nonce.hex(),
        "ciphertext": ciphertext.hex(),
    }

    with open(output_path, "w") as f:
        json.dump(payload, f)

    print(f"[Encrypt] Data encrypted → {output_path}")
    return True
