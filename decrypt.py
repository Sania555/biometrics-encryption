"""
Decrypt: capture live face → compare to enrolled embedding → derive AES key → decrypt.
Access is denied if face doesn't match or ciphertext is tampered.
"""

import json
import numpy as np
from face_auth import capture_face_embedding, embeddings_match
from enroll import load_profile
from crypto_utils import embedding_to_key, decrypt_data
from cryptography.exceptions import InvalidTag

MAX_ATTEMPTS = 3


def decrypt_for_user(username: str, enc_path: str) -> bytes | None:
    """
    1. Load encrypted payload
    2. Capture live face
    3. Compare to enrolled embedding
    4. Derive AES key from live embedding
    5. Decrypt — GCM tag verification ensures integrity
    """
    profile = load_profile(username)
    if not profile:
        return None

    with open(enc_path) as f:
        payload = json.load(f)

    if payload["username"] != username:
        print("[Decrypt] Username mismatch in encrypted file.")
        return None

    salt = bytes.fromhex(payload["salt"])
    nonce = bytes.fromhex(payload["nonce"])
    ciphertext = bytes.fromhex(payload["ciphertext"])
    enrolled_embedding = np.array(profile["enrolled_embedding"])

    for attempt in range(1, MAX_ATTEMPTS + 1):
        print(f"\n[Decrypt] Attempt {attempt}/{MAX_ATTEMPTS} — Look at the camera and press SPACE.")
        live_embedding = capture_face_embedding("AUTHENTICATION — Press SPACE to capture")

        if live_embedding is None:
            print("[Decrypt] Capture cancelled.")
            return None

        matched, distance = embeddings_match(enrolled_embedding, live_embedding)
        print(f"[Decrypt] Face distance: {distance:.4f} (threshold: 0.45) — {'MATCH' if matched else 'NO MATCH'}")

        if not matched:
            print(f"[Decrypt] Face not recognized. {'No more attempts.' if attempt == MAX_ATTEMPTS else 'Try again.'}")
            continue

        # Derive key from live embedding (must match enrolled to produce same key)
        key = embedding_to_key(live_embedding, salt)

        try:
            plaintext = decrypt_data(nonce, ciphertext, key)
            print("[Decrypt] Access granted. Data decrypted successfully.")
            return plaintext
        except InvalidTag:
            # This can happen if face matched visually but embedding drift caused key mismatch
            print("[Decrypt] Decryption failed — key mismatch or data integrity violation.")
            # Fallback: try with enrolled embedding directly (handles minor embedding drift)
            try:
                key_enrolled = embedding_to_key(enrolled_embedding, salt)
                plaintext = decrypt_data(nonce, ciphertext, key_enrolled)
                print("[Decrypt] Access granted via enrolled embedding fallback.")
                return plaintext
            except InvalidTag:
                print("[Decrypt] Integrity check failed. Data may be tampered.")
                return None

    print("[Decrypt] Maximum attempts reached. Access denied.")
    return None
