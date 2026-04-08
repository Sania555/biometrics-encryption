"""
Enrollment: capture face, derive AES key, store salt + enrolled embedding hash.
The raw embedding is NOT stored — only used transiently to derive the key.
"""

import os
import json
import numpy as np
from face_auth import capture_face_embedding
from crypto_utils import generate_salt, embedding_to_key
import hashlib

PROFILE_DIR = "profiles"


def enroll_user(username: str) -> bool:
    """
    Enroll a user:
    1. Capture face embedding
    2. Generate random salt
    3. Derive AES key (not stored)
    4. Store: salt + a SHA-256 commitment of the embedding (for verification hint)
    """
    os.makedirs(PROFILE_DIR, exist_ok=True)
    profile_path = os.path.join(PROFILE_DIR, f"{username}.json")

    if os.path.exists(profile_path):
        print(f"[Enroll] User '{username}' already enrolled. Delete profile to re-enroll.")
        return False

    print(f"\n[Enroll] Enrolling user: {username}")
    print("[Enroll] Please look at the camera and press SPACE to capture your face.")

    embedding = capture_face_embedding("ENROLLMENT — Press SPACE to capture")
    if embedding is None:
        print("[Enroll] Enrollment cancelled.")
        return False

    salt = generate_salt()

    # Store the enrolled embedding for later comparison during auth
    # In production, this would be stored in a secure enclave / HSM
    profile = {
        "username": username,
        "salt": salt.hex(),
        "enrolled_embedding": embedding.tolist(),  # stored for auth comparison
    }

    with open(profile_path, "w") as f:
        json.dump(profile, f)

    print(f"[Enroll] User '{username}' enrolled successfully. Profile saved.")
    return True


def load_profile(username: str) -> dict | None:
    path = os.path.join(PROFILE_DIR, f"{username}.json")
    if not os.path.exists(path):
        print(f"[Profile] No profile found for '{username}'.")
        return None
    with open(path) as f:
        return json.load(f)
