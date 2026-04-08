"""
Biometric-Based Encryption System
Use Case: Face Recognition → AES Key Derivation → Confidential Data Access

Usage:
  python main.py enroll <username>
  python main.py encrypt <username> <plaintext_file> <output.enc>
  python main.py decrypt <username> <input.enc>
  python main.py demo <username>
"""

import sys
import os
from enroll import enroll_user
from encrypt import encrypt_for_user
from decrypt import decrypt_for_user


def cmd_enroll(args):
    if len(args) < 1:
        print("Usage: python main.py enroll <username>")
        return
    enroll_user(args[0])


def cmd_encrypt(args):
    if len(args) < 3:
        print("Usage: python main.py encrypt <username> <plaintext_file> <output.enc>")
        return
    username, src, dst = args[0], args[1], args[2]
    if not os.path.exists(src):
        print(f"File not found: {src}")
        return
    with open(src, "rb") as f:
        plaintext = f.read()
    encrypt_for_user(username, plaintext, dst)


def cmd_decrypt(args):
    if len(args) < 2:
        print("Usage: python main.py decrypt <username> <input.enc>")
        return
    username, enc_path = args[0], args[1]
    if not os.path.exists(enc_path):
        print(f"Encrypted file not found: {enc_path}")
        return
    result = decrypt_for_user(username, enc_path)
    if result:
        print("\n--- DECRYPTED CONTENT ---")
        try:
            print(result.decode("utf-8"))
        except UnicodeDecodeError:
            print(f"[Binary data, {len(result)} bytes]")
        print("-------------------------")


def cmd_demo(args):
    """End-to-end demo: enroll → encrypt sample secret → decrypt via face."""
    if len(args) < 1:
        print("Usage: python main.py demo <username>")
        return
    username = args[0]

    # Step 1: Enroll
    print("\n=== STEP 1: ENROLLMENT ===")
    if not enroll_user(username):
        print("Enrollment failed or user already exists. Proceeding with existing profile.")

    # Step 2: Encrypt a sample secret
    print("\n=== STEP 2: ENCRYPTING CONFIDENTIAL DATA ===")
    secret = b"TOP SECRET: Project Nightfall launch code is ALPHA-7-ZULU-9"
    os.makedirs("data", exist_ok=True)
    enc_path = f"data/{username}_secret.enc"
    from encrypt import encrypt_for_user
    encrypt_for_user(username, secret, enc_path)

    # Step 3: Decrypt via face
    print("\n=== STEP 3: FACE-BASED DECRYPTION ===")
    result = decrypt_for_user(username, enc_path)
    if result:
        print(f"\nDecrypted secret: {result.decode()}")
    else:
        print("\nAccess denied.")


COMMANDS = {
    "enroll": cmd_enroll,
    "encrypt": cmd_encrypt,
    "decrypt": cmd_decrypt,
    "demo": cmd_demo,
}

if __name__ == "__main__":
    if len(sys.argv) < 2 or sys.argv[1] not in COMMANDS:
        print(__doc__)
        sys.exit(1)
    COMMANDS[sys.argv[1]](sys.argv[2:])
