"""
Flask web frontend for the Biometric-Based Encryption System.
Serves the UI and exposes REST endpoints that call the existing backend modules.
"""

import os
import json
import base64
import numpy as np
import cv2
from flask import Flask, render_template, request, jsonify
from flask_cors import CORS

from enroll import enroll_user, load_profile
from encrypt import encrypt_for_user
from decrypt import decrypt_for_user
from face_auth import capture_face_embedding_from_frame, embeddings_match
from crypto_utils import generate_salt, embedding_to_key, encrypt_data, decrypt_data
from cryptography.exceptions import InvalidTag

app = Flask(__name__)
CORS(app)

DATA_DIR = "data"
os.makedirs(DATA_DIR, exist_ok=True)
os.makedirs("profiles", exist_ok=True)


def decode_frame(b64_image: str) -> np.ndarray:
    """Decode a base64 image from the browser webcam into an OpenCV frame."""
    header, data = b64_image.split(",", 1)
    img_bytes = base64.b64decode(data)
    arr = np.frombuffer(img_bytes, np.uint8)
    frame = cv2.imdecode(arr, cv2.IMREAD_COLOR)
    return frame


# ── Routes ────────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/enroll", methods=["POST"])
def api_enroll():
    data = request.json
    username = data.get("username", "").strip()
    image_b64 = data.get("image")

    if not username or not image_b64:
        return jsonify({"success": False, "message": "Username and image required."}), 400

    profile_path = os.path.join("profiles", f"{username}.json")
    if os.path.exists(profile_path):
        return jsonify({"success": False, "message": f"User '{username}' already enrolled. Delete profile to re-enroll."}), 409

    frame = decode_frame(image_b64)
    embedding = capture_face_embedding_from_frame(frame)

    if embedding is None:
        return jsonify({"success": False, "message": "No face detected. Please try again with better lighting."}), 400

    salt = generate_salt()
    profile = {
        "username": username,
        "salt": salt.hex(),
        "enrolled_embedding": embedding.tolist(),
    }
    with open(profile_path, "w") as f:
        json.dump(profile, f)

    return jsonify({"success": True, "message": f"User '{username}' enrolled successfully."})


@app.route("/api/encrypt", methods=["POST"])
def api_encrypt():
    data = request.json
    username = data.get("username", "").strip()
    plaintext = data.get("plaintext", "").strip()

    if not username or not plaintext:
        return jsonify({"success": False, "message": "Username and plaintext required."}), 400

    profile = load_profile(username)
    if not profile:
        return jsonify({"success": False, "message": f"No profile found for '{username}'. Please enroll first."}), 404

    salt = bytes.fromhex(profile["salt"])
    enrolled_embedding = np.array(profile["enrolled_embedding"])
    key = embedding_to_key(enrolled_embedding, salt)
    nonce, ciphertext = encrypt_data(plaintext.encode(), key)

    enc_path = os.path.join(DATA_DIR, f"{username}_secret.enc")
    payload = {
        "username": username,
        "salt": salt.hex(),
        "nonce": nonce.hex(),
        "ciphertext": ciphertext.hex(),
    }
    with open(enc_path, "w") as f:
        json.dump(payload, f)

    return jsonify({
        "success": True,
        "message": "Data encrypted successfully.",
        "ciphertext_preview": ciphertext.hex()[:64] + "...",
        "enc_file": enc_path,
    })


@app.route("/api/decrypt", methods=["POST"])
def api_decrypt():
    data = request.json
    username = data.get("username", "").strip()
    image_b64 = data.get("image")

    if not username or not image_b64:
        return jsonify({"success": False, "message": "Username and image required."}), 400

    profile = load_profile(username)
    if not profile:
        return jsonify({"success": False, "message": f"No profile found for '{username}'. Please enroll first."}), 404

    enc_path = os.path.join(DATA_DIR, f"{username}_secret.enc")
    if not os.path.exists(enc_path):
        return jsonify({"success": False, "message": "No encrypted data found. Please encrypt something first."}), 404

    # Face verification
    frame = decode_frame(image_b64)
    live_embedding = capture_face_embedding_from_frame(frame)

    if live_embedding is None:
        return jsonify({"success": False, "message": "No face detected. Please try again."}), 400

    enrolled_embedding = np.array(profile["enrolled_embedding"])
    matched, distance = embeddings_match(enrolled_embedding, live_embedding)

    if not matched:
        return jsonify({
            "success": False,
            "message": f"Face not recognized (distance: {distance:.4f}). Access denied.",
            "distance": round(distance, 4),
        }), 403

    # Decrypt
    with open(enc_path) as f:
        payload = json.load(f)

    salt = bytes.fromhex(payload["salt"])
    nonce = bytes.fromhex(payload["nonce"])
    ciphertext = bytes.fromhex(payload["ciphertext"])

    try:
        key = embedding_to_key(live_embedding, salt)
        plaintext = decrypt_data(nonce, ciphertext, key)
    except InvalidTag:
        # Fallback to enrolled embedding
        try:
            key = embedding_to_key(enrolled_embedding, salt)
            plaintext = decrypt_data(nonce, ciphertext, key)
        except InvalidTag:
            return jsonify({"success": False, "message": "Decryption failed — integrity check error."}), 500

    return jsonify({
        "success": True,
        "message": "Access granted.",
        "plaintext": plaintext.decode("utf-8"),
        "distance": round(distance, 4),
    })


@app.route("/api/status/<username>")
def api_status(username):
    profile_exists = os.path.exists(os.path.join("profiles", f"{username}.json"))
    enc_exists = os.path.exists(os.path.join(DATA_DIR, f"{username}_secret.enc"))
    return jsonify({"enrolled": profile_exists, "has_encrypted_data": enc_exists})


if __name__ == "__main__":
    app.run(debug=True, port=5000)
