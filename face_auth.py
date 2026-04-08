"""
Face capture and recognition using DeepFace (no C++ compiler needed on Windows).
Produces 128-d face embeddings via the Facenet model.
"""

import cv2
import numpy as np
from deepface import DeepFace

MODEL_NAME = "Facenet"          # 128-d embeddings, fast and accurate
SIMILARITY_THRESHOLD = 0.40     # Cosine distance; lower = stricter


def capture_face_embedding(prompt: str = "Press SPACE to capture, ESC to cancel") -> np.ndarray | None:
    """
    Opens webcam, shows live feed, captures a frame on SPACE.
    Returns 128-d face embedding or None if no face detected / cancelled.
    """
    cap = cv2.VideoCapture(0)
    if not cap.isOpened():
        raise RuntimeError("Cannot open webcam. Check camera permissions.")

    print(f"\n[Camera] {prompt}")
    embedding = None

    while True:
        ret, frame = cap.read()
        if not ret:
            break

        display = frame.copy()
        cv2.putText(display, prompt, (10, 25), cv2.FONT_HERSHEY_SIMPLEX, 0.55, (0, 255, 255), 2)
        cv2.imshow("Biometric Auth", display)

        key = cv2.waitKey(1) & 0xFF
        if key == 27:  # ESC
            print("[Camera] Cancelled.")
            break
        elif key == 32:  # SPACE
            try:
                result = DeepFace.represent(
                    img_path=frame,
                    model_name=MODEL_NAME,
                    enforce_detection=True,
                    detector_backend="opencv",
                )
                embedding = np.array(result[0]["embedding"])
                print("[Camera] Face captured and encoded successfully.")
                break
            except Exception as e:
                print(f"[Camera] No face detected or encoding failed: {e}. Try again.")

    cap.release()
    cv2.destroyAllWindows()
    return embedding


def embeddings_match(enrolled: np.ndarray, live: np.ndarray) -> tuple[bool, float]:
    """
    Compare two embeddings using cosine distance.
    Returns (match: bool, distance: float).
    """
    # Cosine distance: 0 = identical, 1 = completely different
    dot = np.dot(enrolled, live)
    norm = np.linalg.norm(enrolled) * np.linalg.norm(live)
    cosine_sim = dot / (norm + 1e-10)
    distance = 1.0 - cosine_sim
    return distance <= SIMILARITY_THRESHOLD, float(distance)
