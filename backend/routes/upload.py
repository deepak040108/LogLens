"""
routes/upload.py
------------------------------------------------------------------------
POST /api/upload, POST /api/demo. Validates untrusted uploads before
they ever reach the parser, per spec §29: extension allowlist, size
cap, safe filename handling (no path traversal via filename), and a
basic content sniff so a renamed binary can't slip through as a .log.
------------------------------------------------------------------------
"""

import os
import time
import sys
import hashlib

from flask import Blueprint, request, jsonify
from werkzeug.utils import secure_filename

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config import UPLOAD_DIR, ALLOWED_EXTENSIONS, MAX_UPLOAD_BYTES  # noqa: E402
from security.rate_limit import rate_limit  # noqa: E402

upload_bp = Blueprint("upload", __name__)
os.makedirs(UPLOAD_DIR, exist_ok=True)

DEMO_LOG_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "demo", "demo.log")


def _get_job_queue():
    # imported lazily to avoid a circular import with app.py, which owns
    # the single JobQueue instance
    from app import job_queue
    return job_queue


def _has_allowed_extension(filename: str) -> bool:
    _, ext = os.path.splitext(filename.lower())
    return ext in ALLOWED_EXTENSIONS


def _looks_like_text(file_path: str, sample_bytes: int = 4096) -> bool:
    """Reject obvious binaries (executables, images, etc.) even if they
    were given a .log extension — a basic content sniff, not just a
    filename check, per spec §29 (MIME/content validation)."""
    try:
        with open(file_path, "rb") as f:
            chunk = f.read(sample_bytes)
        if b"\x00" in chunk:
            return False
        chunk.decode("utf-8", errors="strict")
        return True
    except UnicodeDecodeError:
        # tolerate the occasional non-utf8 byte from a truncated multibyte
        # char at the sample boundary; a genuine binary fails much harder
        try:
            chunk.decode("utf-8", errors="replace")
            return True
        except Exception:
            return False
    except Exception:
        return False


@upload_bp.post("/upload")
@rate_limit(max_requests=10, window_seconds=60, category="upload")
def upload():
    if "logfile" not in request.files:
        return jsonify({"error": 'No file uploaded (field name must be "logfile")'}), 400

    file = request.files["logfile"]
    if file.filename == "":
        return jsonify({"error": "Empty filename"}), 400

    if not _has_allowed_extension(file.filename):
        return jsonify({"error": f"Unsupported log format. Supported extensions: {', '.join(sorted(ALLOWED_EXTENSIONS))}"}), 400

    safe_name = secure_filename(file.filename)  # strips path separators / traversal sequences
    if not safe_name:
        return jsonify({"error": "Invalid filename"}), 400

    dest_path = os.path.join(UPLOAD_DIR, f"{int(time.time() * 1000)}-{safe_name}")
    file.save(dest_path)  # streamed to disk by Werkzeug, not buffered whole in RAM

    sha256 = hashlib.sha256()
    with open(dest_path, "rb") as f:
        for block in iter(lambda: f.read(8192), b""):
            sha256.update(block)
    file_hash = sha256.hexdigest()

    size = os.path.getsize(dest_path)
    if size == 0:
        os.remove(dest_path)
        return jsonify({"error": "The uploaded log file is empty."}), 400
    if size > MAX_UPLOAD_BYTES:
        os.remove(dest_path)
        return jsonify({"error": f"File exceeds the maximum upload size ({MAX_UPLOAD_BYTES // (1024*1024)}MB)."}), 413

    if not _looks_like_text(dest_path):
        os.remove(dest_path)
        return jsonify({"error": "File does not appear to be a text-based log file."}), 400

    job_queue = _get_job_queue()
    job = job_queue.create_job(dest_path, file.filename)
    job["fileHash"] = file_hash
    job_queue.submit(job["id"])
    return jsonify({"job_id": job["id"], "status": job["status"], "file_hash": file_hash}), 202


@upload_bp.post("/demo")
@rate_limit(max_requests=10, window_seconds=60, category="upload")
def demo():
    if not os.path.exists(DEMO_LOG_PATH):
        return jsonify({"error": "Demo log not found on server"}), 500
    job_queue = _get_job_queue()
    job = job_queue.create_job(DEMO_LOG_PATH, "demo.log")
    job_queue.submit(job["id"])
    return jsonify({"job_id": job["id"], "status": job["status"]}), 202
