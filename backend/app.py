"""
app.py — LogLens Flask entrypoint.
Run with: python app.py   (dev)  or  gunicorn -w 1 --threads 4 --worker-class gthread app:app  (prod)
"""

import os
import json
import math
from flask import Flask, send_from_directory, request
from flask_cors import CORS
from flask.json.provider import DefaultJSONProvider

from routes.upload import upload_bp
from routes.threats import threats_bp
from routes.reports import reports_bp
from routes.auth import auth_bp
from jobs.worker import JobQueue

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
FRONTEND_DIST = os.path.join(BASE_DIR, "static")


class NaNSafeJSONProvider(DefaultJSONProvider):
    def dumps(self, obj, **kwargs):
        return json.dumps(obj, default=str, **kwargs)


app = Flask(__name__, static_folder=None)
app.json_provider_class = NaNSafeJSONProvider
app.json = NaNSafeJSONProvider(app)

# --- Configurable CORS --------------------------------------------------
allowed_origins = os.environ.get("CORS_ALLOWED_ORIGINS", "http://localhost:5173,http://localhost:4000").split(",")
CORS(app, origins=allowed_origins, methods=["GET", "POST", "PATCH", "DELETE"], allow_headers=["Content-Type", "Authorization"])

app.config["MAX_CONTENT_LENGTH"] = 2 * 1024 * 1024 * 1024  # 2GB, matches config.MAX_UPLOAD_BYTES

# --- Basic security headers (spec §29) --------------------------------------
@app.after_request
def set_security_headers(resp):
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["Content-Security-Policy"] = (
        "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; "
        "style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self' data:"
    )
    resp.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    resp.headers["X-XSS-Protection"] = "1; mode=block"
    # Cache-Control for API responses
    if request.path.startswith("/api/"):
        resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate"
    return resp


# Single shared job queue instance -- routes import this via `from app
# import job_queue` (see routes/*.py), which is also why those imports
# are lazy/local rather than top-level (avoids a circular import).
job_queue = JobQueue()

# --- Rate limiting -------------------------------------------------------
from security.rate_limit import apply_global_rate_limit  # noqa: E402
apply_global_rate_limit(app)

# --- Background cleanup --------------------------------------------------
from security.cleanup import start_cleanup_thread  # noqa: E402
start_cleanup_thread(
    os.path.join(BASE_DIR, "tmp-uploads"),
    os.environ.get("LOGLENS_DB_PATH", os.path.join(BASE_DIR, "loglens.db")),
)

app.register_blueprint(auth_bp, url_prefix="/api")
app.register_blueprint(upload_bp, url_prefix="/api")
app.register_blueprint(threats_bp, url_prefix="/api")
app.register_blueprint(reports_bp, url_prefix="/api")


@app.errorhandler(404)
def not_found(e):
    from flask import jsonify, request
    if request.path.startswith("/api/"):
        return jsonify({"error": "Not found"}), 404
    return index()


@app.errorhandler(500)
def server_error(e):
    from flask import jsonify
    return jsonify({"error": "Internal server error"}), 500


@app.get("/")
def index():
    if not os.path.exists(os.path.join(FRONTEND_DIST, "index.html")):
        return (
            "Frontend build not found. Run:\n"
            "  cd frontend && npm install && npm run build\n"
            "then restart this server.",
            200,
            {"Content-Type": "text/plain"},
        )
    return send_from_directory(FRONTEND_DIST, "index.html")


@app.get("/<path:path>")
def static_files(path):
    full = os.path.join(FRONTEND_DIST, path)
    if os.path.exists(full):
        return send_from_directory(FRONTEND_DIST, path)
    return index()  # client-side routing fallback


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 4000))
    print(f"LogLens backend listening on http://localhost:{port}")
    app.run(host="0.0.0.0", port=port, threaded=True)
