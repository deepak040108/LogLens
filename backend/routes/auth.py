"""
routes/auth.py
--------
POST /api/auth/login and POST /api/auth/register endpoints.
"""

import os
import sys

from flask import Blueprint, request, jsonify

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from auth.jwt_auth import register_user, authenticate_user  # noqa: E402
from security.rate_limit import rate_limit  # noqa: E402

auth_bp = Blueprint("auth", __name__)


@auth_bp.post("/auth/login")
@rate_limit(max_requests=5, window_seconds=60, category="login")
def login():
    body = request.get_json(silent=True) or {}
    username = body.get("username", "")
    password = body.get("password", "")
    if not username or not password:
        return jsonify({"error": "Username and password required"}), 400
    result, status = authenticate_user(username, password)
    return jsonify(result), status


@auth_bp.post("/auth/register")
@rate_limit(max_requests=5, window_seconds=60, category="login")
def register():
    body = request.get_json(silent=True) or {}
    username = body.get("username", "")
    password = body.get("password", "")
    result, status = register_user(username, password)
    return jsonify(result), status
