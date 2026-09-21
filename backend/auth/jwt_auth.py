"""
auth/jwt_auth.py
--------
JWT authentication with demo user system, token generation/verification,
and route decorators.
"""

import os
import time
import functools

import bcrypt
import jwt
from flask import request, jsonify

SECRET_KEY = os.environ.get("SECRET_KEY", "loglens-dev-secret-change-in-production")
TOKEN_EXPIRY_HOURS = 24

# In-memory user store (demo purposes)
_users = {}

# Bootstrap demo user: admin / loglens
_demo_pw_hash = bcrypt.hashpw(b"loglens", bcrypt.gensalt())
_users["admin"] = {
    "username": "admin",
    "password_hash": _demo_pw_hash.decode("utf-8"),
}


def _hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def _check_password(password: str, password_hash: str) -> bool:
    return bcrypt.checkpw(password.encode("utf-8"), password_hash.encode("utf-8"))


def create_token(username: str) -> str:
    payload = {
        "sub": username,
        "iat": int(time.time()),
        "exp": int(time.time()) + TOKEN_EXPIRY_HOURS * 3600,
    }
    return jwt.encode(payload, SECRET_KEY, algorithm="HS256")


def verify_token(token: str) -> dict | None:
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        return payload
    except (jwt.ExpiredSignatureError, jwt.InvalidTokenError):
        return None


def register_user(username: str, password: str) -> tuple[dict | None, int]:
    if not username or not password:
        return {"error": "Username and password required"}, 400
    if len(username) < 3:
        return {"error": "Username must be at least 3 characters"}, 400
    if len(password) < 6:
        return {"error": "Password must be at least 6 characters"}, 400
    if username in _users:
        return {"error": "Username already exists"}, 409
    _users[username] = {
        "username": username,
        "password_hash": _hash_password(password),
    }
    return {"message": "User created", "username": username}, 201


def authenticate_user(username: str, password: str) -> tuple[dict | None, int]:
    user = _users.get(username)
    if not user:
        return {"error": "Invalid credentials"}, 401
    if not _check_password(password, user["password_hash"]):
        return {"error": "Invalid credentials"}, 401
    token = create_token(username)
    return {"token": token, "username": username, "expires_in": TOKEN_EXPIRY_HOURS * 3600}, 200


def _extract_token() -> str | None:
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        return auth_header[7:]
    return None


def require_auth(f):
    @functools.wraps(f)
    def decorated(*args, **kwargs):
        token = _extract_token()
        if not token:
            return jsonify({"error": "Authentication required"}), 401
        payload = verify_token(token)
        if not payload:
            return jsonify({"error": "Invalid or expired token"}), 401
        request.user = payload
        return f(*args, **kwargs)
    return decorated


def optional_auth(f):
    @functools.wraps(f)
    def decorated(*args, **kwargs):
        token = _extract_token()
        if token:
            payload = verify_token(token)
            request.user = payload if payload else None
        else:
            request.user = None
        return f(*args, **kwargs)
    return decorated
