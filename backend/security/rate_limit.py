"""
security/rate_limit.py
--------
In-memory sliding-window rate limiter.
"""

import time
import threading
from functools import wraps

from flask import request, jsonify


class SlidingWindowRateLimiter:
    def __init__(self):
        self._windows: dict[str, list[float]] = {}
        self._lock = threading.Lock()

    def is_rate_limited(self, key: str, max_requests: int, window_seconds: int) -> tuple[bool, int]:
        now = time.time()
        window_start = now - window_seconds

        with self._lock:
            if key not in self._windows:
                self._windows[key] = []

            self._windows[key] = [t for t in self._windows[key] if t > window_start]

            if len(self._windows[key]) >= max_requests:
                oldest = self._windows[key][0]
                retry_after = int(oldest + window_seconds - now) + 1
                return True, retry_after

            self._windows[key].append(now)
            return False, 0


_limiter = SlidingWindowRateLimiter()

# Default limits: (max_requests, window_seconds)
DEFAULT_LIMITS = {
    "general": (100, 60),
    "upload": (10, 60),
    "login": (5, 60),
}


def _get_limit_category(endpoint_name: str) -> str:
    if "upload" in endpoint_name or "demo" in endpoint_name:
        return "upload"
    if "login" in endpoint_name:
        return "login"
    return "general"


def rate_limit(max_requests: int = None, window_seconds: int = 60, category: str = None):
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            cat = category or _get_limit_category(f.__name__)
            if max_requests is not None:
                limit = max_requests
            else:
                limit_cfg = DEFAULT_LIMITS.get(cat, DEFAULT_LIMITS["general"])
                limit = limit_cfg[0]

            key = f"{cat}:{request.remote_addr}"
            limited, retry_after = _limiter.is_rate_limited(key, limit, window_seconds)
            if limited:
                resp = jsonify({"error": "Rate limit exceeded", "retry_after": retry_after})
                resp.status_code = 429
                resp.headers["Retry-After"] = str(retry_after)
                return resp
            return f(*args, **kwargs)
        return decorated
    return decorator


def apply_global_rate_limit(app, general_limit=100, window=60):
    @app.before_request
    def _global_rate_limit():
        if request.path.startswith("/api/") and request.path != "/api/health":
            key = f"global:{request.remote_addr}"
            limited, retry_after = _limiter.is_rate_limited(key, general_limit, window)
            if limited:
                resp = jsonify({"error": "Rate limit exceeded", "retry_after": retry_after})
                resp.status_code = 429
                resp.headers["Retry-After"] = str(retry_after)
                return resp
