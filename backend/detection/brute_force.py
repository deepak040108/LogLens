"""
detection/brute_force.py
------------------------------------------------------------------------
Brute force is a FREQUENCY pattern (same IP, many failed auths, short
window), not a single-line regex match, so it's deliberately its own
stateful module rather than another entry in signatures.json. Threshold,
window, and status codes are read from config.py, not hardcoded, per
spec §20.

Thread-safe: uses collections.deque for O(1) pops and a threading.Lock
to protect shared state. Optionally tracks usernames extracted from paths
(e.g., /login?user=admin) for richer reporting.
------------------------------------------------------------------------
"""

import re
import sys
import os
import threading
from collections import deque
from datetime import datetime, timedelta

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config import BRUTE_FORCE_STATUS_CODE, BRUTE_FORCE_THRESHOLD, BRUTE_FORCE_WINDOW_SECONDS  # noqa: E402

# Pattern to extract username-like values from common login paths
_USERNAME_PATTERNS = [
    re.compile(r"[?&](?:user|username|login|email|u)=([^&\s]+)", re.IGNORECASE),
    re.compile(r"/(?:user|login|auth)/([A-Za-z0-9._@-]+)", re.IGNORECASE),
]


def _extract_username(path: str) -> str | None:
    if not path:
        return None
    for pat in _USERNAME_PATTERNS:
        m = pat.search(path)
        if m:
            try:
                from urllib.parse import unquote
                return unquote(m.group(1))
            except Exception:
                return m.group(1)
    return None


class BruteForceTracker:
    def __init__(self, threshold=BRUTE_FORCE_THRESHOLD, window_seconds=BRUTE_FORCE_WINDOW_SECONDS,
                 status_code=BRUTE_FORCE_STATUS_CODE):
        self.threshold = threshold
        self.window = timedelta(seconds=window_seconds)
        self.status_code = status_code
        self._lock = threading.Lock()
        # deque for efficient left-popping
        self._failures_by_ip: dict[str, deque] = {}
        # track usernames attempted per IP for richer findings
        self._usernames_by_ip: dict[str, dict[str, int]] = {}

    def register(self, ip: str, status: int, ts_iso: str | None, path: str = "") -> bool:
        """Call for every parsed row. Returns True the instant an IP
        crosses the threshold within the rolling window."""
        if status != self.status_code:
            return False
        t = _safe_parse_iso(ts_iso) or datetime.utcnow()

        with self._lock:
            dq = self._failures_by_ip.setdefault(ip, deque())
            dq.append(t)
            # Evict old entries outside the window
            while dq and (t - dq[0]) > self.window:
                dq.popleft()

            # Track username if available
            username = _extract_username(path)
            if username:
                user_map = self._usernames_by_ip.setdefault(ip, {})
                user_map[username] = user_map.get(username, 0) + 1

            return len(dq) >= self.threshold

    def get_tracked_usernames(self, ip: str) -> dict[str, int]:
        """Return {username: count} for a given IP."""
        with self._lock:
            return dict(self._usernames_by_ip.get(ip, {}))

    def finding_for(self, ip: str, ts_iso: str, method: str, path: str, status: int) -> dict:
        usernames = self.get_tracked_usernames(ip)
        username_detail = ""
        if usernames:
            top_users = sorted(usernames.items(), key=lambda x: x[1], reverse=True)[:5]
            user_str = ", ".join(f"{u}({c}x)" for u, c in top_users)
            username_detail = f" Attempted usernames: {user_str}."

        return {
            "ip": ip,
            "timestamp": ts_iso,
            "method": method,
            "path": path,
            "status": status,
            "userAgent": None,
            "attack_type": "brute_force",
            "severity": "high",
            "confidence": "high",
            "rule_id": "BF-001",
            "recommendation": "Implement account lockout, rate-limit login endpoints, and use CAPTCHA after failed attempts.",
            "matched_signature": f">= {self.threshold} x HTTP {self.status_code} within {int(self.window.total_seconds())}s",
            "reason": (
                f"{self.threshold} or more HTTP {self.status_code} responses were observed from {ip} "
                f"within a {int(self.window.total_seconds() / 60)}-minute window, consistent with a "
                f"brute-force credential-guessing attempt.{username_detail}"
            ),
            "all_matches": [{"attack_type": "brute_force", "severity": "high", "matched_signature": "behavioral"}],
        }


def _safe_parse_iso(ts_iso):
    if not ts_iso:
        return None
    try:
        return datetime.fromisoformat(ts_iso)
    except Exception:
        return None
