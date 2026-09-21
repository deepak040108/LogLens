"""
detection/rule_state.py
------------------------------------------------------------------------
Tracks which signature categories are enabled/disabled. Persisted to a
small JSON file (not SQLite — this is tiny, static-shaped config data,
not job records) so a toggle survives a server restart. engine.py
checks this on every detect_chunk call to decide which compiled rules
to actually run.
------------------------------------------------------------------------
"""

import json
import os
import threading

STATE_PATH = os.path.join(os.path.dirname(__file__), "rule_state.json")
_lock = threading.Lock()


def _load() -> dict:
    if not os.path.exists(STATE_PATH):
        return {}
    try:
        with open(STATE_PATH, "r") as f:
            return json.load(f)
    except Exception:
        return {}


def _save(state: dict):
    with open(STATE_PATH, "w") as f:
        json.dump(state, f, indent=2)


def is_enabled(category: str) -> bool:
    with _lock:
        state = _load()
    return state.get(category, "enabled") != "disabled"


def set_status(category: str, status: str):
    if status not in ("enabled", "disabled"):
        raise ValueError("status must be 'enabled' or 'disabled'")
    with _lock:
        state = _load()
        state[category] = status
        _save(state)


def all_statuses() -> dict:
    with _lock:
        return _load()
