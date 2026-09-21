"""
analysis/correlation.py
------------------------------------------------------------------------
Groups related events by IP within a time window and detects multi-stage
attack patterns. Correlation findings are appended to the final summary
so analysts can see orchestrated campaigns rather than isolated events.
------------------------------------------------------------------------
"""

from datetime import datetime, timedelta, timezone
from collections import defaultdict


# Time window to group related events (seconds)
GROUP_WINDOW_SECONDS = 600  # 10 minutes

# Threshold for rapid succession detection
RAPID_THRESHOLD = 5
RAPID_WINDOW_SECONDS = 60  # 1 minute


def _parse_ts(ts_iso: str) -> datetime | None:
    if not ts_iso:
        return None
    try:
        dt = datetime.fromisoformat(ts_iso)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except Exception:
        return None


def _time_groups(events: list[dict], window_seconds: int) -> list[list[dict]]:
    """Split events into groups where consecutive events are within window_seconds."""
    if not events:
        return []

    groups = []
    current_group = [events[0]]

    for event in events[1:]:
        prev_ts = _parse_ts(current_group[-1].get("timestamp"))
        curr_ts = _parse_ts(event.get("timestamp"))

        if prev_ts and curr_ts and (curr_ts - prev_ts) <= timedelta(seconds=window_seconds):
            current_group.append(event)
        else:
            groups.append(current_group)
            current_group = [event]

    groups.append(current_group)
    return groups


def _has_recon(events: list[dict]) -> bool:
    recon_types = {"recon", "sensitive_data_access"}
    return any(e.get("attack_type") in recon_types for e in events)


def _has_exploitation(events: list[dict]) -> bool:
    exploit_types = {"sql_injection", "xss", "command_injection", "log4shell", "directory_traversal"}
    return any(e.get("attack_type") in exploit_types for e in events)


def _attack_categories(events: list[dict]) -> set:
    return {e.get("attack_type") for e in events if e.get("attack_type")}


def detect_correlations(all_findings: list[dict]) -> list[dict]:
    """
    Analyze all findings to detect multi-stage and coordinated attack patterns.

    Returns a list of correlation finding dicts with:
      - pattern: name of the detected pattern
      - severity: suggested severity
      - confidence: high/medium/low
      - ips: involved IP addresses
      - details: human-readable explanation
      - affected_events: indices or timestamps of involved events
    """
    if not all_findings:
        return []

    by_ip = defaultdict(list)
    for f in all_findings:
        by_ip[f.get("ip", "unknown")].append(f)

    correlation_findings = []

    for ip, events in by_ip.items():
        # Sort by timestamp
        events.sort(key=lambda e: e.get("timestamp", ""))

        # --- Pattern 1: Reconnaissance-to-Exploitation ---
        if _has_recon(events) and _has_exploitation(events):
            recon_count = sum(1 for e in events if e.get("attack_type") in {"recon", "sensitive_data_access"})
            exploit_count = sum(1 for e in events if e.get("attack_type") in {"sql_injection", "xss", "command_injection", "log4shell", "directory_traversal"})
            categories = _attack_categories(events)
            correlation_findings.append({
                "pattern": "Reconnaissance-to-Exploitation Pattern",
                "severity": "high",
                "confidence": "high",
                "ips": [ip],
                "details": (
                    f"IP {ip} performed {recon_count} reconnaissance probe(s) followed by "
                    f"{exploit_count} exploitation attempt(s). This suggests the attacker "
                    f"reconnoitered the target before launching an attack."
                ),
                "eventCount": len(events),
                "categories": sorted(categories),
            })

        # --- Pattern 2: Multi-Vector Attack ---
        categories = _attack_categories(events)
        if len(categories) >= 3:
            correlation_findings.append({
                "pattern": "Multi-Vector Attack",
                "severity": "high",
                "confidence": "high",
                "ips": [ip],
                "details": (
                    f"IP {ip} launched {len(categories)} distinct attack types "
                    f"({', '.join(sorted(categories))}). This diversity suggests "
                    f"an attacker with broad capabilities or automated tooling."
                ),
                "eventCount": len(events),
                "categories": sorted(categories),
            })

        # --- Pattern 3: Automated Attack Campaign (rapid succession) ---
        sorted_events = sorted(events, key=lambda e: e.get("timestamp", ""))
        time_groups = _time_groups(sorted_events, RAPID_WINDOW_SECONDS)
        for group in time_groups:
            if len(group) >= RAPID_THRESHOLD:
                cats_in_group = _attack_categories(group)
                first_ts = group[0].get("timestamp", "unknown")
                last_ts = group[-1].get("timestamp", "unknown")
                correlation_findings.append({
                    "pattern": "Automated Attack Campaign",
                    "severity": "medium",
                    "confidence": "medium",
                    "ips": [ip],
                    "details": (
                        f"IP {ip} sent {len(group)} attack requests within "
                        f"{RAPID_WINDOW_SECONDS} seconds ({first_ts} to {last_ts}). "
                        f"Attack types in this burst: {', '.join(sorted(cats_in_group))}. "
                        f"This rapid-fire pattern is consistent with automated tooling."
                    ),
                    "eventCount": len(group),
                    "categories": sorted(cats_in_group),
                })

    # De-duplicate: if the same IP has both recon-to-exploit and multi-vector,
    # keep both but they're separate findings.
    return correlation_findings
