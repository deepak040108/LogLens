"""
detection/engine.py
------------------------------------------------------------------------
Loads the signature database (signatures.json), compiles every regex
pattern ONCE at import time (not per-request), and matches log rows
against them using pandas' vectorized str.contains for speed on large
chunks.

Every finding includes a `reason` — a human-readable explanation of
why the line was flagged, and `matched_signature` — the specific
pattern text that tripped, per spec §21/§22. This is mandatory, not
decorative: a SIEM tool that can't say *why* it flagged something
isn't trustworthy for an analyst to act on.
------------------------------------------------------------------------
"""

import json
import os
import re
import warnings
from urllib.parse import unquote

import pandas as pd

warnings.filterwarnings(
    "ignore", message="This pattern is interpreted as a regular expression",
    category=UserWarning,
)

SIGNATURES_PATH = os.path.join(os.path.dirname(__file__), "signatures.json")

with open(SIGNATURES_PATH, "r", encoding="utf-8") as f:
    _RAW_SIGNATURES = json.load(f)

COMPILED_RULES = []
for category, spec in _RAW_SIGNATURES.items():
    for pattern in spec["patterns"]:
        COMPILED_RULES.append({
            "rule_id": spec.get("id", category.upper()),
            "category": category,
            "severity": spec["severity"],
            "description": spec.get("description", category),
            "confidence": spec.get("confidence", "medium"),
            "recommendation": spec.get("recommendation", "Review this finding manually."),
            "pattern": pattern,
            "regex": re.compile(pattern, re.IGNORECASE),
        })

SEVERITY_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}


from detection import rule_state  # noqa: E402


def list_rules():
    """Rules grouped by category, for GET /api/rules (spec §27)."""
    out = []
    for category, spec in _RAW_SIGNATURES.items():
        out.append({
            "rule": category,
            "ruleId": spec.get("id", category.upper()),
            "attackType": category,
            "name": spec.get("name", category),
            "severity": spec["severity"],
            "confidence": spec.get("confidence", "medium"),
            "description": spec.get("description", ""),
            "recommendation": spec.get("recommendation", ""),
            "patternCount": len(spec["patterns"]),
            "status": "enabled" if rule_state.is_enabled(category) else "disabled",
        })
    return out


def _safe_decode(s: str) -> str:
    try:
        return unquote(s)
    except Exception:
        return s


_EXPLANATIONS = {
    "sql_injection": (
        "The request contains a SQL injection pattern commonly used to manipulate database queries. "
        "This could allow the attacker to extract, modify, or delete data, or bypass authentication."
    ),
    "xss": (
        "The request contains a cross-site scripting (XSS) pattern that could execute script in a victim's browser. "
        "This could lead to session hijacking, credential theft, or phishing attacks."
    ),
    "directory_traversal": (
        "The request attempts to traverse outside the web root, commonly used to read sensitive files "
        "like /etc/passwd, /etc/shadow, or application configuration files."
    ),
    "command_injection": (
        "The request contains shell metacharacters chained with a system command, consistent with command injection. "
        "This could allow the attacker to execute arbitrary commands on the server."
    ),
    "log4shell": (
        "The request contains a JNDI lookup string associated with the Log4Shell (CVE-2021-44228) "
        "remote code execution exploit. This is a critical vulnerability that can lead to full system compromise."
    ),
    "recon": (
        "The request matches known scanner tooling or is probing for a sensitive configuration/version-control file. "
        "This is often a precursor to a targeted attack."
    ),
    "sensitive_data_access": (
        "The request attempts to access a sensitive file such as .env, .git, backups, or credentials. "
        "Exposure of these files could leak secrets, private keys, or database passwords."
    ),
    "suspicious_response": (
        "The server responded with an unusual status code that may indicate enumeration, probing, "
        "or a failed exploitation attempt. The pattern of responses suggests malicious intent."
    ),
}


def _explanation(category: str, pattern: str, target: str) -> str:
    base = _EXPLANATIONS.get(category, f"The request matched a {category} signature.")
    return f"{base} Matched pattern: {pattern}"


def detect_chunk(rows: list[dict]) -> list[dict]:
    """
    Regex-only pass (no brute-force here -- that's a separate stateful
    module, see detection/brute_force.py). Returns one finding dict per
    row that tripped at least one signature, each carrying the fields
    required by spec §21: attack_type, severity, matched_signature, reason.
    """
    if not rows:
        return []

    df = pd.DataFrame(rows)
    df["target"] = (
        df["path"].fillna("") + " " +
        df["userAgent"].fillna("") + " " +
        df["referrer"].fillna("")
    ).map(_safe_decode)

    hit_columns = []
    for i, rule in enumerate(COMPILED_RULES):
        if not rule_state.is_enabled(rule["category"]):
            continue
        col = f"__rule_{i}"
        df[col] = df["target"].str.contains(rule["pattern"], regex=True, case=False, na=False)
        hit_columns.append((col, rule))

    findings = []
    for idx, row in df.iterrows():
        matched_rules = [rule for col, rule in hit_columns if row[col]]
        if not matched_rules:
            continue

        primary = max(matched_rules, key=lambda r: SEVERITY_RANK[r["severity"]])

        categories_hit = list({r["category"] for r in matched_rules})
        finding = {
            "ip": row["ip"],
            "timestamp": row["timestamp"],
            "method": row["method"],
            "path": row["path"],
            "status": int(row["status"]),
            "userAgent": row.get("userAgent"),
            "attack_type": primary["category"],
            "severity": primary["severity"],
            "confidence": primary["confidence"],
            "rule_id": primary["rule_id"],
            "recommendation": primary["recommendation"],
            "matched_signature": primary["pattern"],
            "reason": _explanation(primary["category"], primary["pattern"], row["target"]),
            "all_matches": [
                {
                    "attack_type": r["category"],
                    "severity": r["severity"],
                    "rule_id": r["rule_id"],
                    "confidence": r["confidence"],
                    "matched_signature": r["pattern"],
                }
                for r in matched_rules
            ],
        }

        if len(categories_hit) > 1:
            finding["multi_category"] = True
            finding["categories_hit"] = categories_hit

        findings.append(finding)

    return findings
