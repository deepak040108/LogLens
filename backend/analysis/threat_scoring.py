"""
analysis/threat_scoring.py
------------------------------------------------------------------------
Calculates a composite threat score (0-100) for each attacker based on
severity of findings, attack frequency, category diversity, and recency
of activity. Used to prioritize which attackers deserve immediate
attention in the summary view.
------------------------------------------------------------------------
"""

from datetime import datetime, timezone
from collections import Counter

SEVERITY_WEIGHTS = {
    "critical": 40,
    "high": 30,
    "medium": 20,
    "low": 10,
}

MAX_FREQUENCY_POINTS = 25
MAX_DIVERSITY_POINTS = 20
MAX_RECENCY_POINTS = 15


def _parse_ts(ts_iso: str) -> datetime | None:
    if not ts_iso:
        return None
    try:
        return datetime.fromisoformat(ts_iso)
    except Exception:
        return None


def calculate_threat_score(attacker_data: dict, findings: list[dict]) -> dict:
    """
    Compute a 0-100 threat score for a single attacker.

    Parameters
    ----------
    attacker_data : dict
        From aggregator.attacker_ips[ip], must have count, severityCounts,
        typeCounts, firstSeen, lastSeen, ip.
    findings : list[dict]
        All findings for this attacker IP.

    Returns
    -------
    dict with score, level, contributors, summary.
    """
    ip = attacker_data.get("ip", "unknown")
    severity_counts = attacker_data.get("severityCounts", {})
    type_counts = attacker_data.get("typeCounts", {})
    count = attacker_data.get("count", 0)
    last_seen = attacker_data.get("lastSeen")

    contributors = []

    # --- Severity component (0-40) ---
    severity_points = 0
    for sev, weight in SEVERITY_WEIGHTS.items():
        occurrences = severity_counts.get(sev, 0)
        if occurrences > 0:
            # take the full weight of the highest severity found
            severity_points = max(severity_points, weight)
            contributors.append({
                "factor": "severity",
                "points": weight,
                "detail": f"{weight} pts: {sev.capitalize()} severity ({occurrences} finding{'s' if occurrences > 1 else ''})",
            })

    if not severity_points:
        contributors.append({
            "factor": "severity",
            "points": 0,
            "detail": "No significant severity findings",
        })

    # --- Frequency component (0-25) ---
    freq_points = min(count * 2, MAX_FREQUENCY_POINTS)
    contributors.append({
        "factor": "frequency",
        "points": freq_points,
        "detail": f"{count} attempt{'s' if count != 1 else ''} from {ip}",
    })

    # --- Diversity component (0-20) ---
    num_categories = len(type_counts)
    diversity_points = min(num_categories * 5, MAX_DIVERSITY_POINTS)
    contributors.append({
        "factor": "diversity",
        "points": diversity_points,
        "detail": f"{num_categories} different attack {'categories' if num_categories != 1 else 'category'}",
    })

    # --- Recency component (0-15) ---
    recency_points = 0
    last_dt = _parse_ts(last_seen)
    now = datetime.now(timezone.utc)
    if last_dt:
        if last_dt.tzinfo is None:
            last_dt = last_dt.replace(tzinfo=timezone.utc)
        diff = now - last_dt
        minutes_ago = diff.total_seconds() / 60
        if minutes_ago <= 5:
            recency_points = MAX_RECENCY_POINTS
        elif minutes_ago <= 30:
            recency_points = MAX_RECENCY_POINTS - 3
        elif minutes_ago <= 60:
            recency_points = MAX_RECENCY_POINTS - 6
        elif minutes_ago <= 360:
            recency_points = MAX_RECENCY_POINTS - 10
        else:
            recency_points = 0

    contributors.append({
        "factor": "recency",
        "points": recency_points,
        "detail": f"Last activity {last_seen or 'unknown'}",
    })

    score = min(
        severity_points + freq_points + diversity_points + recency_points,
        100,
    )

    if score >= 75:
        level = "critical"
    elif score >= 50:
        level = "high"
    elif score >= 25:
        level = "medium"
    elif score > 0:
        level = "low"
    else:
        level = "info"

    # Build human-readable summary
    top_categories = [cat for cat, _ in sorted(type_counts.items(), key=lambda x: x[1], reverse=True)[:3]]
    sev_label = max(severity_counts, key=lambda s: SEVERITY_WEIGHTS.get(s, 0)) if severity_counts else "none"

    if num_categories > 1:
        summary = f"Multi-category attacker ({', '.join(top_categories)}) with {sev_label} severity payloads"
    elif num_categories == 1:
        summary = f"Focused {top_categories[0]} attacker with {sev_label} severity"
    else:
        summary = "Minimal activity observed"

    return {
        "score": score,
        "level": level,
        "contributors": contributors,
        "summary": summary,
    }


def score_all_attackers(attacker_ips: dict, all_findings: list[dict]) -> dict:
    """
    Score every attacker and return a mapping IP -> threat_score dict.
    Also returns an aggregate overall score.
    """
    findings_by_ip = {}
    for f in all_findings:
        ip = f.get("ip")
        if ip:
            findings_by_ip.setdefault(ip, []).append(f)

    scores = {}
    for ip, attacker_data in attacker_ips.items():
        scores[ip] = calculate_threat_score(attacker_data, findings_by_ip.get(ip, []))

    # Aggregate: weighted average based on count
    total_count = sum(a.get("count", 0) for a in attacker_ips.values()) or 1
    overall_score = 0
    for ip, sc in scores.items():
        weight = attacker_ips.get(ip, {}).get("count", 0) / total_count
        overall_score += sc["score"] * weight
    overall_score = round(overall_score)

    if overall_score >= 75:
        overall_level = "critical"
    elif overall_score >= 50:
        overall_level = "high"
    elif overall_score >= 25:
        overall_level = "medium"
    elif overall_score > 0:
        overall_level = "low"
    else:
        overall_level = "info"

    return {
        "perAttacker": scores,
        "overallScore": overall_score,
        "overallLevel": overall_level,
    }
