"""
analysis/aggregator.py
------------------------------------------------------------------------
Accumulates findings chunk-by-chunk into small running structures, so
the raw findings list is never all held in memory at once for a huge
file — only these running Counters/dicts are, plus a bounded recent-
events ring buffer. pandas is used only at the end, on data that's
already small, to produce sorted rollups.

Now also stores threat scores per attacker and correlation findings,
included in the final to_summary() output.
------------------------------------------------------------------------
"""

import sys
import os
import math
from collections import Counter, deque

import pandas as pd

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from analysis.geoip import resolve_country, resolve_city, resolve_asn  # noqa: E402
from analysis.threat_scoring import calculate_threat_score  # noqa: E402

MAX_RECENT = 500
SEVERITY_ORDER = ["critical", "high", "medium", "low"]


def _sanitize(val):
    """Convert NaN/inf floats to None for valid JSON serialization.
    Also convert float ints (e.g. 209272.0) to actual ints."""
    if val is None:
        return None
    if isinstance(val, float):
        if math.isnan(val) or math.isinf(val):
            return None
        if val == int(val):
            return int(val)
    return val


def _sanitize_dict(d):
    """Recursively sanitize all values in a dict."""
    if not isinstance(d, dict):
        return d
    return {k: _sanitize(v) if not isinstance(v, (dict, list)) else (_sanitize_dict(v) if isinstance(v, dict) else [_sanitize_dict(i) if isinstance(i, dict) else _sanitize(i) if isinstance(i, float) else i for i in v]) for k, v in d.items()}


class Aggregator:
    def __init__(self):
        self.total_lines = 0
        self.total_requests = 0
        self.malformed_lines = 0
        self.total_attacks = 0
        self.status_counts = Counter()
        self.severity_counts = Counter()
        self.attacks_per_hour = Counter()
        self.attacks_by_type = Counter()
        self.attacker_ips = {}
        self.recent_findings = deque(maxlen=MAX_RECENT)
        self.geoip_available = None
        self.all_findings = []  # retained for post-processing (threat scoring, correlation)
        self.correlation_findings = []
        self.threat_scores = {}

    def record_chunk(self, rows: list[dict], findings: list[dict]):
        clean = [r for r in rows if not r.get("malformed")]
        self.total_lines += len(rows)
        self.malformed_lines += len(rows) - len(clean)
        self.total_requests += len(clean)
        for r in clean:
            if r.get("status"):
                self.status_counts[r["status"]] += 1

        self.total_attacks += len(findings)
        self.all_findings.extend(findings)

        for f in findings:
            self.severity_counts[f["severity"]] += 1
            if f.get("timestamp"):
                self.attacks_per_hour[f["timestamp"][:13]] += 1
            self.attacks_by_type[f["attack_type"]] += 1

            ip = f["ip"]
            if ip not in self.attacker_ips:
                geo = resolve_country(ip)
                city_data = resolve_city(ip)
                asn_data = resolve_asn(ip)
                if self.geoip_available is None:
                    self.geoip_available = geo["available"]
                self.attacker_ips[ip] = {
                    "ip": ip,
                    "count": 0,
                    "severityCounts": Counter(),
                    "typeCounts": Counter(),
                    "firstSeen": f["timestamp"],
                    "lastSeen": f["timestamp"],
                    "country": geo["country"],
                    "countryCode": geo["countryCode"],
                    "geoAvailable": geo["available"],
                    "city": city_data.get("city"),
                    "region": city_data.get("region"),
                    "latitude": city_data.get("latitude"),
                    "longitude": city_data.get("longitude"),
                    "asn": asn_data.get("asn"),
                    "organization": asn_data.get("organization"),
                }
            rec = self.attacker_ips[ip]
            rec["count"] += 1
            rec["severityCounts"][f["severity"]] += 1
            rec["typeCounts"][f["attack_type"]] += 1
            rec["lastSeen"] = f["timestamp"] or rec["lastSeen"]

            self.recent_findings.append(f)

    def post_process(self):
        """Called once after all chunks are processed. Computes threat
        scores per attacker and runs attack correlation."""
        # Threat scoring
        for ip, attacker_data in self.attacker_ips.items():
            ip_findings = [f for f in self.all_findings if f.get("ip") == ip]
            self.threat_scores[ip] = calculate_threat_score(attacker_data, ip_findings)

    def set_correlation(self, correlation_findings: list[dict]):
        """Store correlation results from worker after all chunks processed."""
        self.correlation_findings = correlation_findings

    def to_summary(self) -> dict:
        timeline = (
            pd.Series(self.attacks_per_hour).sort_index().reset_index()
            .rename(columns={"index": "hour", 0: "count"}).to_dict("records")
            if self.attacks_per_hour else []
        )

        by_type = (
            pd.Series(self.attacks_by_type).sort_values(ascending=False).reset_index()
            .rename(columns={"index": "attack_type", 0: "count"}).to_dict("records")
            if self.attacks_by_type else []
        )

        total_sev = sum(self.severity_counts.values()) or 1
        severity_breakdown = [
            {"severity": s, "count": self.severity_counts.get(s, 0),
             "percentage": round(100 * self.severity_counts.get(s, 0) / total_sev, 1)}
            for s in SEVERITY_ORDER if self.severity_counts.get(s, 0) or s in ("high", "medium", "low")
        ]

        # Enrich attacker records with threat scores
        attacker_list = []
        for r in self.attacker_ips.values():
            ts = self.threat_scores.get(r["ip"], {})
            attacker_list.append({
                "ip": r["ip"], "count": r["count"],
                "country": _sanitize(r["country"]),
                "countryCode": _sanitize(r["countryCode"]),
                "geoAvailable": r["geoAvailable"],
                "city": _sanitize(r.get("city")), "region": _sanitize(r.get("region")),
                "latitude": _sanitize(r.get("latitude")), "longitude": _sanitize(r.get("longitude")),
                "asn": _sanitize(r.get("asn")), "organization": _sanitize(r.get("organization")),
                "topAttack": r["typeCounts"].most_common(1)[0][0] if r["typeCounts"] else None,
                "severity": max(r["severityCounts"], key=lambda s: (SEVERITY_ORDER.index(s) * -1, r["severityCounts"][s]))
                if r["severityCounts"] else "low",
                "firstSeen": r["firstSeen"], "lastSeen": r["lastSeen"],
                "attackHistory": [{"attack_type": t, "count": c} for t, c in r["typeCounts"].most_common()],
                "threatScore": ts if isinstance(ts, dict) else {"score": ts.get("score", 0) if isinstance(ts, dict) else 0, "level": "info", "contributors": [], "summary": ""},
                "threatLevel": ts.get("level", "info"),
            })

        attackers_df = pd.DataFrame(attacker_list) if attacker_list else pd.DataFrame()

        top_attackers = [_sanitize_dict(r) for r in attackers_df.sort_values("count", ascending=False).head(50).to_dict("records")] if not attackers_df.empty else []

        by_country_list = []
        if not attackers_df.empty:
            geo_ok = attackers_df[attackers_df["geoAvailable"]]
            if not geo_ok.empty:
                by_country = geo_ok.groupby(["country", "countryCode"])["count"].agg(["sum", "count"]).reset_index()
                by_country_list = [
                    {"country": row["country"], "countryCode": row["countryCode"],
                     "attackCount": int(row["sum"]), "uniqueIps": int(row["count"])}
                    for _, row in by_country.iterrows()
                ]

        # Overall threat summary
        all_scores = list(self.threat_scores.values())
        overall_threat_score = 0
        overall_threat_level = "info"
        if all_scores:
            overall_threat_score = round(_sanitize(sum(s["score"] for s in all_scores) / len(all_scores)))
            max_level = max(all_scores, key=lambda s: s["score"])
            overall_threat_level = max_level.get("level", "info")

        return {
            "totalLines": self.total_lines,
            "totalRequests": self.total_requests,
            "malformedLines": self.malformed_lines,
            "totalAttacks": self.total_attacks,
            "uniqueAttackerIps": len(self.attacker_ips),
            "statusCounts": dict(self.status_counts),
            "severityBreakdown": severity_breakdown,
            "timeline": timeline,
            "byType": by_type,
            "byCountry": by_country_list,
            "geoipAvailable": bool(self.geoip_available),
            "topAttackers": top_attackers,
            "recentFindings": [_sanitize_dict(r) for r in list(self.recent_findings)[-100:][::-1]],
            "threatScoring": {
                "overallScore": overall_threat_score,
                "overallLevel": overall_threat_level,
                "perAttacker": {ip: sc for ip, sc in self.threat_scores.items()},
            },
            "correlationFindings": [
                {
                    "type": cf.get("pattern", "Unknown"),
                    "description": cf.get("details", ""),
                    "ips": cf.get("ips", []),
                    "severity": cf.get("severity", "medium"),
                    "confidence": cf.get("confidence", "medium"),
                    "eventCount": cf.get("eventCount", 0),
                    "categories": cf.get("categories", []),
                }
                for cf in self.correlation_findings
            ],
        }
