"""
analysis/timeline.py
------------------------------------------------------------------------
Small helpers for the timeline endpoint (GET /api/timeline/<job_id>) --
kept separate from aggregator.py per the required project structure,
since the aggregator's `timeline` field is the raw hourly rollup and
this module is where range-filtering logic for the frontend's
"change the time range" control (spec §8) lives.
------------------------------------------------------------------------
"""


def filter_timeline(timeline: list[dict], start_hour: str | None, end_hour: str | None) -> list[dict]:
    """timeline entries are {"hour": "YYYY-MM-DDTHH", "count": N}.
    start_hour/end_hour are the same 'YYYY-MM-DDTHH' strings, inclusive."""
    if not start_hour and not end_hour:
        return timeline
    out = []
    for entry in timeline:
        if start_hour and entry["hour"] < start_hour:
            continue
        if end_hour and entry["hour"] > end_hour:
            continue
        out.append(entry)
    return out
