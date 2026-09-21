"""
parser/apache_parser.py
------------------------------------------------------------------------
Streams an Apache access log (Common/Combined Log Format) and yields
parsed rows in CHUNKS as plain dicts.

Memory stays flat regardless of file size: the file object is a lazy
line iterator (Python doesn't load the whole file), and only
CHUNK_SIZE rows are held in Python objects before being yielded and
discarded by the caller.
------------------------------------------------------------------------
"""

import re
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config import CHUNK_SIZE  # noqa: E402

MONTHS = {
    "Jan": "01", "Feb": "02", "Mar": "03", "Apr": "04", "May": "05", "Jun": "06",
    "Jul": "07", "Aug": "08", "Sep": "09", "Oct": "10", "Nov": "11", "Dec": "12",
}

# Combined Log Format:
# 127.0.0.1 - frank [10/Oct/2023:13:55:36 -0700] "GET /index.html HTTP/1.0" 200 2326 "http://ref" "UA"
CLF_PATTERN = re.compile(
    r'^(?P<ip>\S+) \S+ (?P<user>\S+) \[(?P<ts>[^\]]+)\] '
    r'"(?P<method>\S+)\s+(?P<path>\S+)(?:\s+(?P<protocol>\S+))?" '
    r'(?P<status>\d{3}) (?P<size>\d+|-)'
    r'(?:\s+"(?P<referrer>[^"]*)")?'
    r'(?:\s+"(?P<useragent>[^"]*)")?'
)

TS_PATTERN = re.compile(
    r"^(\d{2})/(\w{3})/(\d{4}):(\d{2}):(\d{2}):(\d{2})\s*([+-]\d{4})?"
)


def parse_timestamp(raw: str):
    m = TS_PATTERN.match(raw)
    if not m:
        return None
    day, mon, year, hh, mm, ss, tz = m.groups()
    offset = f"{tz[:3]}:{tz[3:]}" if tz else "+00:00"
    try:
        return f"{year}-{MONTHS.get(mon, '01')}-{day}T{hh}:{mm}:{ss}{offset}"
    except Exception:
        return None


def parse_line(line: str, line_number: int):
    """Parse a single log line into a dict, or a malformed marker.
    A malformed line is skipped, never fatal to the rest of the file."""
    line = line.strip()
    if not line:
        return None
    m = CLF_PATTERN.match(line)
    if not m:
        return {"lineNumber": line_number, "malformed": True}

    g = m.groupdict()
    try:
        status = int(g["status"])
    except (TypeError, ValueError):
        return {"lineNumber": line_number, "malformed": True}

    return {
        "lineNumber": line_number,
        "ip": g["ip"],
        "user": None if g["user"] == "-" else g["user"],
        "timestamp": parse_timestamp(g["ts"]),
        "method": g["method"].upper(),
        "path": g["path"],
        "protocol": g.get("protocol"),
        "status": status,
        "size": 0 if g["size"] == "-" else int(g["size"]),
        "referrer": g.get("referrer") or None,
        "userAgent": g.get("useragent") or None,
        "malformed": False,
    }


def stream_parse_file(file_path, chunk_size=CHUNK_SIZE):
    """Generator: yields lists ("chunks") of parsed row dicts. This is
    what keeps a multi-GB log from ever being fully materialized in
    memory -- see docs/performance.md."""
    chunk = []
    line_number = 0
    total_lines = 0
    with open(file_path, "r", encoding="utf-8", errors="replace") as f:
        for raw_line in f:
            line_number += 1
            total_lines += 1
            entry = parse_line(raw_line, line_number)
            if entry is None:
                continue
            chunk.append(entry)
            if len(chunk) >= chunk_size:
                yield chunk
                chunk = []
    if chunk:
        yield chunk
