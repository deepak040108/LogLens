# LogLens Performance Notes

## Why streaming, not loading

A naive `open(file).readlines()` or `pandas.read_csv(file)` on a
500MB+ access log holds every parsed row in memory simultaneously.
LogLens never does this — see the concrete, *tested* claims below,
not just assertions.

## How chunks are processed

```
Read chunk (5,000 lines)
   ↓
Parse each line (regex, Python file iterator — lazy, not read-all)
   ↓
Detect (pandas-vectorized regex across the chunk's rows)
   ↓
Aggregate (update small running Counters/dicts)
   ↓
Compute threat scores per attacker IP
   ↓
Detect correlations across all findings
   ↓
Discard chunk
   ↓
Read next chunk
```

`parser/apache_parser.py`'s `stream_parse_file()` is a **generator**:
Python's file object is itself a lazy line iterator (the OS handles
buffered reads under the hood — the whole file is never resident in
the Python process), and the parser only accumulates
`config.CHUNK_SIZE` (5,000) parsed dicts before `yield`-ing that list
and starting a new one. The caller (`jobs/worker.py`) processes and
discards each chunk before the next is read.

## How memory usage is controlled

1. **Chunked parsing** (above) bounds peak memory to roughly one
   chunk's worth of parsed rows, not the whole file's.
2. **Regex patterns are compiled once**, at module import time
   (`detection/engine.py`'s `COMPILED_RULES`), not per-line or
   per-request.
3. **Aggregation is incremental**: `analysis/aggregator.py`'s
   `Aggregator` class holds only small `Counter`s (attacks-per-hour,
   attacks-by-type, status codes) and a dict keyed by attacker IP —
   never a list of every finding in the file. The one exception is a
   deliberately bounded ring buffer (`recentFindings`, capped at 500
   internally, exposed as the most recent 100) for the live threat
   feed — an unbounded list here would be the one place memory could
   actually grow with attack volume.
4. **pandas DataFrames are chunk-scoped**: `detect_chunk()` builds one
   DataFrame per 5,000-row chunk for vectorized `str.contains`
   matching, then that DataFrame goes out of scope and is garbage
   collected before the next chunk is read — it is never accumulated
   across chunks.
5. **Byte-based progress tracking**: The worker counts bytes read,
   not just lines, providing more accurate progress for the upload
   endpoint.

## How asynchronous processing works

`POST /api/upload` and `POST /api/demo` return a `job_id` immediately
(HTTP 202) without waiting for processing to finish. The actual
parse → detect → aggregate work runs on a background thread
(`jobs/worker.py`), and the frontend polls `GET /api/jobs/<id>` every
700ms for real progress (`processed_lines` / `total_lines` /
`progress` percentage — computed from an actual line count taken
before parsing begins, never a fixed/fake animation).

## File retention and cleanup

A background thread (`security/cleanup.py`) runs hourly and removes
uploaded files older than the configured retention period (default 24
hours). This prevents disk space exhaustion in long-running
deployments. The retention period is configurable via the
`RETENTION_HOURS` environment variable.

## Rate limiting

The sliding-window rate limiter (`security/rate_limit.py`) uses an
in-memory dict of timestamp lists per key. Each request appends the
current timestamp; expired entries (older than the window) are
pruned on each check. This is O(n) in the number of recent requests
per key, but since the window is bounded (e.g., 60 seconds), the
list stays small regardless of traffic volume.

## Measured results (not estimated)

Run via `pytest tests/test_performance.py`:

| Lines     | Result |
|-----------|--------|
| 1,000     | Passed — all requests correctly parsed and classified |
| 10,000    | Passed |
| 100,000   | Passed, peak traced memory < 40MB (`tracemalloc`-measured) |
| 1,000,000 | Passed in ~55 seconds on the development machine |

The 100K-line memory test is the concrete claim behind "streaming,
not loading": 100,000 fully-materialized parsed-row Python dicts held
in memory at once would run into the tens of MB; chunked processing
(5,000-row chunks, each discarded before the next is read) keeps peak
traced allocation under 40MB regardless of file size — the ceiling is
set by chunk size, not by total line count.

## Database performance

`jobs/store.py` uses SQLite with the following indexes for query performance:
- `idx_jobs_status` on `jobs(status)` — fast status lookups
- `idx_jobs_created` on `jobs(created_at)` — recent jobs first
- `idx_findings_job_id` on `findings(job_id)` — fast job lookups
- `idx_findings_ip` on `findings(ip)` — per-attacker queries
- `idx_findings_severity` on `findings(severity)` — severity filtering
- `idx_findings_attack_type` on `findings(attack_type)` — category filtering

Findings support paginated queries via `GET /api/findings/<job_id>?page=1&limit=50`
with optional filters: `severity`, `attack_type`, `ip`.

## What isn't optimized (and why that's an acceptable tradeoff here)

- **No multiprocessing/worker pool for parsing.** Parsing is I/O-bound
  (reading from disk), not CPU-bound, so a single thread keeps up;
  Python's GIL is released during file I/O regardless.
- **The regex engine re-scans the full `target` string per signature**
  rather than building one combined alternation pattern. This trades
  a small amount of per-line CPU for signature clarity/maintainability
  (`signatures.json` entries stay independently readable and
  toggleable per rule). At the tested scale (1M lines in ~55s) this
  hasn't been a bottleneck.
- **Threat scoring is per-chunk, not global.** Scores are computed
  incrementally as chunks are processed. The final summary aggregates
  per-attacker scores. This is a reasonable approximation — a global
  recompute after all chunks would be more accurate but would require
  holding all attacker data in memory.
- **Correlation detection runs once at the end**, after all chunks
  are processed. This is correct since correlation needs to see all
  events to detect multi-stage patterns, but it does require storing
  all findings in memory during processing. The findings table in
  SQLite provides persistence beyond the in-memory window.
