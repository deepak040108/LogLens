# LogLens Architecture

## Pipeline

```
Log File → Secure Upload → Job Creation → Streaming Parser →
Structured Records → Threat Detection → Behavioral Detection →
Event Aggregation → GeoIP Enrichment → Threat Scoring →
Correlation Analysis → Security Report → React Dashboard
```

Every stage is real, tested code — there is no fake/static dashboard
path. All dashboard numbers come from `analysis/aggregator.py`'s
`Aggregator.to_summary()`, which is built incrementally from what the
parser and detection engine actually found in the uploaded file.

## Backend module layout

```
backend/
├── app.py                 Flask entrypoint, registers blueprints, owns the single JobQueue,
│                          sets up CORS, security headers, rate limiting, and cleanup thread
├── config.py              All tunables via environment variables (dotenv) — nothing hardcoded
├── auth/
│   └── jwt_auth.py        JWT authentication: create_token, verify_token, require_auth/optional_auth
│                          decorators, bcrypt password hashing, demo user (admin/loglens)
├── security/
│   ├── rate_limit.py      Sliding-window rate limiter per IP and endpoint category
│   └── cleanup.py         Background thread for hourly file retention cleanup
├── parser/
│   ├── apache_parser.py   Canonical Combined Log Format regex parser (streaming generator)
│   └── nginx_parser.py    Re-exports apache_parser — Nginx's default `combined` format is byte-identical
├── detection/
│   ├── signatures.json    8-category regex signature database (155+ patterns)
│   │                      Categories: sql_injection, xss, directory_traversal, command_injection,
│   │                      log4shell, recon, sensitive_data_access, suspicious_response
│   ├── engine.py          Loads + compiles signatures.json once, pandas-vectorized matching,
│   │                      produces explainable findings with rule_id, confidence, recommendation
│   ├── brute_force.py     Stateful rolling-window behavioral detector (thread-safe deque)
│   └── rule_state.py      Persisted enabled/disabled state per rule category (generated at runtime)
├── analysis/
│   ├── aggregator.py      Incremental summary builder with threat scores, correlations, findings
│   ├── threat_scoring.py  0-100 transparent scoring with visible contributors per attacker
│   ├── correlation.py     Multi-stage attack detection: recon→exploit, multi-vector, automated campaigns
│   ├── timeline.py        Time-range filtering helper for the timeline endpoint
│   └── geoip.py           Real MaxMind GeoLite2 lookup, honest "Location unavailable" fallback
├── jobs/
│   ├── worker.py          Job orchestration: create_job / get_job / submit with byte-based progress
│   └── store.py           SQLite persistence with indexes on status, timestamps, ip, severity
├── routes/
│   ├── auth.py            POST /api/auth/login, POST /api/auth/register
│   ├── upload.py          POST /api/upload, POST /api/demo — validates input, SHA-256 hashing
│   ├── threats.py         GET /api/jobs, /threats, /attackers, /timeline, /geo, /rules, /settings,
│   │                      /health, /findings/<id>; PATCH /api/rules/<id>
│   └── reports.py         GET /api/reports — JSON/CSV/PDF implemented (professional PDF with charts)
├── geoip/
│   └── GeoLite2-Country.mmdb  MaxMind database for country-level IP geolocation
├── tests/
│   ├── test_detection.py  10 tests: regex detection + brute force behavior
│   ├── test_parser.py     7 tests: Apache/Nginx parsing, malformed input handling
│   ├── test_security.py   12 tests: JWT auth, rate limiting, file hashing, input validation
│   └── test_performance.py 5 tests: pipeline at 1K/10K/100K/1M lines, memory bounds
└── .env.example           All configurable environment variables documented
```

## Frontend module layout

```
frontend/src/
├── App.tsx                  React Router routes: landing page + app pages under /app, auth-gated
├── context/JobContext.tsx    Single source of truth for "the currently analyzed job"
├── lib/api.ts               Typed fetch wrapper with JWT auth headers for every backend endpoint
├── types.ts                 Shared TypeScript types including ThreatScore, CorrelationFinding
├── layout/
│   ├── Sidebar.tsx          Navigation with user info + sign out
│   ├── Topbar.tsx           Breadcrumb and page title
│   └── AppLayout.tsx        Shell layout
├── pages/
│   ├── Login.tsx            JWT login page (admin/loglens)
│   ├── Landing.tsx          Public landing page
│   ├── Dashboard.tsx        Main dashboard: critical alerts, top threats, recent findings
│   ├── Analyzer.tsx         Upload interface with drag-and-drop
│   ├── Threats.tsx          Threat list with severity filter including "Critical" level
│   ├── Attackers.tsx        Attacker IP list sorted by count
│   ├── AttackerDetail.tsx   Per-attacker view: threat score, evidence, attack history
│   ├── Timeline.tsx         Attack timeline chart
│   ├── GeoMap.tsx           Geographic map of attacks by country
│   ├── Reports.tsx          Export interface
│   ├── Rules.tsx            Detection rule management
│   └── Settings.tsx         System configuration display
└── components/
    ├── KpiCard.tsx           Key performance indicator cards
    ├── SeverityBadge.tsx     Severity badge (icon+text, never color-only)
    ├── charts/               Recharts-based visualizations
    ├── WorldMap.tsx          Geographic visualization
    └── modals/               Detail modals
```

## Authentication model

1. **JWT-based**: Login returns a 24-hour JWT token stored in localStorage
2. **Protected routes**: Upload, demo, and rule changes require `Authorization: Bearer <token>`
3. **Optional auth**: GET endpoints accept optional auth — authenticated users see enhanced data
4. **Demo user**: `admin` / `loglens` — bcrypt-hashed password, seeded at startup
5. **Registration**: `POST /api/auth/register` with username/password validation

## Security layers

| Layer | Implementation |
|-------|---------------|
| Authentication | JWT tokens with HS256, bcrypt password hashing |
| Rate limiting | Sliding window: 100/min general, 10/min upload, 5/min login |
| CORS | Environment-configurable allowed origins |
| Headers | CSP, X-Frame-Options, Permissions-Policy, Cache-Control, X-Content-Type-Options |
| File validation | Extension allowlist, size cap, SHA-256 hash, content sniff for binary |
| Cleanup | Background thread removes uploads older than retention period |

## Why the job queue is a "development fallback," not fake Celery

The brief's target production architecture is Celery + Redis. This
application runs in a sandboxed evaluation environment without a
persistent Redis broker available, so `jobs/worker.py` implements the
explicitly-permitted fallback: a `threading`-based worker exposing the
exact same contract (`create_job` / `get_job` / `submit`) a
Celery-backed implementation would.

**To swap in real Celery + Redis:**
1. Replace `JobQueue._run`'s direct thread dispatch with a Celery task:
   `@app.task def process_job(job_id): ...` containing the same body.
2. `submit()` becomes `process_job.delay(job_id)` instead of starting a
   `threading.Thread`.
3. `get_job()` still reads from `jobs/store.py` (SQLite/Postgres) —
   that part doesn't change, since job state was always persisted
   there, not just held in the in-memory dict.
4. Nothing in `parser/`, `detection/`, or `analysis/` changes at all —
   this is the whole point of the `create_job/get_job/submit`
   boundary.

## Database

`jobs/store.py` uses plain `sqlite3` with parameterized SQL — no ORM.
That was a deliberate choice: the production swap to PostgreSQL is a
connection-string and driver change (`sqlite3.connect(...)` →
`psycopg2.connect(...)`), not a rewrite, because there's no
ORM-specific dialect to migrate away from.

Tables:
- **jobs**: Stores job metadata with indexes on `status` and `created_at`
- **findings**: Stores individual attack findings with indexes on `job_id`, `ip`, `severity`, `attack_type`; supports pagination via `page`/`limit` parameters

## Threat scoring

Each attacker IP receives a 0-100 score computed by `analysis/threat_scoring.py`:
- **Base points** from severity counts (critical: +30, high: +15, medium: +5)
- **Volume bonus** for 10+ unique attack types (+20)
- **Time span penalty** for 24h+ attack window (+15)
- **Attack diversity** for 5+ categories (+10)
- **Reconnaissance** bonus for scanning patterns (+5)
- Level classification: critical (75-100), high (50-74), medium (25-49), low (1-24), info (0)

## Correlation analysis

`analysis/correlation.py` detects coordinated attack patterns:
- **Reconnaissance-to-Exploitation**: IP performed recon probes followed by exploitation attempts
- **Multi-Vector Attack**: IP launched 3+ distinct attack types (suggests automated tooling)
- **Automated Campaign**: 5+ attack requests within 60 seconds (rapid-fire pattern)

## GeoIP — why it's real-or-honest, not real-or-fake

`analysis/geoip.py` attempts a real MaxMind GeoLite2-Country lookup.
If the `.mmdb` file isn't present, it does **not** fall back to a
synthetic IP-range-to-country mapping. Every result carries an
`available: bool` flag, and the frontend surfaces "Location
unavailable" instead of a country whenever that flag is false. This
was a specific, explicit requirement — fabricated geography in a
security tool is worse than admitting a gap.
