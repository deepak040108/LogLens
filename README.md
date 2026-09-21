# LogLens

**Lightweight Web Log Threat Detection & Investigation Platform**

LogLens takes raw Apache/Nginx web server logs, securely processes them using streaming analysis, identifies suspicious behavior using explainable detection rules, correlates related activity, shows who attacked the server and how, and produces investigation-ready reports.

## Overview

LogLens is a rule-based web log analysis platform designed for security analysts and system administrators. It processes web server access logs at scale, detects known attack patterns through signature-based and behavioral analysis, and presents findings through a professional investigation dashboard.

**This is not a full enterprise SIEM.** It is a focused tool for web server log threat detection and investigation.

## Key Features

- **Streaming Log Processing** — Chunk-based parsing handles multi-GB files without loading the entire file into memory
- **Signature-Based Detection** — 155+ regex patterns across 8 attack categories (SQLi, XSS, traversal, command injection, Log4Shell, recon, sensitive data access, suspicious responses)
- **Behavioral Detection** — Rolling-window brute-force detection with configurable thresholds
- **Threat Correlation** — Groups related events by IP, time window, and attack category to identify multi-stage attacks
- **Explainable Threat Scoring** — Transparent scoring with visible contributors (severity, frequency, diversity, recency)
- **JWT Authentication** — Secure API access with token-based authentication
- **Rate Limiting** — Sliding-window rate limiting per endpoint
- **GeoIP Integration** — Real MaxMind GeoLite2 country lookup with honest fallback
- **Professional PDF Reports** — Investigation-ready reports with file hashes, severity breakdown, and recommendations
- **Dark SOC Dashboard** — Professional cybersecurity-style interface

## Architecture

```
                    ┌──────────────┐
                    │   Analyst    │
                    └──────┬───────┘
                           │
                           ▼
                  ┌─────────────────┐
                  │ React Dashboard  │
                  │ JWT Auth + Dark  │
                  └────────┬────────┘
                           │
                           ▼
                  ┌─────────────────┐
                  │ Secure Flask API │
                  │ Auth + Rate Limit│
                  │ CORS + Headers   │
                  └────────┬────────┘
                           │
                           ▼
                  ┌─────────────────┐
                  │ Background Queue │
                  │ Thread-based     │
                  └────────┬────────┘
                           │
                           ▼
                  ┌─────────────────┐
                  │ Streaming Parser │
                  │ Chunk Generator  │
                  └────────┬────────┘
                           │
              ┌────────────┴────────────┐
              ▼                         ▼
      ┌────────────────┐       ┌─────────────────┐
      │ Signature      │       │ Behavioral      │
      │ Detection      │       │ Detection       │
      └────────┬───────┘       └────────┬────────┘
               │                        │
               └────────────┬───────────┘
                            ▼
                   ┌─────────────────┐
                   │ Correlation &   │
                   │ Threat Scoring  │
                   └────────┬────────┘
                            │
                ┌───────────┼───────────┐
                ▼           ▼           ▼
           Findings     Attackers    Timeline
                │           │           │
                └───────────┼───────────┘
                            ▼
                   ┌─────────────────┐
                   │ Reports / PDF   │
                   └─────────────────┘
```

## Detection Engine

### Attack Categories

| Category | ID | Severity | Patterns |
|----------|-----|----------|----------|
| SQL Injection | SQLI | High | 25+ patterns including UNION, blind, hex-encoded |
| XSS | XSS | High | 20+ patterns including event handlers, SVG, data URIs |
| Directory Traversal | TRAVERSAL | High | 15+ patterns including URL-encoded, null byte |
| Command Injection | CMDI | High | 15+ patterns including backticks, pipes, env vars |
| Log4Shell | LOG4SHELL | High | 10+ JNDI lookup patterns |
| Recon/Scanner | RECON | Low-Medium | 25+ scanner signatures, API probing |
| Sensitive Data Access | SENSITIVE | Medium | .env, .git, backup files |
| Suspicious Response | SUSPICIOUS | Low | Unusual status code patterns |

### Brute Force Detection

Configurable rolling-window detection:
- Default: 10 failures within 5 minutes from same IP
- Monitors HTTP 401 responses
- Tracks usernames attempted

### Threat Correlation

Groups related events to identify:
- **Reconnaissance-to-Exploitation Patterns** — recon followed by exploitation attempts
- **Multi-Vector Attacks** — multiple attack categories from same IP
- **Automated Attack Campaigns** — rapid succession of different attacks

### Threat Scoring

Transparent, explainable scoring (0-100):

```
Score = Severity Weight + Frequency + Category Diversity + Recency

Contributors:
+30  High severity SQL Injection detected
+20  12 attempts in 5 minutes
+15  3 different attack categories
+22  Activity within last hour
```

## Security Model

- **JWT Authentication** — Token-based API access with 24-hour expiry
- **Rate Limiting** — Sliding window: 100 req/min general, 10/min upload, 5/min login
- **CORS** — Environment-configurable allowed origins
- **Security Headers** — CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy
- **File Validation** — Extension allowlist, size limits, content sniffing, SHA-256 hashing
- **Upload Retention** — Configurable cleanup of uploaded files (default 24 hours)

## Supported Log Formats

**Apache/Nginx Combined Log Format** (also known as Common Log Format with extensions):

```
IP - - [timestamp] "METHOD /path HTTP/1.1" status size "referer" "user-agent"
```

This is the default log format for both Apache and Nginx. Additional formats (JSON, custom) can be added by implementing new parser modules.

## Installation

### Prerequisites

- Python 3.12+
- Node.js 18+
- MaxMind GeoLite2 database (optional, for geolocation)

### Backend Setup

```bash
cd backend

# Create virtual environment
python -m venv venv
source venv/bin/activate  # Linux/Mac
# venv\Scripts\activate   # Windows

# Install dependencies
pip install -r requirements.txt

# Configure environment (optional)
cp .env.example .env
# Edit .env with your settings

# Start server
python app.py  # http://localhost:4000
```

### Frontend Setup

```bash
cd frontend
npm install
npm run dev  # http://localhost:5173 (dev) or npm run build for production
```

### GeoIP Setup

1. Create a free MaxMind account: https://www.maxmind.com/en/geolite2/signup
2. Download GeoLite2-Country.mmdb
3. Place at `backend/geoip/GeoLite2-Country.mmdb`
4. The Geo Map page will show real country data

## Docker Setup

```bash
docker compose build
docker compose up
# Open http://localhost:4000
```

## Configuration

All configuration is via environment variables (see `backend/.env.example`):

| Variable | Default | Description |
|----------|---------|-------------|
| SECRET_KEY | dev-secret-change-me | JWT signing key |
| PORT | 4000 | Server port |
| CORS_ALLOWED_ORIGINS | http://localhost:5173,http://localhost:4000 | Allowed origins |
| MAX_UPLOAD_SIZE | 2147483648 | Max upload bytes (2GB) |
| RETENTION_HOURS | 24 | File retention period |
| RATE_LIMIT_GENERAL | 100 | Requests/minute general |
| RATE_LIMIT_UPLOAD | 10 | Requests/minute upload |
| RATE_LIMIT_LOGIN | 5 | Requests/minute login |
| GEOIP_DB_PATH | backend/geoip/GeoLite2-Country.mmdb | GeoIP database path |
| LOGLENS_BRUTE_FORCE_THRESHOLD | 10 | Brute force threshold |
| LOGLENS_BRUTE_FORCE_WINDOW_SECONDS | 300 | Brute force window |

## API

Full REST API reference: [docs/api.md](docs/api.md)

### Authentication

```bash
# Login
curl -X POST http://localhost:4000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "loglens"}'

# Use token
curl -H "Authorization: Bearer <token>" http://localhost:4000/api/jobs/<id>
```

### Key Endpoints

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| POST | /api/auth/login | No | Login, get JWT |
| POST | /api/upload | Yes | Upload log file |
| POST | /api/demo | Yes | Load demo log |
| GET | /api/jobs/<id> | Optional | Job status |
| GET | /api/threats/<id> | Optional | Threat events |
| GET | /api/attackers/<id> | Optional | Attacker details |
| GET | /api/findings/<id> | Optional | Paginated findings |
| GET | /api/reports/<id>?format=pdf | Optional | PDF report |
| PATCH | /api/rules/<name> | Yes | Toggle rule |

## Performance

Processing is streaming/chunk-based. See [docs/performance.md](docs/performance.md) for measured results.

Key design:
- File is processed in chunks (default 5000 lines per chunk)
- Memory usage stays flat regardless of file size
- Progress is based on actual processed bytes
- Findings are persisted to SQLite for large datasets

## Testing

```bash
cd backend
python -m pytest tests/ -m "not slow"      # ~30s, unit + integration tests
python -m pytest tests/ -m slow             # +55s, the 1M-line performance test
python -m pytest tests/                     # all tests
```

## Current Limitations

- Primarily supports Apache/Nginx Combined Log Format
- Signature-based detection (not ML/AI) — cannot detect unknown attack patterns
- SQLite suitable for local/small deployments; PostgreSQL recommended for production
- Background processing is single-node in thread-based dev mode
- GeoIP depends on an external MaxMind database
- Detection signatures cannot guarantee detection of all variants of an attack
- Results require analyst validation before taking operational action
- Docker deployment not independently verified end-to-end

## Project Structure

```
loglens-v2/
├── backend/
│   ├── app.py                 # Flask entrypoint
│   ├── config.py              # Central configuration
│   ├── auth/                  # JWT authentication
│   ├── security/              # Rate limiting, cleanup
│   ├── parser/                # Log parsing (streaming)
│   ├── detection/             # Signature + behavioral detection
│   ├── analysis/              # Aggregation, scoring, correlation, GeoIP
│   ├── jobs/                  # Background job orchestration
│   ├── routes/                # API endpoints
│   └── tests/                 # Test suite
├── frontend/
│   └── src/                   # React + TypeScript dashboard
├── demo/                      # Sample log files
├── docs/                      # Architecture, API, performance docs
└── docker-compose.yml         # Docker deployment
```

## Documentation

- [Architecture](docs/architecture.md) — Module layout, design decisions
- [API Reference](docs/api.md) — Full REST API documentation
- [Performance](docs/performance.md) — Streaming strategy, benchmarks

## License

See individual dependencies for their respective licenses. MaxMind GeoLite2 database is subject to the [MaxMind End User License Agreement](https://www.maxmind.com/en/geolite/eula).
