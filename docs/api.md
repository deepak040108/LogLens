# LogLens API Reference

All responses are JSON unless noted. Base path: `/api`.

## Authentication

LogLens uses JWT (JSON Web Token) authentication. Include the token in the `Authorization` header:

```
Authorization: Bearer <token>
```

### `POST /api/auth/login`
Authenticate and receive a JWT token.

```json
// Request
{ "username": "admin", "password": "loglens" }

// 200
{ "token": "eyJhbGciOiJIUzI1NiIs...", "user": { "username": "admin", "role": "analyst" } }

// 401
{ "error": "Invalid credentials" }
```

### `POST /api/auth/register`
Create a new user account.

```json
// Request
{ "username": "analyst1", "password": "securepass" }

// 201
{ "message": "User created", "user": { "username": "analyst1", "role": "analyst" } }

// 409
{ "error": "Username already exists" }
```

## Rate Limiting

API endpoints are rate-limited using a sliding window algorithm.

| Endpoint | Limit | Window |
|----------|-------|--------|
| General (GET) | 100 requests | 1 minute |
| Upload (POST /upload, /demo) | 10 requests | 1 minute |
| Login (POST /auth/login) | 5 requests | 1 minute |

When rate limited, the response includes:
```json
// 429
{ "error": "Rate limit exceeded. Try again in X seconds.", "retry_after": 45 }
```

## Upload & Job Lifecycle

### `POST /api/upload`
**Requires authentication.** Multipart form upload, field name `logfile`.

Validates:
- Extension: `.log`, `.txt` only
- Non-empty file
- Size: ≤ 2GB
- Content: text-based (rejects binaries)
- MIME: text content sniffing

Returns SHA-256 file hash for audit trail.

```json
// 202
{
  "job_id": "uuid",
  "status": "queued",
  "file_hash": "sha256:abc123..."
}

// 400 examples
{ "error": "Unsupported log format. Supported extensions: .log, .txt" }
{ "error": "The uploaded log file is empty." }
{ "error": "File does not appear to be a text-based log file." }
{ "error": "File too large. Maximum size: 2GB" }

// 429
{ "error": "Rate limit exceeded. Try again in 45 seconds.", "retry_after": 45 }
```

### `POST /api/demo`
**Requires authentication.** No body. Runs the bundled `demo/demo.log` through the same pipeline as a real upload.

### `GET /api/jobs/<job_id>`
**Optional authentication.** Returns job status and progress.

```json
{
  "job_id": "uuid",
  "status": "queued | processing | completed | failed",
  "total_lines": 956,
  "processed_lines": 956,
  "malformed_lines": 0,
  "progress": 100.0,
  "error": null,
  "summary": { "...": "see below, null until status=completed" }
}
```

## Summary Shape

Embedded in the job response once status is `completed`:

```json
{
  "totalLines": 956,
  "totalRequests": 956,
  "malformedLines": 0,
  "totalAttacks": 39,
  "uniqueAttackerIps": 6,
  "fileHash": "sha256:abc123...",
  "statusCounts": { "200": 800, "401": 61 },
  "severityBreakdown": [
    { "severity": "critical", "count": 5, "percentage": 12.8 },
    { "severity": "high", "count": 30, "percentage": 76.9 },
    { "severity": "medium", "count": 2, "percentage": 5.1 },
    { "severity": "low", "count": 2, "percentage": 5.1 }
  ],
  "timeline": [{ "hour": "2026-08-10T15", "count": 11 }],
  "byType": [{ "attack_type": "sql_injection", "count": 12 }],
  "byCountry": [
    { "country": "Netherlands", "countryCode": "NL", "attackCount": 11, "uniqueIps": 1 }
  ],
  "geoipAvailable": true,
  "topAttackers": [
    {
      "ip": "45.33.32.156",
      "count": 12,
      "country": "United States",
      "countryCode": "US",
      "geoAvailable": true,
      "topAttack": "sql_injection",
      "severity": "critical",
      "firstSeen": "2026-08-10T09:22:14+00:00",
      "lastSeen": "2026-08-10T09:22:31+00:00",
      "threatScore": {
        "score": 87,
        "level": "critical",
        "contributors": [
          { "factor": "severity", "points": 40, "detail": "Critical severity payloads detected" },
          { "factor": "frequency", "points": 24, "detail": "12 attempts" },
          { "factor": "diversity", "points": 5, "detail": "1 attack category" },
          { "factor": "recency", "points": 18, "detail": "Recent activity" }
        ],
        "summary": "Active SQL injection attacker with critical payloads"
      },
      "attackHistory": [{ "attack_type": "sql_injection", "count": 12 }]
    }
  ],
  "correlationFindings": [
    {
      "type": "Multi-Vector Attack",
      "description": "IP 192.168.1.100 used 3 different attack categories within 30 minutes",
      "ips": ["192.168.1.100"],
      "timeWindow": "2026-08-10T10:00 to 2026-08-10T10:30",
      "severity": "high"
    }
  ],
  "recentFindings": [
    {
      "ip": "45.33.32.156",
      "timestamp": "2026-08-10T09:22:14+00:00",
      "method": "GET",
      "path": "/search?q=' OR 1=1--",
      "status": 500,
      "userAgent": "sqlmap/1.7.2",
      "attack_type": "sql_injection",
      "severity": "critical",
      "rule_id": "SQLI-001",
      "confidence": "high",
      "matched_signature": "('\\|'%27)\\s*(or|OR)\\s*...",
      "reason": "Request contains SQL injection pattern: boolean-based blind injection (OR 1=1). Matched signature: ('|'%27)\\s*(or|OR)...",
      "recommendation": "Review the source IP and inspect related requests. Consider blocking if confirmed malicious.",
      "all_matches": [
        {
          "attack_type": "sql_injection",
          "severity": "critical",
          "rule_id": "SQLI-001",
          "matched_signature": "..."
        }
      ]
    }
  ]
}
```

## Queries Over a Completed Job

### `GET /api/threats/<job_id>?severity=&attack_type=&ip=`
**Optional authentication.** Filters `recentFindings`. All query params optional and combinable.

```json
{ "events": [ "...finding objects..." ], "count": 12 }
```

### `GET /api/attackers/<job_id>`
**Optional authentication.** Returns all attackers with threat scores.

```json
{ "attackers": [ "...same shape as topAttackers with threatScore..." ] }
```

### `GET /api/timeline/<job_id>?start=&end=`
**Optional authentication.** `start`/`end` are `"YYYY-MM-DDTHH"` strings, inclusive, both optional.

```json
{ "timeline": [{ "hour": "2026-08-10T15", "count": 11 }] }
```

### `GET /api/geo/<job_id>`
**Optional authentication.**

```json
{ "byCountry": [ "..." ], "geoipAvailable": true }
```

### `GET /api/findings/<job_id>?page=1&limit=50&severity=&attack_type=&ip=`
**Optional authentication.** Paginated findings from the database. Supports filtering by severity, attack type, and IP.

```json
{
  "findings": [ "...finding objects..." ],
  "total": 150,
  "page": 1,
  "limit": 50,
  "pages": 3
}
```

## Reports

### `GET /api/reports/<job_id>?format=json|csv|pdf`
**Optional authentication.**

- `json` — full report with all findings, `Content-Disposition: attachment`
- `csv` — top attackers table
- `pdf` — professional security report with:
  - Report ID and generation timestamp
  - Source file name and SHA-256 hash
  - Executive summary with KPIs
  - Severity breakdown with visual bars
  - Attack type distribution
  - Geographic distribution
  - Top attackers with threat scores
  - Timeline analysis
  - Recent threat events
  - Detection methodology
  - Analyst disclaimer

## Detection Rules

### `GET /api/rules`
**Optional authentication.**

```json
{
  "rules": [
    {
      "rule": "sql_injection",
      "id": "SQLI",
      "attackType": "sql_injection",
      "severity": "high",
      "confidence": "high",
      "description": "SQL injection attempt detected",
      "recommendation": "Review source IP and inspect related requests",
      "patternCount": 25,
      "status": "enabled"
    }
  ]
}
```

### `PATCH /api/rules/<rule_name>`
**Requires authentication.** Body: `{ "status": "enabled" | "disabled" }`.

Takes effect on the next analysis — genuinely skips those regex patterns during detection, not a display-only toggle. Persisted to `detection/rule_state.json`.

## Settings & Health

### `GET /api/settings`
**Optional authentication.** Read-only config values (no secrets exposed):

```json
{
  "bruteForceThreshold": 10,
  "bruteForceWindowSeconds": 300,
  "maxUploadBytes": 2147483648,
  "allowedExtensions": [".log", ".txt"],
  "chunkSize": 5000,
  "jobQueueBackend": "thread",
  "geoipAvailable": true,
  "geoipStatus": "GeoLite2 database loaded",
  "retentionHours": 24,
  "rateLimitGeneral": 100,
  "rateLimitUpload": 10,
  "rateLimitLogin": 5
}
```

### `GET /api/health`
**Public.** No authentication required.

```json
{ "ok": true, "geoipAvailable": true, "geoipStatus": "GeoLite2 database loaded" }
```

## Error Responses

Every error response follows a consistent shape:

```json
{ "error": "Human-readable message" }
```

| Status | Meaning |
|--------|---------|
| 400 | Bad request / validation error |
| 401 | Authentication required or invalid credentials |
| 403 | Insufficient permissions |
| 404 | Resource not found |
| 409 | Conflict (e.g., job not complete) |
| 413 | File too large |
| 429 | Rate limit exceeded |
| 500 | Internal server error (details logged server-side, not exposed) |

## Security Notes

- Stack traces are never returned in production responses
- Filesystem paths are not exposed in API responses
- Uploaded files are stored with randomized server-side filenames
- Files are cleaned up after the configured retention period
- All API responses include security headers (CSP, X-Frame-Options, etc.)
