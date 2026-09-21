"""
jobs/store.py
------------------------------------------------------------------------
Persists job metadata and the final summary to SQLite (config.DB_PATH),
per spec §33. Deliberately uses plain sqlite3 + parameterized SQL
(no ORM) so the production swap to PostgreSQL is a connection-string
and driver change, not a rewrite -- see docs/architecture.md.

Only metadata + the (already-small) JSON summary are persisted, never
the raw uploaded log file or the full findings list -- that's what
keeps this table small even after analyzing many large files.
------------------------------------------------------------------------
"""

import sys
import os
import json
import sqlite3
import threading

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config import DB_PATH  # noqa: E402

_lock = threading.Lock()  # sqlite3 connections aren't thread-safe by default


def _connect():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with _lock, _connect() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS jobs (
                id TEXT PRIMARY KEY,
                original_name TEXT,
                status TEXT NOT NULL,
                total_lines INTEGER DEFAULT 0,
                processed_lines INTEGER DEFAULT 0,
                malformed_lines INTEGER DEFAULT 0,
                progress REAL DEFAULT 0,
                error TEXT,
                summary_json TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_jobs_status ON jobs(status)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_jobs_created ON jobs(created_at)")
        conn.execute("""
            CREATE TABLE IF NOT EXISTS findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                job_id TEXT NOT NULL,
                ip TEXT,
                timestamp TEXT,
                method TEXT,
                path TEXT,
                status INTEGER,
                user_agent TEXT,
                attack_type TEXT,
                severity TEXT,
                rule_id TEXT,
                confidence TEXT,
                matched_signature TEXT,
                reason TEXT,
                recommendation TEXT,
                FOREIGN KEY (job_id) REFERENCES jobs(id)
            )
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_findings_job ON findings(job_id)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_findings_ip ON findings(ip)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_findings_attack_type ON findings(attack_type)")
        conn.commit()


def upsert_job(job: dict):
    with _lock, _connect() as conn:
        conn.execute("""
            INSERT INTO jobs (id, original_name, status, total_lines, processed_lines,
                               malformed_lines, progress, error, summary_json, created_at, updated_at)
            VALUES (:id, :originalName, :status, :totalLines, :processedLines,
                    :malformedLines, :progress, :error, :summaryJson, :createdAt, :updatedAt)
            ON CONFLICT(id) DO UPDATE SET
                status=excluded.status,
                total_lines=excluded.total_lines,
                processed_lines=excluded.processed_lines,
                malformed_lines=excluded.malformed_lines,
                progress=excluded.progress,
                error=excluded.error,
                summary_json=excluded.summary_json,
                updated_at=excluded.updated_at
        """, {
            "id": job["id"],
            "originalName": job.get("originalName"),
            "status": job["status"],
            "totalLines": job["progress"].get("totalLines", 0),
            "processedLines": job["progress"].get("parsedLines", 0),
            "malformedLines": job["progress"].get("malformedLines", 0),
            "progress": job["progress"].get("percent", 0),
            "error": job.get("error"),
            "summaryJson": json.dumps(job["summary"]) if job.get("summary") else None,
            "createdAt": job["createdAt"],
            "updatedAt": job.get("updatedAt", job["createdAt"]),
        })
        conn.commit()


def get_job_row(job_id: str):
    with _lock, _connect() as conn:
        row = conn.execute("SELECT * FROM jobs WHERE id = ?", (job_id,)).fetchone()
        if not row:
            return None
        d = dict(row)
        d["summary"] = json.loads(d.pop("summary_json")) if d.get("summary_json") else None
        return d


def insert_findings(job_id: str, findings_list: list):
    with _lock, _connect() as conn:
        conn.executemany("""
            INSERT INTO findings (job_id, ip, timestamp, method, path, status, user_agent,
                                  attack_type, severity, rule_id, confidence, matched_signature,
                                  reason, recommendation)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, [
            (
                job_id,
                f.get("ip"),
                f.get("timestamp"),
                f.get("method"),
                f.get("path"),
                f.get("status"),
                f.get("user_agent"),
                f.get("attack_type"),
                f.get("severity"),
                f.get("rule_id"),
                f.get("confidence"),
                f.get("matched_signature"),
                f.get("reason"),
                f.get("recommendation"),
            )
            for f in findings_list
        ])
        conn.commit()


def get_findings(job_id: str, page: int = 1, limit: int = 50, filters: dict = None):
    with _lock, _connect() as conn:
        query = "SELECT * FROM findings WHERE job_id = ?"
        count_query = "SELECT COUNT(*) as total FROM findings WHERE job_id = ?"
        params = [job_id]
        count_params = [job_id]

        filters = filters or {}
        if filters.get("severity"):
            query += " AND severity = ?"
            count_query += " AND severity = ?"
            params.append(filters["severity"])
            count_params.append(filters["severity"])
        if filters.get("attack_type"):
            query += " AND attack_type = ?"
            count_query += " AND attack_type = ?"
            params.append(filters["attack_type"])
            count_params.append(filters["attack_type"])
        if filters.get("ip"):
            query += " AND ip = ?"
            count_query += " AND ip = ?"
            params.append(filters["ip"])
            count_params.append(filters["ip"])

        total = conn.execute(count_query, count_params).fetchone()["total"]
        offset = (page - 1) * limit
        query += " ORDER BY id DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])

        rows = conn.execute(query, params).fetchall()
        return {
            "findings": [dict(r) for r in rows],
            "total": total,
            "page": page,
            "limit": limit,
            "pages": max(1, (total + limit - 1) // limit),
        }
