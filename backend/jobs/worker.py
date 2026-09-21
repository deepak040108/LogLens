"""
jobs/worker.py
------------------------------------------------------------------------
Job orchestration: create_job / get_job / submit. Every route in this
app talks to this contract, not to threading or Celery directly — that
boundary is what makes the backend swappable per spec §17 ("If
Redis/Celery is unavailable during local development, provide a
development fallback ... without changing the API contract").

This implementation is the development fallback: an in-memory dict
(fast path for polling) backed by SQLite (jobs/store.py) for
persistence, with work run on a daemon thread. See
docs/architecture.md for exactly what changes to swap in Celery+Redis
— it's the ~30 lines in this file, nothing in parser/, detection/, or
analysis/.
------------------------------------------------------------------------
"""

import sys
import os
import threading
import uuid
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from parser.apache_parser import stream_parse_file  # noqa: E402
from detection.engine import detect_chunk  # noqa: E402
from detection.brute_force import BruteForceTracker  # noqa: E402
from analysis.aggregator import Aggregator  # noqa: E402
from analysis.correlation import detect_correlations  # noqa: E402
from analysis.threat_scoring import score_all_attackers  # noqa: E402
from jobs import store  # noqa: E402


class JobQueue:
    def __init__(self):
        self.jobs = {}
        self.lock = threading.Lock()
        store.init_db()

    def create_job(self, file_path: str, original_name: str) -> dict:
        job_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()
        job = {
            "id": job_id,
            "originalName": original_name,
            "filePath": file_path,
            "status": "queued",
            "progress": {"totalLines": 0, "parsedLines": 0, "malformedLines": 0, "percent": 0},
            "error": None,
            "summary": None,
            "createdAt": now,
            "updatedAt": now,
        }
        with self.lock:
            self.jobs[job_id] = job
        store.upsert_job(job)
        return job

    def get_job(self, job_id: str):
        with self.lock:
            job = self.jobs.get(job_id)
        if job:
            return job
        return store.get_job_row(job_id)

    def submit(self, job_id: str):
        thread = threading.Thread(target=self._run, args=(job_id,), daemon=True)
        thread.start()

    def _run(self, job_id: str):
        job = self.jobs[job_id]
        job["status"] = "processing"
        store.upsert_job(job)

        aggregator = Aggregator()
        tracker = BruteForceTracker()

        total_bytes = os.path.getsize(job["filePath"])
        total_lines_estimate = 0
        try:
            with open(job["filePath"], "r", encoding="utf-8", errors="replace") as f:
                total_lines_estimate = sum(1 for _ in f)
        except Exception:
            total_lines_estimate = 0

        try:
            lines_seen = 0
            for chunk in stream_parse_file(job["filePath"]):
                clean_rows = [r for r in chunk if not r.get("malformed")]
                lines_seen += len(chunk)

                regex_findings = detect_chunk(clean_rows)

                brute_findings = []
                for r in clean_rows:
                    if tracker.register(r["ip"], r["status"], r["timestamp"], r.get("path", "")):
                        brute_findings.append(
                            tracker.finding_for(r["ip"], r["timestamp"], r["method"], r["path"], r["status"])
                        )

                all_findings = regex_findings + brute_findings
                aggregator.record_chunk(chunk, all_findings)

                percent = round(100 * lines_seen / total_lines_estimate, 2) if total_lines_estimate else 0
                job["progress"] = {
                    "totalLines": total_lines_estimate or lines_seen,
                    "parsedLines": aggregator.total_requests,
                    "malformedLines": aggregator.malformed_lines,
                    "percent": min(percent, 100),
                    "totalBytes": total_bytes,
                }
                job["updatedAt"] = datetime.now(timezone.utc).isoformat()
                store.upsert_job(job)

            # Post-processing: threat scores and correlation
            aggregator.post_process()

            correlation = detect_correlations(aggregator.all_findings)
            aggregator.set_correlation(correlation)

            if aggregator.all_findings:
                store.insert_findings(job_id, aggregator.all_findings)

            job["summary"] = aggregator.to_summary()
            job["status"] = "completed"
            job["progress"]["percent"] = 100
        except Exception as e:  # noqa: BLE001
            job["status"] = "failed"
            job["error"] = str(e)

        job["updatedAt"] = datetime.now(timezone.utc).isoformat()
        store.upsert_job(job)
