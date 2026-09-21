"""
security/cleanup.py
--------
Background cleanup job: deletes uploaded files and old DB records
on a configurable schedule.
"""

import os
import time
import threading
import logging
import sqlite3
from datetime import datetime, timezone, timedelta

logger = logging.getLogger(__name__)

RETENTION_HOURS = int(os.environ.get("RETENTION_HOURS", 24))
CLEANUP_INTERVAL = 3600  # run every hour


def cleanup_old_files(upload_dir: str, retention_hours: int = RETENTION_HOURS):
    cutoff = time.time() - retention_hours * 3600
    removed = 0
    if not os.path.isdir(upload_dir):
        return removed
    for fname in os.listdir(upload_dir):
        fpath = os.path.join(upload_dir, fname)
        if os.path.isfile(fpath):
            try:
                if os.path.getmtime(fpath) < cutoff:
                    os.remove(fpath)
                    removed += 1
            except OSError:
                pass
    if removed:
        logger.info("Cleaned up %d old upload files", removed)
    return removed


def cleanup_old_jobs(db_path: str, retention_hours: int = RETENTION_HOURS):
    cutoff_dt = datetime.now(timezone.utc) - timedelta(hours=retention_hours)
    cutoff_iso = cutoff_dt.isoformat()
    removed = 0
    if not os.path.exists(db_path):
        return removed
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.execute(
            "DELETE FROM jobs WHERE status IN ('completed', 'failed') AND updated_at < ?",
            (cutoff_iso,),
        )
        removed = cursor.rowcount
        conn.commit()
        conn.close()
    except Exception as exc:
        logger.warning("Job cleanup failed: %s", exc)
    if removed:
        logger.info("Cleaned up %d old job records", removed)
    return removed


def run_cleanup_loop(upload_dir: str, db_path: str):
    while True:
        time.sleep(CLEANUP_INTERVAL)
        try:
            cleanup_old_files(upload_dir)
            cleanup_old_jobs(db_path)
        except Exception as exc:
            logger.warning("Cleanup cycle failed: %s", exc)


def start_cleanup_thread(upload_dir: str, db_path: str):
    t = threading.Thread(target=run_cleanup_loop, args=(upload_dir, db_path), daemon=True)
    t.start()
    logger.info("Cleanup thread started (interval=%ds, retention=%dh)", CLEANUP_INTERVAL, RETENTION_HOURS)
    return t
