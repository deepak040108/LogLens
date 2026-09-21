"""
routes/threats.py
------------------------------------------------------------------------
GET /api/jobs/<id>, /api/threats/<id>, /api/attackers/<id>,
/api/timeline/<id>, /api/geo/<id>, /api/rules, /api/health.

All read from the same job summary produced by jobs/worker.py — these
are views over one source of truth, not separately-computed data, so
the dashboard's numbers can't drift from the threat feed's numbers.
------------------------------------------------------------------------
"""

import os
import sys

from flask import Blueprint, jsonify, request

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from detection.engine import list_rules  # noqa: E402
from detection import rule_state  # noqa: E402
from analysis.geoip import is_geoip_available, is_geoip_city_available, is_geoip_asn_available, geoip_status_message  # noqa: E402
from analysis.timeline import filter_timeline  # noqa: E402
import config  # noqa: E402
from jobs import store as job_store  # noqa: E402

threats_bp = Blueprint("threats", __name__)


def _get_job_queue():
    from app import job_queue
    return job_queue


def _job_or_404(job_id):
    job_queue = _get_job_queue()
    job = job_queue.get_job(job_id)
    if not job:
        return None
    return job


@threats_bp.get("/jobs/<job_id>")
def get_job(job_id):
    job = _job_or_404(job_id)
    if not job:
        return jsonify({"error": "Job not found"}), 404
    return jsonify({
        "job_id": job["id"],
        "status": job["status"],
        "total_lines": job["progress"].get("totalLines", 0),
        "processed_lines": job["progress"].get("parsedLines", 0),
        "malformed_lines": job["progress"].get("malformedLines", 0),
        "progress": job["progress"].get("percent", 0),
        "error": job.get("error"),
        "summary": job.get("summary"),
    })


@threats_bp.get("/threats/<job_id>")
def get_threats(job_id):
    job = _job_or_404(job_id)
    if not job or not job.get("summary"):
        return jsonify({"error": "Job not found or not yet complete"}), 404

    severity = request.args.get("severity")
    attack_type = request.args.get("attack_type")
    ip = request.args.get("ip")

    events = job["summary"]["recentFindings"]
    if severity:
        events = [e for e in events if e["severity"] == severity]
    if attack_type:
        events = [e for e in events if e["attack_type"] == attack_type]
    if ip:
        events = [e for e in events if e["ip"] == ip]

    return jsonify({"events": events, "count": len(events)})


@threats_bp.get("/findings/<job_id>")
def get_findings(job_id):
    job = _job_or_404(job_id)
    if not job:
        return jsonify({"error": "Job not found"}), 404
    page = request.args.get("page", 1, type=int)
    limit = request.args.get("limit", 50, type=int)
    severity = request.args.get("severity")
    attack_type = request.args.get("attack_type")
    ip = request.args.get("ip")
    result = job_store.get_findings(job_id, page, limit, {"severity": severity, "attack_type": attack_type, "ip": ip})
    return jsonify(result)


@threats_bp.get("/attackers/<job_id>")
def get_attackers(job_id):
    job = _job_or_404(job_id)
    if not job or not job.get("summary"):
        return jsonify({"error": "Job not found or not yet complete"}), 404
    return jsonify({"attackers": job["summary"]["topAttackers"]})


@threats_bp.get("/timeline/<job_id>")
def get_timeline(job_id):
    job = _job_or_404(job_id)
    if not job or not job.get("summary"):
        return jsonify({"error": "Job not found or not yet complete"}), 404
    start = request.args.get("start")
    end = request.args.get("end")
    return jsonify({"timeline": filter_timeline(job["summary"]["timeline"], start, end)})


@threats_bp.get("/geo/<job_id>")
def get_geo(job_id):
    job = _job_or_404(job_id)
    if not job or not job.get("summary"):
        return jsonify({"error": "Job not found or not yet complete"}), 404
    return jsonify({
        "byCountry": job["summary"]["byCountry"],
        "geoipAvailable": job["summary"]["geoipAvailable"],
    })


@threats_bp.get("/rules")
def get_rules():
    return jsonify({"rules": list_rules()})


@threats_bp.patch("/rules/<rule_name>")
def patch_rule(rule_name):
    body = request.get_json(silent=True) or {}
    status = body.get("status")
    if status not in ("enabled", "disabled"):
        return jsonify({"error": "Body must include status: 'enabled' or 'disabled'"}), 400
    all_categories = {r["rule"] for r in list_rules()}
    if rule_name not in all_categories:
        return jsonify({"error": f"Unknown rule '{rule_name}'"}), 404
    rule_state.set_status(rule_name, status)
    return jsonify({"rule": rule_name, "status": status})


@threats_bp.get("/settings")
def get_settings():
    return jsonify({
        "bruteForceThreshold": config.BRUTE_FORCE_THRESHOLD,
        "bruteForceWindowSeconds": config.BRUTE_FORCE_WINDOW_SECONDS,
        "maxUploadBytes": config.MAX_UPLOAD_BYTES,
        "allowedExtensions": sorted(config.ALLOWED_EXTENSIONS),
        "chunkSize": config.CHUNK_SIZE,
        "jobQueueBackend": config.JOB_QUEUE_BACKEND,
        "geoipAvailable": is_geoip_available(),
        "geoipCityAvailable": is_geoip_city_available(),
        "geoipAsnAvailable": is_geoip_asn_available(),
        "geoipStatus": geoip_status_message(),
        "geoipDbPath": config.GEOIP_DB_PATH,
    })


@threats_bp.get("/health")
def health():
    return jsonify({
        "ok": True,
        "geoipAvailable": is_geoip_available(),
        "geoipStatus": geoip_status_message(),
    })
