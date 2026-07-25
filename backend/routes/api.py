"""
REST API — mirrors and extends the reference project's endpoint set,
plus adds /api/network/alerts and /api/ingest/network so live packet
capture can feed the same dashboard as log-based analysis.
"""
import time
from flask import Blueprint, current_app, jsonify, request

from backend.utils.features import IPHistory
from ml.threat_scorer import score_from_rule_severity, classify

api = Blueprint("api", __name__)

REQUIRED_ANALYSE_FIELDS = {"ip_address", "username", "status", "failed_attempts", "port", "hour"}


@api.route("/")
def health():
    return jsonify({
        "success": True,
        "service": "Sentry Threat Detection API",
        "status": "running",
    })


@api.route("/api/stats")
def stats():
    db = current_app.config["DB"]
    return jsonify({"success": True, "data": db.get_stats()})


@api.route("/api/logs")
def logs():
    db = current_app.config["DB"]
    limit = request.args.get("limit", default=100, type=int)
    level = request.args.get("level", default=None, type=str)
    events = db.get_events(limit=limit, level=level, source="log")
    return jsonify({"success": True, "count": len(events), "data": events})


@api.route("/api/alerts")
def alerts():
    db = current_app.config["DB"]
    limit = request.args.get("limit", default=100, type=int)
    return jsonify({"success": True, "data": db.get_alerts(limit=limit)})


@api.route("/api/network/alerts")
def network_alerts():
    db = current_app.config["DB"]
    limit = request.args.get("limit", default=100, type=int)
    events = db.get_events(limit=limit, source="network")
    return jsonify({"success": True, "count": len(events), "data": events})


@api.route("/api/threats/timeline")
def timeline():
    db = current_app.config["DB"]
    return jsonify({"success": True, "data": db.get_timeline()})


@api.route("/api/threats/top-ips")
def top_ips():
    db = current_app.config["DB"]
    limit = request.args.get("limit", default=10, type=int)
    return jsonify({"success": True, "data": db.get_top_ips(limit=limit)})


@api.route("/api/analyse", methods=["POST"])
def analyse():
    payload = request.get_json(silent=True) or {}
    missing = REQUIRED_ANALYSE_FIELDS - set(payload.keys())
    if missing:
        return jsonify({
            "success": False,
            "error": f"Missing required fields: {sorted(missing)}",
        }), 400

    detector = current_app.config["DETECTOR"]
    db = current_app.config["DB"]

    record = {
        "ip_address": payload["ip_address"],
        "username": payload["username"],
        "status": payload["status"],
        "port": int(payload["port"]),
        "hour": int(payload["hour"]),
    }
    ip_history = IPHistory()
    # Seed history so a single ad-hoc analysis still reflects the stated
    # failed_attempts count rather than always looking like a first-timer.
    for _ in range(int(payload.get("failed_attempts", 0))):
        ip_history.observe(record["ip_address"], failed=True)

    result = detector.score_record(
        record, ip_history, failed_attempts_hint=int(payload.get("failed_attempts", 0))
    )

    category = "brute_force" if result["features"]["failed_attempts"] >= 10 else (
        "off_hours" if result["features"]["is_night_hour"] else "normal"
    )

    db.insert_event(
        ts=time.time(),
        source="log",
        category=category,
        ip_address=record["ip_address"],
        username=record["username"],
        port=record["port"],
        status=record["status"],
        failed_attempts=payload.get("failed_attempts", 0),
        threat_score=result["threat_score"],
        threat_level=result["threat_level"],
        threat_color=result["threat_color"],
        is_anomaly=result["is_anomaly"],
        message=f"Ad-hoc analysis: {record['username']}@{record['ip_address']}",
    )

    return jsonify({
        "success": True,
        "input": payload,
        "result": {
            "threat_score": result["threat_score"],
            "threat_level": result["threat_level"],
            "threat_color": result["threat_color"],
            "is_anomaly": result["is_anomaly"],
        },
    })


@api.route("/api/ingest/network", methods=["POST"])
def ingest_network_alert():
    """
    Receives alerts from the live packet-capture process (capture/live_capture.py)
    and stores them alongside log-based events so the dashboard shows a
    unified picture of what's happening on the network.
    """
    payload = request.get_json(silent=True) or {}
    required = {"category", "message"}
    missing = required - set(payload.keys())
    if missing:
        return jsonify({"success": False, "error": f"Missing fields: {sorted(missing)}"}), 400

    db = current_app.config["DB"]
    intensity = payload.get("intensity", 1.0)
    score = score_from_rule_severity(payload["category"], intensity=intensity)
    classified = classify(score)

    db.insert_event(
        ts=payload.get("ts", time.time()),
        source="network",
        category=payload["category"],
        ip_address=payload.get("ip_address"),
        port=payload.get("port"),
        threat_score=classified["threat_score"],
        threat_level=classified["threat_level"],
        threat_color=classified["threat_color"],
        is_anomaly=classified["is_anomaly"],
        message=payload["message"],
        meta=payload.get("meta", {}),
    )
    return jsonify({"success": True, "stored": classified}), 201
