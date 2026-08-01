"""
REST API — mirrors and extends the reference project's endpoint set,
plus adds /api/network/alerts and /api/ingest/network so live packet
capture can feed the same dashboard as log-based analysis.
"""
import time
import secrets
from functools import wraps
from flask import Blueprint, current_app, jsonify, request
from werkzeug.security import generate_password_hash, check_password_hash

from backend.utils.features import IPHistory
from ml.threat_scorer import score_from_rule_severity, classify

api = Blueprint("api", __name__)

REQUIRED_ANALYSE_FIELDS = {"ip_address", "username", "status", "failed_attempts", "port", "hour"}


def get_current_user():
    if current_app.config.get("TESTING"):
        db = current_app.config["DB"]
        user = db.get_user_by_username("test_user")
        if not user:
            db.create_user("test_user", "test_hash", "test_api_key")
            user = db.get_user_by_username("test_user")
        return user

    auth_header = request.headers.get("Authorization")
    if not auth_header:
        return None
    
    parts = auth_header.split()
    if len(parts) == 2 and parts[0].lower() == "bearer":
        token = parts[1]
    else:
        token = parts[0]
        
    db = current_app.config["DB"]
    return db.get_user_by_api_key(token)


def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        user = get_current_user()
        if not user:
            return jsonify({"success": False, "error": "Unauthorized"}), 401
        return f(user, *args, **kwargs)
    return decorated


@api.route("/")
def health():
    return jsonify({
        "success": True,
        "service": "Sentry Threat Detection API",
        "status": "running",
    })


@api.route("/api/register", methods=["POST"])
def register():
    payload = request.get_json(silent=True) or {}
    username = payload.get("username")
    password = payload.get("password")
    
    if not username or not password:
        return jsonify({"success": False, "error": "Username and password required"}), 400
        
    db = current_app.config["DB"]
    password_hash = generate_password_hash(password)
    api_key = secrets.token_hex(24)
    
    success = db.create_user(username, password_hash, api_key)
    if not success:
        return jsonify({"success": False, "error": "Username already exists"}), 400
        
    return jsonify({
        "success": True,
        "message": "User registered successfully",
        "api_key": api_key,
        "username": username
    }), 201


@api.route("/api/login", methods=["POST"])
def login():
    payload = request.get_json(silent=True) or {}
    username = payload.get("username")
    password = payload.get("password")
    
    if not username or not password:
        return jsonify({"success": False, "error": "Username and password required"}), 400
        
    db = current_app.config["DB"]
    user = db.get_user_by_username(username)
    
    if not user or not check_password_hash(user["password_hash"], password):
        return jsonify({"success": False, "error": "Invalid credentials"}), 401
        
    return jsonify({
        "success": True,
        "api_key": user["api_key"],
        "username": user["username"]
    })


@api.route("/api/stats")
@token_required
def stats(user):
    db = current_app.config["DB"]
    return jsonify({"success": True, "data": db.get_stats(user_id=user["id"])})


@api.route("/api/logs")
@token_required
def logs(user):
    db = current_app.config["DB"]
    limit = request.args.get("limit", default=100, type=int)
    level = request.args.get("level", default=None, type=str)
    sort_by = request.args.get("sort", default=None, type=str)
    events = db.get_events(limit=limit, level=level, source="log", sort_by=sort_by, user_id=user["id"])
    return jsonify({"success": True, "count": len(events), "data": events})


@api.route("/api/alerts")
@token_required
def alerts(user):
    db = current_app.config["DB"]
    limit = request.args.get("limit", default=100, type=int)
    sort_by = request.args.get("sort", default=None, type=str)
    return jsonify({"success": True, "data": db.get_alerts(limit=limit, sort_by=sort_by, user_id=user["id"])})


@api.route("/api/entity/<path:ip_address>")
@token_required
def entity_history(user, ip_address):
    db = current_app.config["DB"]
    events = db.get_entity_events(ip_address, user_id=user["id"])
    return jsonify({
        "success": True,
        "ip_address": ip_address,
        "count": len(events),
        "data": events,
    })


@api.route("/api/network/alerts")
@token_required
def network_alerts(user):
    db = current_app.config["DB"]
    limit = request.args.get("limit", default=100, type=int)
    events = db.get_events(limit=limit, source="network", user_id=user["id"])
    return jsonify({"success": True, "count": len(events), "data": events})


@api.route("/api/threats/timeline")
@token_required
def timeline(user):
    db = current_app.config["DB"]
    return jsonify({"success": True, "data": db.get_timeline(user_id=user["id"])})


@api.route("/api/threats/top-ips")
@token_required
def top_ips(user):
    db = current_app.config["DB"]
    limit = request.args.get("limit", default=10, type=int)
    return jsonify({"success": True, "data": db.get_top_ips(limit=limit, user_id=user["id"])})


@api.route("/api/analyse", methods=["POST"])
@token_required
def analyse(user):
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
        attack_type=result.get("attack_type"),
        message=f"Ad-hoc analysis: {record['username']}@{record['ip_address']}",
        meta={
            "explanation": result.get("explanation", ""),
            "feature_contributions": result.get("feature_contributions", []),
            "cold_start": result.get("cold_start", False),
            "baseline_confidence": result.get("baseline_confidence", 1.0),
        },
        user_id=user["id"]
    )

    return jsonify({
        "success": True,
        "input": payload,
        "result": {
            "threat_score": result["threat_score"],
            "threat_level": result["threat_level"],
            "threat_color": result["threat_color"],
            "is_anomaly": result["is_anomaly"],
            "attack_type": result["attack_type"],
            "explanation": result["explanation"],
            "feature_contributions": result["feature_contributions"],
            "cold_start": result.get("cold_start", False),
            "baseline_confidence": result.get("baseline_confidence", 1.0),
        },
    })


@api.route("/api/ingest/network", methods=["POST"])
@token_required
def ingest_network_alert(user):
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
        user_id=user["id"]
    )
    return jsonify({"success": True, "stored": classified}), 201
