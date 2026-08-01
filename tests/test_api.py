"""
Automated tests for the Sentry API and core detection logic.

Usage:
    pytest tests/test_api.py -v
"""
import os
import sys
import tempfile

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from backend.app import create_app
from backend.utils.log_parser import parse_csv_log
from ml.threat_scorer import classify, score_from_isolation_forest, score_from_rule_severity


@pytest.fixture
def client(tmp_path):
    db_path = str(tmp_path / "test.db")
    model_path = str(tmp_path / "missing_model.joblib")  # intentionally absent -> rule fallback
    app = create_app(db_path=db_path, model_path=model_path)
    app.config["TESTING"] = True
    with app.test_client() as c:
        yield c


def test_home(client):
    res = client.get("/")
    assert res.status_code == 200
    assert res.get_json()["success"] is True


def test_stats_empty(client):
    res = client.get("/api/stats")
    data = res.get_json()
    assert res.status_code == 200
    assert data["data"]["total_logs"] == 0


def test_analyse_brute_force_scores_high(client):
    payload = {
        "ip_address": "45.33.32.156",
        "username": "root",
        "status": "Failed",
        "failed_attempts": 40,
        "port": 22,
        "hour": 3,
    }
    res = client.post("/api/analyse", json=payload)
    data = res.get_json()
    assert res.status_code == 200
    assert data["success"] is True
    assert data["result"]["threat_level"] in ("HIGH", "CRITICAL")


def test_analyse_normal_login_scores_low(client):
    payload = {
        "ip_address": "192.168.1.10",
        "username": "alice",
        "status": "Success",
        "failed_attempts": 0,
        "port": 22,
        "hour": 10,
    }
    res = client.post("/api/analyse", json=payload)
    data = res.get_json()
    assert res.status_code == 200
    assert data["result"]["threat_level"] in ("LOW", "MEDIUM")


def test_analyse_missing_fields_returns_400(client):
    res = client.post("/api/analyse", json={"ip_address": "1.2.3.4"})
    assert res.status_code == 400
    assert res.get_json()["success"] is False


def test_get_logs_after_analyse(client):
    client.post("/api/analyse", json={
        "ip_address": "1.2.3.4", "username": "root", "status": "Failed",
        "failed_attempts": 20, "port": 22, "hour": 2,
    })
    res = client.get("/api/logs")
    data = res.get_json()
    assert res.status_code == 200
    assert data["count"] >= 1


def test_get_logs_filtered_by_level(client):
    client.post("/api/analyse", json={
        "ip_address": "1.2.3.4", "username": "root", "status": "Failed",
        "failed_attempts": 50, "port": 22, "hour": 2,
    })
    res = client.get("/api/logs?level=CRITICAL")
    data = res.get_json()
    assert res.status_code == 200
    assert all(e["threat_level"] == "CRITICAL" for e in data["data"])


def test_get_alerts_only_high_and_critical(client):
    client.post("/api/analyse", json={
        "ip_address": "1.2.3.4", "username": "root", "status": "Failed",
        "failed_attempts": 40, "port": 22, "hour": 3,
    })
    client.post("/api/analyse", json={
        "ip_address": "192.168.1.5", "username": "bob", "status": "Success",
        "failed_attempts": 0, "port": 22, "hour": 10,
    })
    res = client.get("/api/alerts")
    data = res.get_json()
    assert res.status_code == 200
    assert all(e["threat_level"] in ("HIGH", "CRITICAL") for e in data["data"])


def test_get_timeline_has_24_buckets(client):
    res = client.get("/api/threats/timeline")
    data = res.get_json()
    assert res.status_code == 200
    assert len(data["data"]) == 24


def test_get_top_ips_respects_limit(client):
    for i in range(15):
        client.post("/api/analyse", json={
            "ip_address": f"10.0.0.{i}", "username": "root", "status": "Failed",
            "failed_attempts": 5, "port": 22, "hour": 4,
        })
    res = client.get("/api/threats/top-ips?limit=10")
    data = res.get_json()
    assert res.status_code == 200
    assert len(data["data"]) <= 10


def test_ingest_network_alert(client):
    res = client.post("/api/ingest/network", json={
        "category": "port_scan",
        "message": "test port scan",
        "ip_address": "8.8.8.8",
        "intensity": 1.2,
    })
    assert res.status_code == 201
    assert res.get_json()["success"] is True

    res2 = client.get("/api/network/alerts")
    assert res2.get_json()["count"] >= 1


def test_threat_scorer_classification():
    low = classify(10)
    high = classify(75)
    critical = classify(95)
    assert low["threat_level"] == "LOW"
    assert high["threat_level"] == "HIGH"
    assert critical["threat_level"] == "CRITICAL"


def test_score_from_isolation_forest_range():
    score = score_from_isolation_forest(raw_decision_score=-0.4, combo_score=4)
    assert 0 <= score <= 100


def test_score_from_rule_severity_varies_with_intensity():
    low_intensity = score_from_rule_severity("port_scan", intensity=0.5)
    high_intensity = score_from_rule_severity("port_scan", intensity=1.3)
    assert high_intensity >= low_intensity


def test_log_parser_reads_csv(tmp_path):
    csv_path = tmp_path / "sample.csv"
    csv_path.write_text(
        "timestamp,ip_address,username,status,port\n"
        "2026-01-01T10:00:00,192.168.1.5,alice,Success,22\n"
    )
    records = parse_csv_log(str(csv_path))
    assert len(records) == 1
    assert records[0]["ip_address"] == "192.168.1.5"


# ─── Attack-type classification tests ─────────────────────────────────────────

from backend.utils.features import IPHistory
from ml.attack_typer import classify_attack_type


def _make_record(ip="1.2.3.4", username="root", status="Failed",
                 port=22, hour=10, user_agent=None):
    return {
        "ip_address": ip,
        "username": username,
        "status": status,
        "port": port,
        "hour": hour,
        "user_agent": user_agent,
    }


def _make_features(failed_attempts=0, hour=10, is_night_hour=0, is_root_attempt=0,
                   ip_attempt_count=1, status_numeric=0, port=22, is_ssh_port=1,
                   fail_rate=0.0, combo_score=0):
    return {
        "failed_attempts": failed_attempts,
        "hour": hour,
        "is_night_hour": is_night_hour,
        "is_root_attempt": is_root_attempt,
        "ip_attempt_count": ip_attempt_count,
        "status_numeric": status_numeric,
        "port": port,
        "is_ssh_port": is_ssh_port,
        "fail_rate": fail_rate,
        "combo_score": combo_score,
    }


def test_attack_type_brute_force():
    """High fail_rate against 1-2 usernames -> brute_force."""
    ip = "45.33.1.1"
    h = IPHistory()
    # Simulate 20 failed attempts on the same username
    for _ in range(20):
        h.observe(ip, failed=True, username="root", port=22, status="Failed")
    record = _make_record(ip=ip, username="root", status="Failed")
    feats = _make_features(
        failed_attempts=20, fail_rate=1.0, ip_attempt_count=20,
        is_root_attempt=1, status_numeric=1,
    )
    result = classify_attack_type(record, feats, h)
    assert result == "brute_force", f"Expected brute_force, got {result}"


def test_attack_type_credential_stuffing():
    """Many distinct usernames from one IP with high failure -> credential_stuffing."""
    ip = "45.33.2.2"
    usernames = ["root", "admin", "alice", "bob", "carol", "dave", "erin", "frank"]
    h = IPHistory()
    for u in usernames:
        h.observe(ip, failed=True, username=u, port=22, status="Failed")
    # 4th+ observe call is what triggers the threshold — do a couple more
    for u in usernames[:4]:
        h.observe(ip, failed=True, username=u, port=22, status="Failed")
    record = _make_record(ip=ip, username="root", status="Failed")
    feats = _make_features(
        failed_attempts=12, fail_rate=1.0, ip_attempt_count=12,
        is_root_attempt=1, status_numeric=1,
    )
    result = classify_attack_type(record, feats, h)
    assert result == "credential_stuffing", f"Expected credential_stuffing, got {result}"


def test_attack_type_lateral_movement():
    """Same IP hitting many distinct ports -> lateral_movement."""
    ip = "45.33.3.3"
    ports = [22, 3389, 3306, 5432, 21, 161, 8080, 9200]
    h = IPHistory()
    for port in ports:
        h.observe(ip, failed=True, username="admin", port=port, status="Failed")
    record = _make_record(ip=ip, username="admin", status="Failed", port=9200)
    feats = _make_features(
        fail_rate=1.0, ip_attempt_count=8, status_numeric=1,
        port=9200, is_ssh_port=0,
    )
    result = classify_attack_type(record, feats, h)
    assert result == "lateral_movement", f"Expected lateral_movement, got {result}"


def test_attack_type_impossible_travel():
    """Same username succeeds from two different /16 subnets -> impossible_travel."""
    username = "alice"
    home_ip = "192.168.1.5"
    foreign_ip = "10.22.5.9"
    h = IPHistory()
    # First success from home
    h.observe(home_ip, failed=False, username=username, port=22, status="Success")
    # Second success from foreign /16
    h.observe(foreign_ip, failed=False, username=username, port=22, status="Success")
    record = _make_record(ip=foreign_ip, username=username, status="Success", hour=10)
    feats = _make_features(fail_rate=0.0, ip_attempt_count=1, status_numeric=0)
    result = classify_attack_type(record, feats, h)
    assert result == "impossible_travel", f"Expected impossible_travel, got {result}"


def test_attack_type_device_spoofing():
    """Same (ip, username) seen with 2+ distinct user-agents -> device_spoofing."""
    ip = "192.168.1.50"
    username = "alice"
    h = IPHistory()
    h.observe(ip, failed=False, username=username, port=22,
              status="Success", user_agent="Mozilla/5.0 (Windows NT 10.0)")
    h.observe(ip, failed=False, username=username, port=22,
              status="Success", user_agent="python-requests/2.28.0")
    record = _make_record(ip=ip, username=username, status="Success",
                          hour=10, user_agent="python-requests/2.28.0")
    feats = _make_features(fail_rate=0.0, ip_attempt_count=2, status_numeric=0)
    result = classify_attack_type(record, feats, h)
    assert result == "device_spoofing", f"Expected device_spoofing, got {result}"


def test_attack_type_off_hours_anomaly():
    """Night-hour access -> off_hours_anomaly."""
    ip = "192.168.1.20"
    h = IPHistory()
    h.observe(ip, failed=True, username="bob", port=22, status="Failed")
    record = _make_record(ip=ip, username="bob", status="Failed", hour=2)
    feats = _make_features(
        failed_attempts=1, fail_rate=1.0, ip_attempt_count=1,
        is_night_hour=1, status_numeric=1,
    )
    result = classify_attack_type(record, feats, h)
    assert result == "off_hours_anomaly", f"Expected off_hours_anomaly, got {result}"


def test_attack_type_normal():
    """Clean daytime success with no attack signals -> normal."""
    ip = "192.168.1.10"
    h = IPHistory()
    h.observe(ip, failed=False, username="alice", port=22, status="Success")
    record = _make_record(ip=ip, username="alice", status="Success", hour=10)
    feats = _make_features(fail_rate=0.0, ip_attempt_count=1, status_numeric=0)
    result = classify_attack_type(record, feats, h)
    assert result == "normal", f"Expected normal, got {result}"


# ─── Explainability tests ─────────────────────────────────────────────────────

def test_analyse_explainability_anomalous(client):
    payload = {
        "ip_address": "45.33.32.156",
        "username": "root",
        "status": "Failed",
        "failed_attempts": 50,
        "port": 22,
        "hour": 2,
    }
    res = client.post("/api/analyse", json=payload)
    data = res.get_json()
    assert res.status_code == 200
    assert data["success"] is True
    
    result = data["result"]
    assert "explanation" in result
    assert "feature_contributions" in result
    
    # It's an anomaly, explanation should reflect that
    assert "Flagged for:" in result["explanation"]
    assert result["threat_level"] in ("HIGH", "CRITICAL")
    # Should not filter everything out
    assert len(result["feature_contributions"]) > 0

def test_analyse_explainability_normal(client):
    payload = {
        "ip_address": "192.168.1.10",
        "username": "alice",
        "status": "Success",
        "failed_attempts": 0,
        "port": 22,
        "hour": 10,
    }
    res = client.post("/api/analyse", json=payload)
    data = res.get_json()
    assert res.status_code == 200
    assert data["success"] is True
    
    result = data["result"]
    assert "explanation" in result
    assert "feature_contributions" in result
    
    # It's normal, should have normal wording
    assert result["threat_level"] in ("LOW", "MEDIUM")
    assert "Normal activity" in result["explanation"] or "Appears benign:" in result["explanation"] or "No significant explanation signals" in result["explanation"]


# ─── Entity History Endpoint Tests ───────────────────────────────────────────

def test_get_entity_history(client):
    target_ip = "45.33.32.156"
    client.post("/api/analyse", json={
        "ip_address": target_ip, "username": "root", "status": "Failed",
        "failed_attempts": 20, "port": 22, "hour": 3,
    })
    res = client.get(f"/api/entity/{target_ip}")
    data = res.get_json()
    assert res.status_code == 200
    assert data["success"] is True
    assert data["ip_address"] == target_ip
    assert data["count"] >= 1
    
    first_event = data["data"][0]
    assert "cold_start" in first_event
    assert "baseline_confidence" in first_event
    assert "explanation" in first_event
    assert "attack_type" in first_event
    assert "feature_contributions" in first_event


def test_get_entity_history_empty(client):
    res = client.get("/api/entity/192.168.99.99")
    data = res.get_json()
    assert res.status_code == 200
    assert data["success"] is True
    assert data["count"] == 0
    assert data["data"] == []


# ─── Task 5: Cold-Start & Concept Drift Tests ───────────────────────────────

def test_ip_history_exponential_decay():
    from backend.utils.features import IPHistory
    history = IPHistory()
    ip = "1.2.3.4"
    # Apply 150 consecutive failures
    for _ in range(150):
        history.observe(ip, failed=True)
    
    # Geometric series with alpha=0.95 converges to 20.
    # After 150 iterations, it should be very close to 20.
    assert 19.9 < history.attempt_count(ip) <= 20.0
    assert history.lifetime_observations[ip] == 150

def test_cold_start_ip_blending(client):
    target_ip = "10.0.0.99"
    # Call 1: cold_start=True, low confidence
    res1 = client.post("/api/analyse", json={
        "ip_address": target_ip, "username": "alice", "status": "Failed",
        "failed_attempts": 0, "port": 22, "hour": 10,
    })
    data1 = res1.get_json()["result"]
    assert data1["cold_start"] is True
    assert data1["baseline_confidence"] == 0.33

    # Call 2: cold_start=True, higher confidence
    res2 = client.post("/api/analyse", json={
        "ip_address": target_ip, "username": "alice", "status": "Failed",
        "failed_attempts": 1, "port": 22, "hour": 10,
    })
    data2 = res2.get_json()["result"]
    assert data2["cold_start"] is True
    assert data2["baseline_confidence"] == 0.67

    # Call 3: cold_start=False, full confidence
    res3 = client.post("/api/analyse", json={
        "ip_address": target_ip, "username": "alice", "status": "Failed",
        "failed_attempts": 2, "port": 22, "hour": 10,
    })
    data3 = res3.get_json()["result"]
    assert data3["cold_start"] is False
    assert data3["baseline_confidence"] == 1.0

