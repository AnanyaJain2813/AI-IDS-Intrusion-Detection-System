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
