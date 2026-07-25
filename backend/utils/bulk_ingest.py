"""
Bulk-ingest a log file (CSV or auth.log) into the database: parses,
scores every record with the trained detector, and inserts it.

Usage:
    python -m backend.utils.bulk_ingest --input data/sample_logs.csv
"""
import argparse
import os
import sys
import time
from datetime import datetime

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))
from backend.utils.log_parser import parse_log_file
from backend.utils.features import IPHistory
from backend.utils.database import Database
from ml.detector import Detector


def categorize(record, features):
    if features["failed_attempts"] >= 10:
        return "brute_force"
    if features["is_night_hour"]:
        return "off_hours"
    if features["is_root_attempt"] and features["status_numeric"]:
        return "privilege_targeting"
    return "normal"


def run(input_path, db_path, model_path):
    records = parse_log_file(input_path)
    detector = Detector(model_path)
    db = Database(db_path)
    ip_history = IPHistory()

    events = []
    for record in records:
        try:
            ts = datetime.fromisoformat(record["timestamp"]).timestamp()
        except (ValueError, TypeError):
            ts = time.time()

        result = detector.score_record(record, ip_history)
        category = categorize(record, result["features"])

        events.append({
            "ts": ts,
            "source": "log",
            "category": category,
            "ip_address": record["ip_address"],
            "username": record["username"],
            "port": record["port"],
            "status": record["status"],
            "failed_attempts": result["features"]["failed_attempts"],
            "threat_score": result["threat_score"],
            "threat_level": result["threat_level"],
            "threat_color": result["threat_color"],
            "is_anomaly": result["is_anomaly"],
            "message": f"{record['username']}@{record['ip_address']} — {category}",
            "meta": {},
        })

    db.insert_many(events)
    print(f"Ingested {len(events)} events from {input_path} into {db_path}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", default="data/sample_logs.csv")
    parser.add_argument("--db", default="backend/sentry.db")
    parser.add_argument("--model", default="backend/models/model.joblib")
    args = parser.parse_args()
    run(args.input, args.db, args.model)
