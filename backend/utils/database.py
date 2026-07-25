"""
SQLite database helper. A single `events` table stores both log-based
records (source='log') and live network alerts (source='network'), so
every part of the system — brute-force logins, port scans, ARP
spoofing, ML anomalies — is queryable and displayable in one place.
"""
import json
import sqlite3
import time
from contextlib import contextmanager

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts REAL NOT NULL,
    source TEXT NOT NULL,          -- 'log' or 'network'
    category TEXT NOT NULL,        -- brute_force, off_hours, port_scan, arp_spoofing, syn_flood, normal, ...
    ip_address TEXT,
    username TEXT,
    port INTEGER,
    status TEXT,
    failed_attempts INTEGER,
    threat_score INTEGER NOT NULL,
    threat_level TEXT NOT NULL,
    threat_color TEXT NOT NULL,
    is_anomaly INTEGER NOT NULL DEFAULT 0,
    message TEXT,
    meta TEXT
);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);
CREATE INDEX IF NOT EXISTS idx_events_level ON events(threat_level);
CREATE INDEX IF NOT EXISTS idx_events_ip ON events(ip_address);
"""


class Database:
    def __init__(self, path):
        self.path = path
        with self._connect() as conn:
            conn.executescript(SCHEMA)

    @contextmanager
    def _connect(self):
        conn = sqlite3.connect(self.path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()

    def insert_event(self, ts, source, category, ip_address=None, username=None,
                      port=None, status=None, failed_attempts=None,
                      threat_score=0, threat_level="LOW", threat_color="#4fd6e8",
                      is_anomaly=0, message="", meta=None):
        with self._connect() as conn:
            conn.execute(
                """INSERT INTO events
                   (ts, source, category, ip_address, username, port, status,
                    failed_attempts, threat_score, threat_level, threat_color,
                    is_anomaly, message, meta)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (ts, source, category, ip_address, username, port, status,
                 failed_attempts, threat_score, threat_level, threat_color,
                 is_anomaly, message, json.dumps(meta or {})),
            )

    def insert_many(self, events):
        with self._connect() as conn:
            conn.executemany(
                """INSERT INTO events
                   (ts, source, category, ip_address, username, port, status,
                    failed_attempts, threat_score, threat_level, threat_color,
                    is_anomaly, message, meta)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                [
                    (e["ts"], e["source"], e["category"], e.get("ip_address"),
                     e.get("username"), e.get("port"), e.get("status"),
                     e.get("failed_attempts"), e["threat_score"], e["threat_level"],
                     e["threat_color"], e.get("is_anomaly", 0), e.get("message", ""),
                     json.dumps(e.get("meta", {})))
                    for e in events
                ],
            )

    def get_events(self, limit=100, level=None, source=None):
        query = "SELECT * FROM events WHERE 1=1"
        params = []
        if level:
            query += " AND threat_level = ?"
            params.append(level.upper())
        if source:
            query += " AND source = ?"
            params.append(source)
        query += " ORDER BY ts DESC LIMIT ?"
        params.append(limit)
        with self._connect() as conn:
            rows = conn.execute(query, params).fetchall()
        return [dict(r) for r in rows]

    def get_alerts(self, limit=100):
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM events WHERE threat_level IN ('HIGH','CRITICAL') "
                "ORDER BY ts DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [dict(r) for r in rows]

    def get_stats(self):
        with self._connect() as conn:
            total = conn.execute("SELECT COUNT(*) c FROM events").fetchone()["c"]
            anomalies = conn.execute("SELECT COUNT(*) c FROM events WHERE is_anomaly=1").fetchone()["c"]
            alerts = conn.execute(
                "SELECT COUNT(*) c FROM events WHERE threat_level IN ('HIGH','CRITICAL')"
            ).fetchone()["c"]
            suspicious_ips = conn.execute(
                "SELECT COUNT(DISTINCT ip_address) c FROM events WHERE threat_level IN ('HIGH','CRITICAL')"
            ).fetchone()["c"]
            avg_score = conn.execute("SELECT AVG(threat_score) a FROM events").fetchone()["a"] or 0
            max_score = conn.execute("SELECT MAX(threat_score) m FROM events").fetchone()["m"] or 0
            levels = {}
            for row in conn.execute("SELECT threat_level, COUNT(*) c FROM events GROUP BY threat_level"):
                levels[row["threat_level"]] = row["c"]
        return {
            "total_logs": total,
            "total_anomalies": anomalies,
            "total_alerts": alerts,
            "suspicious_ips": suspicious_ips,
            "avg_threat_score": round(avg_score, 1),
            "max_threat_score": max_score,
            "threat_levels": {
                "LOW": levels.get("LOW", 0),
                "MEDIUM": levels.get("MEDIUM", 0),
                "HIGH": levels.get("HIGH", 0),
                "CRITICAL": levels.get("CRITICAL", 0),
            },
        }

    def get_timeline(self):
        """Event counts bucketed by hour-of-day (0-23), across all events."""
        buckets = [0] * 24
        with self._connect() as conn:
            for row in conn.execute("SELECT ts FROM events"):
                hour = time.localtime(row["ts"]).tm_hour
                buckets[hour] += 1
        return [{"hour": h, "count": c} for h, c in enumerate(buckets)]

    def get_top_ips(self, limit=10):
        with self._connect() as conn:
            rows = conn.execute(
                """SELECT ip_address, COUNT(*) as event_count,
                          AVG(threat_score) as avg_score,
                          MAX(threat_score) as max_score
                   FROM events
                   WHERE ip_address IS NOT NULL
                   GROUP BY ip_address
                   ORDER BY max_score DESC, event_count DESC
                   LIMIT ?""",
                (limit,),
            ).fetchall()
        return [
            {
                "ip_address": r["ip_address"],
                "event_count": r["event_count"],
                "avg_score": round(r["avg_score"], 1),
                "max_score": r["max_score"],
            }
            for r in rows
        ]
