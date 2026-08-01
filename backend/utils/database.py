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
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    api_key TEXT UNIQUE NOT NULL
);
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
    meta TEXT,
    attack_type TEXT,
    user_id INTEGER REFERENCES users(id)
);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);
CREATE INDEX IF NOT EXISTS idx_events_level ON events(threat_level);
CREATE INDEX IF NOT EXISTS idx_events_ip ON events(ip_address);
"""

MIGRATIONS = [
    # (column_name, ALTER TABLE statement)
    ("attack_type", "ALTER TABLE events ADD COLUMN attack_type TEXT"),
    ("user_id", "ALTER TABLE events ADD COLUMN user_id INTEGER"),
]


class Database:
    def __init__(self, path):
        self.path = path
        with self._connect() as conn:
            conn.executescript(SCHEMA)
        # Safe migrations for pre-existing databases that lack newer columns.
        # executescript() runs in autocommit mode, so we open a fresh connection
        # to check what actually exists after the schema has been applied.
        self._apply_migrations()
        # Create user index after applying migrations
        with self._connect() as conn:
            conn.execute("CREATE INDEX IF NOT EXISTS idx_events_user ON events(user_id);")

    def _apply_migrations(self):
        with self._connect() as conn:
            existing_cols = {row[1] for row in conn.execute("PRAGMA table_info(events)")}
            for col, stmt in MIGRATIONS:
                if col not in existing_cols:
                    conn.execute(stmt)

    @contextmanager
    def _connect(self):
        conn = sqlite3.connect(self.path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()

    def create_user(self, username, password_hash, api_key):
        with self._connect() as conn:
            try:
                conn.execute(
                    "INSERT INTO users (username, password_hash, api_key) VALUES (?, ?, ?)",
                    (username, password_hash, api_key),
                )
                return True
            except sqlite3.IntegrityError:
                return False

    def get_user_by_username(self, username):
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
            return dict(row) if row else None

    def get_user_by_api_key(self, api_key):
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM users WHERE api_key = ?", (api_key,)).fetchone()
            return dict(row) if row else None

    def insert_event(self, ts, source, category, ip_address=None, username=None,
                      port=None, status=None, failed_attempts=None,
                      threat_score=0, threat_level="LOW", threat_color="#4fd6e8",
                      is_anomaly=0, message="", meta=None, attack_type=None, user_id=None):
        with self._connect() as conn:
            conn.execute(
                """INSERT INTO events
                   (ts, source, category, ip_address, username, port, status,
                    failed_attempts, threat_score, threat_level, threat_color,
                    is_anomaly, message, meta, attack_type, user_id)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (ts, source, category, ip_address, username, port, status,
                 failed_attempts, threat_score, threat_level, threat_color,
                 is_anomaly, message, json.dumps(meta or {}), attack_type, user_id),
            )

    def insert_many(self, events):
        with self._connect() as conn:
            conn.executemany(
                """INSERT INTO events
                   (ts, source, category, ip_address, username, port, status,
                    failed_attempts, threat_score, threat_level, threat_color,
                    is_anomaly, message, meta, attack_type, user_id)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                [
                    (e["ts"], e["source"], e["category"], e.get("ip_address"),
                     e.get("username"), e.get("port"), e.get("status"),
                     e.get("failed_attempts"), e["threat_score"], e["threat_level"],
                     e["threat_color"], e.get("is_anomaly", 0), e.get("message", ""),
                     json.dumps(e.get("meta", {})), e.get("attack_type"), e.get("user_id"))
                    for e in events
                ],
            )

    def _format_event(self, row):
        d = dict(row)
        meta_raw = d.get("meta")
        meta = {}
        if meta_raw:
            try:
                meta = json.loads(meta_raw) if isinstance(meta_raw, str) else meta_raw
            except (json.JSONDecodeError, TypeError):
                meta = {}
        if not isinstance(meta, dict):
            meta = {}
        d["explanation"] = meta.get("explanation", d.get("explanation", ""))
        d["feature_contributions"] = meta.get("feature_contributions", d.get("feature_contributions", []))
        d["cold_start"] = bool(meta.get("cold_start", d.get("cold_start", False)))
        d["baseline_confidence"] = meta.get("baseline_confidence", d.get("baseline_confidence", 1.0))
        return d

    def get_events(self, limit=100, level=None, source=None, sort_by=None, user_id=None):
        query = "SELECT * FROM events WHERE 1=1"
        params = []
        if user_id is not None:
            query += " AND user_id = ?"
            params.append(user_id)
        if level:
            query += " AND threat_level = ?"
            params.append(level.upper())
        if source:
            query += " AND source = ?"
            params.append(source)
        if sort_by == "score":
            query += " ORDER BY threat_score DESC, ts DESC LIMIT ?"
        else:
            query += " ORDER BY ts DESC LIMIT ?"
        params.append(limit)
        with self._connect() as conn:
            rows = conn.execute(query, params).fetchall()
        return [self._format_event(r) for r in rows]

    def get_alerts(self, limit=100, sort_by=None, user_id=None):
        query = "SELECT * FROM events WHERE threat_level IN ('HIGH','CRITICAL')"
        params = []
        if user_id is not None:
            query += " AND user_id = ?"
            params.append(user_id)
        if sort_by == "score":
            query += " ORDER BY threat_score DESC, ts DESC LIMIT ?"
        else:
            query += " ORDER BY ts DESC LIMIT ?"
        params.append(limit)
        with self._connect() as conn:
            rows = conn.execute(query, params).fetchall()
        return [self._format_event(r) for r in rows]

    def get_entity_events(self, ip_address, limit=100, user_id=None):
        query = "SELECT * FROM events WHERE ip_address = ?"
        params = [ip_address]
        if user_id is not None:
            query += " AND user_id = ?"
            params.append(user_id)
        query += " ORDER BY ts ASC LIMIT ?"
        params.append(limit)
        with self._connect() as conn:
            rows = conn.execute(query, params).fetchall()
        return [self._format_event(r) for r in rows]

    def get_stats(self, user_id=None):
        with self._connect() as conn:
            user_clause = " WHERE user_id = ?" if user_id is not None else ""
            user_clause_and = " AND user_id = ?" if user_id is not None else ""
            params = (user_id,) if user_id is not None else ()

            total = conn.execute("SELECT COUNT(*) c FROM events" + user_clause, params).fetchone()["c"]
            anomalies = conn.execute("SELECT COUNT(*) c FROM events WHERE is_anomaly=1" + user_clause_and, params).fetchone()["c"]
            alerts = conn.execute(
                "SELECT COUNT(*) c FROM events WHERE threat_level IN ('HIGH','CRITICAL')" + user_clause_and, params
            ).fetchone()["c"]
            suspicious_ips = conn.execute(
                "SELECT COUNT(DISTINCT ip_address) c FROM events WHERE threat_level IN ('HIGH','CRITICAL')" + user_clause_and, params
            ).fetchone()["c"]
            avg_score = conn.execute("SELECT AVG(threat_score) a FROM events" + user_clause, params).fetchone()["a"] or 0
            max_score = conn.execute("SELECT MAX(threat_score) m FROM events" + user_clause, params).fetchone()["m"] or 0
            
            levels = {}
            for row in conn.execute("SELECT threat_level, COUNT(*) c FROM events" + user_clause + " GROUP BY threat_level", params):
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

    def get_timeline(self, user_id=None):
        """Event counts bucketed by hour-of-day (0-23), across all events."""
        buckets = [0] * 24
        query = "SELECT ts FROM events"
        params = []
        if user_id is not None:
            query += " WHERE user_id = ?"
            params.append(user_id)
        with self._connect() as conn:
            for row in conn.execute(query, params):
                hour = time.localtime(row["ts"]).tm_hour
                buckets[hour] += 1
        return [{"hour": h, "count": c} for h, c in enumerate(buckets)]

    def get_top_ips(self, limit=10, user_id=None):
        query = """SELECT ip_address, COUNT(*) as event_count,
                          AVG(threat_score) as avg_score,
                          MAX(threat_score) as max_score
                   FROM events
                   WHERE ip_address IS NOT NULL"""
        params = []
        if user_id is not None:
            query += " AND user_id = ?"
            params.append(user_id)
        query += """ GROUP BY ip_address
                    ORDER BY max_score DESC, event_count DESC
                    LIMIT ?"""
        params.append(limit)
        with self._connect() as conn:
            rows = conn.execute(query, params).fetchall()
        return [
            {
                "ip_address": r["ip_address"],
                "event_count": r["event_count"],
                "avg_score": round(r["avg_score"], 1),
                "max_score": r["max_score"],
            }
            for r in rows
        ]
