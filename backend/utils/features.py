"""
Feature engineering — converts a single normalized log record into the
numeric feature vector the ML model understands.

IP-level context (how many times an IP has appeared, its failure rate)
is tracked in an IPHistory object that the caller maintains across a
whole log file or a live stream, so features stay meaningful record by
record instead of needing the full dataset in memory at once.
"""
from collections import defaultdict
from datetime import datetime

SSH_PORT = 22
ROOT_LIKE_USERNAMES = {"root", "admin", "administrator"}

FEATURE_NAMES = [
    "failed_attempts",
    "hour",
    "is_night_hour",
    "is_root_attempt",
    "ip_attempt_count",
    "status_numeric",
    "port",
    "is_ssh_port",
    "fail_rate",
    "combo_score",
]


class IPHistory:
    """Tracks per-IP attempt/failure counts as records are processed in order."""

    def __init__(self):
        self.attempts = defaultdict(int)
        self.failures = defaultdict(int)

    def observe(self, ip, failed):
        self.attempts[ip] += 1
        if failed:
            self.failures[ip] += 1

    def attempt_count(self, ip):
        return self.attempts.get(ip, 0)

    def fail_rate(self, ip):
        total = self.attempts.get(ip, 0)
        return (self.failures.get(ip, 0) / total) if total else 0.0


def _parse_hour(timestamp):
    try:
        return datetime.fromisoformat(timestamp).hour
    except (ValueError, TypeError):
        return 12  # neutral default if timestamp is unparseable


def extract_features(record, ip_history: IPHistory, failed_attempts_hint=None):
    """
    Build the 10-feature vector for one log record.

    `failed_attempts_hint` lets callers (like the ad-hoc /api/analyse
    endpoint) pass an explicit failed-attempt count instead of relying
    purely on IP history, which is useful for single-record analysis.
    """
    ip = record["ip_address"]
    username = str(record.get("username", "")).lower()
    status = record.get("status", "Success")
    port = int(record.get("port", 0))
    is_failed = status.lower() == "failed"

    hour = record.get("hour")
    if hour is None:
        hour = _parse_hour(record.get("timestamp", ""))

    ip_history.observe(ip, is_failed)

    failed_attempts = (
        failed_attempts_hint if failed_attempts_hint is not None
        else ip_history.failures.get(ip, 0)
    )
    is_night_hour = 1 if (hour >= 0 and hour < 5) else 0
    is_root_attempt = 1 if username in ROOT_LIKE_USERNAMES else 0
    ip_attempt_count = ip_history.attempt_count(ip)
    status_numeric = 1 if is_failed else 0
    is_ssh_port = 1 if port == SSH_PORT else 0
    fail_rate = ip_history.fail_rate(ip)

    combo_score = sum([
        failed_attempts >= 5,
        is_night_hour,
        is_root_attempt,
        ip_attempt_count >= 10,
        is_ssh_port and is_failed,
    ])

    return [
        failed_attempts,
        hour,
        is_night_hour,
        is_root_attempt,
        ip_attempt_count,
        status_numeric,
        port,
        is_ssh_port,
        fail_rate,
        combo_score,
    ]
