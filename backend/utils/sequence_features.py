"""
Per-timestep feature extraction for the sequence model.

The LSTM/GRU autoencoder needs features that represent what happened at a
single point in time, NOT cumulative counters that grow monotonically as
more events arrive for the same IP.  The Isolation Forest feature vector
(features.py) mixes both kinds; this module extracts only the per-timestep
subset.

Excluded cumulative features:
    failed_attempts   — running count, always increases
    ip_attempt_count  — running count, always increases
    fail_rate         — ratio derived from running counts
    combo_score       — threshold-based summary of the above

Kept per-timestep features (6-dim):
    hour              — hour of day (0-23)
    is_night_hour     — binary, 1 if hour in [0,5)
    is_root_attempt   — binary, 1 if username is root/admin/administrator
    status_numeric    — binary, 1 if login failed
    port              — destination port number
    is_ssh_port       — binary, 1 if port == 22
"""
from datetime import datetime

SSH_PORT = 22
ROOT_LIKE_USERNAMES = {"root", "admin", "administrator"}

SEQUENCE_FEATURE_NAMES = [
    "hour",
    "is_night_hour",
    "is_root_attempt",
    "status_numeric",
    "port",
    "is_ssh_port",
]


def _parse_hour(timestamp):
    try:
        return datetime.fromisoformat(timestamp).hour
    except (ValueError, TypeError):
        return 12  # neutral default if timestamp is unparseable


def extract_sequence_features(record):
    """
    Build the 6-dimensional per-timestep feature vector for one log record.

    Unlike extract_features() in features.py, this requires NO IPHistory
    object — every feature here is intrinsic to the single event.
    """
    username = str(record.get("username", "")).lower()
    status = record.get("status", "Success")
    port = int(record.get("port", 0))

    hour = record.get("hour")
    if hour is None:
        hour = _parse_hour(record.get("timestamp", ""))

    is_night_hour = 1 if (hour >= 0 and hour < 5) else 0
    is_root_attempt = 1 if username in ROOT_LIKE_USERNAMES else 0
    status_numeric = 1 if status.lower() == "failed" else 0
    is_ssh_port = 1 if port == SSH_PORT else 0

    return [
        hour,
        is_night_hour,
        is_root_attempt,
        status_numeric,
        port,
        is_ssh_port,
    ]
