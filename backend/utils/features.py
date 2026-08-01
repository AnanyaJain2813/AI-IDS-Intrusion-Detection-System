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
    """Tracks per-IP attempt/failure counts as records are processed in order.

    Extended fields for attack-type classification:
      ip_usernames  — distinct usernames seen per source IP
      ip_ports      — distinct destination ports seen per source IP
      username_last_success_ip — last IP from which each username succeeded
      ip_user_agents — per-(ip, username) set of distinct user-agent strings
    """

    def __init__(self):
        self.attempts = defaultdict(float)
        self.failures = defaultdict(float)
        self.lifetime_observations = defaultdict(int)
        # Attack-type classification helpers
        self.ip_usernames = defaultdict(set)
        self.ip_ports = defaultdict(set)
        self.username_last_success_ip = {}          # username -> most recent success IP
        self.username_prev_success_ip = {}          # username -> second-most-recent success IP
        self.ip_user_agents = defaultdict(set)      # (ip, username) -> set of user-agents

    def observe(self, ip, failed, username=None, port=None,
                user_agent=None, status=None):
        self.lifetime_observations[ip] += 1
        
        # Concept Drift: Exponential decay on behavioral stats
        # alpha = 0.95 means series converges to 20 for continuous activity,
        # allowing fast bursts to cross threshold (10) while naturally decaying old events.
        self.attempts[ip] = self.attempts.get(ip, 0.0) * 0.95 + 1.0
        
        if failed:
            self.failures[ip] = self.failures.get(ip, 0.0) * 0.95 + 1.0
        else:
            self.failures[ip] = self.failures.get(ip, 0.0) * 0.95
        if username:
            self.ip_usernames[ip].add(username)
        if port is not None:
            self.ip_ports[ip].add(port)
        if user_agent and username:
            self.ip_user_agents[(ip, username)].add(user_agent)
        if status and status.lower() == "success" and username:
            # Rotate: prev <- last <- current
            current_last = self.username_last_success_ip.get(username)
            if current_last is not None:
                self.username_prev_success_ip[username] = current_last
            self.username_last_success_ip[username] = ip

    def attempt_count(self, ip):
        return self.attempts.get(ip, 0)

    def fail_rate(self, ip):
        total = self.attempts.get(ip, 0)
        return (self.failures.get(ip, 0) / total) if total else 0.0

    def distinct_usernames(self, ip):
        """Number of distinct usernames seen from this IP."""
        return len(self.ip_usernames.get(ip, set()))

    def distinct_ports(self, ip):
        """Number of distinct destination ports seen from this IP."""
        return len(self.ip_ports.get(ip, set()))

    def last_success_ip(self, username):
        """Return the last IP from which this username succeeded, or None."""
        return self.username_last_success_ip.get(username)

    def distinct_user_agents(self, ip, username):
        """Number of distinct user-agents seen for this (ip, username) pair."""
        return len(self.ip_user_agents.get((ip, username), set()))


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
    user_agent = record.get("user_agent")

    hour = record.get("hour")
    if hour is None:
        hour = _parse_hour(record.get("timestamp", ""))

    ip_history.observe(
        ip, is_failed,
        username=username, port=port,
        user_agent=user_agent, status=status,
    )

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
