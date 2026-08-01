"""
Attack-type classifier — assigns a fine-grained attack-type label to every
scored log event using a priority-ordered set of rule-based heuristics.

The function operates on the features dict and the live IPHistory object
(which has already been updated by extract_features for this record), so
all per-IP counts are post-observation.

Taxonomy (priority order — first match wins):
    credential_stuffing  many distinct usernames from one IP, high fail rate
    brute_force          high fail rate + high failed_attempts, few usernames
    lateral_movement     same IP touching many distinct ports
    impossible_travel    same username succeeds from two different /16 subnets
    device_spoofing      same (ip, username) but different user-agent strings
    off_hours_anomaly    night-hour access (hour 0-4)
    normal               none of the above
"""

# ─── Thresholds ────────────────────────────────────────────────────────────
_CRED_STUFF_MIN_USERNAMES = 4
_CRED_STUFF_MIN_FAIL_RATE = 0.7
_CRED_STUFF_MIN_ATTEMPTS  = 8

_BRUTE_MIN_FAIL_RATE      = 0.8
_BRUTE_MIN_FAILED         = 8
_BRUTE_MAX_USERNAMES      = 2

_LATERAL_MIN_PORTS        = 6
_LATERAL_MIN_ATTEMPTS     = 6

ATTACK_TYPES = [
    "brute_force",
    "credential_stuffing",
    "impossible_travel",
    "lateral_movement",
    "device_spoofing",
    "off_hours_anomaly",
    "normal",
]


def _slash16(ip):
    """Return the /16 prefix of an IPv4 address string, e.g. '192.168'."""
    parts = ip.split(".")
    if len(parts) >= 2:
        return f"{parts[0]}.{parts[1]}"
    return ip


def classify_attack_type(record, features_dict, ip_history):
    """
    Return the most likely attack_type label for this event.

    Parameters
    ----------
    record : dict
        The raw log record (ip_address, username, status, port, user_agent…).
    features_dict : dict
        The feature dict already attached to the result by detector.py
        (keys: failed_attempts, hour, is_night_hour, is_root_attempt,
               ip_attempt_count, status_numeric, port, is_ssh_port,
               fail_rate, combo_score).
    ip_history : IPHistory
        Live per-IP state object — already updated for this record.

    Returns
    -------
    str  One of the ATTACK_TYPES labels.
    """
    ip        = record.get("ip_address", "")
    username  = str(record.get("username", "")).lower()
    status    = record.get("status", "Success")
    user_agent = record.get("user_agent")

    fail_rate       = features_dict.get("fail_rate", 0.0)
    failed_attempts = features_dict.get("failed_attempts", 0)
    ip_attempt_count = features_dict.get("ip_attempt_count", 0)
    is_night_hour   = features_dict.get("is_night_hour", 0)

    dist_usernames = ip_history.distinct_usernames(ip)
    dist_ports     = ip_history.distinct_ports(ip)

    # 1. Credential stuffing — many usernames, high fail rate
    if (dist_usernames >= _CRED_STUFF_MIN_USERNAMES
            and fail_rate >= _CRED_STUFF_MIN_FAIL_RATE
            and ip_attempt_count >= _CRED_STUFF_MIN_ATTEMPTS):
        return "credential_stuffing"

    # 2. Brute force — high fail rate against same account(s)
    if (fail_rate >= _BRUTE_MIN_FAIL_RATE
            and failed_attempts >= _BRUTE_MIN_FAILED
            and dist_usernames <= _BRUTE_MAX_USERNAMES):
        return "brute_force"

    # 3. Lateral movement — probing many distinct ports
    if (dist_ports >= _LATERAL_MIN_PORTS
            and ip_attempt_count >= _LATERAL_MIN_ATTEMPTS):
        return "lateral_movement"

    # 4. Impossible travel — same username succeeds from a different /16
    if status.lower() == "success" and username:
        # IPHistory.observe() rotates: prev_success_ip <- last_success_ip <- current
        # before updating. So username_prev_success_ip holds the IP from the
        # record BEFORE this one where the user succeeded. If that was a
        # different /16 subnet, this looks like impossible travel.
        prev_ip = ip_history.username_prev_success_ip.get(username)
        if prev_ip and _slash16(prev_ip) != _slash16(ip):
            return "impossible_travel"

    # 5. Device spoofing — same (ip, username) seen with multiple user-agents
    if user_agent and username:
        if ip_history.distinct_user_agents(ip, username) >= 2:
            return "device_spoofing"

    # 6. Off-hours anomaly
    if is_night_hour:
        return "off_hours_anomaly"

    # 7. Fallback
    return "normal"
