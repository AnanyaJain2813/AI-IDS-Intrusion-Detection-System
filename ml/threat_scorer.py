"""
Threat scorer — converts a raw Isolation Forest anomaly score plus
rule-based red flags into a single 0-100 threat score, a severity
bucket, and a display color. Used for both log-based and live
network-based events so every alert in the system is comparable.
"""

SEVERITY_THRESHOLDS = [
    (80, "CRITICAL", "#a855f7"),
    (60, "HIGH", "#f0563d"),
    (30, "MEDIUM", "#f0b93d"),
    (0, "LOW", "#4fd6e8"),
]


def severity_for_score(score):
    for threshold, level, color in SEVERITY_THRESHOLDS:
        if score >= threshold:
            return level, color
    return "LOW", "#4fd6e8"


def score_from_isolation_forest(raw_decision_score, combo_score, max_combo=5,
                                 score_low=-0.15, score_high=0.15):
    """
    raw_decision_score: sklearn's decision_function output for this record.
    score_low / score_high: the 2nd/98th percentile of decision_function
        values observed on the training set (stored in the model bundle
        at train time) — this is what the "very anomalous .. very normal"
        range actually looks like for THIS model, since decision_function
        is not reliably bounded to a fixed range like [-0.5, 0.5].
    combo_score: count of independent red flags (0..max_combo), used to
        nudge borderline cases and reward clearly-compounding risk.
    """
    span = max(score_high - score_low, 1e-6)
    normalized = (score_high - raw_decision_score) / span  # ~0 (normal) .. 1 (anomalous)
    normalized = max(0.0, min(1.0, normalized))
    base_score = normalized * 75  # cap the pure-ML contribution at 75

    bonus = min(combo_score, max_combo) * 5  # up to +25 for compounding red flags
    total = round(base_score + bonus)
    return max(0, min(100, total))


def score_from_rule_severity(rule_severity, intensity=1.0):
    """
    For network-layer signature alerts (port scan, SYN flood, ARP spoof,
    brute force) that don't go through the ML model, map a qualitative
    rule severity + intensity multiplier (e.g. how far over threshold)
    onto the same 0-100 scale used everywhere else.
    """
    base = {
        "syn_flood": 85,
        "port_scan": 65,
        "arp_spoofing": 60,
        "brute_force": 70,
        "normal_traffic": 8,
    }.get(rule_severity, 50)
    scaled = base * min(intensity, 1.3)
    return max(0, min(100, round(scaled)))


def classify(score):
    level, color = severity_for_score(score)
    return {
        "threat_score": score,
        "threat_level": level,
        "threat_color": color,
        "is_anomaly": 1 if score >= 60 else 0,
    }
