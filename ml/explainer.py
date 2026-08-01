"""
Explainability layer for Sentry's anomaly detector.

Provides two explainability paths:

1. Isolation Forest (SHAP TreeExplainer)
   - Operates on the StandardScaler-transformed feature space, NOT raw
     features, since the IF was trained on scaled inputs. SHAP on unscaled
     inputs would misattribute contributions to large-magnitude features
     (e.g. port 0-65535 dwarfing binary 0/1 flags).
   - The TreeExplainer is cached at Detector init time (not per-call) so
     it's safe to use on a 5-second dashboard polling loop.

2. Sequence model (per-timestep squared reconstruction error)
   - SHAP's TreeExplainer doesn't apply to GRU autoencoders.
   - Instead: reconstruct the window, compute squared error per-timestep
     per-feature, then sum across the time axis → per-feature contribution.

Both paths produce the same structured output:
    feature_contributions : list[dict]  (top 3 by |magnitude|, filtered
                                          by |value| >= MIN_CONTRIBUTION)
    explanation           : str         (direction-aware plain-English summary)
"""
import numpy as np

# Only contributions with |value| >= this threshold are surfaced in the
# explanation string.  Below this they're noise for normal records.
MIN_CONTRIBUTION = 0.10

# ─── Direction-aware phrase templates ─────────────────────────────────────────
# Each entry: (positive_phrase, negative_phrase)
# positive = pushing toward anomaly, negative = pushing toward normal/benign
_PHRASES = {
    "failed_attempts": (
        "elevated failed login attempts",
        "typical failed-login pattern",
    ),
    "hour": (
        "unusual access hour",
        "normal business-hours access",
    ),
    "is_night_hour": (
        "access during night hours (midnight–5 am)",
        "daytime access window",
    ),
    "is_root_attempt": (
        "privileged account targeted (root/admin)",
        "non-privileged account",
    ),
    "ip_attempt_count": (
        "high volume of connection attempts from this IP",
        "low connection volume from this IP",
    ),
    "status_numeric": (
        "authentication failure",
        "successful authentication",
    ),
    "port": (
        "unusual destination port",
        "expected destination port",
    ),
    "is_ssh_port": (
        "SSH port targeted with failures",
        "non-SSH port or no failures on SSH",
    ),
    "fail_rate": (
        "high failure rate from this IP",
        "low failure rate from this IP",
    ),
    "combo_score": (
        "multiple compounding risk indicators",
        "few compounding risk indicators",
    ),
    # Sequence-model feature names
    "seq_hour": (
        "atypical access-hour sequence",
        "consistent access-hour pattern",
    ),
    "seq_is_night_hour": (
        "recurring off-hours events in sequence",
        "sequence has no off-hours events",
    ),
    "seq_is_root_attempt": (
        "repeated privileged-account targeting in sequence",
        "no privileged accounts targeted in sequence",
    ),
    "seq_status_numeric": (
        "sustained failure pattern across sequence",
        "mostly successful logins in sequence",
    ),
    "seq_port": (
        "varied or unusual ports across sequence",
        "consistent expected port across sequence",
    ),
    "seq_is_ssh_port": (
        "SSH port failure pattern across sequence",
        "no SSH-specific failure pattern in sequence",
    ),
}

_FALLBACK_POSITIVE = "anomalous pattern detected"
_FALLBACK_NEGATIVE = "within expected baseline"


def _phrase(feature_name, contribution_value):
    """Return direction-aware phrase for a feature contribution."""
    pos, neg = _PHRASES.get(feature_name, (_FALLBACK_POSITIVE, _FALLBACK_NEGATIVE))
    return pos if contribution_value > 0 else neg


def build_explanation(feature_contributions, threat_score):
    """
    Build a human-readable explanation string from the top contributions.

    Parameters
    ----------
    feature_contributions : list[dict]  with keys: feature_name, contribution_value
    threat_score : int  0-100 threat score for this record

    Returns
    -------
    str
    """
    # Filter out noise
    significant = [
        fc for fc in feature_contributions
        if abs(fc["contribution_value"]) >= MIN_CONTRIBUTION
    ]

    if not significant:
        if threat_score < 30:
            return "Normal activity — no significant anomaly signals detected."
        return "Moderate anomaly score with no single dominant contributing factor."

    positive_parts = [
        _phrase(fc["feature_name"], fc["contribution_value"])
        for fc in significant
        if fc["contribution_value"] > 0
    ]
    negative_parts = [
        _phrase(fc["feature_name"], fc["contribution_value"])
        for fc in significant
        if fc["contribution_value"] < 0
    ]

    if positive_parts and not negative_parts:
        joined = "; ".join(positive_parts)
        return f"Flagged for: {joined}."
    if negative_parts and not positive_parts:
        joined = "; ".join(negative_parts)
        return f"Appears benign: {joined}."
    if positive_parts and negative_parts:
        pos_joined = "; ".join(positive_parts)
        neg_joined = "; ".join(negative_parts)
        return f"Flagged for: {pos_joined}. Partially offset by: {neg_joined}."

    return "No significant explanation signals."


def explain_isolation_forest(shap_explainer, scaled_vec, feature_names):
    """
    Compute SHAP values for one record using the cached TreeExplainer.

    Parameters
    ----------
    shap_explainer : shap.TreeExplainer  (cached at Detector init)
    scaled_vec     : np.ndarray  shape (1, n_features) — same scaled space
                     the IF was trained on
    feature_names  : list[str]

    Returns
    -------
    list[dict]  top-3 contributions by |magnitude|, each:
        {feature_name: str, contribution_value: float}
    """
    shap_vals = shap_explainer.shap_values(scaled_vec)
    # TreeExplainer returns shape (1, n_features) for IF
    vals = np.array(shap_vals).flatten()

    # IF decision function: negative means anomalous, positive means normal.
    # To align with our phrasing (where positive contribution = pushing toward anomaly),
    # we flip the signs of the SHAP values.
    vals = -vals

    contributions = [
        {"feature_name": name, "contribution_value": round(float(v), 4)}
        for name, v in zip(feature_names, vals)
    ]
    # Sort by |magnitude| descending, take top 3
    contributions.sort(key=lambda c: abs(c["contribution_value"]), reverse=True)
    return contributions[:3]


def explain_sequence_model(seq_model, window_tensor, seq_feature_names, seq_score_normalized):
    """
    Compute per-feature contribution to reconstruction error for a window.

    Squares the reconstruction error per timestep per feature, then sums
    across the time axis to get a per-feature importance score.
    These are normalised to sum to the normalized sequence score (0.0 - 1.0)
    so that normal records (score ~ 0) don't produce large contributions,
    and anomalous records correctly attribute the high score to features.

    Parameters
    ----------
    seq_model            : GRUAutoencoder  (already in eval mode)
    window_tensor        : torch.Tensor  shape (1, N, input_dim)
    seq_feature_names    : list[str]
    seq_score_normalized : float  (0.0 to 1.0)

    Returns
    -------
    list[dict]  top-3 contributions, each with a "seq_" prefix on the name
    """
    import torch

    with torch.no_grad():
        reconstructed = seq_model(window_tensor)
        # Squared error: (1, N, input_dim)
        sq_err = (reconstructed - window_tensor) ** 2
        # Sum across time axis → (1, input_dim)
        per_feature = sq_err.squeeze(0).sum(dim=0).numpy()

    total = per_feature.sum()
    if total < 1e-10:
        # Perfect reconstruction — no anomaly signal
        return [
            {"feature_name": f"seq_{name}", "contribution_value": 0.0}
            for name in seq_feature_names[:3]
        ]

    # Normalise proportions and scale by the anomaly intensity
    normalized = (per_feature / total) * seq_score_normalized

    contributions = [
        {"feature_name": f"seq_{name}", "contribution_value": round(float(v), 4)}
        for name, v in zip(seq_feature_names, normalized)
    ]
    contributions.sort(key=lambda c: abs(c["contribution_value"]), reverse=True)
    return contributions[:3]
