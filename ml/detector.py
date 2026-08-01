"""
Detector — loads the trained Isolation Forest model and scores log
records (either one at a time, for the live /api/analyse endpoint, or
in bulk, for ingesting a full log file) into 0-100 threat scores.

When a trained GRU sequence model is also available, the detector
maintains a per-IP sliding window of recent events, computes a
sequence-based anomaly score from reconstruction error, and blends it
with the Isolation Forest score for an ensemble result.  If the sequence
model file is absent, the detector falls back to IF-only scoring.

Explainability:
  - For the IF path: a SHAP TreeExplainer is cached at __init__ time
    (not per-call) and operates on the scaled feature space that the IF
    was trained on — NOT raw features, to avoid misattributing large-
    magnitude features like port.
  - For the sequence path: per-feature squared reconstruction error,
    summed across the time axis.
"""
import os
from collections import deque

import joblib
import numpy as np

from backend.utils.features import extract_features, IPHistory, FEATURE_NAMES
from backend.utils.sequence_features import extract_sequence_features, SEQUENCE_FEATURE_NAMES
from ml.threat_scorer import score_from_isolation_forest, classify
from ml.attack_typer import classify_attack_type
from ml.explainer import (
    explain_isolation_forest,
    explain_sequence_model,
    build_explanation,
)

# Ensemble weight: how much the IF score vs sequence score contributes.
IF_WEIGHT = 0.7
SEQ_WEIGHT = 0.3


class Detector:
    def __init__(self, model_path, seq_model_path=None, ensemble_strategy="weighted"):
        self.ensemble_strategy = ensemble_strategy  # "weighted" or "max"
        # --- Isolation Forest ---
        self.model = None
        self.scaler = None
        self.score_low = -0.15
        self.score_high = 0.15
        self._shap_explainer = None   # cached SHAP TreeExplainer
        self.population_features_ema = None # Concept drift population track
        try:
            bundle = joblib.load(model_path)
            self.model = bundle["model"]
            self.scaler = bundle["scaler"]
            self.score_low = bundle.get("score_low", self.score_low)
            self.score_high = bundle.get("score_high", self.score_high)
            self._init_shap_explainer()
        except FileNotFoundError:
            pass  # caller should check `.ready` and prompt training if needed

        # --- Sequence model (optional) ---
        self.seq_model = None
        self.seq_scaler_mean = None
        self.seq_scaler_scale = None
        self.seq_error_low = 0.0
        self.seq_error_high = 1.0
        self.seq_window_size = 10
        self._per_ip_windows = {}  # ip -> deque of scaled feature vectors

        if seq_model_path and os.path.isfile(seq_model_path):
            self._load_sequence_model(seq_model_path)

    def _init_shap_explainer(self):
        """
        Cache a SHAP TreeExplainer for the Isolation Forest.

        IMPORTANT: the explainer must use the same scaled feature space the
        IF was trained on.  We pass the scaler's transform so SHAP evaluates
        contributions in that space — not on raw inputs where a port value of
        65535 would dwarf binary 0/1 features and produce meaningless weights.
        """
        try:
            import shap
            self._shap_explainer = shap.TreeExplainer(self.model)
        except Exception as e:
            print(f"[Detector] SHAP TreeExplainer init failed: {e} — explainability disabled")
            self._shap_explainer = None

    def _load_sequence_model(self, path):
        """Load the GRU autoencoder bundle.  Import torch lazily."""
        try:
            import torch
            from ml.sequence_model import GRUAutoencoder

            bundle = torch.load(path, map_location="cpu", weights_only=False)
            input_dim = bundle["input_dim"]
            hidden_dim = bundle["hidden_dim"]

            model = GRUAutoencoder(input_dim=input_dim, hidden_dim=hidden_dim)
            model.load_state_dict(bundle["model_state_dict"])
            model.eval()

            self.seq_model = model
            self.seq_scaler_mean = np.array(bundle["scaler_mean"], dtype=np.float32)
            self.seq_scaler_scale = np.array(bundle["scaler_scale"], dtype=np.float32)
            self.seq_error_low = bundle["error_low"]
            self.seq_error_high = bundle["error_high"]
            self.seq_window_size = bundle["window_size"]
        except Exception as e:
            # Graceful fallback — log but don't crash
            print(f"[Detector] Could not load sequence model from {path}: {e}")
            self.seq_model = None

    @property
    def ready(self):
        return self.model is not None

    @property
    def seq_ready(self):
        return self.seq_model is not None

    def _get_ip_deque(self, ip):
        """Return (or create) the per-IP sliding window deque."""
        if ip not in self._per_ip_windows:
            self._per_ip_windows[ip] = deque(maxlen=self.seq_window_size)
        return self._per_ip_windows[ip]

    def _score_sequence(self, ip, record):
        """
        Append the current record's scaled features to the IP's deque and
        compute the sequence anomaly score (0-100).

        Padding strategy: if the deque has fewer than window_size events,
        use edge-replication — repeat the earliest event to fill the left
        side.  This avoids zero-padding (which looks like a synthetic
        all-zeros event and would trigger false anomalies) and is
        conservative: "before we saw anything, assume the IP was doing
        what it first did."

        Returns (score: int, window_tensor: torch.Tensor)
        """
        import torch

        raw_feats = np.array(extract_sequence_features(record), dtype=np.float32)
        scaled = (raw_feats - self.seq_scaler_mean) / self.seq_scaler_scale

        dq = self._get_ip_deque(ip)
        dq.append(scaled)

        # Build the window with edge-replication padding
        window_list = list(dq)
        if len(window_list) < self.seq_window_size:
            pad_count = self.seq_window_size - len(window_list)
            window_list = [window_list[0]] * pad_count + window_list

        window = np.array(window_list, dtype=np.float32)
        window_tensor = torch.from_numpy(window).unsqueeze(0)  # (1, N, dim)

        from ml.sequence_model import reconstruction_error
        error = reconstruction_error(self.seq_model, window_tensor)

        # Map reconstruction error to 0-100 using calibration range
        span = max(self.seq_error_high - self.seq_error_low, 1e-8)
        normalized = (error - self.seq_error_low) / span
        normalized = max(0.0, min(1.0, normalized))
        seq_score = round(normalized * 100)
        return max(0, min(100, seq_score)), window_tensor

    def _explain(self, scaled_vec, seq_window_tensor, threat_score, seq_score=0):
        """
        Build feature_contributions and explanation for one scored record.

        Uses the cached SHAP TreeExplainer for IF contributions (on the
        ALREADY-SCALED vector) and per-feature squared reconstruction error
        for the sequence model.  If the sequence model is active, its top
        contributions are appended after the IF top-3.

        Returns (feature_contributions: list[dict], explanation: str)
        """
        contributions = []

        # IF path — SHAP on scaled features
        if self._shap_explainer is not None:
            contributions = explain_isolation_forest(
                self._shap_explainer,
                scaled_vec,           # already StandardScaler-transformed
                FEATURE_NAMES,
            )
        else:
            # No SHAP: fall back to raw SHAP-less magnitude of scaled values
            vals = scaled_vec.flatten()
            raw_contribs = [
                {"feature_name": name, "contribution_value": round(float(v), 4)}
                for name, v in zip(FEATURE_NAMES, vals)
            ]
            raw_contribs.sort(key=lambda c: abs(c["contribution_value"]), reverse=True)
            contributions = raw_contribs[:3]

        # Sequence model path — per-feature squared reconstruction error
        if self.seq_ready and seq_window_tensor is not None:
            seq_contribs = explain_sequence_model(
                self.seq_model,
                seq_window_tensor,
                SEQUENCE_FEATURE_NAMES,
                seq_score / 100.0,
            )
            # Merge: take the top-3 overall by magnitude across both sources
            all_contribs = contributions + seq_contribs
            all_contribs.sort(key=lambda c: abs(c["contribution_value"]), reverse=True)
            contributions = all_contribs[:3]

        explanation = build_explanation(contributions, threat_score)
        return contributions, explanation

    def _score_raw_features(self, features):
        if not self.ready:
            combo_score = features[-1]
            return min(100, combo_score * 20)
        scaled_vec = self.scaler.transform(np.array(features).reshape(1, -1))
        raw = self.model.decision_function(scaled_vec)[0]
        return score_from_isolation_forest(
            raw, features[-1], score_low=self.score_low, score_high=self.score_high
        )

    def score_record(self, record, ip_history: IPHistory, failed_attempts_hint=None):
        features = extract_features(record, ip_history, failed_attempts_hint)
        features_np = np.array(features, dtype=float)

        # Track population feature archetype via Exponential Moving Average
        if self.population_features_ema is None:
            self.population_features_ema = features_np.copy()
        else:
            self.population_features_ema = 0.99 * self.population_features_ema + 0.01 * features_np

        raw_score = self._score_raw_features(features)

        seq_window_tensor = None   # populated if sequence model is active
        scaled_vec = np.zeros((1, len(features)))  # fallback for no-model path

        if self.ready:
            scaled_vec = self.scaler.transform(np.array(features).reshape(1, -1))

        if_score_val = raw_score
        # Ensemble with sequence model if available
        if self.seq_ready:
            seq_score, seq_window_tensor = self._score_sequence(record["ip_address"], record)
            if self.ensemble_strategy == "max":
                raw_score = max(raw_score, seq_score)
            else:
                raw_score = round(IF_WEIGHT * raw_score + SEQ_WEIGHT * seq_score)
            raw_score = max(0, min(100, raw_score))
            model_used = f"ensemble_{self.ensemble_strategy}"
        else:
            seq_score = 0
            model_used = "isolation_forest" if self.ready else "rule_based"

        # COLD START BLENDING
        # We use a separate, non-decaying lifetime counter so established IPs never revert to cold_start.
        lifetime = max(ip_history.lifetime_observations.get(record["ip_address"], 0), failed_attempts_hint or 0)
        cold_start = lifetime < 3
        baseline_confidence = round(min(1.0, lifetime / 3.0), 2)
        
        if cold_start:
            # Score the population archetype and blend
            baseline_score = self._score_raw_features(self.population_features_ema)
            score = raw_score * baseline_confidence + baseline_score * (1.0 - baseline_confidence)
            score = round(score)
        else:
            score = raw_score

        result = classify(score)
        result["model_used"] = model_used

        features_dict = dict(zip(FEATURE_NAMES, features))
        result["attack_type"] = classify_attack_type(record, features_dict, ip_history)
        result["features"] = features_dict

        # Explainability — always run even without SHAP (graceful degradation)
        feature_contributions, explanation = self._explain(
            scaled_vec, seq_window_tensor, score, seq_score
        )
        result["feature_contributions"] = feature_contributions
        result["explanation"] = explanation

        result["cold_start"] = cold_start
        result["baseline_confidence"] = baseline_confidence
        result["if_score"] = if_score_val
        result["seq_score"] = seq_score

        return result

    def score_batch(self, records):
        ip_history = IPHistory()
        results = []
        for record in records:
            scored = self.score_record(record, ip_history)
            results.append({**record, **scored})
        return results

