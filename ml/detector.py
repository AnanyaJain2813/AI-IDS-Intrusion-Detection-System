"""
Detector — loads the trained Isolation Forest model and scores log
records (either one at a time, for the live /api/analyse endpoint, or
in bulk, for ingesting a full log file) into 0-100 threat scores.
"""
import joblib
import numpy as np

from backend.utils.features import extract_features, IPHistory
from ml.threat_scorer import score_from_isolation_forest, classify


class Detector:
    def __init__(self, model_path):
        self.model = None
        self.scaler = None
        self.score_low = -0.15
        self.score_high = 0.15
        try:
            bundle = joblib.load(model_path)
            self.model = bundle["model"]
            self.scaler = bundle["scaler"]
            self.score_low = bundle.get("score_low", self.score_low)
            self.score_high = bundle.get("score_high", self.score_high)
        except FileNotFoundError:
            pass  # caller should check `.ready` and prompt training if needed

    @property
    def ready(self):
        return self.model is not None

    def score_record(self, record, ip_history: IPHistory, failed_attempts_hint=None):
        features = extract_features(record, ip_history, failed_attempts_hint)
        combo_score = features[-1]

        if not self.ready:
            # Fall back to a pure rule-based score if no model is trained yet.
            score = min(100, combo_score * 20)
        else:
            vec = self.scaler.transform(np.array(features).reshape(1, -1))
            raw = self.model.decision_function(vec)[0]
            score = score_from_isolation_forest(
                raw, combo_score, score_low=self.score_low, score_high=self.score_high
            )

        result = classify(score)
        result["features"] = dict(zip(
            ["failed_attempts", "hour", "is_night_hour", "is_root_attempt",
             "ip_attempt_count", "status_numeric", "port", "is_ssh_port",
             "fail_rate", "combo_score"],
            features,
        ))
        return result

    def score_batch(self, records):
        ip_history = IPHistory()
        results = []
        for record in records:
            scored = self.score_record(record, ip_history)
            results.append({**record, **scored})
        return results
