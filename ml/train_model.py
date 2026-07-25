"""
Trains the Isolation Forest anomaly model on a log dataset (CSV or
auth.log) and saves the fitted model + scaler for use by ml/detector.py
and the backend API.

Usage:
    python ml/train_model.py --input data/sample_logs.csv --out backend/models/model.joblib
"""
import argparse
import os
import sys
import numpy as np
import joblib
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from backend.utils.log_parser import parse_log_file
from backend.utils.features import extract_features, IPHistory


def build_training_matrix(records):
    ip_history = IPHistory()
    X = []
    for record in records:
        X.append(extract_features(record, ip_history))
    return np.array(X)


def main():
    parser = argparse.ArgumentParser(description="Train the Isolation Forest threat model")
    parser.add_argument("--input", default="data/sample_logs.csv")
    parser.add_argument("--out", default="backend/models/model.joblib")
    parser.add_argument("--contamination", type=float, default=0.1)
    args = parser.parse_args()

    records = parse_log_file(args.input)
    if len(records) < 20:
        print(f"Not enough records ({len(records)}) to train on. Run data/generate_logs.py first.")
        return

    X = build_training_matrix(records)
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    model = IsolationForest(
        n_estimators=250,
        contamination=args.contamination,
        random_state=42,
    )
    model.fit(X_scaled)

    # Calibrate the decision_function range against this training set so
    # scoring at inference time maps to a well-spread 0-100 scale instead
    # of assuming a fixed range that may not match the actual data.
    raw_scores = model.decision_function(X_scaled)
    score_low = float(np.percentile(raw_scores, 2))    # near-most-anomalous seen
    score_high = float(np.percentile(raw_scores, 98))  # near-most-normal seen

    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    joblib.dump(
        {"model": model, "scaler": scaler, "score_low": score_low, "score_high": score_high},
        args.out,
    )
    print(
        f"Trained on {len(records)} records -> saved model to {args.out} "
        f"(calibration range: {score_low:.3f} .. {score_high:.3f})"
    )


if __name__ == "__main__":
    main()
