"""
Trains the GRU autoencoder sequence model on per-IP windows drawn from
mostly-normal traffic and saves the bundle for use by ml/detector.py.

The pipeline:
    1. Parse CSV, sorted by timestamp
    2. Extract per-record 6-dim features (no cumulative counters)
    3. Fit StandardScaler on ALL records, then scale every record
    4. Filter to normal-traffic IPs (exclude known attacker subnets)
    5. Build sliding windows of length N per IP (skip IPs with < N events)
    6. Train the GRU autoencoder to reconstruct normal windows
    7. Calibrate reconstruction-error range (2nd/98th percentile)
    8. Save bundle: model state + scaler params + calibration + metadata

Usage:
    python ml/train_sequence.py --input data/sample_logs.csv --out backend/models/sequence_model.pt
"""
import argparse
import os
import sys
from collections import defaultdict

import numpy as np
import torch
import torch.nn as nn
from torch.utils.data import DataLoader, TensorDataset

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from backend.utils.log_parser import parse_log_file
from backend.utils.sequence_features import extract_sequence_features, SEQUENCE_FEATURE_NAMES
from ml.sequence_model import GRUAutoencoder

# Known attacker subnet prefix from data/generate_logs.py
ATTACKER_PREFIX = "45.33."

WINDOW_SIZE = 10
HIDDEN_DIM = 32
EPOCHS = 80
BATCH_SIZE = 32
LR = 1e-3


def build_scaled_records(records):
    """Extract per-timestep features and fit/apply StandardScaler."""
    raw_features = []
    for record in records:
        raw_features.append(extract_sequence_features(record))
    raw_features = np.array(raw_features, dtype=np.float32)

    # Fit scaler on all records BEFORE windowing
    mean = raw_features.mean(axis=0)
    std = raw_features.std(axis=0)
    # Prevent division by zero for constant features
    std[std < 1e-8] = 1.0

    scaled = (raw_features - mean) / std
    return scaled, mean, std


def build_windows(records, scaled_features, window_size, filter_attackers=True):
    """
    Group records by IP, build sliding windows of `window_size`.

    Padding strategy for training: NO padding. IPs with fewer than
    `window_size` events are simply skipped. This avoids teaching the
    autoencoder any particular padding pattern that could create
    artificial anomaly spikes for short-history IPs at inference time.
    """
    # Group indices by IP, preserving timestamp order (records already sorted)
    ip_groups = defaultdict(list)
    for idx, record in enumerate(records):
        ip = record["ip_address"]
        if filter_attackers and ip.startswith(ATTACKER_PREFIX):
            continue
        ip_groups[ip].append(idx)

    windows = []
    for ip, indices in ip_groups.items():
        if len(indices) < window_size:
            continue  # skip — not enough history for a full window
        # Sliding window with stride 1
        for start in range(len(indices) - window_size + 1):
            window_indices = indices[start : start + window_size]
            window = scaled_features[window_indices]
            windows.append(window)

    return np.array(windows, dtype=np.float32) if windows else np.empty((0, window_size, scaled_features.shape[1]), dtype=np.float32)


def train_autoencoder(windows, input_dim, hidden_dim, epochs, batch_size, lr):
    """Train the GRU autoencoder and return (model, training_losses)."""
    model = GRUAutoencoder(input_dim=input_dim, hidden_dim=hidden_dim)
    optimizer = torch.optim.Adam(model.parameters(), lr=lr)
    criterion = nn.MSELoss()

    dataset = TensorDataset(torch.from_numpy(windows))
    loader = DataLoader(dataset, batch_size=batch_size, shuffle=True)

    losses = []
    for epoch in range(epochs):
        model.train()
        epoch_loss = 0.0
        n_batches = 0
        for (batch,) in loader:
            optimizer.zero_grad()
            reconstructed = model(batch)
            loss = criterion(reconstructed, batch)
            loss.backward()
            optimizer.step()
            epoch_loss += loss.item()
            n_batches += 1
        avg_loss = epoch_loss / max(n_batches, 1)
        losses.append(avg_loss)
        if (epoch + 1) % 20 == 0 or epoch == 0:
            print(f"  Epoch {epoch+1:3d}/{epochs}  loss={avg_loss:.6f}")

    return model, losses


def calibrate_error_range(model, windows):
    """Compute reconstruction error on training windows, return 2nd/98th percentile."""
    model.eval()
    errors = []
    with torch.no_grad():
        tensor = torch.from_numpy(windows)
        # Process in batches to avoid OOM on large datasets
        for i in range(0, len(tensor), 64):
            batch = tensor[i : i + 64]
            reconstructed = model(batch)
            # Per-window MSE
            per_window_mse = ((reconstructed - batch) ** 2).mean(dim=(1, 2))
            errors.extend(per_window_mse.tolist())

    errors = np.array(errors)
    error_low = float(np.percentile(errors, 2))
    error_high = float(np.percentile(errors, 98))
    return error_low, error_high, errors


def main():
    parser = argparse.ArgumentParser(description="Train the GRU sequence anomaly model")
    parser.add_argument("--input", default="data/sample_logs.csv")
    parser.add_argument("--out", default="backend/models/sequence_model.pt")
    parser.add_argument("--window-size", type=int, default=WINDOW_SIZE)
    parser.add_argument("--epochs", type=int, default=EPOCHS)
    parser.add_argument("--hidden-dim", type=int, default=HIDDEN_DIM)
    parser.add_argument("--lr", type=float, default=LR)
    args = parser.parse_args()

    print(f"Loading records from {args.input} ...")
    records = parse_log_file(args.input)
    records.sort(key=lambda r: r.get("timestamp", ""))
    print(f"  {len(records)} records loaded")

    if len(records) < 20:
        print(f"Not enough records ({len(records)}) to train on. Run data/generate_logs.py first.")
        return

    print("Extracting and scaling per-timestep features ...")
    scaled_features, scaler_mean, scaler_scale = build_scaled_records(records)
    input_dim = scaled_features.shape[1]
    print(f"  Feature dim: {input_dim}  ({', '.join(SEQUENCE_FEATURE_NAMES)})")

    print(f"Building windows (size={args.window_size}, normal traffic only) ...")
    windows = build_windows(records, scaled_features, args.window_size, filter_attackers=True)
    print(f"  {len(windows)} training windows from normal-traffic IPs")

    if len(windows) < 5:
        print("Too few training windows. Try increasing --n in generate_logs.py or decreasing --window-size.")
        return

    print(f"Training GRU autoencoder (hidden={args.hidden_dim}, epochs={args.epochs}) ...")
    model, losses = train_autoencoder(
        windows,
        input_dim=input_dim,
        hidden_dim=args.hidden_dim,
        epochs=args.epochs,
        batch_size=BATCH_SIZE,
        lr=args.lr,
    )

    print("Calibrating reconstruction-error range ...")
    error_low, error_high, all_errors = calibrate_error_range(model, windows)
    error_spread = error_high / max(error_low, 1e-10)
    print(f"  error_low (p2)  = {error_low:.6f}")
    print(f"  error_high (p98) = {error_high:.6f}")
    print(f"  spread ratio     = {error_spread:.1f}x")
    print(f"  median error     = {float(np.median(all_errors)):.6f}")

    if error_spread > 100:
        print(
            "  WARNING: error spread is >100x — this may indicate a feature-scaling "
            "issue or degenerate training. Inspect the features going into the model."
        )

    os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
    bundle = {
        "model_state_dict": model.state_dict(),
        "scaler_mean": scaler_mean.tolist(),
        "scaler_scale": scaler_scale.tolist(),
        "error_low": error_low,
        "error_high": error_high,
        "window_size": args.window_size,
        "feature_names": SEQUENCE_FEATURE_NAMES,
        "input_dim": input_dim,
        "hidden_dim": args.hidden_dim,
    }
    torch.save(bundle, args.out)
    print(
        f"\nSaved sequence model to {args.out}\n"
        f"  calibration range: {error_low:.6f} .. {error_high:.6f}"
    )


if __name__ == "__main__":
    main()
