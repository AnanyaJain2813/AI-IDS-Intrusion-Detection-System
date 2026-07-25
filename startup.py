"""
Startup script — run once before the server starts (locally or on a
platform like Render). Generates sample data and trains the model if
they don't already exist, so a fresh clone/deploy has something to show.
"""
import os
import subprocess
import sys

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SAMPLE_CSV = os.path.join(BASE_DIR, "data", "sample_logs.csv")
MODEL_PATH = os.path.join(BASE_DIR, "backend", "models", "model.joblib")
DB_PATH = os.path.join(BASE_DIR, "backend", "sentry.db")


def run(cmd):
    print(f"$ {' '.join(cmd)}")
    subprocess.run(cmd, check=True, cwd=BASE_DIR)


def main():
    if not os.path.exists(SAMPLE_CSV):
        run([sys.executable, "data/generate_logs.py", "--out", SAMPLE_CSV, "--n", "1000"])

    if not os.path.exists(MODEL_PATH):
        run([sys.executable, "ml/train_model.py", "--input", SAMPLE_CSV, "--out", MODEL_PATH])

    if not os.path.exists(DB_PATH):
        run([sys.executable, "-m", "backend.utils.bulk_ingest",
             "--input", SAMPLE_CSV, "--db", DB_PATH, "--model", MODEL_PATH])

    print("Startup complete — data, model, and database are ready.")


if __name__ == "__main__":
    main()
