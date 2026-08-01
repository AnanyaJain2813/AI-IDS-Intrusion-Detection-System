"""
Flask application factory. Loads the trained detector and opens the
SQLite database, then registers the API blueprint.
"""
import os
# pyrefly: ignore [missing-import]
from flask import Flask
from flask_cors import CORS

from backend.utils.database import Database
from ml.detector import Detector

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_DB_PATH = os.path.join(BASE_DIR, "backend", "sentry.db")
DEFAULT_MODEL_PATH = os.path.join(BASE_DIR, "backend", "models", "model.joblib")
DEFAULT_SEQ_MODEL_PATH = os.path.join(BASE_DIR, "backend", "models", "sequence_model.pt")


def create_app(db_path=None, model_path=None, seq_model_path=None):
    app = Flask(__name__)
    CORS(app)

    app.config["DB"] = Database(db_path or DEFAULT_DB_PATH)
    app.config["DETECTOR"] = Detector(
        model_path or DEFAULT_MODEL_PATH,
        seq_model_path=seq_model_path or DEFAULT_SEQ_MODEL_PATH,
    )

    from backend.routes.api import api
    app.register_blueprint(api)

    return app


if __name__ == "__main__":
    app = create_app()
    app.run(debug=True, port=5000)

