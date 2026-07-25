"""WSGI entry point — used by gunicorn in production (see Procfile)."""
from backend.app import create_app

app = create_app()

if __name__ == "__main__":
    app.run()
