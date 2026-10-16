"""LogVault - encrypted cloud log archive and integrity audit system."""
from __future__ import annotations

from pathlib import Path
from typing import Any

from dotenv import load_dotenv
from flask import Flask
from flask_wtf import CSRFProtect

from . import db
from .config import load_config
from .crypto import load_master_key
from .storage import make_storage

csrf = CSRFProtect()


def create_app(test_config: dict[str, Any] | None = None) -> Flask:
    load_dotenv(override=False)
    app = Flask(__name__, instance_relative_config=True)
    app.config.update(load_config())
    if test_config:
        app.config.update(test_config)

    Path(app.instance_path).mkdir(parents=True, exist_ok=True)
    app.config.setdefault("DATABASE", str(Path(app.instance_path) / "logvault.db"))
    if not app.config.get("SECRET_KEY"):
        # Only used for session/CSRF signing. A random value is fine locally.
        if app.config["STORAGE_BACKEND"] == "local" or app.config.get("TESTING"):
            import secrets

            app.config["SECRET_KEY"] = secrets.token_hex(32)
        else:
            raise RuntimeError("SECRET_KEY must be set when STORAGE_BACKEND=r2")

    app.extensions["master_key"] = load_master_key(app)
    app.extensions["storage"] = app.config.get("STORAGE_OBJECT") or make_storage(app)

    csrf.init_app(app)
    db.init_app(app)

    from .views import bp

    app.register_blueprint(bp)
    return app
