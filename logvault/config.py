"""All settings come from environment variables - nothing is hardcoded."""
from __future__ import annotations

import os
from typing import Any

BLOCK_SIZE = 1024 * 1024  # 1 MB


def load_config() -> dict[str, Any]:
    env = os.environ.get
    return {
        "SECRET_KEY": env("SECRET_KEY"),
        "STORAGE_BACKEND": env("STORAGE_BACKEND", "local").lower(),  # local | r2
        "LOCAL_STORAGE_DIR": env("LOCAL_STORAGE_DIR", "instance/local_bucket"),
        "LOGVAULT_MASTER_KEY": env("LOGVAULT_MASTER_KEY"),
        "R2_ACCOUNT_ID": env("R2_ACCOUNT_ID"),
        "R2_ACCESS_KEY_ID": env("R2_ACCESS_KEY_ID"),
        "R2_SECRET_ACCESS_KEY": env("R2_SECRET_ACCESS_KEY"),
        "R2_BUCKET": env("R2_BUCKET"),
        "S3_ENDPOINT_URL": env("S3_ENDPOINT_URL"),  # optional override
        "ALLOWED_EXTENSIONS": ("log", "txt"),
        "MAX_CONTENT_LENGTH": int(env("MAX_UPLOAD_MB", "100")) * 1024 * 1024,
        "ENABLE_TAMPER_DEMO": env(
            "ENABLE_TAMPER_DEMO", "1" if env("STORAGE_BACKEND", "local").lower() == "local" else "0"
        ) == "1",
        "BLOCK_SIZE": BLOCK_SIZE,
    }
