import pytest

from logvault import create_app
from logvault.storage import LocalStorage


@pytest.fixture
def app(tmp_path):
    app = create_app({
        "TESTING": True,
        "WTF_CSRF_ENABLED": False,
        "STORAGE_BACKEND": "local",
        "DATABASE": str(tmp_path / "test.db"),
        "STORAGE_OBJECT": LocalStorage(tmp_path / "bucket"),
        "LOGVAULT_MASTER_KEY": None,
        "BLOCK_SIZE": 1024,  # small blocks keep tests fast; production default is 1 MB
        "ENABLE_TAMPER_DEMO": True,
    })
    return app


@pytest.fixture
def client(app):
    return app.test_client()
