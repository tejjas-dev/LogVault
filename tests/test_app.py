import hashlib
import io
import os
import subprocess
import sys
import zipfile

DATA = (b"2025-01-01 INFO line of log data\n" * 200)  # ~6.6 KB -> 7 blocks of 1 KB


def upload(client, data=DATA, name="app.log"):
    return client.post("/upload", data={"logfile": (io.BytesIO(data), name)},
                       content_type="multipart/form-data", follow_redirects=True)


def file_id(app):
    with app.app_context():
        from logvault.db import get_db
        return get_db().execute("SELECT id FROM files").fetchone()["id"]


def test_index_loads(client):
    r = client.get("/")
    assert r.status_code == 200 and b"Archive a log file" in r.data


def test_upload_shows_history_and_blocks(app, client):
    r = upload(client)
    assert b"app.log" in r.data and b"encrypted block" in r.data
    assert b"app.log" in client.get("/").data
    assert b"Not verified" in client.get("/").data


def test_rejects_wrong_extension_and_empty(client):
    assert b"Only .log and .txt" in upload(client, b"x", "evil.exe").data
    assert b"empty" in upload(client, b"", "e.log").data


def test_stored_blocks_are_encrypted(app, client, tmp_path):
    upload(client)
    blocks = list((tmp_path / "bucket").rglob("*.enc"))
    assert len(blocks) == 7
    assert all(b"INFO" not in p.read_bytes() for p in blocks)


def test_verify_and_restore_match_sha256(app, client):
    upload(client)
    fid = file_id(app)
    assert b"PASS" in client.post(f"/file/{fid}/verify", follow_redirects=True).data
    assert b"Verified" in client.get("/").data
    r = client.get(f"/file/{fid}/restore")
    assert r.status_code == 200
    assert hashlib.sha256(r.data).hexdigest() == hashlib.sha256(DATA).hexdigest()
    assert r.data == DATA


def test_tampering_is_detected_and_restore_blocked(app, client):
    upload(client)
    fid = file_id(app)
    client.post(f"/file/{fid}/tamper")
    r = client.post(f"/file/{fid}/verify", follow_redirects=True)
    assert b"FAIL" in r.data and b"FAILED" in client.get("/").data
    r = client.get(f"/file/{fid}/restore", follow_redirects=True)
    assert b"Restore blocked" in r.data


def test_backup_zip_is_encrypted_and_restorable_offline(app, client, tmp_path):
    upload(client)
    fid = file_id(app)
    r = client.get(f"/file/{fid}/backup")
    assert r.status_code == 200 and r.mimetype == "application/zip"
    zf = zipfile.ZipFile(io.BytesIO(r.data))
    assert "manifest.json" in zf.namelist()
    assert all(b"INFO" not in zf.read(n) for n in zf.namelist() if n.endswith(".enc"))

    # offline restore with the CLI using the same key
    (tmp_path / "b.zip").write_bytes(r.data)
    key = (app.instance_path and open(os.path.join(app.instance_path, "dev_master.key")).read())
    env = {**os.environ, "LOGVAULT_MASTER_KEY": key}
    root = os.path.dirname(os.path.dirname(__file__))
    out = subprocess.run([sys.executable, "restore_backup.py", str(tmp_path / "b.zip"),
                          str(tmp_path / "out.log")], cwd=root, env=env, capture_output=True, text=True)
    assert out.returncode == 0, out.stderr
    assert (tmp_path / "out.log").read_bytes() == DATA


def test_delete_removes_everything(app, client, tmp_path):
    upload(client)
    fid = file_id(app)
    client.post(f"/file/{fid}/delete")
    assert not list((tmp_path / "bucket").rglob("*.enc"))
    assert b"Nothing archived yet" in client.get("/").data


def test_unknown_file_404(client):
    assert client.get("/file/nope").status_code == 404


def test_csrf_enforced_when_enabled(tmp_path):
    from logvault import create_app
    from logvault.storage import LocalStorage
    app = create_app({"TESTING": True, "WTF_CSRF_ENABLED": True, "DATABASE": str(tmp_path / "d.db"),
                      "STORAGE_OBJECT": LocalStorage(tmp_path / "b")})
    r = app.test_client().post("/upload", data={"logfile": (io.BytesIO(b"x"), "a.log")},
                               content_type="multipart/form-data")
    assert r.status_code == 400
