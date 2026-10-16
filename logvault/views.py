from __future__ import annotations

from datetime import datetime, timezone
from pathlib import PurePath

from flask import (Blueprint, abort, current_app, flash, redirect, render_template,
                   request, send_file, url_for)
from werkzeug.utils import secure_filename

from . import service
from .db import get_db

bp = Blueprint("main", __name__)


def _storage():
    return current_app.extensions["storage"]


def _key():
    return current_app.extensions["master_key"]


def _get_file(file_id: str):
    row = get_db().execute("SELECT * FROM files WHERE id = ?", (file_id,)).fetchone()
    if row is None:
        abort(404)
    return row


def _set_status(file_id: str, status: str, detail: str) -> None:
    db = get_db()
    db.execute(
        "UPDATE files SET status=?, detail=?, last_checked=? WHERE id=?",
        (status, detail, datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S"), file_id),
    )
    db.commit()


def _human(n: int) -> str:
    size = float(n)
    for unit in ("B", "KB", "MB", "GB"):
        if size < 1024 or unit == "GB":
            return f"{int(size)} {unit}" if unit == "B" else f"{size:.1f} {unit}"
        size /= 1024


@bp.app_template_filter("human_size")
def human_size(n):
    return _human(n)


@bp.get("/")
def index():
    files = get_db().execute("SELECT * FROM files ORDER BY uploaded_at DESC, rowid DESC").fetchall()
    backend = current_app.config["STORAGE_BACKEND"]
    return render_template("index.html", files=files, backend=backend)


@bp.post("/upload")
def upload():
    f = request.files.get("logfile")
    if not f or not f.filename:
        flash("Please choose a .log or .txt file first.", "error")
        return redirect(url_for("main.index"))
    name = secure_filename(f.filename)
    ext = PurePath(name).suffix.lower().lstrip(".")
    if ext not in current_app.config["ALLOWED_EXTENSIONS"]:
        flash("Only .log and .txt files are allowed.", "error")
        return redirect(url_for("main.index"))
    if not name:
        name = "upload.log"

    try:
        m = service.archive_file(_storage(), _key(), f.stream, name, current_app.config["BLOCK_SIZE"])
    except Exception:
        current_app.logger.exception("upload failed")
        flash("Upload to storage failed. Check storage settings and try again.", "error")
        return redirect(url_for("main.index"))
    if m["block_count"] == 0:
        _storage().delete_prefix(f"files/{m['file_id']}/")
        flash("That file is empty, nothing to archive.", "error")
        return redirect(url_for("main.index"))

    db = get_db()
    db.execute(
        "INSERT INTO files (id, filename, size_bytes, block_count, sha256) VALUES (?,?,?,?,?)",
        (m["file_id"], m["filename"], m["size_bytes"], m["block_count"], m["sha256"]),
    )
    db.commit()
    flash(f"Archived {name}: {m['block_count']} encrypted block(s) stored.", "ok")
    return redirect(url_for("main.detail", file_id=m["file_id"]))


@bp.get("/file/<file_id>")
def detail(file_id):
    return render_template("detail.html", f=_get_file(file_id),
                           tamper_demo=current_app.config["ENABLE_TAMPER_DEMO"])


@bp.get("/file/<file_id>/backup")
def backup(file_id):
    rec = _get_file(file_id)
    try:
        data = service.build_backup_zip(_storage(), rec)
    except Exception:
        current_app.logger.exception("backup failed")
        flash("Could not read blocks from storage.", "error")
        return redirect(url_for("main.detail", file_id=file_id))
    return send_file(data, mimetype="application/zip", as_attachment=True,
                     download_name=f"{rec['filename']}.logvault-backup.zip")


@bp.post("/file/<file_id>/verify")
def verify(file_id):
    rec = _get_file(file_id)
    res = service.restore_file(_storage(), _key(), rec)
    if res.data:
        res.data.close()
    _set_status(file_id, "Verified" if res.ok else "FAILED", res.detail)
    flash(("PASS - " if res.ok else "FAIL - ") + res.detail, "ok" if res.ok else "error")
    return redirect(url_for("main.detail", file_id=file_id))


@bp.get("/file/<file_id>/restore")
def restore(file_id):
    rec = _get_file(file_id)
    res = service.restore_file(_storage(), _key(), rec)
    _set_status(file_id, "Verified" if res.ok else "FAILED", res.detail)
    if not res.ok:
        flash("Restore blocked - " + res.detail, "error")
        return redirect(url_for("main.detail", file_id=file_id))
    return send_file(res.data, mimetype="application/octet-stream", as_attachment=True,
                     download_name=rec["filename"])


@bp.post("/file/<file_id>/tamper")
def tamper(file_id):
    """Demo only: flips one byte in block 0 so you can show the integrity check failing."""
    if not current_app.config["ENABLE_TAMPER_DEMO"]:
        abort(404)
    rec = _get_file(file_id)
    key = service.block_key(file_id, 0)
    blob = bytearray(_storage().get(key))
    blob[-1] ^= 0x01
    _storage().put(key, bytes(blob))
    flash("Demo: block 0 was modified in storage. Now run Verify to see it get caught.", "error")
    return redirect(url_for("main.detail", file_id=rec["id"]))


@bp.post("/file/<file_id>/delete")
def delete(file_id):
    rec = _get_file(file_id)
    _storage().delete_prefix(f"files/{file_id}/")
    db = get_db()
    db.execute("DELETE FROM files WHERE id=?", (file_id,))
    db.commit()
    flash(f"Deleted {rec['filename']} from storage and history.", "ok")
    return redirect(url_for("main.index"))
