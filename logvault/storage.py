"""Storage backends: private Cloudflare R2 (S3 API via boto3) or a local folder."""
from __future__ import annotations

from pathlib import Path


class LocalStorage:
    """Folder on disk that behaves like a bucket - for development and tests."""

    def __init__(self, root: str | Path):
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)

    def _path(self, key: str) -> Path:
        path = (self.root / key).resolve()
        if self.root.resolve() not in path.parents:
            raise ValueError("invalid key")
        return path

    def put(self, key: str, data: bytes) -> None:
        path = self._path(key)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)

    def get(self, key: str) -> bytes:
        return self._path(key).read_bytes()

    def delete_prefix(self, prefix: str) -> None:
        import shutil

        path = self._path(prefix.rstrip("/"))
        if path.exists():
            shutil.rmtree(path)


class R2Storage:
    """Private bucket accessed through the S3-compatible API. No ACLs are ever set."""

    def __init__(self, client, bucket: str):
        self.client = client
        self.bucket = bucket

    def put(self, key: str, data: bytes) -> None:
        self.client.put_object(Bucket=self.bucket, Key=key, Body=data)

    def get(self, key: str) -> bytes:
        return self.client.get_object(Bucket=self.bucket, Key=key)["Body"].read()

    def delete_prefix(self, prefix: str) -> None:
        paginator = self.client.get_paginator("list_objects_v2")
        for page in paginator.paginate(Bucket=self.bucket, Prefix=prefix):
            objs = [{"Key": o["Key"]} for o in page.get("Contents", [])]
            if objs:
                self.client.delete_objects(Bucket=self.bucket, Delete={"Objects": objs})


def make_storage(app):
    backend = app.config["STORAGE_BACKEND"]
    if backend == "local":
        return LocalStorage(app.config["LOCAL_STORAGE_DIR"])
    if backend == "r2":
        import boto3
        from botocore.config import Config

        cfg = app.config
        missing = [k for k in ("R2_ACCESS_KEY_ID", "R2_SECRET_ACCESS_KEY", "R2_BUCKET") if not cfg.get(k)]
        endpoint = cfg.get("S3_ENDPOINT_URL") or (
            f"https://{cfg['R2_ACCOUNT_ID']}.r2.cloudflarestorage.com" if cfg.get("R2_ACCOUNT_ID") else None
        )
        if not endpoint:
            missing.append("R2_ACCOUNT_ID")
        if missing:
            raise RuntimeError("Missing R2 settings: " + ", ".join(missing))
        client = boto3.client(
            "s3",
            endpoint_url=endpoint,
            aws_access_key_id=cfg["R2_ACCESS_KEY_ID"],
            aws_secret_access_key=cfg["R2_SECRET_ACCESS_KEY"],
            region_name="auto",
            config=Config(signature_version="s3v4", retries={"max_attempts": 3}),
        )
        return R2Storage(client, cfg["R2_BUCKET"])
    raise RuntimeError(f"Unknown STORAGE_BACKEND: {backend}")
