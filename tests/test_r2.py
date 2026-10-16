"""R2 code path tested against a fake S3 (moto) - no real credentials needed."""
import io

import boto3
import pytest
from moto import mock_aws

from logvault import create_app
from logvault.storage import R2Storage

DATA = b"error: disk full\n" * 300


@pytest.fixture
def r2_app(tmp_path):
    with mock_aws():
        client = boto3.client("s3", region_name="us-east-1",
                              aws_access_key_id="x", aws_secret_access_key="x")
        client.create_bucket(Bucket="logvault-test")
        app = create_app({"TESTING": True, "WTF_CSRF_ENABLED": False,
                          "DATABASE": str(tmp_path / "r.db"), "BLOCK_SIZE": 1024,
                          "STORAGE_OBJECT": R2Storage(client, "logvault-test")})
        app.fake_s3 = client
        yield app


def test_full_cycle_through_s3_api(r2_app):
    c = r2_app.test_client()
    c.post("/upload", data={"logfile": (io.BytesIO(DATA), "x.log")}, content_type="multipart/form-data")
    keys = [o["Key"] for o in r2_app.fake_s3.list_objects_v2(Bucket="logvault-test")["Contents"]]
    assert any(k.endswith("manifest.json") for k in keys) and sum(k.endswith(".enc") for k in keys) == 5
    with r2_app.app_context():
        from logvault.db import get_db
        fid = get_db().execute("SELECT id FROM files").fetchone()["id"]
    assert c.get(f"/file/{fid}/restore").data == DATA
    c.post(f"/file/{fid}/delete")
    assert "Contents" not in r2_app.fake_s3.list_objects_v2(Bucket="logvault-test")


def test_objects_are_not_public(r2_app):
    c = r2_app.test_client()
    c.post("/upload", data={"logfile": (io.BytesIO(DATA), "x.log")}, content_type="multipart/form-data")
    key = r2_app.fake_s3.list_objects_v2(Bucket="logvault-test")["Contents"][0]["Key"]
    grants = r2_app.fake_s3.get_object_acl(Bucket="logvault-test", Key=key)["Grants"]
    assert all("URI" not in g["Grantee"] for g in grants)  # no AllUsers / AuthenticatedUsers


def test_r2_config_requires_settings(tmp_path):
    with pytest.raises(RuntimeError, match="Missing R2 settings"):
        create_app({"TESTING": True, "STORAGE_BACKEND": "r2", "R2_BUCKET": None,
                    "R2_ACCESS_KEY_ID": None, "R2_SECRET_ACCESS_KEY": None,
                    "DATABASE": str(tmp_path / "x.db")})
