# LogVault

Encrypted cloud log archive & integrity audit system (college mini-project).

Upload `.log` / `.txt` files → split into **1 MB blocks** → encrypt each block with **AES-256-GCM** (unique nonce) → store in a **private Cloudflare R2 bucket** → download an encrypted backup, restore, and **verify with SHA-256**.

Built with Flask, SQLite, boto3 and `cryptography`. No login system, no Redis.

> Based on [simple-flask-s3-uploader](https://github.com/jelmerdejong/simple-flask-s3-uploader) by Jelmer de Jong (MIT). Original license notice kept in `LICENSE`.

## Features

| # | Feature | Where |
|---|---------|-------|
| 1 | Upload `.log`/`.txt`, split in 1 MB blocks | `logvault/crypto.py`, `service.py` |
| 2 | AES-256-GCM, random 96-bit nonce per block, per-file key via HKDF | `crypto.py` |
| 3 | Blocks + manifest in private R2 bucket (S3 API, no ACLs) | `storage.py` |
| 4 | Download encrypted backup (.zip) and restore (online or offline) | `views.py`, `restore_backup.py` |
| 5 | SHA-256 check after restore, PASS/FAIL shown | `service.py` |
| 6 | Upload history + verification status (SQLite) | `db.py`, `templates/` |
| 7 | Documentation site for Cloudflare Pages | `docs-site/` |

## Quick start (no cloud account needed)

```bash
cp .env.example .env          # STORAGE_BACKEND=local is the default
docker compose up --build
# open http://localhost:8000
```

Without Docker:

```bash
python -m venv .venv && source .venv/bin/activate    # Windows: .venv\Scripts\activate
pip install -r requirements-dev.txt
python app.py                                         # http://127.0.0.1:5000
```

In local mode a folder (`instance/local_bucket`) acts as the bucket and a dev key is auto-created in `instance/dev_master.key` (git-ignored).

### Docker commands

```bash
docker compose up --build -d     # build and start
docker compose logs -f           # watch logs
docker compose down              # stop
docker compose down -v           # stop AND delete history/local data
```

## Demo flow (for presentation)

1. Upload a log file → see "N encrypted blocks stored".
2. Open it → **Verify integrity** → green **Verified**.
3. **Download encrypted backup** → open the zip: only `.enc` files (unreadable).
4. **Restore original file** → file downloads, SHA-256 matches.
5. **Demo: corrupt a block** → **Verify** → red **FAILED**; Restore is blocked. (Shows GCM catches tampering.)
6. Offline restore of the zip: `python restore_backup.py my.log.logvault-backup.zip restored.log`

## Cloudflare R2 setup

1. Cloudflare dashboard → **R2 Object Storage** → *Create bucket* (e.g. `logvault-archive`). Keep **public access disabled** (no `r2.dev` URL, no custom domain).
2. **Manage R2 API Tokens** → create token with *Object Read & Write*, scoped to this bucket. Copy Account ID, Access Key ID, Secret Access Key.
3. Generate an encryption key: `python generate_key.py`
4. Edit `.env`:
   ```
   STORAGE_BACKEND=r2
   SECRET_KEY=<long random string>
   LOGVAULT_MASTER_KEY=<key from step 3>
   R2_ACCOUNT_ID=...
   R2_ACCESS_KEY_ID=...
   R2_SECRET_ACCESS_KEY=...
   R2_BUCKET=logvault-archive
   ```
5. `docker compose up --build` and upload a file. Check the bucket: you'll see `files/<id>/blocks/*.enc` and `manifest.json`.

**Back up your `LOGVAULT_MASTER_KEY`.** Without it the data cannot be decrypted. Never commit `.env`.

## Deploy the documentation site (Cloudflare Pages)

The site is static HTML in `docs-site/`, no build step.

- **Dashboard:** Workers & Pages → Create → Pages → Connect to Git → pick the repo → Framework: *None*, Build command: *(empty)*, Output directory: `docs-site`.
- **CLI:** `npx wrangler pages deploy docs-site --project-name logvault-docs`

You get `https://<project>.pages.dev` with **HTTPS** and global **CDN** delivery automatically. Verify: `curl -I https://<project>.pages.dev` → look for `server: cloudflare`, `cf-ray`, and `cf-cache-status: HIT` on a repeat request.

## Tests

```bash
pip install -r requirements-dev.txt
pytest
```
Tests use a temp folder and a fake S3 (`moto`), so **no cloud credentials are needed**. They cover block splitting, nonce uniqueness, tamper detection, upload/restore/verify, backup zip + offline restore, CSRF, deletion, R2 code path, and that objects are not public.

## Cleanup

- Delete files from the app (file page → *Delete from storage*) or empty the bucket in the R2 dashboard.
- Delete the R2 bucket and revoke the API token.
- Delete the Cloudflare Pages project.
- `docker compose down -v` and `docker image rm logvault-logvault` (name may vary).
- Remove `.env` and `instance/` if you don't need them.

## Security notes

- No credentials or keys in code; everything from environment variables.
- Bucket is private; the app never sets ACLs (the old `public-read` setting was removed).
- Each block is bound to its file and position (GCM associated data), so swapping/reordering blocks is detected.
- Manifest (file name, size, SHA-256) is stored unencrypted; file contents are always encrypted.
- Simple by design: one key for the whole app (no per-user keys, no key rotation, no login). Put it behind a VPN/reverse proxy with auth if you deploy it for real.

## Project layout

```
app.py  generate_key.py  restore_backup.py
logvault/   __init__ config crypto storage service db views  templates/ static/
tests/      crypto, app (local backend), r2 (moto)
docs-site/  index.html style.css _headers   <- Cloudflare Pages
Dockerfile  docker-compose.yml  .env.example  .dockerignore
```
