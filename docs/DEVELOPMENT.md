# Development Setup

Complete guide for a new developer to run this backend locally.

All commands in this repository are written for **PowerShell on Windows** (the
place the project is developed). POSIX shells use the same commands with the
venv on `PATH` (`.venv/bin/activate`) and forward slashes.

---

## 1. Prerequisites

| Tool | Version | Notes |
|------|---------|-------|
| Python | **3.10+**; CI and the Docker image use 3.11 | On Windows use the `py` launcher: `py -3.11` |
| MongoDB | 7.x local, or MongoDB Atlas (free tier) | Optional for pure unit tests |
| Redis | 7.x | Optional for pure unit tests; required for auth + presence + offline queue |
| (Optional) Docker | current | For the one-command local stack |

You do **not** need MongoDB/Redis to run the unit tests (they are infra-free).

---

## 2. Clone and create the virtual environment

```powershell
git clone <repository-url> capstonebackend
cd capstonebackend

py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
```

The prompt should now show `(.venv)`.

## 3. Install dependencies

```powershell
pip install -r requirements.txt        # runtime dependencies (pinned)
pip install -r requirements-dev.txt    # pytest, ruff, httpx, pytest-cov (pinned)
```

## 4. Configure the environment

```powershell
Copy-Item .env.example .env
```

Then edit `.env`. For a **pure unit-test workflow** (no Mongo/Redis) you can
leave the defaults — tests force `APP_ENV=test` and never touch the
databases.

To exercise the full API (registration, auth, keys, WebSocket) you need real
MongoDB and Redis (see next section) and a working `.env`:

```powershell
APP_ENV=development
MONGODB_URI=mongodb://localhost:27017/secure_messaging
MONGODB_DB=secure_messaging
REDIS_URL=redis://localhost:6379/0
JWT_SECRET=any-local-development-secret
```

Every supported variable, default, and validation rule is documented in
[ENVIRONMENT.md](ENVIRONMENT.md).

## 5. Run MongoDB and Redis safely

The repository ships a disposable local stack (`docker-compose.yml`) for
**development only**. To start just the infrastructure (and run the backend
with `uvicorn` so you can see server logs):

```powershell
docker compose up -d mongodb redis
```

The compose services use explicit **throwaway credentials** (see
`docker-compose.yml`). Configure your `.env` to match:

```powershell
MONGODB_URI=mongodb://backend:backend_dev_pw@localhost:27017/secure_messaging?authSource=admin
REDIS_URL=redis://:redis_dev_pw@localhost:6379/0
```

Or run the whole stack (backend included) with:

```powershell
docker compose up --build
# open http://localhost:8000/docs ; tear down (deletes the data volume):
docker compose down -v
```

> Never point local development at the production MongoDB/Redis. See
> [DATABASE.md](DATABASE.md) and [CONTRIBUTING.md](CONTRIBUTING.md).

## 6. Start the backend

```powershell
python -m uvicorn server.app:app --host 0.0.0.0 --port 8000
```

- API base URL: `http://localhost:8000`
- Interactive docs: `http://localhost:8000/docs` (Swagger UI)
- Liveness: `GET http://localhost:8000/health` → `{"status":"ok"}`
- Readiness: `GET http://localhost:8000/health/ready` → `{"status":"ready"}`

Startup fails fast if MongoDB is unreachable. Redis being down is only a
warning: auth and queue features degrade until it returns.

### Development login

In `APP_ENV=development` (or `test`) you can obtain a JWT without running the
full proof-of-possession dance:

```powershell
# register once
curl.exe -X POST http://localhost:8000/auth/register -H "Content-Type: application/json" `
    -d '{"user_id":"alice","ik_public":"<64 hex chars>"}'

# dev login
curl.exe -X POST http://localhost:8000/auth/login -H "Content-Type: application/json" `
    -d '{"user_id":"alice"}'
# → {"token":"<JWT>","user_id":"alice"}
```

`POST /auth/login` returns **403 in production**; production clients must use
`/auth/challenge` + `/auth/verify` (see [AUTHENTICATION.md](AUTHENTICATION.md)).

## 7. Run the tests

Unit tests need **no infrastructure** (test env uses fakes; the app lifespan is
intentionally not run in the unit `TestClient`).

```powershell
# Unit + protocol tests (everything except integration)
pytest -m "not integration"

# Coverage for the whole project (server + protocol)
pytest -m "not integration" --cov=server --cov=protocol --cov-report=term-missing:skip-covered
```

Integration tests require live MongoDB + Redis **and** opt-in:

```powershell
$env:RUN_INTEGRATION="1"
pytest -m integration
```

See [TESTING.md](TESTING.md) for the full testing model.

## 8. Lint

```powershell
ruff check server tests protocol
```

Configuration lives in `pyproject.toml` (line length 88; rules E, F, W, I, UP, B).

---

## Troubleshooting quick hits

| Symptom | Fix |
|---------|-----|
| `'uvicorn' is not recognized` | Use `python -m uvicorn ...` or activate the venv |
| `MongoDB unavailable at startup` | Start MongoDB / check `MONGODB_URI` (see [TROUBLESHOOTING.md](TROUBLESHOOTING.md)) |
| Integration tests skip | They require `RUN_INTEGRATION=1` + Mongo + Redis |
| `JWT_SECRET must ... be ... in production` | You set `APP_ENV=production`; use development locally |

More failure modes in [TROUBLESHOOTING.md](TROUBLESHOOTING.md).