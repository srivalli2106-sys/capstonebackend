# 🔐 Secure Messaging App

**End-to-end encrypted messaging backend (FastAPI).**

Everything (messages, keys, files) is encrypted **on the device** before it
ever reaches the server. The server only relays opaque encrypted blobs — it
can never read the message contents.

> ⚠️ This is a learning / demo project. The client-facing crypto (`client/`) is
> **not yet implemented**; `protocol/` is a reference implementation of the
> messaging crypto (X3DH + Double Ratchet) that will drive it. Do not use this
> to protect real, sensitive messages until the full protocol is built and
> audited.

---

## ✨ What this does at a glance

```
Alice's phone                Server (can't read anything)              Bob's phone
      │                              │                                     │
      │  1. Register once            │                                     │
      │  (sends public key)          │                                     │
      │ ────────────────────────────►│                                     │
      │                              │                                     │
      │  2. Alice wants to chat Bob  │                                     │
      │  asks server for Bob's keys  │                                     │
      │ ────────────────────────────►│◄────────────────────────────────────│
      │                              │                                     │
      │  3. Alice & Bob do a secret  │                                     │
      │     key exchange (X3DH)      │                                     │
      │                              │                                     │
      │  4. Alice encrypts message   │                                     │
      │  🔒 "hello bob" → gibberish  │                                     │
      │ ────────────────────────────►│═══════════════►────────────────────►│
      │                              │  (relays gibberish)                 │
      │                              │                                     │  5. Bob decrypts
      │                              │                                     │  🔓 gibberish → "hello bob"
```

---

## 🗂️ Folder structure

```
capstonebackend/
│
├── server/                  ← The backend
│   ├── app.py               ← Entry point; wires routes, CORS, lifespan
│   ├── config.py            ← Centralized configuration (env / .env, validated)
│   ├── db.py                ← MongoDB (users + key bundles)
│   ├── middleware.py        ← JWT auth + rate limiting
│   ├── redis_client.py      ← Online status + offline message queue
│   └── routes/
│       ├── auth.py          ← One-time registration + login
│       ├── keys.py          ← Key bundle upload / fetch / one-time key
│       └── messages.py      ← WebSocket relay for encrypted messages
│
├── protocol/                ← E2EE reference implementation (X3DH + Double Ratchet)
├── tests/                   ← pytest suite (unit + integration)
├── docs/DEPLOYMENT.md       ← production deployment & operations guide
├── docs/E2EE.md             ← end-to-end encryption protocol spec
├── docs/PROTOCOL.md         ← message envelope & wire protocol spec
├── .github/workflows/       ← CI (ruff, unit tests, integration tests, Docker build)
├── Dockerfile               ← production image (non-root, no secrets baked in)
├── docker-compose.yml       ← disposable local dev stack (backend + Mongo + Redis)
├── requirements.txt         ← Runtime dependencies (pinned)
├── requirements-dev.txt     ← Test/lint dependencies (pinned)
├── pyproject.toml           ← Test & lint configuration
├── .env.example             ← Template for environment variables
└── README.md
```

---

## API endpoints (as implemented)

| Method | Path                          | Auth | Description                                   |
|--------|-------------------------------|------|-----------------------------------------------|
| GET    | `/health`                     | —    | Liveness probe → `{"status": "ok"}`           |
| GET    | `/health/ready`               | —    | Readiness probe → `200 {"status":"ready"}` / `503 {"status":"unavailable"}` |
| POST   | `/auth/register`              | —    | One-time registration (user_id + identity key)|
| POST   | `/auth/login`                 | —    | Returns a JWT for authenticated requests      |
| POST   | `/keys/upload`                | JWT  | Upload signed prekey + one-time prekey        |
| GET    | `/keys/bundle/{user_id}`      | JWT  | Fetch a user's key bundle (consumes OPK)      |
| GET    | `/keys/prekeys/{user_id}`     | JWT  | OPK availability status                       |
| WS     | `/ws`                        | JWT  | Real-time envelope relay (first-frame `{"type":"auth","token":"..."}`, then `{"id","type","recipient","data"}`); idle timeout, keepalive pings, per-IP cap |

Interactive docs: **http://localhost:8000/docs** (Swagger UI).

> 📦 **Wire protocol:** the message envelope, ULID message ids, the message-type
> catalog, and delivery/replay semantics are specified in
> **[docs/PROTOCOL.md](docs/PROTOCOL.md)**. The end-to-end crypto (X3DH +
> Double Ratchet) is specified in **[docs/E2EE.md](docs/E2EE.md)**.
>
> 🔒 The `protocol/` package is the E2EE reference implementation used to pin
> the crypto behavior; the server binary does not link it.

---

## 🛠️ Prerequisites

| Tool | Why | Notes |
|------|-----|-------|
| **Python 3.10+** | Runs the backend | On Windows use the `py` launcher (`py -3.11`), or add Python to PATH |
| **MongoDB Atlas** | Cloud database for users & keys | Free tier is fine |
| **Redis** | Online status + offline queue | Optional locally; required for offline messaging |

---

## 🚀 Setup & run

### 1. Create and activate the virtual environment

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
```

### 2. Install dependencies

```powershell
pip install -r requirements.txt
```

(For development/tests, also `pip install -r requirements-dev.txt`.)

### 3. Configure the environment

Copy `.env.example` to `.env` and fill in real values, **or** export the
variables directly:

```powershell
$env:MONGODB_URI="mongodb+srv://USERNAME:PASSWORD@cluster0.xxxxx.mongodb.net"
$env:MONGODB_DB="secure_messaging"
```

> 🔑 Keep credentials in `.env` (git-ignored), never in source code.

| Variable             | Default | Purpose |
|----------------------|---------|---------|
| `APP_ENV`            | `development` | `development` \| `test` \| `production` |
| `DEBUG`              | `false` | Debug behavior |
| `HOST`, `PORT`       | `0.0.0.0`, `8000` | Bind address |
| `LOG_LEVEL`          | `INFO` | Python logging level |
| `MONGODB_URI`        | `mongodb://localhost:27017` | MongoDB connection string |
| `MONGODB_DB`         | `secure_messaging` | Database name |
| `REDIS_URL`          | `redis://localhost:6379/0` | Redis connection URL |
| `JWT_SECRET`         | `change-me-in-production-please` | JWT signing secret |
| `JWT_ALGORITHM`      | `HS256` | JWT signing algorithm |
| `JWT_EXPIRY_HOURS`   | `24` | Token lifetime in hours |
| `CORS_ORIGINS`       | `*` | Comma-separated allowed origins |

**Production validation:** when `APP_ENV=production`, the app refuses unsafe
config — placeholder/short `JWT_SECRET`, placeholder Mongo URIs
(`mongodb+srv://USERNAME:PASSWORD@…`), and CORS wildcard `*`.

### 4. Start the server

```powershell
python -m uvicorn server.app:app --host 0.0.0.0 --port 8000
```

Then open http://localhost:8000/docs to try the API.

### Optional: run the full local stack with Docker

```powershell
docker compose up --build
# open http://localhost:8000/docs ; shut down with:
docker compose down -v   # -v also deletes the throwaway Mongo data volume
```

> The compose stack uses explicit **throwaway local credentials** (see
> `docker-compose.yml`) and is for development only — never for production.

---

## 📦 Deploying

See **[docs/DEPLOYMENT.md](docs/DEPLOYMENT.md)** — a provider-neutral guide to
production configuration, the Docker image, health checks (liveness vs.
readiness), reverse-proxy/TLS requirements, MongoDB & Redis security, backups,
secrets management, scaling, and rollback.

---

## 🧪 Running the tests

Tests are split into **unit** (no infrastructure) and **integration**
(needs real MongoDB + Redis).

```powershell
# Unit tests — no MongoDB/Redis required
pytest -m "not integration"

# Integration tests — requires RUN_INTEGRATION=1 and running MongoDB + Redis
$env:RUN_INTEGRATION="1"
pytest -m integration
```

Integration tests cover the one-time registration flow, login, key-bundle
upload/fetch with OPK consumption, and the WebSocket relay (online relay +
offline queueing). GitHub Actions CI (`.github/workflows/ci.yml`) runs the
full suite — including integration tests — against disposable MongoDB and
Redis service containers on every push/PR.

Lint with:

```powershell
ruff check server tests protocol
```

---

## 🔒 Security model

| Property | How it's achieved |
|----------|-------------------|
| **One-time registration** | Unique index on `user_id` — cannot re-register or impersonate |
| **End-to-end encryption** | Messages encrypted before leaving the device (client planned; protocol reference in `protocol/`) |
| **Forward secrecy** | Double Ratchet — fresh key per message (client planned) |
| **Per-session keys** | Fresh X3DH key exchange per session (client planned) |
| **Identity verification** | X3DH with signed prekeys bound to the registered Ed25519 identity (client planned; verification helper in `protocol/keys.py`) |
| **Message integrity** | Tampering fails AEAD decryption (client planned) |

All of the above rely on a client implementation; the server's part is already
in place (key-bundle exchange incl. `ik_public`, single-use OPK consumption on
fetch, and opaque relay of the ciphertext).

The server-side guarantees implemented **today**: JWT auth on protected
routes, per-IP rate limiting (one-time registration, login, keys), opaque
relay of message blobs, and strict config validation for production.

---

## 🛣️ Roadmap — backend hardening

- [x] **Phase 1** — Centralized configuration + project foundation
- [x] **Phase 2** — Automated test suite + CI + docs
- [x] **Phase 8** — Service + repository layers (Phase 3–8)
- [x] **Phase 9** — Comprehensive testing & verification
- [x] **Phase 10** — Docker / CI-CD / production config / deployment
- [x] **Phase 11** — Message ids, envelope, message types, protocol doc
- [x] **Phase 12** — WS operational hardening: idle timeout, keepalive pings,
  per-IP connection cap
- [x] **Phase 13** — E2EE protocol reference: X3DH + Double Ratchet specified
  (`docs/E2EE.md`) and implemented in the `protocol/` package, with the server
  exposing `ik_public` on key bundles so peers can verify signed prekeys

---

## 🛠️ Common errors & fixes

| Error | Cause | Fix |
|-------|-------|-----|
| `'uvicorn' is not recognized` | uvicorn not on PATH | Use `python -m uvicorn ...` instead |
| `ServerSelectionTimeoutError` | Can't reach Mongo | Check `MONGODB_URI` / password / internet |
| `409 Conflict` on register | Username already taken | Pick a different `user_id` |
| `Missing bearer token` on `/keys/*` | Not authorized | Paste your login token in the 🔒 Authorize button |
| `ValueError: JWT_SECRET must ...` | Production config unsafe | Set a strong `JWT_SECRET`, real Mongo URI, and specific CORS origins |

---

Made with ❤️ for secure, private communication.