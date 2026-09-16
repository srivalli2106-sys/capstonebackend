# Architecture

This document describes the **current** implementation. Everything here is
verified against the source in `server/` and `protocol/`. If a claim in another
document contradicts this one, this is the source of truth.

The backend is a single FastAPI (ASGI) application that:

- serves an HTTP/JSON API for registration, proof-of-possession auth, and key-bundle exchange,
- hosts one WebSocket endpoint that relays opaque, end-to-end-encrypted message envelopes,
- stores identity/key material in MongoDB,
- uses Redis for auth challenges, token revocation, rate limiting, presence, and the offline queue,
- never runs the E2EE crypto at runtime.

---

## 1. High-level layout

```
capstonebackend/
├── server/                  Runtime application (imported by uvicorn)
│   ├── app.py               FastAPI wiring: middlewares, routes, lifespan, health
│   ├── config.py            Pydantic settings (env / .env), production validation
│   ├── request_id.py        X-Request-ID middleware + RequestContext ContextVar
│   ├── logging_config.py    Root logger setup (StreamHandler, context filter)
│   ├── exceptions.py        App error hierarchy + centralized handlers
│   ├── security.py          Security headers + AllowedHosts middleware
│   ├── db.py                MongoDB client lifecycle + unique indexes
│   ├── redis_client.py      Redis pool lifecycle (presence/queue/session helpers)
│   ├── jwt_auth.py          JWT create/verify (single source of truth)
│   ├── auth_service.py      PoP verification, /login, revocation, require_auth
│   ├── auth_store.py        Redis-backed challenges + revocation blacklist
│   ├── middleware.py        Compat re-exports + Redis sliding-window rate limits
│   ├── ws_auth.py           WebSocket first-frame auth + lifecycle guards
│   ├── ws_registry.py       Process-local WS budget + per-user takeover registry
│   ├── envelope.py          Message-envelope wire format (Phase 11)
│   ├── message_id.py        ULID-style message ids
│   ├── routes/
│   │   ├── auth.py          POST /auth/register|login|challenge|verify|logout
│   │   ├── keys.py          POST /keys/upload; GET /keys/bundle, /keys/prekeys
│   │   └── messages.py      WebSocket /ws relay endpoint
│   ├── services/            Business rules (no persistence logic)
│   │   ├── user_service.py      Registration validation
│   │   ├── key_service.py       Key-bundle upload / lookups / atomic OPK handoff
│   │   ├── message_service.py   Envelope validation, dedup, deliver-or-queue, flush
│   │   └── presence_service.py  Online/offline markers, keep-alive (degrade-by-design)
│   └── repositories/        Persistence mechanics (no business rules)
│       ├── protocols.py        Structural contracts implemented by the fakes in tests
│       ├── user_repository.py      Mongo: users
│       ├── key_repository.py       Mongo: key_bundles (+ atomic OPK consumption)
│       ├── message_repository.py   Redis: pending:{user_id} queue
│       └── presence_repository.py  Redis: online:{user_id}, conn:{user_id}
├── protocol/                E2EE reference implementation (X3DH + Double Ratchet).
│                            NEVER imported by the server runtime.
├── tests/                   pytest suite (unit + integration, infra-free unit env)
├── requirements.txt         Pinned runtime deps
├── requirements-dev.txt     Pinned test/lint deps
├── pyproject.toml           pytest / ruff / coverage configuration
├── Dockerfile, docker-compose.yml, .env.example, .github/workflows/ci.yml
└── docs/                    This documentation set
```

### Layering

```
HTTP/WS route  →  service  →  repository  →  driver (Mongo/Redis)
     │             │             │
     │             │             └─ repositories/* (persistence mechanics only)
     │             └─ services/*    (business rules, injected repos/fakes)
     └─ routes/*    (thin HTTP/WS adapter: parse, auth/rate-limit, call service)
```

- **Routes** are thin transport adapters. They parse/validate the wire input,
  apply auth + rate limiting, and delegate decisions to a service.
- **Services** own business rules and hold injected dependencies (defaulting to
  the module-level repository singletons) so unit tests can inject fakes.
- **Repositories** own only persistence mechanics (document shapes, atomic
  operations). They never encode policy.
- **Services never import MongoDB/Redis machinery directly**; they depend on
  the structural contracts in `server/repositories/protocols.py`.

---

## 2. Configuration (`server/config.py`)

`Settings(BaseSettings)` reads every value from environment variables and an
optional `.env` file (`case_sensitive=False`, unknown keys ignored).

Three environments (`APP_ENV`):

| Value        | Purpose                                    | Validation                          |
|--------------|--------------------------------------------|-------------------------------------|
| `development`| Local/permisive defaults                    | Algorithm + issuer always checked   |
| `test`       | Automated tests (module-level settings in tests are forced to `test`) | same |
| `production` | Fail-fast safe startup                      | See [ENVIRONMENT.md](ENVIRONMENT.md) #production-validation |

The complete variable list (33 variables, defaults, and validation rules) is in
[ENVIRONMENT.md](ENVIRONMENT.md).

---

## 3. Startup / lifespan (`server/app.py`)

`setup_logging()` runs at import time (idempotent). The `lifespan` runs on app
startup:

1. logs the app identity,
2. **pings MongoDB and fails fast** (`RuntimeError`) if it is unreachable
   (bounded by `MONGODB_SERVER_SELECTION_TIMEOUT_MS`),
3. `init_db()` creates the unique indexes (idempotent),
4. pings Redis; if unavailable it logs a warning and **keeps serving**
   (presence/queue/rate-limit degrade at runtime; they recover when Redis
   returns),
5. serves until shutdown,
6. on shutdown: closes every live WebSocket with `1001` first (so each
   connection's `finally` cleanup can run against Redis), waits 50 ms, then
   closes MongoDB and Redis clients, each failure logged independently.

### Middleware order

Registration order in `app.py` (Starlette semantics: **last registered runs
first**):

```
entering  →  SecurityHeaders → RequestID → CORS → AllowedHosts → router
```

| Position | Middleware | Responsibility |
|----------|------------|----------------|
| innermost | `AllowedHostsMiddleware` | Validates the `Host` header against `ALLOWED_HOSTS` (`*` disables; WebSocket handshakes included) |
| next      | `CORSMiddleware`          | CORS from `CORS_ORIGINS` |
| next      | `RequestIDMiddleware`     | Normalizes incoming `X-Request-ID`, stamps `X-Request-ID` on responses, logs one completion record per request, drives the `request_id` ContextVar |
| outermost | `SecurityHeadersMiddleware` | Adds `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy` always; HSTS only when `SECURE_TRANSPORT=true` |

Security headers and request IDs are applied even to host-rejected and CORS
responses by design.

### Error handling (`server/exceptions.py`)

Every error renders one JSON contract:

```json
{ "error": { "code": "...", "message": "...", "request_id": "..." } }
```

| Handler | Input | Output |
|---------|-------|--------|
| `ApplicationError` | `InvalidRequest` / `ResourceNotFound` / `Forbidden` / `Conflict` / `DependencyUnavailable` | its mapped status + `code` |
| `HTTPException` (FastAPI + Starlette) | JWT 401s, rate-limit 429s, route 404/405 | `http_<status>` + detail message |
| `RequestValidationError` | Pydantic 422s | `validation_error` |
| `PyMongoError` / `RedisError` | driver failures | `503 dependency_unavailable` (stable, no driver detail) |
| `Exception` / 500 | unexpected | `500 internal_error` (traced in logs, generic body) |

Error bodies never include tracebacks, driver details, header values, or env
secrets.

---

## 4. Request flows

### 4.1 HTTP registration

```
Client                 Route (routes/auth.py)       Service/repo          MongoDB
  │  POST /auth/register {user_id, ik_public}        │                      │
  │ ─────────────────────► check_rate_limit("register")                      │
  │                      │ user_service.register(user_id, ik_public)         │
  │                      │        └─ UserRepository.register_user() ◄──────append (unique user_id)
  │                      │  DuplicateKeyError ─► 409 conflict                 │
  │ ◄────────────────────    201 {"status":"registered","user_id":...}       │
```

### 4.2 Proof-of-possession auth (production path)

```
Client                        Route                              Service/store         Redis
  │  POST /auth/challenge {user_id}                                │                   │
  │ ─────────────────────► rate-limit; user exists?                │                   │
  │                      │ auth_service.create_challenge ◄── SET auth_challenge:{user_id}=nonce (TTL)
  │  (sign nonce with the device's Ed25519 private key)            │                   │
  │  POST /auth/verify {user_id, nonce, signature}                 │                   │
  │ ─────────────────────► rate-limit                              │                   │
  │                      │ verify_credentials ── GETDEL (atomic consume) ───►          │
  │                      │ verify Ed25519 sig against ik_public    │                   │
  │  ◄──────────────────── 200 {token (JWT)}
```

`/auth/login` (development/test only) issues a JWT for an existing user without
the PoP dance; the route returns **403 in production**.

### 4.3 Key-bundle exchange

```
Alice                 Server (routes/keys.py, services/key_service.py)     MongoDB
  │  POST /keys/upload {spk_public, spk_sig, opk_public}  (Auth: JWT)
  │ ─────────────────────► validate hex/32-byte; user exists?
  │                      │ KeyRepository.upsert_key_bundle() ─► upsert (version bump)
  │  GET /keys/bundle/{bob}  (Auth: JWT)
  │ ─────────────────────► read bundle; read user (for ik_public)
  │                      │ consume_opk()  ─► find_one_and_update (atomic, BEFORE doc)
  │  ◄──────────────────── {user_id, ik_public, spk_public, spk_sig, opk_public, version}
  │                          (exactly one concurrent fetch receives the OPK)
```

### 4.4 WebSocket message relay

See [WEBSOCKET.md](WEBSOCKET.md) for the full lifecycle; an envelope flowing
Alice → Bob:

```
Alice ──(WS /ws)──► routes/messages.py
                       │ verify_ws_token (JWT + revocation, fail closed)
                       │ receive_ws_event_with_idle_timeout
                       │ message_service.handle_message(sender, raw)
                       │   ├─ bound by MAX_WS_MESSAGE_CHARS (65 536)
                       │   ├─ normalize_envelope → server-authoritative envelope
                       │   ├─ dedup (sender, id) 300 s
                       │   └─ recipient online? ──► ws_registry.registry.get(bob)
                       │        yes ──► forward envelope JSON on Bob's live socket
                       │        no  ──► Redis LPUSH pending:{bob} (queue)
Bob   ◄───────────────── (on connect: flush_pending LPOPs queue in order)
```

---

## 5. Storage model

### MongoDB (`server/db.py`, `repositories/`)
- `users` — `{user_id (unique index), ik_public (32 bytes Ed25519 public), created_at}`
- `key_bundles` — `{user_id (unique index), spk_public, spk_sig, opk_public | null, version, uploaded_at}`
- One shared async client/pool (`AsyncIOMotorClient`) with bounds from settings.
- Messages are **not** stored in MongoDB.

### Redis (`server/redis_client.py`, `repositories/`)
- `auth_challenge:{user_id}` — PoP nonce, TTL-bounded, single-use (GETDEL/Lua)
- `auth_revoked:{jti}` — token blacklist, TTL bounded by remaining token life
- `ratelimit:{category}:{identity}` — sorted-set sliding window via `middleware.py`
- `online:{user_id}` — presence marker (TTL `WS_PRESENCE_TTL_SECONDS`)
- `conn:{user_id}` — current connection id marker
- `pending:{user_id}` — FIFO offline queue (opaque envelope JSON strings)
- `session:{token_id}` — low-level helper keys, no current caller

See [DATABASE.md](DATABASE.md) for the details.

---

## 6. Distinct responsibilities (don't mix these up)

| Concern | Where it lives | Failure behavior |
|---------|----------------|------------------|
| HTTP auth (Bearer JWT) | `auth_service.require_auth` | Fail closed |
| WebSocket auth | `ws_auth.verify_ws_token` (first-frame) | Fail closed (4001) |
| Cryptographic peer identity | Ed25519 `ik_public` + SPK signature → verified by the *client* via `protocol/keys.py` helper | Client-side, out of scope here |
| Application message routing | `message_service` (deliver/queue/flush) | Degrades, never lies about queueing |
| E2EE protocol | `protocol/` reference package | Not run by the server |

---

## 7. The `protocol/` boundary

`protocol/` is a pure-Python **reference implementation** of the E2EE layer
(X3DH + Double Ratchet) that the backend relays. It is a unit-test target and a
specification companion to [E2EE.md](E2EE.md). It is **never imported by the
server runtime or built into the Docker image** (the Dockerfile copies only
`server/`). It is not an audited crypto library.

```
Device (client)                    Server                    Device (client)
  encrypt(data) ──► envelope.data ──► relay ──► envelope.data ──► decrypt(data)
  (protocol/)      (opaque)         (never      (opaque)         (protocol/)
                                    decrypts)
```

---

## 8. Health / readiness

| Endpoint | Type | Response |
|----------|------|----------|
| `GET /health` | Liveness | `200 {"status":"ok"}` (process up) |
| `GET /health/ready` | Readiness | `200 {"status":"ready"}` when Mongo **and** Redis reachable, else `503 {"status":"unavailable"}`. Deliberately leaks no infrastructure detail. |

The Docker image's built-in `HEALTHCHECK` uses `/health`. Orchestrators/Render
health checks should use `/health` or `/health/ready` (see
[DEPLOYMENT.md](DEPLOYMENT.md)).