# Backend Structure

## Directory layout

```
capstonebackend/
├── server/
│   ├── app.py              FastAPI app, middleware stack, lifespan, /health
│   ├── config.py           Pydantic Settings, env parsing, production checks
│   ├── middleware.py       rate limiter (sliding window) + auth re-exports
│   ├── exceptions.py       error hierarchy + centralized handlers
│   ├── request_id.py       X-Request-ID middleware + context accessor
│   ├── security.py         AllowedHosts + SecurityHeaders middleware
│   ├── logging_config.py   structured logging setup
│   ├── db.py               Mongo client, ping, index init
│   ├── redis_client.py     Redis client, ping
│   ├── jwt_auth.py         JWT create/verify (HS256, issuer pin, jti)
│   ├── auth_service.py     PoP verify, dev login, revoke, require_auth
│   ├── auth_store.py       Redis challenge + revocation helpers
│   ├── envelope.py         envelope wire format + validation
│   ├── message_id.py       ULID-style message id generator/validator
│   ├── ws_auth.py          first-frame auth, close codes, WS rate gates
│   ├── ws_registry.py      per-process connection registry + budget
│   ├── routes/
│   │   ├── auth.py         /auth/*
│   │   ├── keys.py         /keys/*
│   │   └── messages.py     /ws relay endpoint
│   ├── services/
│   │   ├── user_service.py     registration rules
│   │   ├── key_service.py      bundle rules + OPK consumption policy
│   │   ├── presence_service.py online/conn markers + keep-alive
│   │   └── message_service.py  deliver/queue/flush decisions
│   ├── repositories/
│   │   ├── protocols.py        repository interfaces (injectable)
│   │   ├── user_repository.py  users: MongoDB
│   │   ├── key_repository.py   key_bundles: MongoDB (atomic OPK consume)
│   │   ├── message_repository.py  offline queue: Redis
│   │   └── presence_repository.py presence: Redis
├── protocol/               (top-level package, sibling of server/)
│   ├── keys.py             X3DH/SPK/OPK key model, SPK signing context
│   ├── x3dh.py             X3DH computation, byte-compatible with the frontend
│   ├── kdf.py              HKDF wrappers
│   ├── ratchet.py          Double Ratchet (symmetric sender/responder)
│   └── session.py          E2EE session state (init/accept/export)
├── tests/                  pytest suite (unit + integration)
├── requirements.txt        pinned runtime deps
├── requirements-dev.txt    pinned dev/test deps
├── pyproject.toml          pytest/lint configuration
├── Dockerfile              production image (single process)
├── docker-compose.yml      disposable local stack (mongo/redis/backend)
└── .env.example            documented environment template
```

## Request lifecycle

1. `uvicorn server.app:app` starts; lifespan pings MongoDB (fail fast), runs
   `init_db()` index creation, pings Redis (warning only).
2. Request enters `AllowedHostsMiddleware` -> `CORSMiddleware` ->
   `RequestIDMiddleware` -> `SecurityHeadersMiddleware`.
3. Route handlers call `check_rate_limit(request, category)` then delegate to
   services; services use repositories for persistence.
4. Errors bubble to `install_exception_handlers(app)` which renders the
   unified error contract. Every response gets `X-Request-ID`.

## Key module rules

- `config.py` is the only place environment is read. `settings` is a module
  singleton.
- `jwt_auth.py` holds no storage; `auth_service.require_auth` is the
  authenticated dependency (verification + revocation, fail closed).
- `key_service.upload` validates hex/sizes and upserts the bundle;
  `key_service.get_bundle` returns the peer's bundle and atomically consumes
  one OPK via `key_repository.consume_opk`.
- `message_service` never inspects payloads: it validates envelopes,
  deduplicates, checks presence, forwards or queues, and flushes on connect.
- The WebSocket route (`routes/messages.py`) is a thin adapter: frame I/O,
  budget reservation, auth handshake, and cleanup all happen there; decisions
  live in services.

## Middleware order note

Security-header and request-ID middleware are registered OUTSIDE
AllowedHosts, so even host-rejected and CORS-preflight responses receive the
headers and a request ID.

## Persistence

- MongoDB: `users` (unique `user_id`, `ik_public` bytes, `created_at`) and
  `key_bundles` (unique `user_id`, X25519/SPK/OPK publics, `version`,
  `uploaded_at`). Indexes are created in `init_db()`.
- Redis key prefixes: `ratelimit:{category}:{identity}`,
  `auth_challenge:{user_id}`, `auth_revoked:{jti}`, `online:{user_id}`,
  `conn:{user_id}`, `pending:{user_id}`.

## Configuration snapshot

See `ENVIRONMENT.md` for the full variable table and production validation
rules enforced by `Settings._check_production`.