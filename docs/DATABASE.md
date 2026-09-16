# Database

How the backend uses MongoDB and Redis, and how to run them safely for
development and production.

> ## NEVER run development tests against production MongoDB.
>
> Unit tests never touch any database (fakes are injected). Integration tests
> require `RUN_INTEGRATION=1` and should always point at a **local** or
> dedicated **dev** database — never the production cluster.

---

## 1. MongoDB

### 1.1 What is stored

| Collection | Document shape | Purpose |
|------------|----------------|---------|
| `users` | `{user_id, ik_public, created_at}` | One-time registration. `ik_public` is the 32-byte Ed25519 public identity key (stored as raw bytes; hex-string on the wire). |
| `key_bundles` | `{user_id, spk_public, spk_sig, opk_public \| null, version, uploaded_at}` | Signed-prekey + one-time-prekey material for E2EE. `opk_public` is **nulled after consumption**; `version` increments on every upload. |

Messages are **not** stored in MongoDB. The offline queue lives in Redis
(`pending:{user_id}`).

### 1.2 Indexes

Created idempotently at startup by `init_db()` in `server/db.py`:

- `users` — unique index on `user_id`
- `key_bundles` — unique index on `user_id`

These unique indexes are what make registration and key-bundle upserts
single-owner (no read-then-write race):

- `UserRepository.register_user` inserts; a `DuplicateKeyError` → `409 Like
  conflict` (returned as `Conflict("...already registered.")`).
- `KeyRepository.upsert_key_bundle` does an `update_one` when the bundle exists
  (bumping `version`), else `insert_one` with `version: 1`.

### 1.3 Connection lifecycle (`server/db.py`)

- One shared `AsyncIOMotorClient` per process, lazily created by `get_db()`.
- Pool/behavioral bounds come from settings (`MONGODB_*`): app name,
  server-selection/connect/socket timeouts, min/max pool, max idle time.
- `ping_mongo()` issues a `db.command("ping")` bounded by the server-selection
  timeout.
- Startup: `lifespan` pings Mongo then calls `init_db()`; an unreachable Mongo
  at startup raises `RuntimeError` and the app **fails fast**.
- Shutdown: `close_db()` closes the client (each dependency is closed
  independently, errors logged but never swallowed).

### 1.4 Atomic OPK consumption

`GET /keys/bundle/{user_id}` hands out a one-time prekey exactly once:

```
consume_opk(user_id):
  find_one_and_update(
    {user_id, opk_public: {"$exists": True, "$ne": None}},
    {"$set": {opk_public: None}},
    return_document=BEFORE)              # returns the pre-consumption document
```

MongoDB serializes the update per document, so **concurrent consumers can
never receive the same OPK**; the winning caller receives the consumed value in
the response, everyone else sees `None`.

### 1.5 MongoDB Atlas / production

- Use Atlas (or an equivalent managed service), or a self-hosted MongoDB with
  `--auth` enabled, bound to a private network — never exposed publicly.
- Use a dedicated least-privilege user per environment; different credentials
  per env.
- Enable encryption at rest (key bundles are identity-critical) and continuous
  backups with a tested restore.
- Only the connection string and database name are configured (`MONGODB_URI`,
  `MONGODB_DB`).
- Development seed data: there is none; integration tests create their own data
  and rely on the unique indexes.

---

## 2. Redis

### 2.1 What is stored

| Key | Type | Purpose |
|-----|------|---------|
| `auth_challenge:{user_id}` | string | PoP nonce; short TTL (`AUTH_CHALLENGE_TTL_SECONDS`), single-use (atomic GETDEL/Lua) |
| `auth_revoked:{jti}` | string | Token blacklist; TTL bounded by remaining token lifetime |
| `ratelimit:{category}:{identity}` | sorted set | Sliding-window rate limits (register/login/challenge/verify/logout/keys/general/ws_connect/ws_message) |
| `online:{user_id}` | string | Presence marker, TTL `WS_PRESENCE_TTL_SECONDS`, refreshed every half-life while connected |
| `conn:{user_id}` | string | Current connection id marker (drives takeover + last-connection cleanup) |
| `pending:{user_id}` | list | FIFO offline queue of opaque envelope JSON strings |
| `session:{token_id}` | string | Low-level helper; **no current caller** |

### 2.2 Connection lifecycle (`server/redis_client.py`)

- One shared `redis.asyncio` client/pool, lazily created by `get_redis()`
  (`decode_responses=True`, bounds from `REDIS_*` settings).
- Startup: Redis is **optional at boot** — a failed `ping_redis()` logs a
  warning and the app keeps serving (features degrade at runtime and recover).
- Shutdown: `close_redis()` closes the pool.

### 2.3 Failure behavior by feature (deliberate)

| Feature | On Redis failure |
|---------|------------------|
| Auth challenge / revocation / `require_auth` | **Fail closed** — error propagates as `503 dependency_unavailable`; a token is never accepted when revocation can't be checked |
| WebSocket connect/message rate gates | **Degrade open** — logs a warning and allows |
| Presence markers (`online:`, `conn:`) | **Degrade** — treated as offline/cleared; connections still work |
| Offline queue | Never claims a message was queued if the write failed (logs `NOT queued`) |
| Rate limiter (HTTP) | Fails closed (429 handling requires Redis) → 503 |

### 2.4 Development / production

- Development: `docker compose up -d redis` (throwaway password `redis_dev_pw`
  — dev only), or a local Redis. Configure `REDIS_URL` in `.env`.
- Production: set a strong `requirepass` in `REDIS_URL`
  (`redis://:password@host:6379/0`), bind to the private network, enable
  encryption-in-transit on managed Redis, enable `appendonly` if offline
  messages must survive a restart (otherwise a Redis flush simply means
  "everyone appears offline", recovered naturally).
- Redis data is ephemeral by design (TTLs on everything).

---

## 3. Safe-use rules

- Unit tests: no database needed (fakes; `APP_ENV=test`).
- Integration tests: local/dev database only, opt-in via `RUN_INTEGRATION=1`.
- Manual API testing: a local MongoDB + Redis (compose or native).
- Production: managed/self-hosted hardened instances, least-privilege users,
  encryption, backups. See [DEPLOYMENT.md](DEPLOYMENT.md).