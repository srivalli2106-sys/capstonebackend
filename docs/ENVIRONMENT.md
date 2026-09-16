# Environment Variables

The authoritative list. Every variable is read by `server/config.py`
(`Settings(BaseSettings)`) from the process environment and/or a `.env` file in
the repository root. Values are case-insensitive names, `.env` keys are
case-insensitive, and unknown keys are ignored.

Three files/layers exist:

| File/place | Purpose | Committed? |
|------------|---------|------------|
| `.env.example` | Safe template of every variable with defaults/examples. Never contains real credentials. | Yes |
| `.env` | Your local configuration (real local values). git-ignored. | No |
| Render "Environment" panel | Production secrets injected at runtime. **Do not** store these in the repo. | No |

> Never commit real secrets. Generate a real JWT secret with
> `python -c "import secrets; print(secrets.token_urlsafe(48))"`.

---

## Application

| Variable | Req. | Purpose | Default | Validation |
|----------|------|---------|---------|------------|
| `APP_ENV` | — | Environment: `development` \| `test` \| `production` | `development` | Must be one of the three; `production` triggers fail-fast validation (below) |
| `DEBUG` | — | Debug behavior flag | `false` | Bool |
| `HOST` | — | Bind address | `0.0.0.0` | — |
| `PORT` | — | Bind port | `8000` | Int |
| `LOG_LEVEL` | — | Python logging level (`DEBUG|INFO|WARNING|ERROR`) | `INFO` | Uppercased by `setup_logging()` |

## MongoDB

| Variable | Req. | Purpose | Default | Validation |
|----------|------|---------|---------|------------|
| `MONGODB_URI` | prod | Connection string | `mongodb://localhost:27017` | Production rejects the `USERNAME:PASSWORD` placeholder marker |
| `MONGODB_DB` | prod | Database name | `secure_messaging` | — |
| `MONGODB_SERVER_SELECTION_TIMEOUT_MS` | — | Server selection timeout | `5000` | `>= 100` |
| `MONGODB_CONNECT_TIMEOUT_MS` | — | Connect timeout | `10000` | `>= 100` |
| `MONGODB_SOCKET_TIMEOUT_MS` | — | Socket timeout; unset = driver default | `None` | `>= 100` or unset |
| `MONGODB_MAX_POOL_SIZE` | — | Connection pool max | `50` | `>= 1` |
| `MONGODB_MIN_POOL_SIZE` | — | Connection pool min | `0` | `>= 0` |
| `MONGODB_MAX_IDLE_TIME_MS` | — | Max idle connection lifetime | `300000` | `>= 0` |

## Redis

| Variable | Req. | Purpose | Default | Validation |
|----------|------|---------|---------|------------|
| `REDIS_URL` | prod | Connection URL (`redis://:password@host:6379/0` when auth is on) | `redis://localhost:6379/0` | — |
| `REDIS_MAX_CONNECTIONS` | — | Client pool size | `10` | `>= 1` |
| `REDIS_SOCKET_CONNECT_TIMEOUT` | — | Connect timeout (seconds) | `3.0` | `>= 0` |
| `REDIS_SOCKET_TIMEOUT` | — | Socket timeout (seconds) | `5.0` | `>= 0` |
| `REDIS_HEALTH_CHECK_INTERVAL` | — | Pool health-check interval | `30` | `>= 1` |

## JWT

| Variable | Req. | Purpose | Default | Validation |
|----------|------|---------|---------|------------|
| `JWT_SECRET` | prod | HMAC signing/verification secret | `change-me-in-production-please` | Production: non-empty, `>= 16` chars, not a known placeholder |
| `JWT_ALGORITHM` | — | Signing algorithm | `HS256` | Must be `HS256`, `HS384`, or `HS512` (in every environment) |
| `JWT_EXPIRY_HOURS` | — | Token lifetime | `24` | Int |
| `JWT_ISSUER` | — | Issuer claim, validated on verify | `secure-messaging-api` | Must be non-empty |

## Authentication (proof of possession)

| Variable | Req. | Purpose | Default | Validation |
|----------|------|---------|---------|------------|
| `AUTH_CHALLENGE_TTL_SECONDS` | — | Lifetime of a challenge nonce | `120` | `>= 5` |

## WebSocket

| Variable | Req. | Purpose | Default | Validation |
|----------|------|---------|---------|------------|
| `WS_AUTH_TIMEOUT_SECONDS` | — | Seconds to send the first (auth) frame | `10.0` | `>= 1` |
| `WS_MAX_CONNECTIONS` | — | Hard per-process connection budget | `1000` | `>= 1` |
| `WS_MAX_CONNECTIONS_PER_IP` | — | Per-IP cap (0 disables) | `20` | `>= 0` |
| `WS_IDLE_TIMEOUT_SECONDS` | — | Max silence after auth before close `4008` (0 disables) | `180.0` | `>= 0` |
| `WS_KEEPALIVE_SECONDS` | — | Server ping interval; must be < idle timeout (0 disables) | `30.0` | `>= 0` |
| `WS_PRESENCE_TTL_SECONDS` | — | Lifetime of `online:`/`conn:` Redis markers | `300` | `>= 30` |
| `WS_CONNECT_RATE_PER_MINUTE` | — | WS connect rate limit (sliding window) | `60` | `>= 1` |
| `WS_MESSAGE_RATE_PER_MINUTE` | — | WS message rate limit per user | `120` | `>= 1` |

## Security / transport / CORS

| Variable | Req. | Purpose | Default | Validation |
|----------|------|---------|---------|------------|
| `CORS_ORIGINS` | prod | Comma-separated allowed origins | `*` | Production rejects a bare `*` |
| `ALLOWED_HOSTS` | prod | Comma-separated allowed `Host` headers; `*` disables enforcement | `*` | Production rejects a bare `*` |
| `SECURE_TRANSPORT` | prod | True when served over TLS (HTTPS/WSS); gates the HSTS header | `false` | Production requires `true` |

---

## Production fail-fast validation

When `APP_ENV=production`, `Settings._check_production()` **refuses to start**
unless all of the following hold:

- `JWT_SECRET` is set, at least 16 characters, and **not** one of:
  - `change-me-in-production-please`
  - `dev-only-change-me`
  - `change-me-to-a-long-random-string`
- `MONGODB_URI` does **not** contain `USERNAME:PASSWORD` (the `.env.example`
  placeholder)
- `CORS_ORIGINS` is a specific list, not `*`
- `ALLOWED_HOSTS` is a specific list, not `*`
- `SECURE_TRANSPORT=true`

Example safe production values (also see [DEPLOYMENT.md](DEPLOYMENT.md)):

```
APP_ENV=production
SECURE_TRANSPORT=true
ALLOWED_HOSTS=secure-messaging.onrender.com
CORS_ORIGINS=https://your-client.example.com
JWT_SECRET=<generated>
```

Failures raise `ValueError` at import time; the process logs the message and
exits — an incorrectly configured deployment never serves traffic.

## Local example (`.env.example`)

`.env.example` shows defaults and inline guidance for every variable above and
is safe to use as a starting point. Copy it to `.env` and adjust `MONGODB_URI`,
`REDIS_URL`, and `JWT_SECRET` for your local services (see
[DEVELOPMENT.md](DEVELOPMENT.md)).