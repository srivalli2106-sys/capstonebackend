# Environment

## Frontend variables (capstonefrontend)

Everything prefixed `VITE_` is inlined into the client bundle by Vite and is
therefore PUBLIC. Never place secrets in these variables.

| Variable | Required | Default | Behavior |
| --- | --- | --- | --- |
| `VITE_API_BASE_URL` | Yes | none | HTTP(S) base URL of the backend REST API. Missing value throws at app start. |
| `VITE_WS_BASE_URL` | No | derived | WebSocket base URL. When omitted it is derived: `https://` -> `wss://`, `http://` -> `ws://` from the API base URL. |

The WebSocket endpoint is `${wsBaseUrl}/ws`. Deriving it from the API base URL
matters in production: without it, a relative `/ws` would resolve against the
Vercel origin and 404. See `src/config/env.ts`.

Production value used in this project:

```
VITE_API_BASE_URL=https://secure-messaging-backend-g7v0.onrender.com
# VITE_WS_BASE_URL=wss://secure-messaging-backend-g7v0.onrender.com   (derived)
```

## Backend variables (capstonebackend)

All configuration lives in `server/config.py` (Pydantic Settings) and is read
from environment variables, optionally from a local `.env` file.

### Application

| Variable | Default | Notes |
| --- | --- | --- |
| `APP_ENV` | `development` | One of `development`, `test`, `production`. Production enables fail-fast secret validation. |
| `DEBUG` | `false` | Debug logging/behavior. |
| `HOST` | `0.0.0.0` | Bind address. |
| `PORT` | `8000` | HTTP port. |
| `LOG_LEVEL` | `INFO` | `DEBUG \| INFO \| WARNING \| ERROR`. |

### MongoDB

| Variable | Default | Notes |
| --- | --- | --- |
| `MONGODB_URI` | `mongodb://localhost:27017` | Atlas or local connection string. Production must be a real value (placeholder marker `USERNAME:PASSWORD` is rejected). |
| `MONGODB_DB` | `secure_messaging` | Database name. |
| `MONGODB_SERVER_SELECTION_TIMEOUT_MS` | `5000` | Startup connectivity bound. |
| `MONGODB_CONNECT_TIMEOUT_MS` | `10000` | Connection timeout. |
| `MONGODB_SOCKET_TIMEOUT_MS` | unset | Optional per-socket timeout. |
| `MONGODB_MAX_POOL_SIZE` | `50` | Connection pool upper bound. |
| `MONGODB_MIN_POOL_SIZE` | `0` | Pool lower bound. |
| `MONGODB_MAX_IDLE_TIME_MS` | `300000` | Max idle time per connection. |

### Redis

| Variable | Default | Notes |
| --- | --- | --- |
| `REDIS_URL` | `redis://localhost:6379/0` | Used for rate limits, challenges, revocation, presence, offline queue. |
| `REDIS_MAX_CONNECTIONS` | `10` | Pool cap (single reused client). |
| `REDIS_SOCKET_CONNECT_TIMEOUT` | `3` | Seconds. |
| `REDIS_SOCKET_TIMEOUT` | `5` | Seconds. |
| `REDIS_HEALTH_CHECK_INTERVAL` | `30` | Seconds. |

### JWT

| Variable | Default | Notes |
| --- | --- | --- |
| `JWT_SECRET` | dev placeholder | MUST be a strong random value in production; known placeholders are rejected (`change-me-in-production-please`, `dev-only-change-me`, `change-me-to-a-long-random-string`), and length must be >= 16. |
| `JWT_ALGORITHM` | `HS256` | One of `HS256`, `HS384`, `HS512`; anything else is rejected in every environment. |
| `JWT_EXPIRY_HOURS` | `24` | Token lifetime. |
| `JWT_ISSUER` | `secure-messaging-api` | Claim in issued tokens and enforced on verification; must not be empty. |

### Proof of possession

| Variable | Default | Notes |
| --- | --- | --- |
| `AUTH_CHALLENGE_TTL_SECONDS` | `120` | Lifetime of a challenge nonce (min 5). |

### WebSocket

| Variable | Default | Notes |
| --- | --- | --- |
| `WS_AUTH_TIMEOUT_SECONDS` | `10` | Seconds to complete the first-frame auth handshake before close 4001. |
| `WS_MAX_CONNECTIONS` | `1000` | Per-process concurrent connection budget (reserved pre-auth). |
| `WS_MAX_CONNECTIONS_PER_IP` | `20` | Per-IP concurrent cap; `0` disables. |
| `WS_IDLE_TIMEOUT_SECONDS` | `180` | Silent connection close (4008); `0` disables. |
| `WS_KEEPALIVE_SECONDS` | `30` | Interval between server pings; must be below the idle timeout. |
| `WS_PRESENCE_TTL_SECONDS` | `300` | Lifetime of `online:` / `conn:` markers (refreshed every half-life). |
| `WS_CONNECT_RATE_PER_MINUTE` | `60` | Connect attempts per IP per minute. |
| `WS_MESSAGE_RATE_PER_MINUTE` | `120` | Inbound frames per user per minute. |

### CORS and transport security

| Variable | Default | Notes |
| --- | --- | --- |
| `CORS_ORIGINS` | unset (=> `*`) | Comma-separated origins. Explicit empty = no browser origins. Production rejects `*`. |
| `ALLOWED_HOSTS` | `*` | Comma-separated acceptable `Host` header values; `*` disables validation. Production rejects `*`. |
| `SECURE_TRANSPORT` | `false` | Must be `true` in production; gates the HSTS header (never sent over plaintext HTTP). |

## Production validation

With `APP_ENV=production`, startup raises a `ValueError` (fail fast) if any of
these hold:

- `JWT_SECRET` missing, shorter than 16 chars, or a known placeholder.
- `MONGODB_URI` contains the `USERNAME:PASSWORD` placeholder.
- `CORS_ORIGINS` resolves to `*`.
- `ALLOWED_HOSTS` resolves to `*`.
- `SECURE_TRANSPORT` is false.
- `JWT_ALGORITHM` is not in `{HS256, HS384, HS512}` or `JWT_ISSUER` is empty
  (this check applies in every environment).