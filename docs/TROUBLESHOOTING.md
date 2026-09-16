# Troubleshooting

Symptom → cause → fix. Cross-references: [ENVIRONMENT.md](ENVIRONMENT.md),
[DEVELOPMENT.md](DEVELOPMENT.md), [DATABASE.md](DATABASE.md),
[AUTHENTICATION.md](AUTHENTICATION.md), [WEBSOCKET.md](WEBSOCKET.md),
[DEPLOYMENT.md](DEPLOYMENT.md).

## Boot / configuration

| # | Symptom | Cause | Verify | Resolve |
|---|---------|-------|--------|---------|
| 1 | App **boot-loops** on Render / production | `APP_ENV=production` fail-fast validation raised at import | Render logs: `ValueError` message (placeholder JWT/Mongo URI, `CORS_ORIGINS=*`, `ALLOWED_HOSTS=*`, `SECURE_TRANSPORT` off) | Fix the offending variable (see [ENVIRONMENT.md](ENVIRONMENT.md) §Production fail-fast) and redeploy |
| 2 | `RuntimeError: MongoDB unavailable` at startup | Mongo unreachable, or `MONGODB_URI`/`MONGODB_DB` wrong | `mongosh`, or check `MONGODB_SERVER_SELECTION_TIMEOUT_MS` / Atlas whitelist | Start Mongo / fix URI / whitelist Render egress IPs ([DATABASE.md](DATABASE.md), [DEPLOYMENT.md](DEPLOYMENT.md)) |
| 3 | Only a Redis warning at startup | Redis down locally | ping Redis; `REDIS_URL` password/quotes | Redis is optional at boot; auth/queue degrade until it returns ([DATABASE.md](DATABASE.md) §2.3) |
| 4 | `JWT_SECRET must be at least 16 characters` etc. | Local `.env` left at placeholder / n/a | `env`/`.env` | Set a real `JWT_SECRET`; use `APP_ENV=development` locally |
| 5 | Wrong `ALLOWED_HOSTS` on Render | Host header ≠ configured value | Response `400  Invalid host`; Render URL / custom domain | Set `ALLOWED_HOSTS` to the exact public host (CNAME included) |

## HTTP API

| # | Symptom | Cause | Verify | Resolve |
|---|---------|-------|--------|---------|
| 6 | `409 ... already registered` | `user_id` already in `users` (unique index) | Find doc in Mongo | Choose a new id; or contact ops (no delete API — cleanup is direct DB work) |
| 7 | Registration `422` | Wrong hex length / `ik_public` not 64 hex chars | Request body | Send exactly 64 lowercase/uppercase hex chars |
| 8 | `POST /auth/login` returns `403` | You're in `APP_ENV=production` (dev login is disabled) | Check `APP_ENV` | Use `/auth/challenge` + `/auth/verify` with a real Ed25519 signature ([AUTHENTICATION.md](AUTHENTICATION.md)) |
| 9 | `/challenge`, `/verify`, logout, keys → `401 Authentication failed` | Generic identity failure (unknown user, bad signature, consumed/expired nonce, revoked token) | Check client signature + nonce reuse | All reasons map to the same 401 by design; re-run the flow with a fresh challenge |
| 10 | `503 dependency_unavailable` on protected routes | Redis down during `require_auth` revocation check (fail-closed) | Redis ping | Restart Redis; connection recovers. It fails closed **on purpose** ([DATABASE.md](DATABASE.md) §2.3) |
| 11 | `429 Too Many Requests` | Register/login/keys/etc. rate limited (< 60/min per IP default) | Response `Retry-After` | Back off; check rate-limiter keys in Redis |
| 12 | `GET /keys/bundle/{user_id}` returns `None` `opk_public` | OPK already consumed by an earlier fetch (single-use) | Mongo document `opk_public: null` | The OPK was already handed out **once**; re-upload a fresh bundle or inspect what the previous caller received |
| 13 | Fetching your own bundle | You're looking up a user without a bundle / bundle with null OPK | Document state | 404 only if `user_id` unknown to Mongo entirely |

## WebSocket

| # | Symptom | Cause | Verify | Resolve |
|---|---------|-------|--------|---------|
| 14 | `1001` on connect/disconnect | Server shut down (deploy/restart) | Render logs "Server shutting down" | Reconnect with exponential backoff after the deploy window |
| 15 | `1013` | Global budget, per-IP cap, or connect rate limit exceeded | Count connected sockets / flush keys | Retry later; raise `WS_MAX_CONNECTIONS*` / rate setting only if justified |
| 16 | `4001` auth failed | Bad token, expired, revoked, auth frame slow (> `WS_AUTH_TIMEOUT_SECONDS`) or non-first | Check frame order/format; JWT validity | Send `{"type":"auth","token":"<JWT>"}` as the **first frame**; re-login |
| 17 | `4000` replacement | Second connection for same user took over | Server closed code 4000 | Another device logged in — stop; reconnect only after it signs out |
| 18 | `4008` idle timeout | No application frame within `WS_IDLE_TIMEOUT_SECONDS` | Wire captured silence | Clients should send keepalives or expect reconnect; server pings do not extend toward apps that already go quiet |
| 19 | Messages dropped, socket stays open | Rate limit (120/min default) or malformed envelope | Server logs; `/auth/verify` offline-queue path | Send fewer frames; fix the envelope (see [PROTOCOL.md](PROTOCOL.md)) |
| 20 | Receiver gets envelope but duplicate deliveries | Same `(sender, id)` sent twice within 300 s | Dedup window (in-process) | Keep the same `id` only for genuine retries; never reuse an `id` for a new message |
| 21 | Offline message "lost" | `NOT queued` in logs = Redis write failed during queue | Server logs | Message was never accepted; client must retry with the same `id` ([WEBSOCKET.md](WEBSOCKET.md) §6) |
| 22 | Online status wrong / still shows online | Presence markers TTL-based (last refreshed by the owning connection) | Redis keys `online:`/`conn:` | Markers expire after `WS_PRESENCE_TTL_SECONDS`; reconnects refresh them |
| 23 | Can't reach `/ws` | Client tried `ws://` over TLS / wrong path | URL | Use `wss://` and the exact `/ws` route |

## Tests

| # | Symptom | Cause | Verify | Resolve |
|---|---------|-------|--------|---------|
| 24 | Integration tests "skipped" | `RUN_INTEGRATION=1` not set, or no Mongo/Redis | pytest output shows `SKIPPED` | Set `$env:RUN_INTEGRATION="1"` and point them at local/dev DBs ([TESTING.md](TESTING.md)) |
| 25 | Unit `TestClient` fails with lifespan errors | You imported the app from a non-test context, or lifespan side-effects | `APP_ENV` value | `tests/conftest.py` forces `APP_ENV=test`; unit tests don't run lifespan by design |
| 26 | WebSocket tests flake against real infra | Rate-limit settings differ between the unit-test env and the integration fixtures | `tests/integration/conftest.py` neutralizes rate limits; run with `-m integration` against local/dev DBs ([TESTING.md](TESTING.md)) | Only run websocket integration tests with `RUN_INTEGRATION=1` and local DBs |

## Deployment

| # | Symptom | Cause | Verify | Resolve |
|---|---------|-------|--------|---------|
| 27 | Health check unhealthy loop | Wrong port; `HOST`/`PORT` override broke Render's routing | Logs on boot; Render internal port | Use Render's `$PORT`; don't hardcode 8000 ([DEPLOYMENT.md](DEPLOYMENT.md)) |
| 28 | `/health` ok but `/health/ready` 503 | Mongo or Redis unreachable **from the Render service** | Atlas IP whitelist; Redis endpoint | Fix connectivity; readiness is **intentionally** dependency-aware |
| 29 | Stuck "deploying" | Build failed on `pip install` (network) or Docker build step | Build tab | Retry; use native Python deploy path to avoid Docker builds ([DEPLOYMENT.md](DEPLOYMENT.md)) |
| 30 | Set a variable but behavior didn't change | `.env` overrides environment values on some hosts / Render cached | Config echo | Render redeploys; secret changes require a new deploy; confirm with `/health/ready` after rotate |

## Misc

| # | Symptom | Cause | Verify | Resolve |
|---|---------|-------|--------|---------|
| 31 | `503` on *every* rate-limited route | Redis down (rate limiter fails closed) | `ping_redis` | Restart Redis; not a config issue (see #10) |
| 32 | Logs show wrong client IP | `--proxy-headers` not enabled | Logs; `X-Forwarded-For` | Run uvicorn with `--proxy-headers` (Dockerfile already does) |
| 33 | Security headers missing | `SECURE_TRANSPORT=false` disables HSTS | `curl` headers | Set `SECURE_TRANSPORT=true` in prod — HSTS is intentionally only sent over TLS |
| 34 | `JWT_EXPIRY_HOURS` mismatch across devices | Old tokens still valid until `exp` | `jti`/`exp` decode | Wait, or revoke via logout; secret rotation invalidates immediately (see [DEPLOYMENT.md](DEPLOYMENT.md) §9) |

---

If an entry above doesn't match, open with the request ID from the response
header (`X-Request-ID`) and the logs around that timestamp.