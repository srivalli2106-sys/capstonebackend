# Deployment Guide

Operational reference for running the Secure Messaging backend at production
quality. Everything here is provider-neutral: it holds whether you deploy on
bare metal, a VM, Kubernetes, or a PaaS, as long as the constraints below are
honoured.

---

## 1. Architecture

```
                    TLS (HTTPS / WSS)
   App / WS clients ──────────────►  Reverse proxy / TLS terminator
                                     (sets X-Forwarded-* headers,
                                      validates client certs or runs
                                      authentication offload if desired)
                                             │  HTTP/WS over internal network
                                             ▼
                                     FastAPI ASGI app  (uvicorn, 1 worker)
                                     ├── MongoDB   — users, key bundles, sessions
                                     └── Redis     — presence, offline queue,
                                                     rate limiting, WS auth (PoP)
```

Key properties:

- **Single application worker.** The WebSocket registry, presence counts and
  the rate-limit windows live in process memory. Running multiple workers
  without externalizing that state would fragment presence/queues and weaken
  rate limiting. Scale out later only after making that state shared
  (Phase 12 hardening), then scale horizontally behind sticky routing.
- **No static files, no job workers.** This is an API-only process.
- **TLS terminates at the reverse proxy.** The app itself does not speak TLS;
  it relies on `X-Forwarded-Proto` being trusted (see §5).

---

## 2. Environment variables

The authoritative list lives in `.env.example`. The non-negotiable production
settings are:

| Variable             | Production requirement |
|----------------------|------------------------|
| `APP_ENV`            | `production` (enables fail-fast config validation) |
| `MONGODB_URI`        | Real URI with credentials. Placeholder `mongodb+srv://USERNAME:PASSWORD@…` is rejected. |
| `MONGODB_DB`         | Real database name |
| `REDIS_URL`          | Real URL (with password when Redis auth is on) |
| `JWT_SECRET`         | Strong random ≥ 32 bytes. Placeholders/weak values are rejected. Generate: `python -c "import secrets; print(secrets.token_urlsafe(48))"` |
| `JWT_ALGORITHM`      | `HS256`, `HS384`, or `HS512` (anything else is rejected) |
| `JWT_ISSUER`         | Set deliberately; verified on every token |
| `CORS_ORIGINS`       | Explicit origin list (no `*`). Production rejects wildcard. Must exactly match the client origin(s), including scheme/port. |
| `ALLOWED_HOSTS`      | Explicit Host-header allow-list (the public hostname). `*` is rejected in production. |
| `SECURE_TRANSPORT`   | `true` — must be set when served over TLS; gates the HSTS header |
| `LOG_LEVEL`          | `INFO` or `WARNING` normally; `DEBUG` only while diagnosing |
| `AUTH_CHALLENGE_TTL_SECONDS` | Session lifetime / PoP challenge TTL |

Startup sanity checks (`server/config.py`, effective only in `production`):

- `JWT_SECRET` must not be a *known placeholder* and must be long/entropy-rich.
- `MONGODB_URI` must not still contain the `USERNAME:PASSWORD` marker.
- `ALLOWED_HOSTS` must not be `*` and must contain at least one host.
- `CORS_ORIGINS` must not be `*`.
- `SECURE_TRANSPORT` must be `true`.

If any check fails the app refuses to start — the container/process should be
restarted with corrected configuration, and monitors should alert.

## 3. Boot sequence

On startup the app, in order:

1. Pings MongoDB (bounded by `MONGODB_SERVER_SELECTION_TIMEOUT_MS`) — **fails
   fast** with `RuntimeError` if unreachable.
2. Builds/updates indexes (`init_db`): unique `user_id`, unique key-bundle
   `key_id`, message-session indexes, etc. This is the only "migration" step
   and it is idempotent — safe to run on every deploy.
3. Pings Redis; if Redis is down the app still serves but presence/offline
   queue/rate limiting degrade (a warning is logged). Health checks will show
   `not ready` until Redis returns.

On shutdown it closes live WebSockets (code `1001`) before closing DB/pool
resources so each handler's cleanup completes.

## 4. Deployment process

The suggested repeatable flow:

1. Build the image: `docker build -t secure-messaging-backend:<tag> .`
   (CI does this on every push; the Dockerfile has no embedded secrets and
   runs as an unprivileged user.)
2. Push the tagged image to your registry.
3. Release: start the new container, run the readiness probe, then (if you use
   blue/green or rolling) stop the old one.

Rollout order for a coordinated change (e.g. new DB indexes) is safe because
index creation is idempotent and happens before serving.

## 5. Health checks

| Endpoint       | Type      | Meaning | Expected |
|----------------|-----------|---------|----------|
| `GET /health`      | **Liveness**   | process is up and serving the ASGI app | `200 {"status":"ok"}` |
| `GET /health/ready` | **Readiness**  | all required infra (Mongo + Redis) reachable | `200 {"status":"ready"}` or `503 {"status":"unavailable"}` |

- Use `/health` for "restart the container" decisions.
- Use `/health/ready` for "send traffic / keep in the LB pool" decisions; it
  performs no details-leaking checks and returns a generic 503 body.
- The Dockerfile defines a built-in `HEALTHCHECK` using `/health`; override it
  with `/health/ready` at the orchestration layer if appropriate.

## 6. Reverse proxy / TLS requirements

- Terminate TLS with a modern configuration (TLS 1.2+ server minimum,
  HTTP→HTTPS redirect).
- Forward `X-Forwarded-For`, `X-Forwarded-Proto`, and `X-Forwarded-Host` and
  **strip these headers from untrusted inbound traffic** at the edge.
- The app enables `--proxy-headers`; by default uvicorn only trusts forwarded
  headers that arrive from `127.0.0.1`. If the proxy runs on another host,
  set `--forwarded-allow-ips` (uvicorn CLI/Docker `CMD` override) to the
  proxy's IP/CIDR. Client IPs are what the per-IP rate limiter uses — getting
  this right matters.
- Enforce realistic header size / timeout limits at the edge to protect the
  WebSocket handshake.
- Keep the app on the internal network and expose only the proxy publicly.

## 7. MongoDB security & backups

- Use **MongoDB Atlas** (or equivalent managed service) or a self-hosted MongoDB
  with authentication enabled; never bind a database publicly.
- Use a dedicated user with least privilege for this app; separate credentials
  per environment.
- The DB holds users, their public key bundles, and (opaque, E2E-encrypted)
  message/session metadata. **Encrypt at rest** (Atlas encryption / volume
  encryption) since key bundles are identity-critical.
- Enable backups: continuous/point-in-time for Atlas, or `mongodump` +
  oplog snapshots otherwise. Test a restore before you need it.
- For self-hosted: bind `127.0.0.1`/private network, enable `--auth`, keep
  MongoDB patched, restrict the firewall to the app hosts only.

## 8. Redis security

- Set a **strong `requirepass`** and put it in `REDIS_URL` as
  `redis://:password@host:6379/0`.
- Bind Redis to the private network only; never expose it to the internet.
- Data is ephemeral (presence markers, rate windows, offline queue with
  bounded TTL). Enable `appendonly` if you want offline messages to survive a
  restart; otherwise a flush is equivalent to "everyone appears offline" and
  is recovered naturally.
- Keep Redis patched; if using a managed Redis, enable encryption in transit.

## 9. Logging & observability

- Container logs go to **stdout** (`PYTHONUNBUFFERED=1` set in the image) —
  collect with any log shipper.
- Every request carries `X-Request-ID`; the same ID is attached to error JSON
  and structured log output, which makes correlating client reports with logs
  straightforward.
- Recommended alerts: process restart loops, readiness 503, JWT auth failure
  spikes, per-IP rate-limit hits, 5xx ratio.

## 10. Secrets management

- **Never** put secrets in the image, repo, compose files, or container env at
  build time. `.env` is git-ignored; `.dockerignore` excludes it.
- Inject secrets at runtime: Kubernetes Secrets / a secrets manager / an env
  file mounted read-only. All config is loaded from environment variables.
- Rotate `JWT_SECRET` by coordinated restart (all instances take the new
  value); existing tokens become invalid — schedule intentionally.
- Rotate MongoDB/Redis credentials: update `MONGODB_URI`/`REDIS_URL`, restart,
  verify readiness, then revoke the old credential.

## 11. Scaling

- **Today:** one app instance is the correct size (process-local WS state).
- WebSocket connections are long-lived; size the instance on open
  connections (`WS_MAX_CONNECTIONS=1000` cap is per-process) and on Redis ops.
- To scale horizontally later: externalize presence/registry/rate-limit state
  (Phase 12) and then run N instances behind sticky-load-balanced WSS.

## 12. Rollback

- Because deploys are immutable images, rollback = redeploy the previous
  tagged image (same env config). Runtime migrations are forward-compatible
  (idempotent index creation), so older images tolerate newer data.
- If a bad deploy changed schema irreversibly, restore from the §7 backups.

## 13. Local development stack (for reference)

`docker compose up --build` starts a disposable MongoDB + Redis + backend.
Throwing away any of this state is trivial: `docker compose down -v`. See
`docker-compose.yml` for the (intentionally throwaway) local credentials.