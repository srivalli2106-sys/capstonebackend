# Deployment (Render)

Authoritative guide to deploying the Secure Messaging backend to
**Render** as a native Python service. The repository also ships a Dockerfile;
Docker is **supporting infrastructure only** — Render's native Python
environment works without it.

> Read [ENVIRONMENT.md](ENVIRONMENT.md) for the complete variable reference and
> the production fail-fast rules before deploying.

---

## 1. Architecture and constraints

```
  App / WS clients ──HTTPS/WSS──► Render Web Service (uvicorn, 1 worker)
                                     ├── MongoDB Atlas   (users, key bundles)
                                     └── Redis (managed or self-hosted)
                                        (challenges, revocation, rate limits,
                                         presence, offline queue)
```

**Single worker today.** The WebSocket registry (budget, per-IP counts,
user→socket map) and the envelope dedup window are **process-local** (see
[WEBSOCKET.md](WEBSOCKET.md) §Current assumptions). Render web services run one
process per instance — that is correct for this app. Run **exactly one
instance** at `services = 1`; scaling horizontally requires externalizing that
state first.

TLS: uvicorn/Render terminate TLS at the proxy. The app reads
`X-Forwarded-*` (`uvicorn --proxy-headers` is in the Docker CMD / start
command) and uses that for client IPs in rate limiting. Render's proxy is
trusted for the forwarded headers as long as the app only listens on the
private port.

## 2. Render setup (Web Service)

1. Create a **Web Service** in Render, connect the repository and branch
   (`develop` or a release branch; see [CONTRIBUTING.md](CONTRIBUTING.md)).
2. Choose **Python** as the runtime/environment (native Python build), or
   **Docker** if you prefer to use the shipped `Dockerfile`. Native Python is
   the simplest: Render runs `pip install -r requirements.txt` for the build.
3. Set the environment variables from §4 (Render "Environment" panel). Never
   commit secrets.
4. Set the health check path (**§5**).
5. Deploy. Verify with the smoke checks in **§7**.

### Build / start commands

| Field | Native Python (recommended) | Docker |
|-------|------------------------------|--------|
| Build command | `pip install -r requirements.txt` | (Render uses the Dockerfile) |
| Start command | `uvicorn server.app:app --host 0.0.0.0 --port $PORT --proxy-headers` | `docker build` via Dockerfile (CMD already runs uvicorn with `--proxy-headers`) |

Use the Render-injected `$PORT` for the bind port. Do not set `HOST`/`PORT`
from the environment unless you know the Render port.

> `--proxy-headers` matters: client IPs used by the per-IP rate limiter come
> from forwarded headers. Render's proxy is local to the service, so the
> default trust (127.0.0.1) is fine.

## 3. MongoDB Atlas

- Create a cluster; a free M0 tier is fine for a demo.
- Create a dedicated database user with a strong password (least privilege;
  separate credentials per environment).
- Whitelist/allowlist access for the Render service IPs (Render egress IPs are
  shared — tighten with network-peering-only or Atlas IP access lists as needs
  require).
- Connection string:
  `mongodb+srv://<user>:<password>@<cluster>.mongodb.net/<dbname>?retryWrites=true&w=majority`
  → set as `MONGODB_URI`; set `MONGODB_DB` to the database name (default
  `secure_messaging`).
- Enable backups (Atlas continuous/PITR). Encryption at rest is on by default
  for Atlas.
- `init_db()` creates the two unique indexes at startup — no manual index
  setup or migration step needed; it is idempotent on every deploy.

## 4. Environment variables on Render

Set these in the Render **Environment** panel (as **secret** values):

```
APP_ENV=production
SECURE_TRANSPORT=true
ALLOWED_HOSTS=<your-app>.onrender.com
CORS_ORIGINS=https://<your-client-origin>   # or leave empty if no frontend yet
MONGODB_URI=mongodb+srv://<user>:<password>@<cluster>.mongodb.net/<db>?retryWrites=true&w=majority
MONGODB_DB=secure_messaging
REDIS_URL=redis://:<password>@<redis-host>:<port>/0
JWT_SECRET=<generated - python -c "import secrets; print(secrets.token_urlsafe(48))">
JWT_ALGORITHM=HS256
JWT_ISSUER=secure-messaging-api
LOG_LEVEL=INFO
```

Optional tuning (see [ENVIRONMENT.md](ENVIRONMENT.md)): `AUTH_CHALLENGE_TTL_SECONDS`,
`WS_*` limits, `MONGODB_*`/`REDIS_*` pool bounds, `JWT_EXPIRY_HOURS`.

Production fail-fast validation (`APP_ENV=production`) refuses to start with
placeholder JWT secrets, placeholder Mongo URIs, an explicit `CORS_ORIGINS=*`,
`ALLOWED_HOSTS=*`, or `SECURE_TRANSPORT` off. If the service crashes in a loop
at boot, that validation is the first thing to check (Render logs show the
`ValueError` message).

- **CORS**: set to the **exact** client origin(s) including scheme/port
  (e.g. `https://app.example.com`). If the deployment has no frontend yet,
  set `CORS_ORIGINS=` to an explicitly empty value — this resolves to a
  zero-length allow list (no browser cross-origin requests are permitted,
  same-origin and non-browser traffic still works) and is **accepted** by
  production validation. The literal `*` is rejected in production.
- **ALLOWED_HOSTS**: the host header the app will receive — typically
  `<app>.onrender.com` (and your custom domain after the CNAME). If your proxy
  forwards a different public host, list that one.
- **SECURE_TRANSPORT=true** — required (gates the HSTS header so the browser
  sees `Strict-Transport-Security` once served over HTTPS).

## 5. Health checks

| Endpoint | Type | Used for |
|----------|------|----------|
| `GET /health` | liveness | "is the process up" — route restarts on failure |
| `GET /health/ready` | readiness | checks Mongo **and** Redis reachable → `200 {"status":"ready"}` or `503 {"status":"unavailable"}` |

Set Render's health check path to `/health` (simple liveness; Render restarts
the service on failure). If you want deploy-gating on dependencies, use
`/health/ready`. The readiness body intentionally leaks no infrastructure
details.

## 6. Redis

- Use a managed Redis (Render's own Redis, Upstash, Redis Cloud, etc.)
  **or** a hardened self-hosted Redis: `requirepass` set, private-network only,
  TLS in transit where available.
- Set `REDIS_URL` accordingly (with the password, e.g.
  `rediss://:password@host:port/0` for TLS).
- Data is ephemeral by design (TTLs). Enable AOF/appendonly if offline
  messages must survive a Redis restart; otherwise a flush only reads as
  "everyone offline" and recovers naturally.
- Redis being down at app start is a **warning**, not fatal: auth/queue
  features degrade and recover (see [DATABASE.md](DATABASE.md) §failure
  behavior). Mongo down at start is fatal by design.

## 7. Deployment verification (smoke tests)

After a deploy, from a machine NOT behind the production CORS origin, run:

```powershell
# 1. Process up
curl.exe -s https://<app>.onrender.com/health
# → {"status":"ok"}

# 2. Dependencies reachable
curl.exe -s https://<app>.onrender.com/health/ready
# → {"status":"ready"}

# 3. Register + dev-login are disabled in prod; PoP path works:
curl.exe -s -X POST https://<app>.onrender.com/auth/challenge `
    -H "Content-Type: application/json" -d '{"user_id":"alice"}'
# → 200 {"user_id":"alice","nonce":"<64 hex>"}

# 4. Wrong signature is a generic 401 (fail-closed):
#    (verify then logout paths are covered by the integration suite against a
#    staging instance; never point production databases at local tests.)
```

Verify in the Render logs: startup `application starting`, `mongodb reachable`,
`database ready`, `redis ready` (or the degraded-Redis warning). Check one
request shows an `X-Request-ID` header and structured log lines.

## 8. HTTPS / WSS / client hosts

- Render serves HTTPS automatically on the `*.onrender.com` domain and for
  custom domains with an auto-provisioned certificate (or your own).
- The app's `X-Request-ID`, `X-Content-Type-Options`, `X-Frame-Options`,
  `Referrer-Policy`, and (with `SECURE_TRANSPORT=true`) HSTS headers are set on
  every response.
- WS clients must use `wss://` (or `wss://<custom-domain>`).

## 9. Logs, monitoring, and rollback

- Logs: Render "Logs" tab. The log format includes `request_id`, method/path,
  status, duration — correlate client reports by the `X-Request-ID` echoed in
  responses.
- Watch for: boot-loop from fail-fast config errors, `/health/ready` 503,
  auth-failure spikes (`401`), per-IP rate-limit hits (`429`), `503
  dependency_unavailable` (Redis in auth path).
- Rollback: in Render, re-deploy a previous deploy (immutable deploys — the
  same code+env as before). Index creation is idempotent and forward
  compatible, so older builds tolerate newer data.
- Secrets rotation: change `JWT_SECRET` and restart all instances
  (existing tokens invalidate — schedule it); rotate Mongo/Redis credentials
  by switching the variable, redeploying, verifying `/health/ready`, then
  revoking the old credential.

## 10. Scaling (and why not yet)

- Today: **one instance, one worker**. Sizing: long-lived WebSockets + Redis
  ops; the per-process `WS_MAX_CONNECTIONS=1000` budget is the ceiling for one
  instance (raise with caution).
- To scale horizontally later: externalize the WebSocket registry and the
  dedup window (Redis pub/sub + a shared registry, or sticky instances), then
  run N instances. Until that work lands, more instances would fragment
  presence, takeover, and dedup across processes.

## 11. What NOT to do

- Do not set `APP_ENV` to `development`/`test` in production (disables
  fail-fast validation and enables password-less `/auth/login`).
- Do not use `CORS_ORIGINS=*` or `ALLOWED_HOSTS=*` in production (rejected
  anyway by fail-fast). If the deployment has no frontend yet, leave
  `CORS_ORIGINS` set to an explicitly empty value — do **not** set `*`.
- Do not point `MONGODB_URI`/`REDIS_URL` at development credentials, and never
  run local/test tooling against the production databases.
- Do not run multiple workers/instances without externalizing process-local WS
  state.