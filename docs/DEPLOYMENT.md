# Deployment

## Frontend (Vercel, static SPA)

- Build: Vite (React + TS). Output is static; no server runtime.
- Routing: `vercel.json` rewrites every path to `/index.html` (SPA fallback)
  so `/chat` and `/settings` deep-links resolve.
- Env vars at build time: `VITE_API_BASE_URL`
  (`https://secure-messaging-backend-g7v0.onrender.com`) and optionally
  `VITE_WS_BASE_URL` (derived `wss://…` otherwise).
- Size budget (post-optimization): CSS ~37.9 kB (gzip ~6.5 kB), JS ~303.7 kB
  (gzip ~95.1 kB).

## Backend (Render, single process)

- Web service: `https://secure-messaging-backend-g7v0.onrender.com`
- A single Uvicorn process behind Render's TLS edge (FastAPI + WebSockets);
  designed single-instance (in-memory assumptions are avoided, state is in
  MongoDB/Redis).
- Startup: `config.load()` require a valid `JWT_SECRET` (placeholders are
  rejected), connect MongoDB (fail fast on unavailability), warn on Redis
  ping failure, expose `/health` + `/health/ready`.
- Docker: `python:3.11-slim`, install requirements, `EXPOSE 8000`, run
  Uvicorn on `0.0.0.0:8000`; `docker-compose.yml` bundles Mongo + Redis + API
  for a local replica.

## Infrastructure

| Service | Role | Notes |
| --- | --- | --- |
| Vercel | static frontend | SPA rewrites |
| Render | API + WebSocket | single process, TLS edge |
| MongoDB Atlas | users, identity fingerprints | `users` collection, unique on user_id |
| Upstash Redis | JWT revoke, nonces, rate-limit, presence, offline queue | sliding-window limiter |

## Environment checklist

| Variable | Frontend | Backend |
| --- | --- | --- |
| `VITE_API_BASE_URL` | required | — |
| `VITE_WS_BASE_URL` | optional | — |
| `DATABASE_URL` | — | MongoDB URI (placeholder `USERNAME:PASSWORD` must be replaced) |
| `REDIS_URL` | — | Redis URI |
| `JWT_SECRET` | — | >= 16 chars, random; dev placeholders rejected |
| `JWT_EXPIRY_HOURS` | — | default 24 |
| `APP_ENV` | — | `development` \| `test` \| `production` |
| `SECURE_TRANSPORT` | — | enables HSTS / restricts http |

## Go-live steps

1. Provision Mongo + Redis; set `DATABASE_URL`, `REDIS_URL`.
2. `JWT_SECRET` to a long random value; `SECURE_TRANSPORT=true` in prod.
3. Deploy backend; confirm `/health/ready`.
4. Build frontend with `VITE_API_BASE_URL` pointing at the backend; deploy to
   Vercel on the main branch.
5. Smoke test: register -> login (challenge/verify) -> upload bundle ->
   two-user chat over WSS.

## Secrets and hygiene

- No real secrets in the repo: `.env.example` ships placeholders only;
  `config.load()` fails rather than boot with a default secret.
- CORS is restricted to the frontend origin; `AllowedHosts` denies unknown
  Hosts; HSTS on when `SECURE_TRANSPORT`.
- Rotation of `JWT_SECRET` invalidates outstanding tokens (all fail closed).