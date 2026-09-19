# Setup

## Prerequisites

- Node.js 18+ and npm for the frontend.
- Python 3.11+ and Docker (with compose) for the backend stack.
- Optional: Docker Desktop or a local MongoDB/Redis for integration tests.

## Cloning

The project is split into two repositories:

```
D:\Capstone\capstonefrontend   React SPA
D:\Capstone\capstonebackend    FastAPI backend
```

## Frontend (capstonefrontend)

```powershell
cd D:\Capstone\capstonefrontend
copy .env.example .env           # VITE_API_BASE_URL; VITE_WS_BASE_URL optional
npm install
npm run dev                      # Vite dev server, prints local URL
```

Scripts (from `package.json`):

| Script | Behavior |
| --- | --- |
| `npm run dev` | Vite dev server with HMR |
| `npm run typecheck` | `tsc --noEmit` (TypeScript strict) |
| `npm run build` | `tsc --noEmit && vite build` |
| `npm run preview` | Serve the production build locally |
| `npm test` | Vitest test run (`vitest run`) |
| `npm run test:watch` | Vitest watch mode |

The production build is emitted to `dist/`. The backend URL is baked in at
build time via `VITE_API_BASE_URL`; because Vite inlines `import.meta.env`
values, rebuild after changing it.

## Backend (capstonebackend)

```
Windows PowerShell
cd D:\Capstone\capstonebackend
py -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
pip install -r requirements-dev.txt
copy .env.example .env
uvicorn server.app:app --host 0.0.0.0 --port 8000
```

Interactive API docs at `http://localhost:8000/docs` (development).

### Local stack with Docker Compose

```powershell
cd D:\Capstone\capstonebackend
docker compose up --build     # backend + mongodb + redis, throwaway dev creds
# app at http://localhost:8000/docs
```

Tear down with `docker compose down -v` (removes the data volume).

Integration tests against the compose stack:

```powershell
$env:RUN_INTEGRATION = "1"
$env:MONGODB_URI = "mongodb://backend:backend_dev_pw@localhost:27017/secure_messaging?authSource=admin"
$env:MONGODB_DB = "secure_messaging"
$env:REDIS_URL = "redis://:redis_dev_pw@localhost:6379/0"
pytest -m integration
```

### Running tests

```powershell
pytest                      # unit tests only (no integration)
pytest -m integration       # integration tests (requires RUN_INTEGRATION=1)
ruff check .                # lint
```

Coverage: `pytest --cov=server --cov-report=term-missing -m "not integration"`.

## Environment notes

- The backend is a single-process design (WebSocket registry, presence, and
  rate limiting are process-local). Do not run multiple uvicorn workers
  without first externalizing that state (see `DEPLOYMENT.md`).
- `APP_ENV=production` rejects placeholder secrets, wildcard CORS, wildcard
  host lists, and a `SECURE_TRANSPORT=false` value at startup (see
  `ENVIRONMENT.md`).
- The frontend `.env` only ever contains public values; never put secrets in
  a `VITE_` variable.