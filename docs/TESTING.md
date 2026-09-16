# Testing

The repository's quality bar and how to run the suite locally and in CI.

## 1. Suite layout (`tests/`)

| Group | Where | Needs infra? |
|-------|-------|--------------|
| Unit tests | `tests/test_*.py` (non-`integration`) | **No** — fake repositories are injected; the app lifespan is intentionally not run in the unit `TestClient` |
| Protocol tests | `tests/test_protocol_*.py` | No — pure reference crypto |
| Integration tests | `tests/integration/test_*.py` | **Yes** — live MongoDB + Redis |

Test configuration lives in `pyproject.toml`:

```toml
[tool.pytest.ini_options]
testpaths = ["tests"]
asyncio_mode = "auto"
asyncio_default_fixture_loop_scope = "function"
markers = ["integration: requires MongoDB and Redis; skipped unless RUN_INTEGRATION=1"]
```

`tests/conftest.py` forces `APP_ENV=test` before any server module import and
registers a skip hook: **any test marked `integration` is skipped unless
`RUN_INTEGRATION=1`** is set.

### Why integration tests are deselected locally

They need real MongoDB + Redis and create real data. By default they are
collected but auto-skipped, so `pytest` always passes on a machine without the
databases. CI runs them explicitly against disposable service containers.

## 2. Commands

```powershell
# Everything except integration (unit + protocol + websocket + security)
pytest -m "not integration"

# A single area
pytest tests/test_keys_routes.py -m "not integration"
pytest tests/test_protocol_ratchet.py

# Integration — only with real local/dev MongoDB + Redis
$env:RUN_INTEGRATION="1"
pytest -m integration

# Coverage (server + protocol; branch coverage)
pytest -m "not integration" --cov=server --cov=protocol --cov-report=term-missing:skip-covered

# Ruff lint (the full lint command used by CI)
ruff check server tests protocol
```

> Never run integration tests against production databases. Use local dev
> instances (see [DEVELOPMENT.md](DEVELOPMENT.md) and [DATABASE.md](DATABASE.md)).

## 3. What the tests cover

- **Config** (`test_config.py`) — defaults; every environment; production
  fail-fast (placeholder secrets, CORS `*`, host `*`, `SECURE_TRANSPORT`,
  Mongo placeholder marker); algorithm/issuer validation.
- **Auth** (`test_auth_routes.py`, `test_auth_service.py`, `test_auth_store.py`,
  `test_jwt*.py`) — register validation + conflict, challenge/verify flow,
  atomic challenge consumption, generic 401s, revocation TTL, fail-closed
  503s, expiry/issuer/algorithm pinning.
- **Keys/identity** (`test_key_service.py`, `test_keys_routes.py`,
  `test_repositories.py`, `test_user_service.py`) — bundle upload validation,
  single-use OPK served on the consuming fetch, 404 contracts, atomic
  `find_one_and_update`, unique-index duplicate handling.
- **WebSocket** (`test_websocket.py`, `test_ws_auth.py`, `test_ws_registry.py`,
  `test_messaging_policy.py`, `test_envelope.py`, `test_message_id.py`,
  `test_presence_service.py`, `test_rate_limit.py`) — first-frame auth,
  handshake timeout, takeover, capacity/per-IP budget, idle timeout, keepalive,
  token expiry/revocation watcher, rate gates, envelope validation, dedup,
  deliver-or-queue honesty, flush-and-requeue, presence degrade.
- **Security/middleware** (`test_security.py`, `test_request_id.py`,
  `test_exceptions.py`, `test_dependency_errors.py`, `test_health.py`) —
  security headers, HSTS gating, host validation, request-id echo + error
  contract, centralized handlers, health/readiness.
- **Protocol** (`test_protocol_keys.py`, `test_protocol_x3dh.py`,
  `test_protocol_ratchet.py`, `test_protocol_session.py`) — key generation,
  SPK signature verification, X3DH both sides (with/without OPK, tamper,
  foreign payloads), DH ratchet + symmetric ratchet, AEAD tamper evidence,
  replay/out-of-order/skip-bound behavior, skipped-key persistence,
  state export/import, version guards.
- **Redis client** (`test_redis_client.py`), **db** (`test_db.py`), **routes**
  (`test_routes.py`).
- Integration (`tests/integration/`) — real register/login/duplicate flows,
  key upload/fetch with OPK consumption, WebSocket online relay + offline
  queueing, and **concurrent atomic OPK consumption**.

## 4. CI behavior (`.github/workflows/ci.yml`)

On every push to `main` and every PR:

1. **Lint** — `ruff check server tests protocol` (Ubuntu, Python 3.11).
2. **Unit tests** — `pytest -m "not integration" --cov=server --cov=protocol
   --cov-report=term-missing --cov-report=xml:coverage.xml` with
   `APP_ENV=test`; coverage.xml uploaded as an artifact.
3. **Docker build** — `docker build -t secure-messaging-backend:ci .`
   (verifies the production image builds).
4. **Integration tests** — `pytest -m integration` with `RUN_INTEGRATION=1`
   against disposable `mongo:7` and `redis:7` service containers.

## 5. Coverage expectations

Current project targets (verified values as of the last full local run):

- overall `server + protocol` branch coverage **≈ 96%**;
- the `protocol/` package is **100% covered**;
- integration-only paths (lifespan, Mongo/Redis code) are exercised by CI.

Coverage is informational in CI (no hard gate), but PRs are expected to extend
the existing high-coverage areas for new logic.