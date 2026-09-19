# Testing

## Frontend (Vitest)

- Runner: Vitest 1.x (`package.json`: `test: vitest run`, `test:watch`,
  `typecheck`, `build` = typecheck + `vite build`).
- Environment: `node` with `fake-indexeddb` (IndexedDB tests run without a
  browser), `test/setup.ts`, tests under `test/**/*.test.ts`.
- Env for tests: `VITE_API_BASE_URL=https://api.example.test`,
  `VITE_WS_BASE_URL=wss://ws.example.test`.
- Coverage today: 19 test files, 228 `it`/`test`, 71 `describe` (includes
  `fake-indexeddb`-backed encrypted history tests).

Scope:

| Area | Files |
| --- | --- |
| crypto (X3DH, ratchet, KDF, identity store) | `test/crypto*`, `test/identity*` |
| auth + api clients | `test/auth*`, `test/api*` |
| realtime controllers/components | `test/realtime*`, `test/components*` |
| encrypted local history | `test/chatStore.test.ts`, `test/chatHistory.test.ts` |
| routing/state/bootstrap | `test/router*`, `test/app*`, `test/setup*` |

Notable patterns:
- Cross-implementation vectors: double-ratchet tests pin ciphertexts against
  values produced by the backend `protocol/` module.
- Fake IndexedDB and mocked `WebSocket`/fetch keep all suites fast and
  hermetic.

## Backend (pytest)

- Suite: `pytest` (unit) with `tests/` following the module layout
  (`test_<module>.py`, `integration/`).
- Python 3.11, deps in `requirements.txt` / `requirements-dev.txt`.
- Lint: `ruff check .`.
- Current totals: **379 test functions**, of which **8 are integration**
  (marked, run only with `RUN_INTEGRATION=1`; gated because they need
  MongoDB + Redis).

**Unit** (no external services; pure/protocol/logic):
`test_config, test_jwt_auth, test_auth_service, test_auth_routes, test_keys_routes,
test_key_service, test_messaging_policy, test_message_service, test_presence_service,
test_rate_limit, test_ws_auth, test_ws_registry, test_websocket, test_user_service,
test_repositories, test_envelope, test_exceptions, test_request_id, test_redis_client,
test_security, test_db, test_dependency_errors, test_health, test_jwt,
test_auth_store, test_protocol_x3dh, test_protocol_session, test_protocol_ratchet,
test_protocol_keys`.

**Integration** (`RUN_INTEGRATION=1`, real Mongo/Redis):
`integration/test_auth_flows, test_auth_keys_flow, test_messaging_ws,
test_opk_concurrency` (+ `integration/conftest.py`).

## Protocol cross-checks

- X3DH, Double Ratchet, session init/accept, and key models are verified
  independently on both sides:
  - backend `protocol/` + `tests/test_protocol_*.py`
  - frontend `src/crypto/` + `test/crypto*.test.ts`
- The same constants (`secure-messaging-x3dh-v1`, `-dr-{root,chain,message}-v1`,
  `SPK_SIGN_CONTEXT`) are asserted on both sides so a drift breaks CI.

## Commands

```bash
# frontend
cd capstonefrontend
npm run typecheck
npm test          # vitest run
npm run build     # typecheck + vite build

# backend
cd capstonebackend
pip install -r requirements.txt -r requirements-dev.txt
ruff check .
pytest                # unit suite
RUN_INTEGRATION=1 pytest -m integration   # live-service suite
```