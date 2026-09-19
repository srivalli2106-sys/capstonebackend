# Troubleshooting

## WebSocket will not connect

- Check `VITE_WS_BASE_URL` / derived origin matches the deployed API.
- JWT expired? Server closes `4001`; re-login.
- Token revoked (logout elsewhere)? Same `4001`.
- Entering while another tab is connected? Expect `4000 REPLACED` on the old
  socket after re-login.
- Rate limited on connect? The upgrade is refused with HTTP `429`
  (`ws_connect` 60/min/IP). Wait and retry.
- Server capacity? `1013` — the client retries on the backoff schedule.

## Messages do not arrive / cannot send

- First message to a peer triggers X3DH (`session_init`). If the peer's
  bundle fetch fails (`404`), they were never registered with a bundle —
  re-register or have the peer unlock their device.
- Session lost after a reload: sessions are memory-only by design; the next
  message re-runs the handshake (see `SESSION_MANAGEMENT.md`).
- Offline peer: message is queued server-side (opaque ciphertext) and flushed
  on reconnect. Absence of a `delivery_receipt` is expected until the peer
  reconnects.
- `4003 POLICY_VIOLATION`: `ws_message` rate (120/min) exceeded — slow down.

## Login / auth failures

- 401 `Authentication failed` is intentionally generic. Causes: wrong
  passphrase (wrong key), stale challenge (expired 120 s TTL), replayed
  nonce, or the wrong server (base URL mismatch).
- If `IdentityError` is `no_record` the key was never created on this device
  — you must register (there is no server-side recovery).

## Rate limiting

- `register` is 1/hour per user_id; `verify`/`challenge` are sub-minute
  buckets. Sustained retries from a script will 429.
- Fast dev loops hitting login? The dev-only `POST /auth/login` is
  10/60 s; switch to the PoP flow.

## Health / readiness

- `/health/ready` returns `503` until MongoDB and Redis respond. The app
  refuses to serve if `config.load()` fails (bad `JWT_SECRET`, unreachable
  Mongo at startup).
- Redis down: HTTP auth paths go `503` (fail closed); WS runs but limits
  degrade open. Diagnose via Render/Upstash dashboards.

## Local development

| Symptom | Fix |
| --- | --- |
| Frontend build fails | `npm run typecheck`; then `npm run build` |
| Vite port conflict | default 5173 — change if needed |
| Backend refuses to start | `DATABASE_URL`/`REDIS_URL` unreachable, or `JWT_SECRET` is a placeholder |
| `RUN_INTEGRATION` tests skip | they need live Mongo/Redis; run with `RUN_INTEGRATION=1 pytest -m integration` |
| WSS/WS scheme mismatch | ensure `https`→`wss` derivation (or set `VITE_WS_BASE_URL`) |

## Cross-implementation ciphertext drift

- If backend and frontend ciphertexts ever diverge, first check the shared
  constants (`secure-messaging-x3dh-v1`, `-dr-*` info strings,
  `SPK_SIGN_CONTEXT`) and the order of X3DH DH terms — both are pinned by
  `test_protocol_*` and the frontend vector suites.