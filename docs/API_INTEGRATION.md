# API Integration

How the frontend talks to the backend: base URL resolution, request envelope,
error contract, and every endpoint used.

## Base URL

`src/config/env.ts`:

- `VITE_API_BASE_URL` (required) — API origin, e.g. `https://secure-messaging-backend-g7v0.onrender.com`.
- `VITE_WS_BASE_URL` (optional) — WS origin; derived from the API origin
  otherwise (`https` -> `wss`, `http` -> `ws`).

The same config feeds both the REST client and the WebSocket controller, so
API and WS can never point at different deployments.

## REST client (`src/api/http.ts`)

- `request<T>(path, options)` — relative paths against the base URL.
- Sends `X-Request-ID` (a fresh ULID-style id per request) which the server
  echoes on every response and in error bodies.
- `DEFAULT_TIMEOUT_MS = 10_000`; supports `AbortSignal` and an optional
  `authToken` header (`Authorization: Bearer <jwt>`).
- 401 responses invoke the single registered unauthorized handler
  (`setUnauthorizedHandler`) which signs the user out.

### Success / error shape

```ts
ApiSuccess<T> { ok: true;  data: T; status: number }
ApiError      { ok: false; status; statusText; code; requestId }
```

Endpoint errors match the server contract `{ "error": { "code", "message",
"request_id" } }` (see `ERROR_HANDLING.md`).

## Endpoint reference (`src/api/*.ts`)

### `POST /auth/register`
```json
{ "user_id": "alice", "ik_public": "<64 hex>" }
```
- 201 `{ "status": "registered", "user_id" }`
- 409 conflict (user exists), 422 validation (bad user_id/key length)

### `POST /auth/challenge`
```json
{ "user_id": "alice" }
```
- 200 `{ "user_id", "nonce": "<64 hex>" }`; 404 unknown user, 422.

### `POST /auth/verify`
```json
{ "user_id": "alice", "nonce": "<64 hex>", "signature": "<128 hex>" }
```
- 200 `{ "token": "<jwt>", "user_id" }`
- 401 Authentication failed (unknown user, expired/missing/consumed
  challenge, bad signature), 422 malformed.

### `POST /auth/logout`
- 200 `{ "status": "logged_out" }`; revokes the JWT server-side.

### `POST /keys/upload`
```json
{ "xdh_public", "spk_public", "spk_sig": "<128 hex>", "opk_public": "...|null" }
```
- 200 `{ "status": "ok", "user_id" }`; 404 unknown user, 422 malformed key.

### `GET /keys/bundle/{user_id}`
- 200
  ```json
  { "user_id", "ik_public", "xdh_public", "spk_public", "spk_sig",
    "opk_public": "...|null", "version": 1 }
  ```
- The OPK is returned WITH atomic server-side consumption (only one
  requester gets it). 404 if unknown.

### `GET /keys/prekeys/{user_id}`
- 200 `{ "user_id", "opk_available": true|false, "version" }` — used by the
  sender to decide whether to attach an OPK when initiating.

### `GET /health`, `GET /health/ready`
- Health and readiness probes; ready returns 503 until dependencies
  (MongoDB/Redis) are reachable.

## Sequence for a fresh conversation

```
1. GET  /keys/prekeys/bob        -> opk_available?
2. GET  /keys/bundle/bob         -> SPK + signature (+ OPK, consumed)
3. X3DH in the browser
4. WS:  session_init envelope
5. WS:  text envelopes (ratchet ciphertext)
```

## Auth header vs. WS auth

- REST: `Authorization: Bearer <JWT>`.
- WS: first-frame `{ "type": "auth", "token": "<JWT>" }` (never a header).
- JWT lifetime: `JWT_EXPIRY_HOURS` (default 24). On expiry the server closes
  the socket (`4001`); the client reconnects with a fresh token.

## Conventions

- All request bodies are JSON; responses are JSON.
- Hex encoding: lowercase, exactly N chars (`KEY_HEX_CHARS = 64`,
  signature hex 128, nonce hex 64).
- Idempotency: client message ids are the de-dup key server-side.
- No secrets in URLs or query strings; tokens travel only in headers or
  first-frame auth.