# Error Handling

## Server contract

Every HTTP error is a single JSON document with a stable shape:

```json
{ "error": { "code": "not_found", "message": "...", "request_id": "..." } }
```

- `code` uses machine-friendly strings: `conflict` (409),
  `invalid_request` (400), `not_found` (404), `validation_error` (422),
  `internal` (500), plus `http_{status}` for unusual statuses.
- `request_id` is the `X-Request-ID` echoed from the request headers; every
  response carries it too, so logs and support tickets can be correlated.
- Validation errors normalise FastAPI/HTTPException/rate-limit failures into
  this contract; the ErrorHandler middleware guarantees it even on
  unhandled exceptions (500, no stack traces leaked).
- Failures are explicit:

| Situation | Result |
| --- | --- |
| Register: user exists | 409 `conflict` |
| Unknown bundle user | 404 `not_found` |
| Bad hex / short signature / long user_id | 422 `validation_error` |
| Unauthenticated / bad signature | 401 generic `Authentication failed` |
| Rate limited | 429 (typed message) |
| Redis/MongoDB down on a dependent path | 503 (fail closed) |

## WebSocket errors

Closes are typed by code (see `WEBSOCKET.md`):

| Code | Meaning |
| --- | --- |
| 1000, 1001 | normal / going away |
| 1009 | frame too large |
| 1013 | server capacity |
| 4000 | session replaced |
| 4001 | auth required / token revoked or expired |
| 4003 | policy violation (ws_message rate) |
| 4008 | idle timeout |

Inbound invalid frames (bad message id, unknown type, missing recipient,
oversize) are rejected without closing the healthy conduit; the client treats
that as a dropped envelope, not a fatal error.

## Client contract (`src/api/http.ts`, typed errors)

```ts
ApiSuccess<T> { ok: true;  data: T }
ApiError      { ok: false; status; statusText; code; requestId }
```

- Every request carries its own `X-Request-ID` and a 10 s timeout.
- A 401 anywhere triggers the registered unauthorized handler
  (`setUnauthorizedHandler`) which discards the local session and redirects
  to login — consistent with the WS `4001` path.
- Network/timeout failures surface as `NetworkError` / timeout typed errors,
  never as a bare thrown `Error`, so the UI can distinctively render offline,
  server-down, auth-expired, and rate-limited states.
- Client validation (user_id length, nonce/signature hex, key sizes) happens
  before any fetch; the user sees friendly copy instead of server 422s most
  of the time.

## Client crypto errors

`RatchetError`/`X3dhError`/`IdentityError` carry categorize codes
(e.g. `missing_ikx`, `invalid_signature`, `no_record`, `wrong_passphrase`).
The app maps them to `chat/error` UI copy, and a failed handshake can be
retried without killing the connection.