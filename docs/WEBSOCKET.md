# WebSocket

## Overview

The realtime transport is a single WebSocket per client, used for:

- server-authenticated envelope exchange (messages, session control, receipts),
- presence fan-out,
- typing indicators,
- server-initiated close codes that drive the client's reconnect policy.

## Endpoint

| Environment | Endpoint |
| --- | --- |
| Local frontend dev | `ws://localhost:8000/ws` |
| Production | `wss://secure-messaging-backend-g7v0.onrender.com/ws` |

The URL is derived from the `VITE_WS_BASE_URL` env var (with https→wss /
http→ws derivation in `src/config/env.ts`); `VITE_API_BASE_URL` is the
https sibling otherwise.

## Authentication

The connection is NOT authenticated by headers. The client sends an `auth`
frame as its absolutely first frame:

```json
{ "type": "auth", "token": "<JWT>" }
```

- The server reads the first frame within `WS_AUTH_TIMEOUT_SECONDS` (default
  10 s), verifies the JWT, and registers the socket in the registry.
- Failure to authenticate closes the connection with
  `4001 AUTH_REQUIRED`.
- If a bearer token later expires or is revoked, a background task closes the
  socket with `4001` while it is still online (fail closed).

## Frames (server-authoritative)

Clients send a partial envelope; the server validates, stamps, and re-sends
it (or routes it to the peer):

```json
// client -> server (simplified)
{ "id": "01H5...", "type": "text", "recipient": "bob", "data": "..." }
```

```json
// server -> client (routed)
{
  "version": 1,
  "id": "01H5...",
  "type": "text",
  "sender": "alice",
  "recipient": "bob",
  "timestamp": 1700000000000,
  "data": "..."
}
```

Types: `text`, `file`, `session_init`, `session_accept`,
`delivery_receipt`, `read_receipt`, `typing`. The server never inspects or
logs `data` (message payloads are opaque).

Envelope limits:

| Limit | Value |
| --- | --- |
| `MAX_WS_MESSAGE_CHARS` | 65,536 |
| `MAX_DATA_CHARS` | 65,520 |
| close code over limit | `1009 TOO_LARGE` |

## Server-side rate gates

- `ws_connect`: sliding window (default 60 / minute / IP); over limit →
  HTTP 429 before the socket upgrade.
- `ws_message`: sliding window (default 120 / minute / user); over limit →
  the message is dropped with `4003 POLICY_VIOLATION` on the peer socket if
  a delivery attempt was made.
- Redis outages degrade open: the WS still runs, messages are routed (limits
  not enforced), the fail-closed HTTP paths are unaffected.

## Close codes

| Code | Meaning | Client behavior |
| --- | --- | --- |
| 1000 | normal (requested cleanup) | none |
| 1001 | going away (app teardown) | none |
| 1009 | frame too large | backoff retry |
| 1013 | server capacity / overload | retry immediately (4008) or backoff |
| 4000 | session replaced (same user logged in elsewhere) | STOP (no retry) |
| 4001 | auth required / revoked / expired | STOP (no retry) |
| 4003 | policy violation (rate limit) | STOP (no retry) |
| 4008 | idle timeout | retry immediately |

### Client retry policy (`src/realtime/WebSocketController.ts`)

| Close / error | Behavior |
| --- | --- |
| 4000, 4001, 4003 | stop, do not reconnect |
| 4008 | reconnect immediately |
| 1009, 1013, 1001, network error | exponential backoff retry |
| intentional close (dispose/login switch) | no retry |

Backoff schedule: `[1000, 2000, 4000, 8000, 15000, 30000]` ms (max delay
30 s). The JWT is re-read from the auth controller on every reconnect.

## Heartbeat / idle

- The server closes idle sockets with `4008` after `WS_IDLE_TIMEOUT_SECONDS`
  (default 60 s).
- The client reconnects immediately on `4008`, renewing the connection and
  its JWT before it expires.

## Out-of-band queuing (reliability)

If the recipient is offline, the server stores the envelope in the offline
queue (`pending:{user_id}`) instead of a live socket. On reconnect, the
pending queue is flushed to the socket. See `MESSAGING.md`.

## Client architecture

| Piece | Role |
| --- | --- |
| `WebSocketClient` | raw socket, first-frame auth, send, close |
| `WebSocketController` | lifecycle, backoff/retry, reconnect policy, auth integration |
| `ChatController` | sessions, encryption dispatch, decryption, receipts |
| `setup.ts` | transport wiring (`setRealtimeTransport`), singleton lifecycle |
| `messageId.ts` | ULID-style message ids (see `MESSAGING.md`) |
| `types.ts` | envelope + close-code constants |