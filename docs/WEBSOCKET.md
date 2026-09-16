# WebSocket Messaging

The `/ws` endpoint (`server/routes/messages.py`) is the real-time transport for
the message envelope. This document covers the full connection lifecycle,
guards, and the current scaling assumptions.

---

## 1. Connection lifecycle

```
client                                   server (routes/messages.py)
  │  connect ws://host/ws
  │ ───────────────────────────────────► try_reserve()        (budget, 1013 if full)
  │                                     try_register_ip()     (per-IP cap, 1013)
  │                                     allow_ws_connect()    (rate gate, 1013)
  │                                     ws.accept()
  │  FIRST frame { "type":"auth","token":"<JWT>" }
  │ ───────────────────────────────────► receive_auth_token (within WS_AUTH_TIMEOUT_SECONDS)
  │                                     verify_ws_token (JWT + revocation, fail closed)
  │                                     register → takeover old conn (4000)
  │                                     presence connect (best effort)
  │                                     flush_pending (deliver queued envelopes)
  │  { "id","type","recipient","data" }  ←─────────────  (loop)
  │ ───────────────────────────────────► envelope validation + dedup + forward/queue
  │  (or control frames; pings/pongs reset the idle window)
  │ ◄─────────────────────────────────── close (any code) / disconnect / idle 4008
```

### Handshake details

- The **first frame** must be the auth message. It must arrive within
  `WS_AUTH_TIMEOUT_SECONDS` (default 10 s) or the socket is closed `4001`
  "Authentication timed out".
- The token is verified exactly like HTTP auth (pinned algorithm, issuer,
  claims, expiry, **revocation**) and any failure closes `4001`. The token is
  never logged or echoed.
- Query-string tokens are not used.
- After auth the connection is owned by that one user; a second auth frame is
  never expected.

## 2. Connection guards (order applied)

| Guard | Default | On failure |
|-------|---------|------------|
| Global budget `WS_MAX_CONNECTIONS` | 1000 | close `1013` before accept |
| Per-IP cap `WS_MAX_CONNECTIONS_PER_IP` (0 disables) | 20 | close `1013` (no per-IP detail leaks) |
| Connect rate limit `WS_CONNECT_RATE_PER_MINUTE` (per IP) | 60/min | close `1013` "Rate limit exceeded" |
| Auth timeout `WS_AUTH_TIMEOUT_SECONDS` | 10 s | close `4001` |
| Idle timeout `WS_IDLE_TIMEOUT_SECONDS` (0 disables) | 180 s | close `4008` "Idle timeout" |
| Message rate limit `WS_MESSAGE_RATE_PER_MINUTE` (per user) | 120/min | **drop the frame only**, keep connection |

Rate gates degrade **open** on Redis failure (log + allow); auth is **fail
closed**.

## 3. Token lifetime / revocation watcher

After auth a background task (`ws_auth._watch_token_lifetime`) re-checks every
`max(1, WS_PRESENCE_TTL_SECONDS // 10)` seconds:

- token expired → close `4001` "Session expired";
- token revoked (logout happened) → close `4001` promptly;
- **revocation read fails → close `4001`** (fail closed — never hold a
  connection on an unverifiable token).

## 4. Keepalive and idle timeout

- The server sends WS ping frames every `WS_KEEPALIVE_SECONDS` (default 30 s,
  0 disables). Peers answer pings at the protocol level; the resulting pong
  (or any application frame) resets the idle window, so healthy idle
  connections are never condemned and NAT/proxy tunnels stay warm.
- `WS_IDLE_TIMEOUT_SECONDS` (default 180 s) bounds the time with **no
  application frame**; it must exceed the keepalive interval.

## 5. Message validation (`server/envelope.py`, `message_service.py`)

Inbound frames are validated before any relay/queue work:

- whole frame bounded by `MAX_WS_MESSAGE_CHARS` (65 536 chars) else close `1009` "Message too large";
- envelope fields: valid ULID `id`, known `type`, non-empty `recipient` ≤ 64
  chars, `data` a non-empty string ≤ `MAX_DATA_CHARS` (65 520);
- server is authoritative over `version`, `sender`, and `timestamp` — a
  spoofed `sender` is overwritten;
- **replay/deduplication**: `(sender, id)` is remembered for 300 s in a
  bounded in-process window; a repeat is dropped silently;
- malformed envelopes/binary frames are **dropped without closing** the
  connection.

The envelope schema and type catalog are specified in
[PROTOCOL.md](PROTOCOL.md).

## 6. Delivery: forward vs queue

- Recipient online (presence marker set and a live socket in the registry):
  the envelope JSON is pushed on the live socket immediately.
- Recipient offline (or the push fails): the envelope is appended to
  `pending:{user_id}` (Redis list, FIFO).
- **Queue honesty**: if the Redis queue write fails, the server logs
  `NOT queued` and does nothing further — it never reports the message as
  queued.
- On connect, `flush_pending` LPOPs the whole queue and sends envelopes in
  order; on a send failure it re-queues the failed envelope and stops so
  remaining order is preserved.

## 7. Presence

- `online:{user_id}` and `conn:{user_id}` Redis markers (TTL
  `WS_PRESENCE_TTL_SECONDS`), refreshed every half-life by a per-connection
  `keep_alive` task while the connection's `conn_id` is still the current one.
- Presence is **degrade-by-design**: Redis failures are logged and ignored so
  an operational blip never blocks a valid connection. Presence is **not** a
  security boundary (auth stays fail-closed).
- When the last live connection for a user disconnects, presence is cleared.

## 8. Takeover (one connection per user per process)

Registering a second connection for the same user replaces the first: the old
socket is closed `4000` "Replaced by new connection". Removal is guarded by
`conn_id`, so a superseded connection's disconnect can never evict the
replacement.

## 9. Cleanup and graceful shutdown

- `finally` block per connection: cancels the background tasks (join with
  `return_exceptions=True`), removes the user mapping (conn_id-guarded), clears
  presence only when no connection remains, and releases the budget/per-IP
  slots — each exactly once.
- App shutdown (`lifespan`): `registry.close_all(1001)` closes every live
  socket first (1001 "Server shutting down"), waits 50 ms for teardown work,
  then closes MongoDB and Redis pools.

## 10. Close codes

| Code | Reason | Client action |
|------|--------|---------------|
| `1000` | Normal | none |
| `1001` | Server shutting down | reconnect with backoff after the window |
| `1009` | Message too large | split payload; don't retry the same frame |
| `1013` | Capacity / per-IP cap / connect rate limit | reconnect with exponential backoff + jitter |
| `4000` | Replaced by a newer connection | stop; another device took over |
| `4001` | Auth failed / session expired / revoked | re-authenticate (login or refresh) |
| `4003` | Policy violation (binary first frame etc.) | fix the client |
| `4008` | Idle timeout | reconnect; resend pending envelopes with their original `id` |

## 11. Current single-process / single-worker assumptions

The following state is **process-local today**. Running multiple uvicorn
workers or instances without externalizing it will fragment behavior:

- `ws_registry.registry` — connection budget counter, per-IP counts, and the
  user→socket map (receiver lookup, takeover);
- the envelope **dedup window** (`_seen_ids` in `message_service`);
- the keepalive/presence refresh tasks (they belong to the process that owns
  the socket).

Presence markers, the offline queue, rate limits, auth challenges, and
revocation live in **Redis** and are already shared across instances.

**Therefore:** run exactly **one app instance/worker** today (the Dockerfile
CMD and [DEPLOYMENT.md](DEPLOYMENT.md) enforce this). Horizontal scaling
requires externalizing the registry + dedup state (see DEPLOYMENT.md §Scaling).