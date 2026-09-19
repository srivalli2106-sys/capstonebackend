# Rate Limiting

Two independent belts: an HTTP limiter (fail closed) and WebSocket gates
(degrade open). Backend implementation: `server/security.py` /
`server/middleware.py` with Redis sliding windows
`ratelimit:{category}:{identity}`.

## HTTP rate limits

| Category | Limit | Identity | Behavior over limit |
| --- | --- | --- | --- |
| `register` | 1 / 3600 s | user_id (IP fallback) | 429 |
| `login` (dev only) | 10 / 60 s | user_id + IP | 429 |
| `challenge` | 10 / 60 s | user_id | 429 |
| `verify` | 20 / 60 s | user_id + IP | 429 |
| `logout` | 30 / 60 s | user_id | 429 |
| `keys` | 30 / 60 s | user_id | 429 |
| general default | 100 / 60 s | IP | 429 |

- Sliding window in Redis; a counter is incremented atomically and the
  request is allowed only if the count is within the window.
- **Fail closed**: if Redis is unreachable the endpoint refuses with 503 —
  a limiter outage never silently disables limits.
- Identity keys use the authenticated user id where known; unauthenticated
  calls fall back to IP.

## WebSocket gates

| Gate | Limit | Identity | Behavior over limit |
| --- | --- | --- | --- |
| `ws_connect` | 60 / minute | IP | HTTP 429 before the WS upgrade |
| `ws_message` | 120 / minute | user | drop the frame; 4003 on the peer socket |

- `ws_connect` is checked pre-upgrade; a fresh window per connection is
  started on success.
- `ws_message` is checked per inbound frame.
- **Degrade open**: on a Redis outage the WS continues running and frames
  route without limit enforcement (delivery preferred over strict metering).

## Client backoff (frontend)

`WebSocketController.DEFAULT_BACKOFF = [1000, 2000, 4000, 8000, 15000, 30000]`

| Event | Client action |
| --- | --- |
| HTTP 429 | surface the typed error; user retries naturally |
| WS `4003 POLICY_VIOLATION` (message rate) | STOP: no reconnect loop |
| WS network / 1009 / 1013 / 1001 | exponential backoff via the schedule |
| WS `4008 IDLE_TIMEOUT` | reconnect immediately |
| WS `4000 REPLACED`, `4001 AUTH` | stop; ask the user to sign in again |

Rate-limit failures therefore translate into clear user-visible states
rather than silent infinite retry loops.