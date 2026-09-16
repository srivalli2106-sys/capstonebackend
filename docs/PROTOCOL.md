# Message Protocol

This document describes the message protocol the backend speaks today
(Phase 11), the ordering and replay guarantees the server provides, and the
integration points where the E2EE protocol (X3DH / Double Ratchet, Phase 13)
attaches.

Everything below uses **opaque payloads**: the server validates the envelope's
routing and identity, and never inspects the message contents.

---

## 1. Transport

Two channels exist:

| Channel | Endpoint | Use |
|---------|----------|-----|
| HTTP/JSON | REST endpoints (`/auth/*`, `/keys/*`) | Registration, login, key-bundle exchange |
| WebSocket | `/ws` | Real-time relay + offline delivery of envelopes |

WebSocket authentication is the first-frame `{"type": "auth", "token": "<JWT>"}`
handshake (see `server/ws_auth.py`). Query-string tokens are ignored.

## 2. Message envelope

Every delivered/queued message is one JSON object with exactly these fields:

```json
{
  "version": 1,
  "type": "text",
  "id": "01J8Z4F6JGF9P9Z1K3X2V0WXYQ",
  "sender": "alice",
  "recipient": "bob",
  "timestamp": 1750000000000,
  "data": "<base64url-encoded opaque payload>"
}
```

| Field | Set by | Meaning |
|-------|--------|---------|
| `version` | **server** | Envelope schema version (`1`). A client-supplied value is ignored. |
| `id` | client | Globally unique message id (see §3). |
| `type` | client | One value from the message-type registry (see §4). |
| `sender` | **server** | The authenticated user. A client-supplied `sender` is **overwritten** — spoofing is impossible. |
| `recipient` | client | Target user id (≤ 64 chars). |
| `timestamp` | **server** | Epoch **milliseconds** when the server accepted the envelope. |
| `data` | client | Opaque application payload (≤ 65520 chars). |

**Inbound frame** (client → server) is the same shape minus the server-owned
fields:

```json
{ "id": "...", "type": "text", "recipient": "bob", "data": "..." }
```

Validation (`server/envelope.py`, `normalize_envelope`): malformed JSON,
non-object, invalid `id`, unknown `type`, empty/absent/oversized `recipient`
or `data`, and frames larger than the transport bound (65 536 chars) are
**dropped silently** — the connection stays open.

## 3. Message ids (ULID)

Ids are ULIDs: 26 characters of Crockford base32 encoding a 48-bit millisecond
timestamp (10 chars) + 80 bits of randomness (16 chars).

* **Sortable** — ids sort lexicographically by creation time, giving clients a
  deterministic order key for offline refetch and reconciliation.
* **Unique** — 80 random bits; safe to use as a per-message nonce seed.
* **Monotonic** — within a server process the embedded timestamp never
  decreases (a clock regression reuses the previous millisecond).

Server-side ordering for offline delivery is the **queue insertion order**
(`pending:{user_id}` Redis list, FIFO). The `id` is what allows a client to
detect and discard duplicates after a reconnect/retry.

## 4. Message types

Fixed catalog (`server/envelope.py`, `MessageType`):

| Type | Meaning |
|------|---------|
| `text` | User text message. |
| `file` | File transfer message (payload carries opaque metadata/ciphertext; the server relays it unchanged). |
| `session_init` | X3DH initiation frame (Phase 13): identity/one-time prekey identifiers + X3DH init ciphertext. Opaque to the server. |
| `session_accept` | X3DH acceptance frame (Phase 13). Opaque to the server. |
| `delivery_receipt` | Control frame acknowledging delivery of a message id. |
| `read_receipt` | Control frame acknowledging read. |
| `typing` | Presence/typing indicator (high-frequency, small payload). |

Unknown `type` values are rejected at the boundary. The type registry is the
single place new message types are registered — Phase 13 plugs the
crypto-protocol frames in here (`session_init`, `session_accept`) without any
server-side treatment change, because `data` stays opaque.

## 5. Delivery semantics

1. Server authenticates the sender, validates the envelope, stamps
   `sender`/`version`/`timestamp`, and builds the server-authoritative envelope.
2. **Replay protection**: the pair `(sender, id)` is remembered for 300 s in a
   bounded in-process window. A repeated id inside the window is dropped.
   *(Scope note: this is an in-process accelerator. End-to-end replay
   protection is provided by message ids + client nonce handling, and by token
   revocation — the server does not keep cross-restart message journals.)*
3. If the recipient is **online**, the envelope is pushed on the live socket.
4. If the recipient is **offline** (or the online push fails), the envelope is
   appended to `pending:{user_id}`.
5. On connect, the server LPOPs the whole queue and flushes envelopes in order.
   A send failure re-queues the failed envelope and stops, so order is
   preserved for the rest.

The server never decrypts, validates content, or logs `data`.

## 6. WebSocket close codes & client guidance

All closure close-codes the server can send, and what a client should do:

| Code | Reason | Client action |
|------|--------|---------------|
| `1000` | Normal | None (deliberate). |
| `1001` | Shutdown | Reconnect with backoff after the maintenance window. |
| `1009` | Frame too large | Split the payload; do not retry the same frame. |
| `1013` | Capacity / per-IP cap reached | **Reconnect with exponential backoff + jitter**; do not hammer. |
| `4000` | Replaced by newer connection (same user) | Stop — another device took over; reconnect only after the user session ends. |
| `4001` | Auth failed / revoked / expired | Re-authenticate (login or refresh) before retrying. |
| `4003` | Policy violation (unsupported frame, binary, etc.) | Fix the client; do not retry the same frame. |
| `4008` | Idle timeout | Reconnect; resend **pending** (unacked) envelopes with their original `id`. |

Operational contract for well-behaved clients:

- **Never send more than one auth frame**; the socket is owned by the first
  authenticated identity.
- **Treat every close as a hint to reconnect with backoff**, except deliberate
  `1000` and session-level `4000`.
- **Resend unsent envelopes with the same `id`** — the server's five-minute
  dedup window makes retries idempotent. Generate a fresh `id` only for a
  genuinely new message.
- **Answer server pings automatically.** Peers that respect the RFC respond at
  the protocol level; the resulting pong keeps the connection from hitting
  `4008` while idle. Clients may additionally send their own data or keepalive
  frames — any application frame also resets the idle window.
- **Do not self-heal a `4001`** by replaying a revoked token; re-login instead.

## 7. Security properties

| Property | Mechanism |
|----------|-----------|
| Sender authenticity | `sender` is stamped from the authenticated JWT; spoofed claims ignored. |
| Recipient integrity | `recipient` is validated (present, ≤ 64 chars). |
| Replay (duplicate) handling | Dedup on `(sender, id)` within the window + unique-id nonces. |
| Traffic analysis | Payloads opaque; envelope metadata (senders/recipients/timestamps) is necessarily visible to the server. |
| Message integrity (content) | Provided end-to-end by the client crypto (Phase 13) — server cannot forge valid ciphertext. |

## 8. E2EE integration (Phase 13)

The server never runs client crypto — it only moves the *material* the
crypto protocol needs. Transport, ordering, and replay handling are unchanged
from §2–§5.

* `session_init` / `session_accept` are reserved envelope types (§4); `data`
  stays opaque.
* Key bundles via `/keys/*` carry the X3DH material (SPK + signature + OPK).
  Bundle fetch consumes the OPK atomically, so every X3DH init uses a fresh
  one-time prekey; the bundle also exposes the registered `ik_public` so the
  initiator can verify the signed prekey.
* The full protocol is specified in
  **[docs/E2EE.md](E2EE.md)** (X3DH + Double Ratchet + wire framing), with a
  reference implementation in the `protocol/` package and its unit tests.

The server code in this repository does not change when a client crypto
implementation lands.