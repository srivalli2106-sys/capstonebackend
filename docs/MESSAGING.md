# Messaging

End-to-end messaging over the authenticated WebSocket. Content of every
envelope is end-to-end encrypted; the server only relays and stamps.

## Message identity (`src/realtime/messageId.ts`)

Message ids are ULID-style 26-character strings:

```
10 chars: 48-bit milliseconds-since-epoch (big-endian, Crockford base32)
16 chars: 80 random bits
```

- Alphabet: `0123456789ABCDEFGHJKMNPQRSTVWXYZ` (Crockford, no `I`, `L`, `O`,
  `U`).
- Generated client-side; the server keeps them, so ids are sortable and
  collision-resistant without server coordination.
- `validMessageId()` is enforced by the server envelope parser.

## Envelope model

Inbound (client → server) is a subset; the response (server → recipient) is a
full server-authoritative envelope. The server never rewrites `data`.

```json
{ "id": "...", "type": "text", "recipient": "bob", "data": "..." }
```

```json
{ "version": 1, "id": "...", "type": "text", "sender": "alice",
  "recipient": "bob", "timestamp": 1700000000000, "data": "..." }
```

## Types

| Type | Purpose |
| --- | --- |
| `text` | encrypted text message (ratchet ciphertext) |
| `file` | encrypted file/attachment reference |
| `session_init` | X3DH init frame (base64url) to start a session |
| `session_accept` | recipient's ratchet public key for the session |
| `delivery_receipt` | ack: reached the recipient's device/app |
| `read_receipt` | ack: recipient read the conversation |
| `typing` | typing indicator (fire-and-forget) |

## Send path (client)

1. Encrypt plaintext via the Double Ratchet with the session (`ChatController`
   → `E2EESession`).
2. Compose an envelope with a fresh message id.
3. Send over the WS (or buffer while disconnected). Replays on reconnect use
   the same id, which the server de-duplicates.

## Server path (`server/services/message_service.py`)

1. **Validate**: message id syntax, type, recipient present, size bounds,
   `rate_limit(ws_message)`. Invalid → error/close, payload never inspected.
2. **Authorize session**: only registered users send.
3. **Deduplicate**: sender/envelope id inside the replay window
   (`DEDUP_TTL_SECONDS`): duplicates are dropped silently.
4. **Presence**: `online:{user_id}` marker;
   - online → deliver to the live socket (fail → offline queue),
   - offline → enqueue in `pending:{user_id}` (pruned after TTL,
     deliverable on reconnect),
   - a failed queue write is never claimed as "queued" (no phantom acks).
5. **Fallback**: if Redis is one of the dependencies and it fails, message
   delivery fails rather than pretending success.

## Receive path (client)

1. Inbound envelope → find the session for `(sender, recipient)`.
2. `session_accept` / `session_init` → complete the handshake and store the
   session.
3. `text`/`file` → `ratchet.decrypt(data)`, render the plaintext.
4. `delivery_receipt`/`read_receipt` → update message status.
5. `typing` → show/hide the typing indicator.

In-memory session store: sessions live in `ChatController` and are cleared on
lock, logout, and app teardown. Nothing is persisted to disk (see
`SESSION_MANAGEMENT.md` and `LIMITATIONS.md`).

## Local history (encrypted at rest)

Conversation history *is* persisted locally and encrypted at rest
(`src/persistence/chatStore.ts`), separate from the identity store:

- Database `secure-messaging-chat`, object store `conversations`, record key
  `"<selfUserId>::<peerUserId>"`. A record stores only `selfUserId`,
  `peerUserId`, `updatedAt`, `ivHex`, `ciphertextHex` — never plaintext.
- The cipher is AES-256-GCM. The key is derived from the device's X25519
  identity private key (`ikx`) via HKDF-SHA256 with the domain-separated
  context `secure-messaging-chat-history-v1<separator><selfUserId>`, imported
  non-extractable, so it never leaves the Web Crypto boundary.
- The associated data binds each ciphertext to `selfUserId` and `peerUserId`;
  one device key cannot decrypt another account's rows.
- Writes happen on a 400 ms debounce after send/receive/receipt/read changes.
  `deleteConversation` removes the row and closes the in-memory session;
  "delete for me" removes the message from the local thread only. Logout or
  identity lock flushes pending saves first, then locks the store and drops
  the key.
- Outbound messages persisted mid-send (`sending`) restore as `failed`, never
  as a falsely confirmed status. Undecryptable or tampered rows are skipped
  silently so storage corruption cannot break chat.
- Sessions/ratchet state are **not** persisted: on reload the peer
  re-establishes a session via `session_init` before the restored thread can
  send again.

## Read/delivery receipts

- Receipts reference the original `id` and are relayed the same way.
- Receipt rendering exists on the sender side; the read-receipt UI is wired
  into the chat view (status ticks) but delivery/read timestamps are not
  persisted server-side.

## Offline buffering

- The client does NOT batch messages while offline: un-encrypted plaintext is
  never staged. Pending client messages are re-sent on reconnect.
- Server-side pending queue carries opaque ciphertext only.

## Server send timeout

- `MESSAGE_QUEUE_TTL_SECONDS` bounds how long undelivered messages stay in
  the offline queue before being pruned.
- Live-socket sends have a bounded wait; on timeout the message is queued if
  the recipient is offline-capable, otherwise failed loudly.