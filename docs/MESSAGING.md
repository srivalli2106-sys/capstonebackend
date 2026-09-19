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

## Hybrid classical + post-quantum E2EE

End-to-end sessions are established by an explicitly versioned handshake
that combines X25519 + Ed25519 (classical) with ML-KEM-768 + ML-DSA-44
(post-quantum). Two protocol versions are wired through the same code
path; classical v1 clients interoperate with hybrid v2 peers without
ever mixing formats.

### Versioned wire format

`session_init` carries an opaque `data` field whose leading byte selects
the protocol:

| Version | Bytes | Layout |
| --- | --- | --- |
| `v1` (classical) | 66 | `version(1) \| ik_x_public_A(32) \| ek_public_A(32) \| opk_index(1; 0xFF = none)` |
| `v2` (hybrid)    | 2338 | `version(1) \| ik_x_public_A(32) \| kem_ciphertext(1088) \| alice_pq_kem_public(1184) \| ek_public_A(32) \| opk_index(1)` |

The classical SK, AD, and init payload are unchanged from the previous
protocol; the v2 path adds exactly the ML-KEM-768 ciphertext plus the
initiator's ML-KEM-768 public key, and the responder decapsulates the
ciphertext with its own ML-KEM-768 private key to obtain a 32-byte PQ
shared secret (`Z_pq`). The Double Ratchet, the AEAD, the AD, and every
other downstream piece are byte-compatible between v1 and v2.

### Key bundle extensions

The key bundle served by `/keys/bundle/{user_id}` now optionally carries
PQ material:

| Field | Size (hex chars) | Meaning |
| --- | --- | --- |
| `pq_kem_public` | 2368 | ML-KEM-768 public key (1184 bytes) |
| `pq_sig_public` | 2624 | ML-DSA-44 public key (1312 bytes) |
| `pq_binding_sig`| 4840 | ML-DSA-44 signature (2420 bytes) over the canonical hybrid context |
| `protocol_version` | 1 digit | `1` = classical only, `2` = hybrid (classical + PQ) |

The classical Ed25519 SPK signature (`spk_sig`) and the ML-DSA binding
signature over the canonical context

```
HYBRID_BIND_CONTEXT ("secure-messaging-hybrid-binding-v1")
  || ik_public || xdh_public || spk_public || protocol_version
  || pq_kem_public || pq_sig_public
```

are both verified on the initiating device. The server only validates the
byte lengths and the classical SPK signature; it does not verify ML-DSA
signatures (the server has no ML-DSA implementation; verification happens
on the peer device during the handshake, exactly like every other E2EE
operation).

### Hybrid KDF

Both sides independently derive the same hybrid root secret via a
domain-separated, length-prefixed HKDF-SHA256 composition:

```
transcript = SHA-256(
    "secure-messaging-hybrid-kem-handshake-v1"
    || version_tag (1 byte: 1 or 2)
    || alice_ik_pub || alice_ikx_pub
    || bob_ik_pub || bob_ikx_pub || bob_spk_pub
    || bob_pq_kem_public || bob_pq_sig_public,
)

ikm = transcript
      || LP(Z_classical) || Z_classical
      || LP(Z_pq)       || Z_pq

root_secret = HKDF-SHA256(ikm, info="secure-messaging-hybrid-root-v1", length=32)
```

`LP(x)` is a 2-byte big-endian length prefix so the two 32-byte shared
secrets can never be confused on concatenation; the `version_tag`
distinguishes v1 and v2 transcripts. `Z_classical` is the classical X3DH
shared secret; `Z_pq` is the ML-KEM-768 shared secret. Both sides call
exactly the same function with exactly the same inputs and obtain
exactly the same `root_secret`, which feeds the existing Double Ratchet
unchanged. The construction is documented and pinned in
`src/crypto/hybridKdf.ts` (and mirrored on the backend in
`protocol/hybrid_kdf.py`); the two implementations share deterministic
test vectors and any change requires regenerating both sides together.

### Library and runtime

PQ operations happen ONLY on the device, using
`@noble/post-quantum` (`ml_kem768` and `ml_dsa44`). PQ private keys are
generated on the device and persisted only inside the encrypted
device-keys envelope (PBKDF2-SHA256 + AES-GCM under the passphrase).
The server never sees a PQ private key, never runs ML-KEM, and never
verifies ML-DSA signatures.

### Compatibility

* Classical-only clients (`protocol_version == 1`) continue to work
  without any change.
* A hybrid peer (`protocol_version == 2`) refuses a v1 peer that
  advertises PQ material but lacks the binding signature (or has a
  wrong-length PQ field); the rejection is explicit and surfaces as a
  `KeyBundleError` so the UI can fall back to classical mode if the
  user opts in.
* A v2 INIT payload with malformed or truncated KEM ciphertext is
  rejected by `parseInitPayloadV2` (size 2338 enforced exactly).
* There is no silent downgrade: a hybrid session either establishes
  using the hybrid KDF or fails loudly; the protocol version is
  cryptographically bound to the transcript.

See `docs/HYBRID_PQ.md` for a more detailed rationale, threat-model
notes, and the exact wire-format hex examples.