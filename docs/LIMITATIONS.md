# Limitations

Honest account of what the capstone does not do, and why.

## E2EE lifecycle

- **Sessions are memory-only.** Ratchet state, skipped-key buffers, and the
  X3DH root are never persisted. An app restart or reload forces a fresh
  `session_init`. `export()`/`import()` exist and are tested but are not wired
  into the app.
- **History is persisted, but locally and per-device.** Conversation history
  survives reload via an AES-256-GCM IndexedDB store (`secure-messaging-chat`)
  bound to the device identity key. Limitations that remain:
  - no cross-device sync: the rows live on one device only;
  - no restore-to-new-device path: a lost passphrase or wiped device makes
    local history unrecoverable (no back-up by design);
  - deletes are local-only (delete-for-me, delete-conversation): ciphertext
    still queued on the server or held by the peer is not removed;
  - the offline queue still holds server-side ciphertext until TTL/prune.
- **Export format caveat.** Frontend and backend serialize ratchet/session
  state with slightly different AD-length packing (`>B 8B…` vs `>B B B I`);
  the formats are verified per side, but byte-level cross-compatibility is
  not asserted. Deliberately out of the shipped path.

## Keys and identities

- **No key rotation.** `SPK`/OPK replacement or a re-issue of `ik_public`
  after compromise is not implemented (only the initial upload).
- **No recovery.** A lost passphrase is unrecoverable; there is no backup or
  admin reset by design.
- **Single device.** One identity per device, one socket per user — a second
  login replaces the first (`4000 REPLACED`).

## Messaging surface

- **No contact / conversation management.** No search, lists, group chats,
  or conversation metadata beyond the rendered thread.
- **Attachments** exist only as a `file` envelope type; there is no upload or
  blob transport.
- **Receipts** are emitted but not persisted; the chat UI shows status ticks
  in-memory only.
- **Typing indicators** are fire-and-forget; no presence history.
- **No notifications** (no web push; offline peers are caught by the queue
  flush on next connect).

## Security posture gaps

- **Metadata is visible** (sender, recipient, timestamps, envelope types,
  typing) to the server even though payloads are opaque.
- **Client-side crypto** relies on Web Crypto + `@noble/curves` +
  `@noble/post-quantum`; audit is manual and pinned dependencies are the
  only guard against supply-chain compromise.
- **JWT via HS256** means one shared secret across instances (deployed
  single-process).
- **WS rate gates degrade open** on a Redis outage (delivery preserved over
  strict metering); HTTP paths stay fail-closed.
- No CSP/`Trusted Types` hardening in the built bundle.
- The hybrid KDF's combined security level is not formally analyzed;
  the construction is documented in `docs/HYBRID_PQ.md` and pinned by
  shared deterministic test vectors, but no precise "bits of security"
  claim is made for the combination.
- The ML-DSA binding signature is verified on the peer device only; the
  server does not have an ML-DSA implementation and validates the bundle
  structurally (byte lengths and the classical Ed25519 SPK signature).
- PQ mode is opt-in. Classical-only clients continue to work with the
  previous protocol byte-for-byte.

## Deployment constraints

- Single-instance backend; no horizontal scaling or multi-replica sessions.
- JWT revocation and rate state rely on Redis; losing Redis preserves auth
  security but stops strict metering for WS.
- `Vercel`-published frontend has no server-rendered fallback content (pure
  SPA + rewrite).

## Deliberately excluded for scope

- Mobile/native clients, push, media processing, group E2EE (Sender Keys,
  MLS), user search, moderation/abuse reporting, admin console, localization,
  offline-first PWA.
- Migration of users or data between environments.

These items are the natural "future work" track (see `CAPSTONE_REVIEW.md`).