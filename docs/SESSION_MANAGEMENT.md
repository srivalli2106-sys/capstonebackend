# Session Management

How E2EE sessions are created, routed, stored, and torn down on both sides.

## What a session is

A `E2EESession` pairs two users' devices:

- the X3DH shared secret (`SK`) as the ratchet root key,
- the associated data (`AD = IKX_A || IKX_B`),
- two ratchet chain states (sending and receiving),
- flags for who initiated.

Frontend session state lives in `src/crypto/e2eeSession.ts`
(`E2EESession.initiate` / `.accept`), hearted by `DoubleRatchet`
(`src/crypto/doubleRatchet.ts`).

## Lifecycle

### 1. Initiation

- Alice fetches Bob's bundle: `GET /keys/bundle/{bob}` (SPK + signature,
  OPK optional).
- She verifies the SPK binding, agrees `SK`, and builds the init frame:
  66 bytes `version|IKX_A|EK_A|opk_index`.
- She sends `session_init` (base64url frame) and stores the pending session.

### 2. Acceptance

- Bob receives `session_init`, recomputes `SK` from his private keys and the
  carried identity/ephemeral publics, marks the OPK index consumed.
- Bob replies with `session_accept` carrying his fresh ratchet public key;
  both sides then run the Double Ratchet symmetrically.

### 3. Steady state

- All `text`/`file` messages are ratchet ciphertexts keyed by the session.
- The peer's ratchet public key change (a DH ratchet step) is handled inside
  `DoubleRatchet` automatically; no session renegotiation is needed.

## Where sessions live

| Storage question | Answer |
| --- | --- |
| Client | in-memory `Map` in `ChatController`, cleared on lock/logout/dispose |
| Server | none — the server only relays opaque envelopes |
| Disk / IndexedDB | never (by design) |

## Persistence and export

- `E2EESession.export()` / `import()` and `DoubleRatchet.export_state()` /
  `from_state_bytes()` exist and are exercised by unit tests
  (deterministic round-trip), but are NOT wired into the running app.
- Cross-implementation byte-equality of the session/state formats is not an
  invariant of the shipped product; docs therefore do not assert that the
  frontend and backend pack the AD length identically (the backend uses
  `>B B B I` for the exported header while the frontend compacts AD length
  into one byte plus padding). Treat the formats as test-only.
- Consequence: an app restart loses all sessions, so conversations resume via
  a fresh `session_init`. This is a deliberate limitation (see
  `LIMITATIONS.md`). Conversation *history* is separate and IS persisted
  encrypted at rest (`src/persistence/chatStore.ts`), so the thread rehydrates
  on reload even though the session must be re-established before sending.

## Multiple devices and reconnects

- One socket per user on the server: a new connection with the same user
  replaces the old one (close `4000 REPLACED`). This keeps per-user channels
  single-writer and simple.
- After reconnect the client re-authenticates with a fresh JWT and any pending
  offline-cached messages are flushed to the socket.
- Sessions are re-established lazily on the first message to a peer whose
  session is missing.

## Lock and logout

| Event | Effect |
| --- | --- |
| `lock()` | identity keys wiped from memory, sessions cleared, socket closed intentionally, JWT removed from sessionStorage |
| `logout()` | same, plus the auth token is revoked server-side |
| app teardown / dispose | `disposeRealtimeTransport()` closes everything; nothing persisted |

## Implications for the reviewer

- No session keys are ever at rest (no backup, no export in UI).
- Server never sees session material; the E2EE boundary is the browser.
- Idle timeouts and replacement sockets are handled by close-code policy
  (`WEBSOCKET.md`).