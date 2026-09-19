# Security

Security properties and controls across the stack, with the threat posture
in `THREAT_MODEL.md`.

## Authentication

- **Proof-of-possession, no shared password**: the server stores only an
  Ed25519 public fingerprint (`ik_public`). The client signs a server-issued
  random nonce with its private key.
- **Nonce**: 32 random bytes, 64 hex chars, server-generated, single-use,
  TTL-limited (default 120 s), atomically consumed; expiry/replay of a
  consumed challenge is rejected.
- **Fail closed**: unknown user, missing/expired/replayed challenge, malformed
  input, and bad signature all yield the same generic 401
  "Authentication failed" — no user enumeration through timing or message.
- **No secret storage server-side**: the passphrase and derived keys exist
  only in the browser; the server cannot decrypt or re-derive them.

## Credential/PBKDF2 handling (client)

- `PBKDF2-SHA256`, 600,000 iterations, 16-byte per-record random salt,
  256-bit key — used to derive the identity key from the passphrase.
- Passphrase unlocks the wrapped identity in IndexedDB; nobody but the device
  owner can open a device seed.
- Passphrase is ephemeral in JS memory; it is not persisted anywhere.

## Tokens (JWT)

- HS256 with a random server-side secret (`JWT_SECRET`, dev placeholder
  values are rejected / blocked), default 24 h expiry.
- Claims: `sub`, `iss`, `iat`, `exp`, `jti`, plus `user_id` (legacy mirror
  for key routes). Verifier requires all of them, pins the algorithm and
  issuer.
- Server-side revocation map `auth_revoked:{jti}`: logout and admin revoke
  fail closed; WebSocket connections watch revocation and close `4001`.
- JWT never stored in `localStorage`; it lives in `sessionStorage` (cleared
  on lock/logout). No XSS-adjacent persistence.

## Transport

- Production: HTTPS/WSS end to end; `SECURE_TRANSPORT` enables HSTS and
  forbids `http` cookies.
- `AllowedHosts` middleware drops unknown `Host` headers; CORP/CORS policies
  restrict browser embedding and cross-origin API use to the configured
  frontend.
- `X-Request-ID` echoes on every response and every error body, linking a
  server-side trace to one client request.

## Realtime

- WS auth: mandatory first-frame `auth` within `WS_AUTH_TIMEOUT_SECONDS`
  (default 10 s) or close `4001`.
- JWT revocation/expiry closes live sockets `4001` (background watcher).
- Rate gates `ws_connect` (per IP) and `ws_message` (per user); over-limit
  connections refused with 429, over-limit frames close the peer with `4003`.
- Message ids de-duplicated server-side (replay-resilient).

## Server hardening

- Middleware order: AllowedHosts -> SecurityHeaders -> RequestID -> CORS ->
  ErrorHandler; errors normalize to a single JSON contract, internal
  exceptions never leak stack traces.
- Playloads are opaque: the message service never deserializes or logs
  envelope `data`; logs redact JWT and keys.
- Redis-outage semantics: HTTP auth/keys/lookup fail closed (503), WS limits
  degrade open (delivery continues).

## Key hygiene

- All key material stays in the browser: X25519 X3DH identity, SPK/OPKs, the
  ML-KEM-768 kem identity, the ML-DSA-44 sig identity, and the derived
  ratchet/chain/message keys.
- Signed prekey binding uses an explicit domain-separated context
  (`secure-messaging-signed-prekey-v1`) preventing signature reuse across
  apps/roles.
- PQ key bundle binding uses an explicit domain-separated context
  (`secure-messaging-hybrid-binding-v1`) that signs the exact classical
  and PQ public material together so a classical-only attacker cannot
  silently inject or substitute PQ material.
- OPKs are single-use and consumed atomically server-side.

## Hybrid classical + post-quantum E2EE

- Authentication continues to use Ed25519 (signing the SPK and the ML-DSA
  binding signature covers both Ed25519 and ML-DSA contexts on every bundle
  upload). ML-DSA-44 adds a second authentication family with PQ guarantees.
- Key establishment combines X25519 DH (classical X3DH) and ML-KEM-768
  encapsulation. Both shared secrets are combined via a domain-separated,
  length-prefixed HKDF-SHA256 (see `MESSAGING.md` and
  `docs/HYBRID_PQ.md`) so the two components can never be confused.
- The hybrid root secret feeds the existing Double Ratchet unchanged.
- ML-KEM-768 and ML-DSA-44 (NIST FIPS 203 / FIPS 204) are used via
  `@noble/post-quantum` on the device; the server has no PQ library and
  performs only structural validation (byte lengths, classical SPK sig).
- Hybrid mode is opt-in via a `protocol_version` field in the key bundle
  (`1` = classical only, `2` = hybrid). Classical-only clients continue
  to work without any change.

### What the hybrid construction is and is not

* The combined root secret is NOT an arbitrary concatenation; the IKM to
  HKDF-Expand is framed as `transcript || LP(Z_classical) || Z_classical ||
  LP(Z_pq) || Z_pq` where `LP` is a 2-byte big-endian length prefix. The
  framing is locked in shared test vectors across the two implementations.
* We do NOT claim "quantum-proof" or "post-quantum secure" beyond what
  the implemented construction actually provides. A successful quantum
  adversary that breaks ML-KEM-768 still has to also break the classical
  X3DH shared secret to recover the ratchet root. A successful quantum
  adversary that breaks Ed25519 still has to forge a valid ML-DSA-44
  binding signature. The two authentication families and the two key
  agreement families give us defense in depth; the specific security
  level of the combination is an open research question and we make no
  precise claim beyond "neither classical-only nor PQ-only compromise
  breaks the handshake unaided".
* The hybrid KDF info string (`secure-messaging-hybrid-root-v1`) and
  the transcript context (`secure-messaging-hybrid-kem-handshake-v1`)
  are versioned constants; changing them breaks every existing transcript
  and is gated by tests on both sides.

## Local history at rest (client)

- Chat history is persisted locally under a **dedicated** IndexedDB database
  (`secure-messaging-chat`) and is AES-256-GCM encrypted at rest.
- The storage key is HKDF-SHA256 of the device's X25519 identity private key
  (`ikx`) with a domain-separated context (`secure-messaging-chat-history-v1`
  + account); the derived AES-GCM key is imported **non-extractable**, so it
  cannot be read out of the Web Crypto boundary.
- Rows are authenticated data (AD = context + `selfUserId` + `peerUserId`):
  one account/device key cannot decrypt another's rows, and tampered rows are
  skipped rather than surfaced.
- Plaintext never touches disk: records carry only iv/ciphertext hex plus
  envelope metadata. The store drops its key on lock/logout, so local history
  is unreadable while the device is locked.