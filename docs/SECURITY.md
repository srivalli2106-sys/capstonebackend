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

- All key material stays in the browser: X25519 X3DH identity, SPK/OPKs, and
  the derived ratchet/chain/message keys.
- Signed prekey binding uses an explicit domain-separated context
  (`secure-messaging-signed-prekey-v1`) preventing signature reuse across
  apps/roles.
- OPKs are single-use and consumed atomically server-side.