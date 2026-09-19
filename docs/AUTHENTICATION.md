# Authentication

The production authentication path is proof of possession (PoP): a client
proves it holds the private half of the Ed25519 identity key it registered,
by signing a server-issued nonce.

## Endpoints

All bodies are JSON. Rate limits apply per endpoint (see `RATE_LIMITING.md`).

### POST /auth/register

Creates a user with its registered Ed25519 public identity key.

```json
// request
{ "user_id": "alice", "ik_public": "<64 hex chars>" }
// 201
{ "status": "registered", "user_id": "alice" }
// 409 conflict
{ "error": { "code": "conflict", "message": "...", "request_id": "..." } }
```

- `user_id` bounded to 64 characters; unique index enforces one registration.
- `ik_public` is the hex form of the RFC 8032 Ed25519 public key (32 bytes ->
  64 hex chars). The backend does not verify the key at registration; it is
  verified later when a signature arrives.
- `user_id` is also used as a MongoDB document key and a Redis key suffix.

### POST /auth/login (development/test only)

Returns a JWT for any existing user without proof of possession. Hard-disabled
when `APP_ENV=production` (HTTP 403). Production clients must never use it.

### POST /auth/challenge

```json
// request
{ "user_id": "alice" }
// 200
{ "user_id": "alice", "nonce": "<64 hex chars = 32 random bytes>" }
// 404 not_found  (unknown user)
```

- Nonce is 32 random bytes, hex-encoded (64 chars).
- Challenge is stored in Redis (`auth_challenge:{user_id}`) with a TTL of
  `AUTH_CHALLENGE_TTL_SECONDS` (default 120s).

### POST /auth/verify

```json
// request
{ "user_id": "alice", "nonce": "<64 hex>", "signature": "<128 hex>" }
// 200
{ "token": "<jwt>", "user_id": "alice" }
// 401  Authentication failed  (generic, always)
```

- The signature is a raw Ed25519 signature over the RAW 32 nonce bytes
  (`bytes.fromhex(nonce_hex)`), NOT the ASCII hex string. The frontend signs
  the decoded bytes (see `AuthController.runChallengeVerifyAgainstUnlocked`).
- The challenge is consumed ATOMICALLY before signature verification, so a
  challenge is single-use even against signature-oracle attempts.
- Every failure path returns the identical message `Authentication failed`
  with 401: unknown user, malformed hex, wrong lengths (nonce != 32 bytes or
  signature != 64 bytes), missing/replayed/expired challenge, or bad
  signature. Nothing about the failure reason is leaked.

### POST /auth/logout

Bearer-token protected. Revokes the token's `jti` in Redis
(`auth_revoked:{jti}`) for the remaining token lifetime.

```json
{ "status": "logged_out" }
```

## JWT

Created and verified in `server/jwt_auth.py`.

| Claim | Meaning |
| --- | --- |
| `sub` | user_id |
| `iss` | configured issuer (`JWT_ISSUER`), validated on verify |
| `iat` | issued-at epoch seconds |
| `exp` | expiry epoch seconds (`JWT_EXPIRY_HOURS`, default 24h) |
| `jti` | cryptographically random token id (128 bits) for revocation |
| `user_id` | legacy mirror claim, kept equal to `sub` for consumers |

Verification:

- Pins the configured algorithm (HS256 default; only HS256/384/512 accepted).
- Requires the full claim set (`sub`, `iss`, `iat`, `exp`, `jti`).
- Validates the issuer.
- Rejects expired signatures and maps every failure to HTTP 401 with a stable
  message (`Token expired` / `Invalid token`). No token bytes, algorithms, or
  internal detail are logged or returned.

Revocation is checked by `AuthService.require_auth` (HTTP) and
`ws_auth.verify_ws_token` (WebSocket). A Redis error during the revocation
check fails closed: HTTP routes propagate 503; the WebSocket handshake
rejects with 4001. Tokens are never silently accepted when revocation state
cannot be verified.

## Frontend integration

- `AuthController.register` performs: local identity creation, backend
  register, then PoP login, with rollback of the local record on failure.
- `AuthController.login` unlocks locally FIRST (wrong passphrase never reaches
  the backend, which avoids leaking user existence), then runs PoP.
- A JWT is persisted in `sessionStorage` (`secure-messaging:jwt` +
  `secure-messaging:user_id`) so reloads inside a tab keep the session; it is
  never stored in `localStorage`.
- A single 401 hook clears the session when any API call or WebSocket
  handshake fails authentication (`/auth/logout` responses are excluded from
  the hook).
- Identity unlock state is tracked separately from JWT state; the transport
  disconnects when the identity is locked even if the JWT is still valid.

## Security properties

- The challenge TTL is short by design: a stolen challenge is only usable for
  that window.
- The challenge nonce is fresh per request and single-use.
- Because verification is fail-closed and generic, this endpoint gives an
  attacker no oracle for user existence or failure detail.