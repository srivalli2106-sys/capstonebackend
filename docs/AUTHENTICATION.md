# Authentication

How a client proves who it is, gets a token, and is checked on every protected
operation. Implemented in `server/auth_service.py`, `server/jwt_auth.py`,
`server/auth_store.py`, and wired in `server/routes/auth.py`.

---

## 1. Identity model

- Each user registers **once** with a `user_id` and the 64-hex-char public half
  of an **Ed25519 identity key** (`ik_public`, 32 bytes). A unique index on
  `user_id` makes re-registration impossible (409).
- The device keeps the Ed25519 private key; the server stores only the public
  half and uses it to verify proof of possession.

## 2. Production login: proof of possession (challenge/verify)

```
POST /auth/challenge  { "user_id": "alice" }
  → checks the user exists, then stores a fresh 32-byte random nonce
    (auth_challenge:alice, TTL = AUTH_CHALLENGE_TTL_SECONDS, 120 s by default)
  → 200 { "user_id": "alice", "nonce": "<64 hex chars>" }

(client signs the nonce with its Ed25519 private key)

POST /auth/verify  { "user_id": "alice", "nonce": "<hex>", "signature": "<hex>" }
  → atomically consumes the challenge (single-use, see below)
  → verifies the 64-byte Ed25519 signature against ik_public
  → 200 { "token": "<JWT>", "user_id": "alice" }
```

- **One outstanding challenge per user**: a new `/challenge` replaces the
  previous one.
- **Atomic consumption**: the nonce is removed with `GETDEL` (or a Lua fallback
  on Redis < 6.2). A replayed challenge can never succeed, even concurrently.
- **Fail closed**: unknown user, bad hex, wrong size, missing/replayed/expired
  challenge, and invalid signature all return the identical
  `401 {"error":{"code":"http_401","message":"Authentication failed",...}}`.
  Nothing about the failure reason leaks.
- A Redis error during this path propagates as `503 dependency_unavailable`
  (never "accept").

## 3. Development login (local/test convenience)

```
POST /auth/login  { "user_id": "alice" }
  → returns a JWT for any EXISTING user, no proof of possession
```

- Enabled in `APP_ENV=development` and `test` only.
- **Returns HTTP 403 in production**; production clients must use the
  challenge/verify flow.
- Purpose: lets you exercise Swagger and manual workflows locally without a
  client that can sign.

## 4. JWT format (`server/jwt_auth.py`)

Tokens are `PyJWT` HMAC JWTs. Every issued token carries:

| Claim | Meaning |
|-------|---------|
| `sub` | `user_id` (authoritative) |
| `iss` | `JWT_ISSUER` (default `secure-messaging-api`), validated on every verify |
| `iat` | issued-at (epoch seconds) |
| `exp` | `iat + JWT_EXPIRY_HOURS * 3600` |
| `jti` | unique random token id (`secrets.token_urlsafe(16)`) used for revocation |
| `user_id` | legacy duplicate of `sub` kept for existing consumers |

Verification (every path that checks a token):

- signature — pinned to the **configured** algorithm (`HS256|HS384|HS512`);
  the `algorithms=[JWT_ALGORITHM]` list accepts exactly one value, so `none`
  and mixed-algorithm attacks are impossible;
- `iss` — must equal `JWT_ISSUER`;
- all required claims `{sub, iss, iat, exp, jti}` present and type-safe.

Failures are collapsed to stable `401` messages ("Token expired" / "Invalid
token"); token bytes, algorithms, and internals are never logged or returned.

## 5. Revocation & logout

- `POST /auth/logout` (Bearer JWT) blacklists the token's `jti` for **the rest
  of its lifetime** (`auth_revoked:{jti}`, TTL = `exp - now`, clamped to ≥ 1 s).
- `require_auth` checks the blacklist on every protected HTTP route.
- WebSocket connections re-check revocation periodically and close (4001) when
  a token is revoked (see [WEBSOCKET.md](WEBSOCKET.md)).
- Revocation TTL is bounded by token lifetime — the blacklist never grows
  unbounded.

## 6. Protected HTTP routes

| Route | Protection |
|-------|------------|
| `POST /keys/upload` | `require_auth` |
| `GET /keys/bundle/{user_id}` | `require_auth` |
| `GET /keys/prekeys/{user_id}` | `require_auth` |
| `POST /auth/logout` | `require_auth` |
| `GET /auth/challenge` `/verify` | public (rate-limited) |

`require_auth` (`server/auth_service.py`) is the centralized FastAPI
dependency: verifies signature/algorithm/issuer/expiry/required claims **and**
revocation. If the revocation read fails (Redis down) it raises `503` — a token
is never silently accepted. Unauthenticated requests get
`401 Missing bearer token`.

## 7. WebSocket authentication relationship

The WebSocket handshake uses the **same** tokens (`verify_access_token` +
revocation via `is_token_revoked`) but the token is sent as the **first frame**
(`{"type":"auth","token":"<JWT>"}`), not in the query string. Verification is
strictly fail-closed; failures close the socket with `4001`. Details in
[WEBSOCKET.md](WEBSOCKET.md).

## 8. Dependencies

| Dependency | Used for | Failure |
|------------|----------|---------|
| Redis | challenge storage + atomic consume; revocation blacklist | Fail closed (503 / 4001) |
| MongoDB | user lookup (`ik_public`, existence) | 503 dependency_unavailable |

## 9. Security notes

- Ed25519 is used only for **signing/verification** (identity). X3DH identity
  keys (X25519 `IKX`) are a separate, client-held key — see
  [E2EE.md](E2EE.md).
- Knowing a user's `ik_public` does not grant login: the challenge is bound to
  the private key via the signature.
- Tokens are opaque to the server; only `jti` is tracked for revocation.