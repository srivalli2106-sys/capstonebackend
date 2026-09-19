# Architecture

## System overview

Two independent deployments cooperate: a browser SPA that owns all
cryptography and identity state, and a stateless HTTP/WebSocket API that owns
accounts, key-bundle storage, authentication, and reliable ciphertext relay.

```
                        ┌───────────────────────────────────────────┐
                        │              Browser / SPA                │
                        │                                            │
                        │  React UI ─ controllers ─ crypto layer     │
                        │   AuthController     Ed25519 / X25519      │
                        │   KeyController      X3DH                  │
                        │   WebSocketController  Double Ratchet      │
                        │   ChatController     AES-256-GCM / PBKDF2  │
                        │        │                    │              │
                        │   IndexedDB (encrypted)     │              │
                        └────────┼────────────────────┼──────────────┘
                                 │ HTTPS REST         │ WSS
                                 ▼                    ▼
                        ┌───────────────────────────────────────────┐
                        │            Backend API (FastAPI)          │
                        │                                            │
                        │  Middleware: SecurityHeaders → RequestID   │
                        │              → CORS → AllowedHosts         │
                        │  Routes: /auth /keys /ws /health           │
                        │  Services: auth, key, message, presence    │
                        │  Crypto: JWT (HS256), Ed25519 verify, PoP  │
                        │                                            │
                        └──────────┬──────────────────┬──────────────┘
                                   │                  │
                                   ▼                  ▼
                           MongoDB (Atlas)      Redis (Upstash)
                           users, key_bundles   ratelimits, challenges,
                                                revocation, presence,
                                                offline queue
```

## Responsibilities by component

### Frontend (capstonefrontend)

- Generates and holds the Ed25519 auth identity plus X25519 device keys.
- Encrypts the private material to IndexedDB under a passphrase-derived key.
- Runs proof-of-possession authentication against `/auth/*`.
- Publishes and fetches key bundles via `/keys/*`.
- Establishes X3DH sessions and encrypts/decrypts every message with the
  Double Ratchet.
- Maintains one WebSocket connection for realtime delivery and enforces the
  client-side envelope contract.

### Backend (capstonebackend)

- Registers identities and stores public auth keys.
- Issues challenges and verifies Ed25519 proof of possession.
- Issues and verifies HS256 JWTs with issuer pinning and jti revocation.
- Stores key bundles in MongoDB and atomically consumes the one-time prekey.
- Runs a single `/ws` endpoint: first-frame auth, envelope validation,
  dedup, presence, per-user rate gates, offline queueing, and reconnect
  flush.
- Enforces per-IP HTTP rate limits using a Redis sliding window.
- Renders every HTTP error through one JSON contract and stamps every
  response with a request ID.

## Frontend module dependency graph

```
main.tsx
  └─ App.tsx
       ├─ realtime/setup.ts        wiring of the realtime stack
       │    ├─ WebSocketController  transport lifecycle + reconnect
       │    │    └─ WebSocketClient  browser socket wrapper
       │    └─ ChatController        in-memory E2EE session store
       │         ├─ crypto/e2eeSession (X3DH + Double Ratchet)
       │         ├─ crypto/keyBundle (bundle parsing)
       │         └─ api/keys (bundle fetch)
       ├─ routes/router.tsx         react-router routes
       ├─ components/*               AppShell, RequireAuth, AuthLayout
       ├─ pages/*                    per-route pages
       └─ controllers (singletons)
            ├─ auth/AuthController      identity + JWT state
            ├─ keys/KeyController       bundle upload orchestration
            └─ api/*                    typed HTTP wrappers (http.ts)
```

## Backend middleware stack

Executed in this order on the way in (last registered runs first):

```
SecurityHeaders → RequestID → CORS → AllowedHosts → router
```

- `AllowedHostsMiddleware` (innermost) validates the `Host` header from
  `ALLOWED_HOSTS`; `*` disables it in development.
- `CORSMiddleware` applies `CORS_ORIGINS`; `allow_credentials=True`,
  methods and headers `*`.
- `RequestIDMiddleware` generates an `X-Request-ID` per request, echoes it
  on the response, and correlates logs.
- `SecurityHeadersMiddleware` adds headers (HSTS only when
  `SECURE_TRANSPORT=true`).
- Centralized error handlers convert all failures to
  `{"error": {"code", "message", "request_id"}}`.

## Reliability properties

- MongoDB is mandatory: startup fails fast if it is unreachable.
- Redis is best-effort at startup: presence, offline queue, and rate limits
  degrade at runtime rather than blocking users.
- The WebSocket registry, presence, and rate limiting are process-local by
  design; exactly one server process is supported (see `DEPLOYMENT.md`).
- All delivery, queueing, and rate-limit paths treat an unverifiable state as
  a failure that never claims success.