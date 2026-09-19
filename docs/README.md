# Secure Messaging

A proof-of-possession authenticated, end-to-end encrypted (E2EE) one-to-one
messaging application built as a university capstone. Cryptography runs
entirely in the browser; the backend signs users in, relays opaque ciphertext,
and never sees plaintext.

This documentation set is canonical and identical in both repositories:

- `D:\Capstone\capstonefrontend` - React 18 + TypeScript + Vite single-page app
- `D:\Capstone\capstonebackend` - FastAPI service with MongoDB and Redis

## What it does

1. Users register with a self-generated Ed25519 identity key (`ik_public`).
   The private seed never leaves the browser except as ciphertext in
   IndexedDB, protected by a passphrase (PBKDF2 + AES-256-GCM).
2. Login is a proof-of-possession exchange: the backend issues a nonce, the
   client signs it with its local Ed25519 key, and the backend returns a JWT
   (`POST /auth/challenge` + `POST /auth/verify`).
3. Each device provisions X25519 X3DH key material (identity IKX, signed
   prekey SPK, one-time prekey OPK) and publishes the public bundle via
   `POST /keys/upload`.
4. Conversations establish X3DH sessions (the initiator fetches the peer
   bundle via `GET /keys/bundle/{user_id}`), then encrypt messages with a
   Signal-style Double Ratchet (AES-256-GCM + HKDF-SHA256).
5. Ciphertext is relayed over a single authenticated WebSocket at
   `/ws`. The server enforces envelope format, rate limits, deduplication,
   presence, and an offline queue; it cannot read message content.

## Repositories and prerequisites

- Frontend: Node.js 18+ (Vite 5, React 18). Scripts: `npm run dev`,
  `npm run build`, `npm run typecheck`, `npm test`.
- Backend: Python 3.11+ (FastAPI, motor, pymongo, redis, PyJWT,
  cryptography). Run with `uvicorn server.app:app`. See `docs/SETUP.md`.

## Documentation index

| Document | Covers |
| --- | --- |
| `ARCHITECTURE.md` | System overview, components, module breakdown |
| `SETUP.md` | Local development setup for both repos |
| `ENVIRONMENT.md` | Every environment variable and its behavior |
| `FRONTEND_STRUCTURE.md` | Frontend module layout and wiring |
| `BACKEND_STRUCTURE.md` | Backend module layout and wiring |
| `APPLICATION_FLOW.md` | End-to-end flows (register, login, chat) |
| `AUTHENTICATION.md` | Proof-of-possession auth, JWT, logout |
| `IDENTITY_AND_KEY_STORAGE.md` | Local identity lifecycle and IndexedDB schema |
| `KEY_MANAGEMENT.md` | X3DH key bundle lifecycle |
| `X3DH.md` | X3DH key agreement implementation |
| `DOUBLE_RATCHET.md` | Double Ratchet message encryption |
| `ENCRYPTION.md` | Full cryptographic inventory and wire formats |
| `WEBSOCKET.md` | Realtime transport, close codes, rate gates |
| `MESSAGING.md` | Envelope types and delivery/queue semantics |
| `SESSION_MANAGEMENT.md` | Session lifecycle on client and server |
| `DATA_FLOW.md` | Bytes from plaintext to ciphertext and back |
| `API_INTEGRATION.md` | Frontend HTTP/WS integration layer |
| `SECURITY.md` | Security model, trust boundaries, headers |
| `THREAT_MODEL.md` | Adversaries, assets, mitigations, residual risk |
| `RATE_LIMITING.md` | Rate limits and sliding-window mechanics |
| `ERROR_HANDLING.md` | Error contract, codes, request IDs, WS close codes |
| `STATE_MANAGEMENT.md` | Frontend controller singletons and hooks |
| `UI_UX.md` | Pages, routing, components, styles |
| `TESTING.md` | Test strategy, commands, coverage facts |
| `DEPLOYMENT.md` | Vercel, Render, Atlas, Upstash deployment |
| `TROUBLESHOOTING.md` | Common problems and fixes |
| `LIMITATIONS.md` | Honest list of what is not implemented |
| `CAPSTONE_REVIEW.md` | Phase-by-phase summary and reflection |

## Design invariants

- The server never stores or logs plaintext or private key material.
- Identity private keys never leave the JS heap except as AEAD ciphertext.
- The server is authoritative over `sender`, `timestamp`, and `version` on
  every envelope; client-supplied values are overwritten.
- Sessions are ephemeral in-memory state on both sides; nothing ratchet
  related is persisted.
- Production configuration fails fast on missing or placeholder secrets.