# Capstone Review

## What was built

A full-stack, end-to-end encrypted chat application:

- **Frontend** (React 18 + TypeScript + Vite): identity creation and
  passphrase-gated unlock, X3DH + Double Ratchet implementation, key bundle
  management, authenticated WebSocket transport with a typed reconnect
  policy, in-memory session management, receipts and typing indicators.
- **Backend** (Python 3.11 + FastAPI + MongoDB + Redis): proof-of-possession
  auth (challenge/verify, JWT), key bundle distribution with atomic OPK
  consumption, server-authoritative envelope relay, replay de-duplication,
  offline queue, Redis rate limiting (fail-closed HTTP, degrade-open WS),
  health/readiness, security middleware, and a mirrored `protocol/` package
  for cross-implementation protocol vectors.
- **Deployment**: Vercel SPA frontend and a Render-hosted API/WebSocket
  endpoint with Atlas MongoDB and Upstash Redis.

## Evaluation against capstone criteria

| Requirement | Status |
| --- | --- |
| Full-stack architecture | Implemented and integrated end to end |
| Cryptographic correctness | X3DH + Double Ratchet, AES-256-GCM, HKDF/PBKDF2; identical constants verified on both sides |
| Real-time messaging | WebSocket relay, offline queuing, ordered/reordered delivery via skip keys |
| Security posture | PoP auth, JWT revocation, fail-closed defaults, opaque payloads, typed errors |
| Test coverage | 379 backend tests (including 8 integration) + 196 frontend cases; cross-implementation protocol vectors |
| Deployability | Production URLs, health/readiness probes, documented env secrets handling |

## What works end to end

1. Register → local identity → bundle upload.
2. Login via nonce signature → JWT → WS auth.
3. First message bootstraps X3DH → ratchet exchange → plaintext only at the
   two endpoints.
4. Offline delivery via Redis queue; reconnects flush pending ciphertext.
5. Receipts/typing relayed; rate limits and close codes drive the UX.

## What is proven

- Protocol byte-compatibility between `src/crypto/` and `protocol/` through
  shared test vectors.
- Fail-closed behavior when MongoDB/Redis are unavailable (health `503`,
  startup refusal, HTTP `503`, WS `4001`); WS metering degrades open only.
- Replay/expiry protections on challenges, JWTs, and message indices.

## What is missing (see `LIMITATIONS.md`)

- Session/history persistence, key rotation, recovery, contacts/groups/
  attachments, notifications, admin tooling, group E2EE schemes.

## Reflections

- The strongest design decision was the byte-pinned cross-implementation
  protocol with shared HKDF domain separation; it turned "two teams' crypto"
  into one testable spec and made failures localize cleanly.
- The main trade-off accepted: no persistence, in exchange for a firmer
  security boundary (keys never leave memory). Future work should address
  encrypted-at-rest sessions and key rotation while preserving the same
  invariants.
- Client-side crypto was implemented against Web Crypto + `@noble/curves`
  and independently mirrored in `protocol/` using `cryptography`; the two
  implementations double-check each other in CI.

## Future work

- Encrypted session persistence + import/export UX; key rotation endpoints
  and revocation UI; group messaging (Sender Keys/MLS-style E2EE); web push
  for offline recipients; CSP/Trusted Types; multi-replica deployment with a
  stateless WS broker.