# Capstone Review

## What was built

A full-stack, end-to-end encrypted chat application:

- **Frontend** (React 18 + TypeScript + Vite): identity creation and
  passphrase-gated unlock, X3DH + Double Ratchet implementation, key bundle
  management, authenticated WebSocket transport with a typed reconnect
  policy, encrypted-at-rest local history, in-memory session management,
  hybrid classical + post-quantum E2EE (ML-KEM-768 + ML-DSA-44),
  receipts and typing indicators, and a WhatsApp-style chat UI (date
  separators, typing bubble, scroll/jump-to-latest, delete-for-me and
  delete-conversation with confirmation).
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
| Test coverage | 379 backend tests (including 8 integration) + ~250 frontend cases; cross-implementation protocol vectors; hybrid PQ KDF vectors pinned on both sides |
| Deployability | Production URLs, health/readiness probes, documented env secrets handling |

## What works end to end

1. Register → local identity → bundle upload.
2. Login via nonce signature → JWT → WS auth.
3. First message bootstraps X3DH (classical v1 OR hybrid v2) → ratchet exchange
   → plaintext only at the two endpoints.
4. Offline delivery via Redis queue; reconnects flush pending ciphertext.
5. Receipts/typing relayed; rate limits and close codes drive the UX.
6. Conversation history survives reload, encrypted at rest on the device; on
   relaunch the thread rehydrates and the session re-establishes before
   sending resumes.
7. Hybrid v2 session: ML-KEM-768 encapsulation + ML-DSA-44 binding
   signature verified end-to-end on the peer device; hybrid root secret
   feeds the same Double Ratchet as v1.

## What is proven

- Protocol byte-compatibility between `src/crypto/` and `protocol/` through
  shared test vectors.
- Fail-closed behavior when MongoDB/Redis are unavailable (health `503`,
  startup refusal, HTTP `503`, WS `4001`); WS metering degrades open only.
- Replay/expiry protections on challenges, JWTs, and message indices.

## What is missing (see `LIMITATIONS.md`)

- Session/ratchet persistence, cross-device history sync, key rotation,
  recovery, contacts/groups/attachments, notifications, admin tooling, group
  E2EE schemes, formally analyzed security level for the combined hybrid
  KDF.

## Reflections

- The strongest design decision was the byte-pinned cross-implementation
  protocol with shared HKDF domain separation; it turned "two teams' crypto"
  into one testable spec and made failures localize cleanly. Adding the
  hybrid classical + post-quantum layer preserved that property by
  pinning another set of constants (`secure-messaging-hybrid-binding-v1`,
  `secure-messaging-hybrid-kem-handshake-v1`,
  `secure-messaging-hybrid-root-v1`) shared between the two implementations
  and verified by deterministic test vectors.
- The main trade-off accepted: encrypted-at-rest history keeps the thread
  across reloads while keys still never leave memory unprotected; ratchet
  state remains deliberately unpersisted for forward secrecy. Future work
  should address session persistence and key rotation while preserving the
  same invariants.
- Client-side crypto was implemented against Web Crypto + `@noble/curves`
  and `@noble/post-quantum`, and independently mirrored in `protocol/`
  using `cryptography`; the two implementations double-check each other
  in CI.

## Future work

- Encrypted session persistence + cross-device history sync + import/export
  UX; key rotation endpoints and revocation UI; group messaging (Sender
  Keys/MLS-style E2EE); web push for offline recipients; CSP/Trusted Types;
  multi-replica deployment with a stateless WS broker.