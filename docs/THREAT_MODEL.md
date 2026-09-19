# Threat Model

## Assets

| Asset | Attacker goal |
| --- | --- |
| message plaintext | read, forge, replay |
| identity seed / device keys | impersonate a user, decrypt history |
| passphrase | unlock identity seed |
| JWT | session hijack, impersonation |
| sessions / ratchet state | derive keys, decrypt an active conversation |
| user metadata | fingerprint users, build profiles |

## Adversary classes

1. **Network observer**: sees TLS traffic only; can capture ciphertext
   packets (not plaintext), metadata (sender/recipient/timestamps), and WebSocket
   envelopes.
2. **Server operator / DB dump**: MongoDB/Redis data: user ids, identity
   fingerprints, JWTs, offline ciphertext queues. No plaintext, no keys.
3. **Compromised peer**: the legitimate counterparty who can always read a
   conversation.
4. **Offline attacker with device storage**: IndexedDB blobs and ambient
   caches extracted from the machine.
5. **Malicious JS / supply chain**: any script that can run in the app origin
   (XSS-equivalent). Not currently mitigated beyond React defaults.

## Threat-to-mitigation matrix

| Threat | Mitigation | Residual risk |
| --- | --- | --- |
| Password theft / DB leak | server stores only `ik_public`; PoP via challenge nonce | passphrase entropy is the residual risk |
| Passphrase brute force | PBKDF2 600k iterations, random salt | weak passphrases stay weak; client-side |
| Replay of challenge | single-use, TTL, atomic consume | none |
| Mittm impersonation | X3DH identity binding + TLS; SPK signed and verified | compromised CA / cert issuance |
| Message forgery | AEAD with authenticated header + AD-bound X3DH identities | none in-band |
| Message replay | per-message chain index + server id de-dup window | window races in multi-device setups (single-device now) |
| Message reordering | skipped-key buffer up to MAX_SKIP=1000 | delivery beyond buffer is dropped |
| Forward secrecy breach | per-ratchet, per-message keys; old keys discarded | none (in-memory only) |
| DoS / ab/use | HTTP rate limits (fail closed) + WS rate gates + timeouts | Redis-out WS degrades open |
| Device theft | passphrase-gated unlock; keys in memory only | machine-level compromise of the browser process |
| UI spoofing / phishing | server-authoritative envelopes, verified sender | contested-identity handling is out of scope |

## Residual risks (documented limitations)

- **No persistence**: sessions and history are memory-only; an app restart
  forces a fresh X3DH handshake. See `LIMITATIONS.md`.
- **Metadata leakage**: recipients, senders, timestamps, frame types, and
  typing indicators are visible to the server as metadata.
- **Client-side crypto review burden**: Web Crypto / noble-curves / a package
  pinned in `package.json`; audit is manual.
- **JWT secret distribution**: HS256 means one shared secret across replicas;
  deployed single-instance.
- **Out-of-band recovery**: a lost passphrase is unrecoverable by design
  (no back-door, no reset). Registered users cannot be un-fingerprinted if
  their key is compromised (rotation not implemented).

## Recommended follow-ups

- Session persistence (encrypted at rest) to survive restarts.
- Key rotation endpoint (`/keys/rotate`) and revocation UX.
- DoS guards per-socket and per-IP byte budgets; WS auth backoff.
- Content Security Policy + `Trusted Types` hardening.
- Independent third-party crypto audit of `protocol/` and `src/crypto/`.