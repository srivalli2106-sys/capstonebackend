# Threat Model

## Assets

| Asset | Attacker goal |
| --- | --- |
| message plaintext | read, forge, replay |
| identity seed / device keys | impersonate a user, decrypt history |
| passphrase | unlock identity seed |
| JWT | session hijack, impersonation |
| sessions / ratchet state | derive keys, decrypt an active conversation |
| local chat history (ciphertext at rest) | read a stored thread (needs the device key + passphrase-gated unlock) |
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
| Quantum attacker on classical X3DH | ML-KEM-768 shared secret still secures the hybrid root (assuming ML-KEM-768 unbroken) | ML-KEM-768 cryptanalysis advances (FIPS 203) |
| Classical attacker on ML-KEM-768 | X25519 DH still secures the hybrid root | ECDLP break (negligible in practice) |
| Signature forgery on Ed25519 | ML-DSA-44 binding signature still authenticates the bundle | ML-DSA-44 cryptanalysis advances (FIPS 204) |
| Signature forgery on ML-DSA-44 | Ed25519 SPK signature still authenticates the bundle | large-scale quantum computer against Ed25519 |
| Silent hybrid → classical downgrade | `protocol_version` is cryptographically bound into the transcript and the binding sig; the KDF rejects v1 transcripts when v2 was negotiated | none observed |
| Bundle material swap (tamper PQ pubs in transit) | ML-DSA binding sig covers all bundle fields; Ed25519 SPK sig covers `ik || xdh || spk` | full key compromise |
| Local history leak (offline) | AES-256-GCM at rest, key from device identity, non-extractable, account bound | device key + passphrase both compromised |
| Local history tampering | AEAD with AD bound to both account ids; tampered rows skipped | none beyond silent loss of that row |
| UI spoofing / phishing | server-authoritative envelopes, verified sender | contested-identity handling is out of scope |

## Residual risks (documented limitations)

- **Session ratchet state not persisted**: sessions and ratchet state are
  memory-only; an app restart forces a fresh X3DH handshake. Conversation
  history is persisted encrypted at rest, but **sessions are never saved**.
- **History is single-device and local-only**: no cloud sync; the stored rows
  are bound to one device key. A lost passphrase/identity means the local
  history is unrecoverable (consistent with the no-recovery rule).
- **"Delete" is local-only**: delete-for-me and delete-conversation remove
  local state; they do not delete ciphertext queued on the server or on the
  peer's device.
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

- Session persistence (encrypted at rest) to survive restarts (history is now
  persisted; ratchet/session state is not).
- Key rotation endpoint (`/keys/rotate`) and revocation UX.
- DoS guards per-socket and per-IP byte budgets; WS auth backoff.
- Content Security Policy + `Trusted Types` hardening.
- Independent third-party crypto audit of `protocol/` and `src/crypto/`.