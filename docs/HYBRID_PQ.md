# HYBRID_PQ — Classical + Post-Quantum E2EE

This document describes the hybrid classical + post-quantum E2EE layer
that augments the existing X25519 + Ed25519 + Double Ratchet + AES-256-GCM
protocol with ML-KEM-768 and ML-DSA-44.

The goal is defense in depth: a successful cryptanalytic attack against
either the classical or the post-quantum family alone does not break the
handshake unaided. We make no claim stronger than what the construction
actually provides.

## Threat model delta (additions to `THREAT_MODEL.md`)

| New threat | Mitigation |
| --- | --- |
| Quantum attacker breaks X25519 ECDLP | ML-KEM-768 still secures `Z_pq` in the hybrid root |
| Classical attacker breaks ML-KEM-768 | X25519 ECDLP still secures `Z_classical` |
| Quantum attacker forges Ed25519 SPK sig | ML-DSA-44 binding sig covers the same bundle fields |
| Classical attacker forges ML-DSA-44 sig | Ed25519 SPK sig covers the same bundle fields |
| Attacker swaps PQ public material in transit | ML-DSA binding sig is over all bundle fields (classical + PQ) together |
| Silent downgrade to classical | `protocol_version` is bound into the transcript and into the binding sig |
| Reused secret across contexts | All KDF inputs are domain-separated (`secure-messaging-hybrid-kem-handshake-v1` for the transcript, `secure-messaging-hybrid-root-v1` for HKDF-Expand info) |
| Ambiguous concatenation attack | Each shared secret in the IKM is length-prefixed with a 2-byte big-endian length |

## Algorithms

| Role | Algorithm | Standard | Implementation |
| --- | --- | --- | --- |
| Authentication (classical) | Ed25519 | RFC 8032 | `@noble/curves` |
| Authentication (PQ) | ML-DSA-44 | NIST FIPS 204 | `@noble/post-quantum` |
| Key agreement (classical) | X25519 | RFC 7748 | `@noble/curves` |
| Key agreement (PQ) | ML-KEM-768 | NIST FIPS 203 | `@noble/post-quantum` |
| Key derivation | HKDF-SHA256 | RFC 5869 | Web Crypto + `cryptography` |
| Message encryption | AES-256-GCM | NIST SP 800-38D | Web Crypto + `cryptography` |
| Session ratchet | Double Ratchet | (existing) | unchanged |

## Construction

### Key bundle binding

The device signs a canonical binding context with its long-term ML-DSA
key:

```
HYBRID_BIND_CONTEXT = b"secure-messaging-hybrid-binding-v1"

binding_message =
    HYBRID_BIND_CONTEXT
    || ik_public        // Ed25519, 32 bytes
    || xdh_public       // X25519, 32 bytes
    || spk_public       // X25519, 32 bytes
    || protocol_version // b"v2"
    || pq_kem_public    // ML-KEM-768, 1184 bytes
    || pq_sig_public    // ML-DSA-44, 1312 bytes

pq_binding_sig = ML-DSA-44.sign(device.pq_sig_priv, binding_message)
```

The classical Ed25519 SPK signature is unchanged:

```
spk_sig = Ed25519.sign(device.auth_priv,
                       b"secure-messaging-signed-prekey-v1" || spk_public)
```

The initiating device verifies BOTH signatures before using the bundle.
The server only verifies the Ed25519 SPK signature (it has no ML-DSA
implementation); ML-DSA verification happens on the peer device during
the handshake.

### Session transcript

```
TRANSCRIPT_CONTEXT = b"secure-messaging-hybrid-kem-handshake-v1"

transcript = SHA-256(
    TRANSCRIPT_CONTEXT
    || version_tag     // 1 byte (1 or 2)
    || alice_ik_pub    // 32 bytes
    || alice_ikx_pub   // 32 bytes
    || bob_ik_pub      // 32 bytes
    || bob_ikx_pub     // 32 bytes
    || bob_spk_pub     // 32 bytes
    || bob_pq_kem_public // 1184 bytes
    || bob_pq_sig_public // 1312 bytes,
)
```

### Hybrid KDF

```
ROOT_INFO = b"secure-messaging-hybrid-root-v1"

LP(x) = 2-byte big-endian length prefix of x (length prefix prevents
       ambiguous concatenation; the two shared secrets cannot be confused
       even when one of them is short).

ikm = transcript
      || LP(Z_classical) || Z_classical
      || LP(Z_pq)       || Z_pq

root_secret = HKDF-SHA256(
    ikm,
    info  = ROOT_INFO,
    salt  = b"",
    length = 32,
)
```

`Z_classical` is the existing X3DH shared secret (the 32-byte output of
the classical X3DH key schedule). `Z_pq` is the 32-byte ML-KEM-768
shared secret (Alice encapsulates to Bob's `pq_kem_public`; Bob
decapsulates with his own `pq_kem_private`).

Both sides MUST arrive at the same `root_secret`, which then seeds the
existing Double Ratchet exactly as the classical X3DH shared secret does
today.

### Wire format (session_init)

```
v1 = >B 32s 32s B
   = version(1) | ik_x_public_A(32) | ek_public_A(32) | opk_index(1)

v2 = >B 32s 1088s 1184s 32s B
   = version(1)
     | ik_x_public_A(32)
     | kem_ciphertext(1088)        // ML-KEM-768 capsule from Alice
     | alice_pq_kem_public(1184)   // ML-KEM-768 public key
     | ek_public_A(32)
     | opk_index(1)
```

The responder (`x3dhRespondHybrid`) decapsulates `kem_ciphertext` using
its own `pq_kem_private` to recover `Z_pq`. The classical X3DH inputs
(`ik_x_public_A`, `ek_public_A`, `opk_index`) are processed identically
to the v1 responder path.

### Compatibility / downgrade rules

* A classical-only client (`protocol_version == 1`) advertises no PQ
  material; its bundle is byte-compatible with the previous protocol.
* A hybrid client (`protocol_version == 2`) MUST publish all three PQ
  fields plus a valid binding signature; partial hybrids are rejected
  by the bundle parser (HTTP 400) and by the client-side verifier.
* A v2 INIT payload with malformed length, truncated KEM ciphertext, or
  unknown version byte is rejected with a precise `X3dhError`.
* A v2 INIT arriving at a classical-only responder (or vice versa)
  produces no hybrid session; the responder surfaces a version
  mismatch and the UI may fall back to classical if the user opts in.

There is NO silent downgrade: a hybrid session either establishes with
the hybrid KDF or fails loudly. Mixed-version sessions are not
constructed.

## Where PQ private material lives

* `pq_kem_private` (2400 bytes opaque) is generated on the device,
  stored ONLY inside the encrypted device-keys envelope (`pbkdf2-sha256`
  + `AES-256-GCM` under the passphrase), and never transmitted.
* `pq_sig_private` (2560 bytes opaque) is generated on the device,
  stored the same way, and never transmitted.
* `pq_binding_sig` (2420 bytes) is the ML-DSA signature over the
  binding context; it is the only PQ-derivative artefact that leaves
  the device, and it is public.

## Server responsibilities

* Store PQ PUBLIC keys (1184 + 1312 bytes) and the binding signature
  (2420 bytes) in the key bundle, alongside the classical material.
* Validate byte lengths (1184, 1312, 2420) and the classical Ed25519
  SPK signature.
* Reject any bundle whose `protocol_version` field is invalid.
* Reject any hybrid bundle missing a PQ field.
* DO NOT generate, derive, store, or verify PQ private material.

The server's complete PQ responsibility is structural validation plus
the classical Ed25519 check. The ML-DSA binding signature is verified
end-to-end on the peer device during the handshake, which is the only
place that can verify it correctly.

## Testing

* `tests/test_hybrid_kdf.py` (backend) and `test/hybridKdf.test.ts`
  (frontend) share the same deterministic test vectors; both
  implementations MUST stay byte-compatible.
* `tests/test_x3dh_v2.py` (backend) and `test/x3dhV2.test.ts`
  (frontend) verify the v2 wire format (pack, unpack, dispatch, and
  length rejection).
* `tests/test_hybrid_session.py` (backend) and `test/hybridSession.test.ts`
  (frontend) exercise the full hybrid handshake end-to-end using
  injected ML-KEM encaps/decaps callbacks. The frontend test uses
  `@noble/post-quantum` for real ML-KEM and ML-DSA operations; the
  backend test uses a deterministic mock so the protocol code can be
  exercised without a native PQ library in the test runner.
* `test/pq.test.ts` (frontend) exercises ML-KEM-768 keygen/encaps/decaps
  and ML-DSA-44 sign/verify with tamper-rejection.
* `test/keyBundlePq.test.ts` (frontend) verifies the bundle parser
  accepts valid hybrid bundles and rejects incomplete or tampered
  ones.

## Limitations and honest gaps

* The ML-DSA binding signature is verified client-side, not server-side.
  This is by design (the server has no PQ library) but means a peer
  MUST verify the binding signature before completing a hybrid session.
* The server does NOT distinguish "this device is hybrid-capable" from
  "this device is classical-only" beyond the bundle fields; a hybrid
  peer must refuse a classical peer's PQ-less bundle explicitly.
* The combined security level of the hybrid KDF is not formally
  analyzed; we make no precise claim beyond defense in depth. The
  deterministic test vectors pin the construction so any future change
  is auditable.
* The hybrid mode is opt-in. A classical-only device remains
  byte-compatible with the previous protocol and does not need to
  regenerate keys.
