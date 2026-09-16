"""protocol — reference implementation of the E2EE layer (Phase 13).

This package is a self-contained, pure-Python reference implementation of the
message-encryption scheme the backend relays:

  * X3DH key agreement (:mod:`protocol.x3dh`) between a device and a peer's
    key bundle (identity key, signed prekey, one-time prekeys) already stored
    and served by the backend (:mod:`server.repositories.key_repository`).
  * The Double Ratchet (:mod:`protocol.ratchet`) providing per-message forward
    secrecy and tamper-evident AEAD ciphertext.
  * A thin session orchestrator (:mod:`protocol.session`) that glues X3DH to
    the ratchet and mirrors the ``session_init`` / ``session_accept`` envelope
    types in :mod:`server.envelope`.

The server never runs this package: it only stores key material, serves it
over ``/keys/*``, and relays ciphertext produced here, unchanged, inside the
message envelope's opaque ``data`` field. Clients embed this package (or an
equivalent implementation) to build the E2EE layer.

Security note: this is a reference implementation for a learning / demo
project. It is not an audited, production-grade cryptographic library.
"""
