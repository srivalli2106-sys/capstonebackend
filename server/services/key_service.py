"""key_service.py — key-bundle upload, retrieval, and OPK consumption rules.

Owns the business decisions that used to live in :mod:`server.routes.keys`:
user existence, hex/byte-length validation of key material, the upload
(upsert) decision, bundle retrieval followed by single-use OPK consumption,
and OPK availability reporting. Persistence mechanics (including the atomic
OPK consumption) are delegated to the injected repositories so the atomic
find-one-and-update stays at the database level.

PQ (post-quantum) material is optional: a bundle may declare
``protocol_version == 1`` and omit every PQ field, in which case the
classical X3DH + Double Ratchet path is used exactly as before. When
``protocol_version == 2``, the server structurally validates the byte
lengths of the supplied PQ public material; cryptographic verification of
the ML-DSA binding signature happens on the peer's device during the
handshake, because the server has no ML-DSA implementation.
"""

from __future__ import annotations

from ..exceptions import InvalidRequest, ResourceNotFound
from ..repositories.key_repository import key_repository
from ..repositories.protocols import KeyRepository, UserRepository
from ..repositories.user_repository import user_repository
from protocol.keys import (  # noqa: I001  (absolute: protocol is a top-level package)
    PROTOCOL_VERSION_CLASSICAL,
    PROTOCOL_VERSION_HYBRID,
)

# xdh_public/spk_public/opk_public are hex-encoded 32-byte X25519 keys ->
# 64 hex chars / 32 bytes. spk_sig is a hex-encoded 64-byte Ed25519 signature
# -> 128 hex chars / 64 bytes.
_KEY_BYTES = 32
_SIGNATURE_BYTES = 64
_PQ_KEM_BYTES = 1184  # ML-KEM-768 public key (hex chars = 2368)
_PQ_SIG_BYTES = 1312  # ML-DSA-44 public key (hex chars = 2624)
_PQ_SIG_LENGTH_BYTES = 2420  # ML-DSA-44 signature (hex chars = 4840)


class KeyService:
    """Business rules for key bundles (no persistence logic)."""

    def __init__(
        self,
        users: UserRepository | None = None,
        keys: KeyRepository | None = None,
    ) -> None:
        self._users = users or user_repository
        self._keys = keys or key_repository

    async def upload(
        self,
        user_id: str,
        xdh_public_hex: str,
        spk_public_hex: str,
        spk_sig_hex: str,
        opk_public_hex: str | None,
        pq_kem_public_hex: str | None = None,    # optional ML-KEM-768 public key
        pq_sig_public_hex: str | None = None,    # optional ML-DSA-44 public key
        pq_binding_sig_hex: str | None = None,   # optional ML-DSA-44 signature
        protocol_version: int = PROTOCOL_VERSION_CLASSICAL,
    ) -> dict[str, str]:
        """Validate and upsert the user's key bundle.

        All PQ parameters default to ``None``/classical so every previously-
        existing caller — including the entire test suite — continues to
        work byte-identically.

        Raises :class:`ResourceNotFound` for unknown users and
        :class:`InvalidRequest` for malformed/mis-sized key material.
        """
        user = await self._users.get_user(user_id)
        if user is None:
            raise ResourceNotFound("User not found. Register first.")

        try:
            xdh_bytes = bytes.fromhex(xdh_public_hex)
            spk_bytes = bytes.fromhex(spk_public_hex)
            sig_bytes = bytes.fromhex(spk_sig_hex)
        except ValueError as exc:
            raise InvalidRequest(
                "xdh_public, spk_public, and spk_sig must be hex"
            ) from exc
        if len(xdh_bytes) != _KEY_BYTES:
            raise InvalidRequest("xdh_public must be 32 bytes")
        if len(spk_bytes) != _KEY_BYTES:
            raise InvalidRequest("spk_public must be 32 bytes")
        if len(sig_bytes) != _SIGNATURE_BYTES:
            raise InvalidRequest("spk_sig must be 64 bytes")

        # OPK is optional and stays a classical X25519 key.
        opk_bytes: bytes | None = None
        if opk_public_hex is not None:
            try:
                opk_bytes = bytes.fromhex(opk_public_hex)
            except ValueError as exc:
                raise InvalidRequest("opk_public must be hex") from exc
            if len(opk_bytes) != _KEY_BYTES:
                raise InvalidRequest("opk_public must be 32 bytes")

        # Optional PQ material. We validate byte lengths structurally; we
        # do NOT verify ML-DSA signatures here (server has no ML-DSA impl).
        pq_kem_bytes: bytes | None = None
        if pq_kem_public_hex is not None:
            try:
                pq_kem_bytes = bytes.fromhex(pq_kem_public_hex)
            except ValueError as exc:
                raise InvalidRequest("pq_kem_public must be hex") from exc
            if len(pq_kem_bytes) != _PQ_KEM_BYTES:
                raise InvalidRequest(
                    f"pq_kem_public must be {_PQ_KEM_BYTES} bytes (ML-KEM-768)"
                )

        pq_sig_bytes: bytes | None = None
        if pq_sig_public_hex is not None:
            try:
                pq_sig_bytes = bytes.fromhex(pq_sig_public_hex)
            except ValueError as exc:
                raise InvalidRequest("pq_sig_public must be hex") from exc
            if len(pq_sig_bytes) != _PQ_SIG_BYTES:
                raise InvalidRequest(
                    f"pq_sig_public must be {_PQ_SIG_BYTES} bytes (ML-DSA-44)"
                )

        pq_binding_sig_bytes: bytes | None = None
        if pq_binding_sig_hex is not None:
            try:
                pq_binding_sig_bytes = bytes.fromhex(pq_binding_sig_hex)
            except ValueError as exc:
                raise InvalidRequest("pq_binding_sig must be hex") from exc
            if len(pq_binding_sig_bytes) != _PQ_SIG_LENGTH_BYTES:
                raise InvalidRequest(
                    f"pq_binding_sig must be {_PQ_SIG_LENGTH_BYTES} bytes (ML-DSA-44)"
                )

        # Cross-field consistency: a hybrid bundle must include every PQ
        # public field. Partial hybrids are rejected (no silent downgrade).
        if protocol_version == PROTOCOL_VERSION_HYBRID:
            missing = [
                name
                for name, value in (
                    ("pq_kem_public", pq_kem_bytes),
                    ("pq_sig_public", pq_sig_bytes),
                    ("pq_binding_sig", pq_binding_sig_bytes),
                )
                if value is None
            ]
            if missing:
                raise InvalidRequest(
                    "protocol_version=2 requires every PQ field; missing: "
                    + ", ".join(missing)
                )
        elif protocol_version not in (PROTOCOL_VERSION_CLASSICAL, PROTOCOL_VERSION_HYBRID):
            raise InvalidRequest(
                f"protocol_version must be {PROTOCOL_VERSION_CLASSICAL} or {PROTOCOL_VERSION_HYBRID}"
            )

        await self._keys.upsert_key_bundle(
            user_id,
            xdh_bytes,
            spk_bytes,
            sig_bytes,
            opk_bytes,
            pq_kem_bytes,
            pq_sig_bytes,
            pq_binding_sig_bytes,
            int(protocol_version),
        )
        return {"status": "ok", "user_id": user_id}

    async def get_bundle(self, target_user_id: str) -> dict[str, object]:
        """Return the bundle as a hex-encoded response dict, consuming the OPK.

        The OPK is consumed through the repository's atomic
        ``find_one_and_update`` (single-use, concurrency-safe): exactly one of
        any concurrent fetches receives the available prekey and serves it in
        the response; every other caller sees ``None``. The other bundle
        fields are read once, before consumption (consumption only nulls the
        one-time prekey).

        The peer's registered Ed25519 auth identity (``ik_public``) rides along
        so the X3DH initiator can verify the signed prekey. The X25519 X3DH
        identity (``xdh_public``) is also served so the initiator can compute
        ``DH(EK_A, IKX_B)`` and bind the session AD to the two X3DH
        identities.

        PQ material is included when present (``protocol_version`` = 2); the
        ML-DSA binding signature is relayed as opaque hex and verified by
        the peer's device.
        """
        bundle = await self._keys.get_key_bundle(target_user_id)
        if bundle is None:
            raise ResourceNotFound("Key bundle not found")
        user = await self._users.get_user(target_user_id)
        if user is None:
            raise ResourceNotFound("Key bundle not found")

        opk_public = await self._keys.consume_opk(target_user_id)

        return {
            "user_id": bundle["user_id"],
            "ik_public": user["ik_public"].hex(),
            "xdh_public": bundle["xdh_public"].hex(),
            "spk_public": bundle["spk_public"].hex(),
            "spk_sig": bundle["spk_sig"].hex(),
            "opk_public": opk_public.hex() if opk_public is not None else None,
            "pq_kem_public": (
                bundle["pq_kem_public"].hex()
                if bundle.get("pq_kem_public") is not None
                else None
            ),
            "pq_sig_public": (
                bundle["pq_sig_public"].hex()
                if bundle.get("pq_sig_public") is not None
                else None
            ),
            "pq_binding_sig": (
                bundle["pq_binding_sig"].hex()
                if bundle.get("pq_binding_sig") is not None
                else None
            ),
            "protocol_version": int(bundle.get("protocol_version", PROTOCOL_VERSION_CLASSICAL)),
        }

    async def opk_status(self, target_user_id: str) -> dict[str, object]:
        """Report whether an unconsumed OPK is available for the user."""
        bundle = await self._keys.get_key_bundle(target_user_id)
        if bundle is None:
            raise ResourceNotFound("Key bundle not found")

        return {
            "user_id": bundle["user_id"],
            "opk_available": bundle.get("opk_public") is not None,
            "version": bundle.get("version", 1),
        }


key_service = KeyService()
