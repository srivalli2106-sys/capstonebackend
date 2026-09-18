"""key_service.py — key-bundle upload, retrieval, and OPK consumption rules.

Owns the business decisions that used to live in :mod:`server.routes.keys`:
user existence, hex/byte-length validation of key material, the upload
(upsert) decision, bundle retrieval followed by single-use OPK consumption,
and OPK availability reporting. Persistence mechanics (including the atomic
OPK consumption) are delegated to the injected repositories so the atomic
find-one-and-update stays at the database level.
"""

from __future__ import annotations

from ..exceptions import InvalidRequest, ResourceNotFound
from ..repositories.key_repository import key_repository
from ..repositories.protocols import KeyRepository, UserRepository
from ..repositories.user_repository import user_repository

# xdh_public/spk_public/opk_public are hex-encoded 32-byte X25519 keys ->
# 64 hex chars / 32 bytes. spk_sig is a hex-encoded 64-byte Ed25519 signature
# -> 128 hex chars / 64 bytes.
_KEY_BYTES = 32
_SIGNATURE_BYTES = 64


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
    ) -> dict[str, str]:
        """Validate and upsert the user's key bundle.

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

        opk_bytes = None
        if opk_public_hex is not None:
            try:
                opk_bytes = bytes.fromhex(opk_public_hex)
            except ValueError as exc:
                raise InvalidRequest("opk_public must be hex") from exc
            if len(opk_bytes) != _KEY_BYTES:
                raise InvalidRequest("opk_public must be 32 bytes")

        await self._keys.upsert_key_bundle(
            user_id, xdh_bytes, spk_bytes, sig_bytes, opk_bytes
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
        so the X3DH initiator can verify the signed prekey (Phase 13). The
        X25519 X3DH identity (``xdh_public``) is also served so the initiator
        can compute ``DH(EK_A, IKX_B)`` and bind the session AD to the two
        X3DH identities.
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
            "version": bundle.get("version", 1),
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
