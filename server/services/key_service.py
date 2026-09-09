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

# spk/sig/opk are hex-encoded 32-byte X25519 keys -> 64 hex chars; 32 bytes.
_KEY_BYTES = 32


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
            spk_bytes = bytes.fromhex(spk_public_hex)
            sig_bytes = bytes.fromhex(spk_sig_hex)
        except ValueError as exc:
            raise InvalidRequest("spk_public and spk_sig must be hex") from exc
        if len(spk_bytes) != _KEY_BYTES:
            raise InvalidRequest("spk_public must be 32 bytes")

        opk_bytes = None
        if opk_public_hex is not None:
            try:
                opk_bytes = bytes.fromhex(opk_public_hex)
            except ValueError as exc:
                raise InvalidRequest("opk_public must be hex") from exc
            if len(opk_bytes) != _KEY_BYTES:
                raise InvalidRequest("opk_public must be 32 bytes")

        await self._keys.upsert_key_bundle(user_id, spk_bytes, sig_bytes, opk_bytes)
        return {"status": "ok", "user_id": user_id}

    async def get_bundle(self, target_user_id: str) -> dict[str, object]:
        """Return the bundle as a hex-encoded response dict, consuming the OPK.

        The OPK is consumed through the repository's atomic
        ``find_one_and_update`` (single-use, concurrency-safe); the bundle is
        then re-read for the response. Exactly one OPK is ever handed out.
        """
        bundle = await self._keys.get_key_bundle(target_user_id)
        if bundle is None:
            raise ResourceNotFound("Key bundle not found")

        await self._keys.consume_opk(target_user_id)
        bundle = await self._keys.get_key_bundle(target_user_id)

        return {
            "user_id": bundle["user_id"],
            "spk_public": bundle["spk_public"].hex(),
            "spk_sig": bundle["spk_sig"].hex(),
            "opk_public": (
                bundle["opk_public"].hex() if bundle.get("opk_public") else None
            ),
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
