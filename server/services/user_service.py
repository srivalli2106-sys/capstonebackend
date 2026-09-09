"""user_service.py — user/account registration business rules.

Owns the validation semantics and duplicate-user handling that used to live
in the :mod:`server.routes.auth` register handler. Persistence mechanics are
delegated to the injected :class:`UserRepository`.
"""

from __future__ import annotations

from ..exceptions import Conflict, InvalidRequest
from ..repositories.protocols import UserRepository
from ..repositories.user_repository import user_repository

# Ed25519 public identity keys are hex-encoded 32 bytes -> 64 hex chars.
_IDENTITY_KEY_BYTES = 32


class UserService:
    """Business rules for account registration (no persistence logic)."""

    def __init__(self, users: UserRepository | None = None) -> None:
        self._users = users or user_repository

    async def register(self, user_id: str, ik_public_hex: str) -> str:
        """Register ``user_id``; raises on invalid input or duplicates.

        Returns the registered ``user_id`` on success. Validation order and
        messages match the pre-refactor route contract exactly.
        """
        if len(user_id) < 3:
            raise InvalidRequest("user_id too short")

        try:
            ik_bytes = bytes.fromhex(ik_public_hex)
        except ValueError as exc:
            raise InvalidRequest("ik_public must be hex") from exc
        if len(ik_bytes) != _IDENTITY_KEY_BYTES:
            raise InvalidRequest("ik_public must be 32 bytes")

        ok = await self._users.register_user(user_id, ik_bytes)
        if not ok:
            raise Conflict(
                f"User '{user_id}' already registered. Re-registration is not allowed."
            )
        return user_id


user_service = UserService()
