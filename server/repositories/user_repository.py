"""user_repository.py — MongoDB persistence for the ``users`` collection.

Owns registration and user lookups. One-time registration is enforced by the
unique ``user_id`` index created at startup (see :func:`server.db.init_db`);
a duplicate insert is detected via ``DuplicateKeyError`` so no read-then-write
race exists. Connection/pool lifecycle lives in :mod:`server.db`.
"""

from __future__ import annotations

from datetime import datetime, timezone

from pymongo.errors import DuplicateKeyError

from ..db import get_db


class UserRepository:
    """Persistence mechanics for user documents (no business rules)."""

    async def register_user(self, user_id: str, ik_public: bytes) -> bool:
        """Insert a new user; False when ``user_id`` already exists.

        Only the unique-index violation is treated as "already registered";
        any other driver error propagates so it surfaces as a dependency
        failure rather than a false 409.
        """
        db = get_db()
        doc = {
            "user_id": user_id,
            "ik_public": ik_public,
            "created_at": datetime.now(timezone.utc),
        }
        try:
            await db["users"].insert_one(doc)
            return True
        except DuplicateKeyError:
            return False

    async def get_user(self, user_id: str) -> dict | None:
        db = get_db()
        return await db["users"].find_one({"user_id": user_id})


user_repository = UserRepository()
