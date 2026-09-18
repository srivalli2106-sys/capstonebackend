"""key_repository.py — MongoDB persistence for the ``key_bundles`` collection.

Owns SPK/OPK key-bundle mechanics: upsert (version-bumping), read, and the
single-use OPK consumption. Consumption uses one atomic
``find_one_and_update`` guarded on an unconsumed OPK so concurrent consumers
can never receive the same key — deliberately not a Python read-then-write.
"""

from __future__ import annotations

from datetime import datetime, timezone

from pymongo import ReturnDocument

from ..db import get_db


class KeyRepository:
    """Persistence mechanics for key bundles (no business rules)."""

    async def upsert_key_bundle(
        self,
        user_id: str,
        xdh_public: bytes,
        spk_public: bytes,
        spk_sig: bytes,
        opk_public: bytes | None,
    ) -> None:
        db = get_db()
        bundle = await db["key_bundles"].find_one({"user_id": user_id})
        if bundle is not None:
            await db["key_bundles"].update_one(
                {"user_id": user_id},
                {
                    "$set": {
                        "xdh_public": xdh_public,
                        "spk_public": spk_public,
                        "spk_sig": spk_sig,
                        "opk_public": opk_public,
                        "version": bundle.get("version", 1) + 1,
                        "uploaded_at": datetime.now(timezone.utc),
                    }
                },
            )
            return
        await db["key_bundles"].insert_one(
            {
                "user_id": user_id,
                "xdh_public": xdh_public,
                "spk_public": spk_public,
                "spk_sig": spk_sig,
                "opk_public": opk_public,
                "version": 1,
                "uploaded_at": datetime.now(timezone.utc),
            }
        )

    async def get_key_bundle(self, user_id: str) -> dict | None:
        db = get_db()
        return await db["key_bundles"].find_one({"user_id": user_id})

    async def consume_opk(self, user_id: str) -> bytes | None:
        """Atomically return and consume (set to null) the user's OPK.

        Returns None when no OPK is currently available. MongoDB serializes
        the update per document, so concurrent consumers are safe.
        """
        db = get_db()
        bundle = await db["key_bundles"].find_one_and_update(
            {
                "user_id": user_id,
                "opk_public": {"$exists": True, "$ne": None},
            },
            {"$set": {"opk_public": None}},
            return_document=ReturnDocument.BEFORE,
        )
        if bundle is None:
            return None
        return bundle.get("opk_public")


key_repository = KeyRepository()
