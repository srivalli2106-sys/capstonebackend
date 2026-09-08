"""
db.py — MongoDB (Atlas) database models and async client.

Uses Motor (async MongoDB driver).

Collections:
  users       — one-time registration (user_id UNIQUE, ik_public)
  key_bundles — SPK + OPK bundles, OPK deleted after use
"""

from __future__ import annotations

from datetime import datetime, timezone

from motor.motor_asyncio import AsyncIOMotorClient

from .config import settings

# MongoDB connection string and database name come from the centralized
# configuration. Format: mongodb+srv://<user>:<password>@<cluster>.mongodb.net/<database>
DATABASE_URL = settings.mongodb_uri
DATABASE_NAME = settings.mongodb_database

_client: AsyncIOMotorClient | None = None


def get_db():
    global _client
    if _client is None:
        _client = AsyncIOMotorClient(DATABASE_URL)
    return _client[DATABASE_NAME]


async def init_db() -> None:
    """Create unique indexes. Registering the same user_id twice fails."""
    db = get_db()
    await db["users"].create_index("user_id", unique=True)
    await db["key_bundles"].create_index("user_id", unique=True)


# ---------------------------------------------------------------------------
# Users
# ---------------------------------------------------------------------------


async def register_user(user_id: str, ik_public: bytes) -> bool:
    """
    Insert a new user. Returns False (raises no error) if user_id already exists.
    The unique index on user_id enforces one-time registration.
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
    except Exception:
        return False


async def get_user(user_id: str) -> dict | None:
    db = get_db()
    return await db["users"].find_one({"user_id": user_id})


# ---------------------------------------------------------------------------
# Key bundles
# ---------------------------------------------------------------------------


async def upsert_key_bundle(
    user_id: str,
    spk_public: bytes,
    spk_sig: bytes,
    opk_public: bytes | None,
) -> None:
    db = get_db()

    bundle = await db["key_bundles"].find_one({"user_id": user_id})

    if bundle is not None:
        update = {
            "$set": {
                "spk_public": spk_public,
                "spk_sig": spk_sig,
                "opk_public": opk_public,
                "version": bundle.get("version", 1) + 1,
                "uploaded_at": datetime.now(timezone.utc),
            }
        }
        await db["key_bundles"].update_one({"user_id": user_id}, update)
        return

    await db["key_bundles"].insert_one({
        "user_id": user_id,
        "spk_public": spk_public,
        "spk_sig": spk_sig,
        "opk_public": opk_public,
        "version": 1,
        "uploaded_at": datetime.now(timezone.utc),
    })


async def get_key_bundle(user_id: str) -> dict | None:
    db = get_db()
    return await db["key_bundles"].find_one({"user_id": user_id})


async def consume_opk(user_id: str) -> bytes | None:
    """
    Return the OPK public key and set it to None (consumed).
    Returns None if no OPK available.
    """
    db = get_db()
    bundle = await db["key_bundles"].find_one({"user_id": user_id})
    if bundle is None or bundle.get("opk_public") is None:
        return None

    opk = bundle["opk_public"]
    await db["key_bundles"].update_one(
        {"user_id": user_id}, {"$set": {"opk_public": None}}
    )
    return opk
