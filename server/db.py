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
from pymongo import ReturnDocument
from pymongo.errors import DuplicateKeyError

from .config import settings

# MongoDB connection string and database name come from the centralized
# configuration. Format: mongodb+srv://<user>:<password>@<cluster>.mongodb.net/<database>
DATABASE_URL = settings.mongodb_uri
DATABASE_NAME = settings.mongodb_database

_client: AsyncIOMotorClient | None = None


def _client_options() -> dict:
    """Explicit connection/pool bounds sourced from the centralized settings.

    socketTimeoutMS stays unset (None) unless configured so long-running
    reads are not silently killed.
    """
    return {
        "appname": settings.app_name,
        "serverSelectionTimeoutMS": settings.mongodb_server_selection_timeout_ms,
        "connectTimeoutMS": settings.mongodb_connect_timeout_ms,
        "socketTimeoutMS": settings.mongodb_socket_timeout_ms,
        "maxPoolSize": settings.mongodb_max_pool_size,
        "minPoolSize": settings.mongodb_min_pool_size,
        "maxIdleTimeMS": settings.mongodb_max_idle_time_ms,
    }


def get_db():
    """Return a lazily-created, app-wide DB handle (one shared client/pool)."""
    global _client
    if _client is None:
        _client = AsyncIOMotorClient(DATABASE_URL, **_client_options())
    return _client[DATABASE_NAME]


async def ping_mongo() -> bool:
    """Verify MongoDB connectivity. Bounded by the server-selection timeout."""
    db = get_db()
    await db.command("ping")
    return True


async def close_db() -> None:
    """Close the shared client so the event loop exits cleanly on shutdown."""
    global _client
    if _client is not None:
        await _client.close()
        _client = None


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
    except DuplicateKeyError:
        # Only the unique-index violation means "already registered"; other
        # driver errors propagate so they surface as dependency failures.
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
    """Return the OPK public key and set it to None (consumed).

    Uses a single atomic find-one-and-update guarded by
    ``{"opk_public": {"$ne": None}}``: MongoDB serializes the update per
    document, so concurrent consumers can never receive the same OPK.
    Returns None if no OPK is currently available.
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
