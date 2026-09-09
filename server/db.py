"""
db.py — MongoDB (Atlas) connection lifecycle and schema initialization.

Collections:
  users       — one-time registration (user_id UNIQUE, ik_public)
  key_bundles — SPK + OPK bundles, OPK deleted after use

The unique ``user_id`` indexes that enforce one-time registration and
single-user key bundles are created here at startup (``init_db``).

All document read/write persistence lives in the repositories layer
(:mod:`server.repositories.user_repository`, :mod:`server.repositories.key_repository`);
this module owns only the shared client, its bounds, health checks, and
shutdown.
"""

from __future__ import annotations

from motor.motor_asyncio import AsyncIOMotorClient

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
