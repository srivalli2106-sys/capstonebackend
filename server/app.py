"""
app.py — FastAPI application entry point.

Wires up all routes, database initialization, and CORS.
Run with: uvicorn server.app:app --host 0.0.0.0 --port 8000
"""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pymongo.errors import PyMongoError
from redis.exceptions import RedisError

from .config import settings
from .db import close_db, init_db, ping_mongo
from .exceptions import install_exception_handlers
from .logging_config import setup_logging
from .redis_client import close_redis, ping_redis
from .request_id import RequestIDMiddleware
from .routes import auth, keys, messages

setup_logging()
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(application: FastAPI):
    logger.info(
        "application starting: %s version=%s",
        settings.app_name,
        settings.app_version,
    )

    # MongoDB is mandatory for normal operation, so verify connectivity up
    # front (bounded by MONGODB_SERVER_SELECTION_TIMEOUT_MS) and fail fast
    # with a clear log instead of serving requests against an unhealthy DB.
    logger.info("checking mongodb connectivity...")
    try:
        await ping_mongo()
    except PyMongoError as exc:
        logger.error(
            "mongodb unavailable at startup; application cannot continue.",
            exc_info=True,
        )
        raise RuntimeError("MongoDB unavailable at startup") from exc
    logger.info("mongodb reachable.")

    logger.info("initializing database indexes...")
    await init_db()
    logger.info("database ready.")

    # Redis only needs a graceful startup: presence/offline-queue degrade
    # gracefully at runtime, so log a warning and keep serving.
    try:
        await ping_redis()
        logger.info("redis ready.")
    except RedisError:
        logger.warning(
            "redis unavailable at startup; presence and offline-queue "
            "features are degraded until redis returns."
        )

    yield

    logger.info("application shutting down...")
    # Close each dependency independently: a failure on one must not skip
    # the other, and shutdown errors are never allowed to be swallowed
    # silently (they are logged with a traceback).
    try:
        await close_db()
        logger.info("mongodb connection closed.")
    except PyMongoError:
        logger.exception("error closing mongodb connection.")
    try:
        await close_redis()
        logger.info("redis connection closed.")
    except RedisError:
        logger.exception("error closing redis connection.")
    logger.info("application shutdown complete.")


app = FastAPI(
    title=settings.app_name,
    description="E2E encrypted messaging with Double Ratchet protocol",
    version=settings.app_version,
    lifespan=lifespan,
)

# ---------------------------------------------------------------------------
# CORS
# ---------------------------------------------------------------------------

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins_list,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Configures the root logger (idempotent) and correlates each HTTP request
# with a request ID that is echoed on the response and included in logs.
app.add_middleware(RequestIDMiddleware)

# Centralized error handling: every error renders as
# {"error": {"code", "message", "request_id"}}.
install_exception_handlers(app)

# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

app.include_router(auth.router)
app.include_router(keys.router)
app.include_router(messages.router)


@app.get("/health")
async def health():
    return {"status": "ok"}
