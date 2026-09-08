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

from .config import settings
from .db import init_db
from .exceptions import install_exception_handlers
from .logging_config import setup_logging
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
    logger.info("initializing database connection...")
    await init_db()
    logger.info("database ready.")
    yield
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
