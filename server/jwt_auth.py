"""
jwt_auth.py — JWT creation and verification (Phase 6).

Single source of truth for token signing/verification. HTTPS routes use the
:func:`server.auth_service.require_auth` dependency (which also checks
revocation and fails closed); this module deliberately carries no storage.

Issued tokens carry:
  sub    — user_id
  iss    — configured issuer (required + validated on verify)
  iat    — issued-at epoch seconds
  exp    — expiry epoch seconds (configurable via JWT_EXPIRY_HOURS)
  jti    — cryptographically random unique token ID (for revocation)
  user_id — legacy claim kept for existing consumers (keys routes, the
            Phase-6 WebSocket handshake) so they only ever read one source.

Verification pins the configured algorithm (default HS256), requires the
full claim set, and validates the issuer. All failures map to HTTP 401 with
a stable message; no token bytes, algorithms, or cryptographic internals are
ever logged or returned to the client.
"""

from __future__ import annotations

import secrets
import time
from typing import Any

import jwt
from fastapi import HTTPException

from .config import settings

# READ-ONLY configuration snapshot for the JWT layer.
JWT_SECRET = settings.jwt_secret
JWT_ALGORITHM = settings.jwt_algorithm
JWT_EXPIRY_HOURS = settings.jwt_expiry_hours
JWT_ISSUER = settings.jwt_issuer

# Claims that must be present on every token we accept (jwti, sub, iss, iat, exp).
_REQUIRED_CLAIMS: frozenset[str] = frozenset({"sub", "iss", "iat", "exp", "jti"})

_VERIFY_OPTIONS: dict[str, Any] = {"require": sorted(_REQUIRED_CLAIMS)}


def new_token_id() -> str:
    """Return a cryptographically unpredictable token ID (128 random bits)."""
    return secrets.token_urlsafe(16)


def create_access_token(user_id: str) -> str:
    """Create a signed access token for ``user_id``.

    ``jti`` is generated fresh per call, so two tokens for the same user are
    always distinct and individually revocable.
    """
    now = int(time.time())
    payload = {
        "sub": user_id,
        "iss": JWT_ISSUER,
        "iat": now,
        "exp": now + JWT_EXPIRY_HOURS * 3600,
        "jti": new_token_id(),
        "user_id": user_id,  # legacy claim for existing consumers
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


def verify_access_token(token: str) -> dict:
    """Verify ``token`` and return its claims as a dict.

    Verifies signature, pinned algorithm (configured, e.g. HS256), issuer,
    expiry, and the presence of every required claim. Raises
    ``fastapi.HTTPException`` (401) on any failure with a stable message that
    never distinguishes the underlying reason.
    """
    try:
        payload = jwt.decode(
            token,
            JWT_SECRET,
            algorithms=[JWT_ALGORITHM],
            issuer=JWT_ISSUER,
            options=_VERIFY_OPTIONS,
        )
    except jwt.ExpiredSignatureError as exc:
        raise HTTPException(status_code=401, detail="Token expired") from exc
    except jwt.InvalidTokenError as exc:
        raise HTTPException(status_code=401, detail="Invalid token") from exc

    # Type-safety after decode: claims must be strings/ints we can rely on.
    if not isinstance(payload.get("sub"), str):
        raise HTTPException(status_code=401, detail="Invalid token")
    if not isinstance(payload.get("jti"), str) or not payload["jti"]:
        raise HTTPException(status_code=401, detail="Invalid token")

    claims: dict = dict(payload)
    # Existing consumers read token["user_id"]; keep it populated and equal to
    # the authoritative subject.
    claims["user_id"] = claims["sub"]
    return claims
