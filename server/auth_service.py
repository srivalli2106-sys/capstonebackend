"""
auth_service.py — authentication service and dependency (Phase 6).

The production authentication flow is proof of possession:

  POST /auth/challenge  {user_id}                -> nonce (32 random bytes)
  client signs the nonce with its Ed25519 private key
  POST /auth/verify     {user_id, nonce, signature} -> JWT

Verification is fail-closed: unknown users, missing/replayed/expired
challenges, malformed inputs, and invalid signatures all produce the same
generic 401 so nothing about the failure reason is leaked. A Redis error
during challenge/revocation handling propagates (503 dependency contract),
never degrading to "accept".

:func:`require_auth` is the centralized FastAPI dependency for protected
HTTP routes: it verifies signature/algorithm/issuer/expiry/required claims
and the revocation status, failing closed when Redis is unavailable.
"""

from __future__ import annotations

import time

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from fastapi import Depends, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from . import auth_store
from .config import settings
from .exceptions import ResourceNotFound
from .jwt_auth import create_access_token, verify_access_token
from .repositories.user_repository import user_repository

# One generic message for every failed verification; never surfaces whether a
# user is unknown, a challenge is missing/replayed/expired, or the signature
# was invalid for one cryptographic reason or another.
_AUTH_FAILED = "Authentication failed"

# Ed25519 public identity keys and signatures are fixed-size. Public keys are
# 32 bytes (as registered via /auth/register); signatures are 64 bytes.
_IDENTITY_KEY_BYTES = 32
_SIGNATURE_BYTES = 64
_NONCE_BYTES = 32

_bearer = HTTPBearer(auto_error=False)


# ---------------------------------------------------------------------------
# Authentication flow
# ---------------------------------------------------------------------------


async def create_challenge(user_id: str) -> str:
    """Validate the user exists and issue a short-lived nonce challenge."""
    user = await user_repository.get_user(user_id)
    if user is None:
        raise ResourceNotFound("User not found")
    return await auth_store.issue_challenge(
        user_id, settings.auth_challenge_ttl_seconds
    )


async def verify_credentials(user_id: str, nonce_hex: str, signature_hex: str) -> str:
    """Verify proof of possession of ``user_id``'s Ed25519 identity key.

    Consumes the challenge atomically, then verifies the signature over the
    nonce against the stored identity public key. Returns a signed access
    token. Any failure raises 401 with the generic message.
    """
    user = await user_repository.get_user(user_id)
    if user is None:
        raise HTTPException(status_code=401, detail=_AUTH_FAILED)

    try:
        nonce = bytes.fromhex(nonce_hex)
        signature = bytes.fromhex(signature_hex)
    except ValueError as exc:
        raise HTTPException(status_code=401, detail=_AUTH_FAILED) from exc
    if len(nonce) != _NONCE_BYTES or len(signature) != _SIGNATURE_BYTES:
        raise HTTPException(status_code=401, detail=_AUTH_FAILED)

    # Atomic consume BEFORE verification: the challenge is single-use even
    # against signature oracle attempts.
    if not await auth_store.consume_challenge(user_id, nonce_hex):
        raise HTTPException(status_code=401, detail=_AUTH_FAILED)

    try:
        public_key = Ed25519PublicKey.from_public_bytes(user["ik_public"])
        public_key.verify(signature, nonce)
    except (InvalidSignature, ValueError, KeyError) as exc:
        raise HTTPException(status_code=401, detail=_AUTH_FAILED) from exc

    return create_access_token(user_id)


async def development_login(user_id: str) -> str:
    """Development/test-only user_id login (disabled in production).

    Kept so local Swagger/manual workflows do not need to run the full
    proof-of-possession dance. The route layer refuses to call this when
    the deployment environment is production.
    """
    user = await user_repository.get_user(user_id)
    if user is None:
        raise ResourceNotFound("User not found")
    return create_access_token(user_id)


# ---------------------------------------------------------------------------
# Logout / revocation
# ---------------------------------------------------------------------------


def _token_remaining_seconds(claims: dict) -> int:
    """Remaining lifetime of the token in ``claims``, clamped to [1, exp-now]."""
    return max(1, int(claims["exp"]) - int(time.time()))


async def revoke_token(claims: dict) -> None:
    """Blacklist the token's ``jti`` until its expiry (bounded TTL)."""
    await auth_store.revoke_token(claims["jti"], _token_remaining_seconds(claims))


# ---------------------------------------------------------------------------
# Centralized authenticated-dependency for protected HTTP routes
# ---------------------------------------------------------------------------


async def require_auth(
    creds: HTTPAuthorizationCredentials | None = Depends(_bearer),
) -> dict:
    """FastAPI dependency: require a valid, non-revoked access token.

    Validates signature, configured algorithm, issuer, expiry, required
    claims, and revocation status. Revocation check failures (Redis errors)
    propagate as 503 — the token is never silently accepted.
    """
    if creds is None:
        raise HTTPException(status_code=401, detail="Missing bearer token")
    claims = verify_access_token(creds.credentials)
    if await auth_store.is_token_revoked(claims["jti"]):
        raise HTTPException(status_code=401, detail="Invalid token")
    return claims
