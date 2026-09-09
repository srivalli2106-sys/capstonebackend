"""
auth.py — Registration, development login, proof-of-possession auth, logout.

POST /register
  - Body: { user_id, ik_public (hex) }
  - Creates a user document. Returns 409 if user_id already exists.
  - One-time only: unique index on user_id enforces it.

POST /login   (DEVELOPMENT/TEST ONLY)
  - Body: { user_id }
  - Returns a JWT for any existing user WITHOUT proof of possession.
  - Returns HTTP 403 when the deployment is configured as production
    (via APP_ENV). Production clients MUST use /challenge + /verify.

POST /challenge
  - Body: { user_id }
  - Returns a short-lived random nonce for the user's existing identity key.

POST /verify
  - Body: { user_id, nonce (hex), signature (hex) }
  - Verifies the Ed25519 signature of the nonce against the registered
    ik_public, atomically consuming the challenge, and returns a JWT.
  - Nonce: 32 bytes hex (64 chars). Signature: 64 bytes hex (128 chars).

POST /logout
  - Auth required (Bearer JWT). Revokes the token's jti until its expiry.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, Field

from .. import auth_service
from ..config import settings
from ..db import register_user
from ..exceptions import Conflict, Forbidden, InvalidRequest
from ..middleware import check_rate_limit

router = APIRouter(prefix="/auth", tags=["auth"])


# user_id is used as a MongoDB document key and Redis key suffix, so it is
# bounded. ik_public is a hex-encoded 32-byte Ed25519 identity key = 64 chars.
# Challenge nonces are 32 bytes -> 64 hex chars; Ed25519 signatures are
# 64 bytes -> 128 hex chars.
_MAX_USER_ID_LENGTH = 64
_MAX_IDENTITY_KEY_HEX_LENGTH = 64
_NONCE_HEX_CHARS = 64
_SIGNATURE_HEX_CHARS = 128


class RegisterRequest(BaseModel):
    user_id: str = Field(max_length=_MAX_USER_ID_LENGTH)
    ik_public: str = Field(max_length=_MAX_IDENTITY_KEY_HEX_LENGTH)  # hex identity key


class RegisterResponse(BaseModel):
    status: str
    user_id: str


class LoginRequest(BaseModel):
    user_id: str = Field(max_length=_MAX_USER_ID_LENGTH)


class LoginResponse(BaseModel):
    token: str
    user_id: str


class ChallengeRequest(BaseModel):
    user_id: str = Field(max_length=_MAX_USER_ID_LENGTH)


class ChallengeResponse(BaseModel):
    user_id: str
    nonce: str


class VerifyRequest(BaseModel):
    user_id: str = Field(max_length=_MAX_USER_ID_LENGTH)
    nonce: str = Field(min_length=_NONCE_HEX_CHARS, max_length=_NONCE_HEX_CHARS)
    signature: str = Field(
        min_length=_SIGNATURE_HEX_CHARS, max_length=_SIGNATURE_HEX_CHARS
    )


class VerifyResponse(BaseModel):
    token: str
    user_id: str


class LogoutResponse(BaseModel):
    status: str


@router.post("/register", response_model=RegisterResponse, status_code=201)
async def register(body: RegisterRequest, request: Request):
    await check_rate_limit(request, "register")

    if not body.user_id or len(body.user_id) < 3:
        raise InvalidRequest("user_id too short")

    try:
        ik_bytes = bytes.fromhex(body.ik_public)
    except ValueError as exc:
        raise InvalidRequest("ik_public must be hex") from exc

    if len(ik_bytes) != 32:
        raise InvalidRequest("ik_public must be 32 bytes")

    ok = await register_user(body.user_id, ik_bytes)
    if not ok:
        raise Conflict(
            f"User '{body.user_id}' already registered. Re-registration is not allowed."
        )

    return RegisterResponse(status="registered", user_id=body.user_id)


@router.post("/login", response_model=LoginResponse)
async def login(body: LoginRequest, request: Request):
    # user_id-only login is a DEVELOPMENT/TEST convenience. It is disabled in
    # production, where proof of possession via /challenge + /verify is the
    # only path — gated by the configured environment, not by hostname.
    if settings.env == "production":
        raise Forbidden(
            "Password-less user-id login is disabled in production. Use "
            "POST /auth/challenge then POST /auth/verify."
        )

    await check_rate_limit(request, "login")

    token = await auth_service.development_login(body.user_id)
    return LoginResponse(token=token, user_id=body.user_id)


@router.post("/challenge", response_model=ChallengeResponse)
async def challenge(body: ChallengeRequest, request: Request):
    await check_rate_limit(request, "challenge")

    nonce = await auth_service.create_challenge(body.user_id)
    return ChallengeResponse(user_id=body.user_id, nonce=nonce)


@router.post("/verify", response_model=VerifyResponse)
async def verify(body: VerifyRequest, request: Request):
    await check_rate_limit(request, "verify")

    token = await auth_service.verify_credentials(
        body.user_id, body.nonce, body.signature
    )
    return VerifyResponse(token=token, user_id=body.user_id)


@router.post("/logout", response_model=LogoutResponse)
async def logout(
    request: Request, claims: dict = Depends(auth_service.require_auth)
):
    await check_rate_limit(request, "logout")

    await auth_service.revoke_token(claims)
    return LogoutResponse(status="logged_out")
