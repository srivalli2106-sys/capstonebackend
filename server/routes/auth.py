"""
auth.py — Registration (one-time) and login routes.

POST /register
  - Body: { user_id, ik_public (hex) }
  - Creates a user document. Returns 409 if user_id already exists.
  - One-time only: unique index on user_id enforces it.

POST /login
  - Body: { user_id }
  - Verifies user exists, returns JWT.
"""

from __future__ import annotations

from fastapi import APIRouter, Request
from pydantic import BaseModel, Field

from ..db import get_user, register_user
from ..exceptions import Conflict, InvalidRequest, ResourceNotFound
from ..middleware import check_rate_limit, create_token

router = APIRouter(prefix="/auth", tags=["auth"])


# user_id is used as a MongoDB document key and Redis key suffix, so it is
# bounded. ik_public is a hex-encoded 32-byte X25519 identity key = 64 chars.
_MAX_USER_ID_LENGTH = 64
_MAX_IDENTITY_KEY_HEX_LENGTH = 64


class RegisterRequest(BaseModel):
    user_id: str = Field(max_length=_MAX_USER_ID_LENGTH)
    ik_public: str = Field(max_length=_MAX_IDENTITY_KEY_HEX_LENGTH)  # hex X25519 key


class RegisterResponse(BaseModel):
    status: str
    user_id: str


class LoginRequest(BaseModel):
    user_id: str = Field(max_length=_MAX_USER_ID_LENGTH)


class LoginResponse(BaseModel):
    token: str
    user_id: str


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
    await check_rate_limit(request, "login")

    user = await get_user(body.user_id)
    if user is None:
        raise ResourceNotFound("User not found")

    token = create_token(user["user_id"])
    return LoginResponse(token=token, user_id=user["user_id"])
