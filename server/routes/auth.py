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

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel

from ..db import get_user, register_user
from ..middleware import check_rate_limit, create_token

router = APIRouter(prefix="/auth", tags=["auth"])


class RegisterRequest(BaseModel):
    user_id: str
    ik_public: str  # hex-encoded X25519 public key


class RegisterResponse(BaseModel):
    status: str
    user_id: str


class LoginRequest(BaseModel):
    user_id: str


class LoginResponse(BaseModel):
    token: str
    user_id: str


@router.post("/register", response_model=RegisterResponse, status_code=201)
async def register(body: RegisterRequest, request: Request):
    await check_rate_limit(request, "register")

    if not body.user_id or len(body.user_id) < 3:
        raise HTTPException(status_code=400, detail="user_id too short")

    try:
        ik_bytes = bytes.fromhex(body.ik_public)
    except ValueError:
        raise HTTPException(status_code=400, detail="ik_public must be hex")

    if len(ik_bytes) != 32:
        raise HTTPException(status_code=400, detail="ik_public must be 32 bytes")

    ok = await register_user(body.user_id, ik_bytes)
    if not ok:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"User '{body.user_id}' already registered. Re-registration is not allowed.",
        )

    return RegisterResponse(status="registered", user_id=body.user_id)


@router.post("/login", response_model=LoginResponse)
async def login(body: LoginRequest, request: Request):
    await check_rate_limit(request, "login")

    user = await get_user(body.user_id)
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")

    token = create_token(user["user_id"])
    return LoginResponse(token=token, user_id=user["user_id"])
