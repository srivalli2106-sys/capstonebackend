"""
keys.py — Key bundle upload, retrieval, and OPK consumption (MongoDB Atlas).

POST /keys/upload
  - Auth required (JWT)
  - Body: { spk_public (hex), spk_sig (hex), opk_public (hex, nullable) }
  - Upserts the user's key bundle

GET /keys/bundle/{user_id}
  - Auth required (JWT)
  - Returns the key bundle for user_id
  - Consumes the OPK (sets it to None in DB); the response carries the
    just-consumed one-time prekey (single-use, delivered to exactly one caller)
  - Returns 404 if user not found

GET /keys/prekeys/{user_id}
  - Auth required (JWT)
  - Returns remaining OPK status (present or consumed)
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, Field

from ..middleware import check_rate_limit, require_auth
from ..services.key_service import key_service

router = APIRouter(prefix="/keys", tags=["keys"])


# ---------------------------------------------------------------------------
# Request / Response models
# ---------------------------------------------------------------------------


# spk/sig/opk are hex-encoded 32-byte X25519 key material = 64 hex chars;
# the byte-length checks in the route already enforce the fixed size, and the
# hex-length cap keeps oversized strings from being parsed in the first place.
_MAX_KEY_HEX_LENGTH = 64


class UploadKeyBundleRequest(BaseModel):
    spk_public: str = Field(max_length=_MAX_KEY_HEX_LENGTH)  # hex
    spk_sig: str = Field(max_length=_MAX_KEY_HEX_LENGTH)    # hex
    opk_public: str | None = Field(
        default=None, max_length=_MAX_KEY_HEX_LENGTH
    )  # hex, nullable


class KeyBundleResponse(BaseModel):
    user_id: str
    ik_public: str  # hex — registered Ed25519 auth identity (verifies spk_sig)
    spk_public: str   # hex
    spk_sig: str      # hex
    opk_public: str | None = None  # hex
    version: int


class OPKStatusResponse(BaseModel):
    user_id: str
    opk_available: bool
    version: int


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@router.post("/upload", status_code=200)
async def upload_key_bundle(
    body: UploadKeyBundleRequest,
    request: Request,
    auth: dict = Depends(require_auth),
):
    await check_rate_limit(request, "keys")

    user_id = auth["user_id"]

    await key_service.upload(
        user_id, body.spk_public, body.spk_sig, body.opk_public
    )
    return {"status": "ok", "user_id": user_id}


@router.get("/bundle/{target_user_id}", response_model=KeyBundleResponse)
async def get_bundle(
    target_user_id: str,
    request: Request,
    auth: dict = Depends(require_auth),
):
    await check_rate_limit(request, "keys")

    result = await key_service.get_bundle(target_user_id)
    return KeyBundleResponse(**result)


@router.get("/prekeys/{target_user_id}", response_model=OPKStatusResponse)
async def opk_status(
    target_user_id: str,
    request: Request,
    auth: dict = Depends(require_auth),
):
    await check_rate_limit(request, "keys")

    result = await key_service.opk_status(target_user_id)
    return OPKStatusResponse(**result)
