"""
keys.py — Key bundle upload, retrieval, and OPK consumption (MongoDB Atlas).

POST /keys/upload
  - Auth required (JWT)
  - Body: { spk_public (hex), spk_sig (hex), opk_public (hex, nullable) }
  - Upserts the user's key bundle

GET /keys/bundle/{user_id}
  - Auth required (JWT)
  - Returns the key bundle for user_id
  - Consumes the OPK (sets it to None in DB)
  - Returns 404 if user not found

GET /keys/prekeys/{user_id}
  - Auth required (JWT)
  - Returns remaining OPK status (present or consumed)
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel

from ..db import consume_opk, get_key_bundle, get_user, upsert_key_bundle
from ..middleware import check_rate_limit, require_auth

router = APIRouter(prefix="/keys", tags=["keys"])


# ---------------------------------------------------------------------------
# Request / Response models
# ---------------------------------------------------------------------------


class UploadKeyBundleRequest(BaseModel):
    spk_public: str   # hex
    spk_sig: str      # hex
    opk_public: str | None = None  # hex, nullable


class KeyBundleResponse(BaseModel):
    user_id: str
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

    user = await get_user(user_id)
    if user is None:
        raise HTTPException(status_code=404, detail="User not found. Register first.")

    try:
        spk_bytes = bytes.fromhex(body.spk_public)
        sig_bytes = bytes.fromhex(body.spk_sig)
    except ValueError:
        raise HTTPException(status_code=400, detail="spk_public and spk_sig must be hex")

    if len(spk_bytes) != 32:
        raise HTTPException(status_code=400, detail="spk_public must be 32 bytes")

    opk_bytes = None
    if body.opk_public is not None:
        try:
            opk_bytes = bytes.fromhex(body.opk_public)
        except ValueError:
            raise HTTPException(status_code=400, detail="opk_public must be hex")
        if len(opk_bytes) != 32:
            raise HTTPException(status_code=400, detail="opk_public must be 32 bytes")

    await upsert_key_bundle(user_id, spk_bytes, sig_bytes, opk_bytes)
    return {"status": "ok", "user_id": user_id}


@router.get("/bundle/{target_user_id}", response_model=KeyBundleResponse)
async def get_bundle(
    target_user_id: str,
    request: Request,
    auth: dict = Depends(require_auth),
):
    await check_rate_limit(request, "keys")

    bundle = await get_key_bundle(target_user_id)
    if bundle is None:
        raise HTTPException(status_code=404, detail="Key bundle not found")

    # Consume the OPK (set to NULL)
    await consume_opk(target_user_id)

    # Re-read after consumption
    bundle = await get_key_bundle(target_user_id)

    return KeyBundleResponse(
        user_id=bundle["user_id"],
        spk_public=bundle["spk_public"].hex(),
        spk_sig=bundle["spk_sig"].hex(),
        opk_public=bundle["opk_public"].hex() if bundle.get("opk_public") else None,
        version=bundle.get("version", 1),
    )


@router.get("/prekeys/{target_user_id}", response_model=OPKStatusResponse)
async def opk_status(
    target_user_id: str,
    request: Request,
    auth: dict = Depends(require_auth),
):
    await check_rate_limit(request, "keys")

    bundle = await get_key_bundle(target_user_id)
    if bundle is None:
        raise HTTPException(status_code=404, detail="Key bundle not found")

    return OPKStatusResponse(
        user_id=bundle["user_id"],
        opk_available=bundle.get("opk_public") is not None,
        version=bundle.get("version", 1),
    )
