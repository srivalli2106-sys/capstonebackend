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


# Classical key sizes (hex-encoded): 32 bytes = 64 hex chars.
# PQ public keys: ML-KEM-768 = 1184 bytes = 2368 hex chars;
#               ML-DSA-44 = 1312 bytes = 2624 hex chars.
#               ML-DSA-44 sig  = 2420 bytes = 4840 hex chars.
_MAX_KEY_HEX_LENGTH = 64
_MAX_SIGNATURE_HEX_LENGTH = 128
_PQ_KEM_HEX_LENGTH = 2368
_PQ_SIG_HEX_LENGTH = 2624
_PQ_SIG_SIG_HEX_LENGTH = 4840


class UploadKeyBundleRequest(BaseModel):
    xdh_public: str = Field(max_length=_MAX_KEY_HEX_LENGTH)  # hex X25519 identity
    spk_public: str = Field(max_length=_MAX_KEY_HEX_LENGTH)  # hex
    spk_sig: str = Field(
        min_length=_MAX_SIGNATURE_HEX_LENGTH,
        max_length=_MAX_SIGNATURE_HEX_LENGTH,
    )  # hex Ed25519 signature (64 bytes)
    opk_public: str | None = Field(
        default=None, max_length=_MAX_KEY_HEX_LENGTH
    )  # hex, nullable
    # --------------------------------------------------------------------
    # Post-quantum material (optional; included for hybrid v2 mode).
    # Defaults are all None so existing classical clients work unchanged.
    # --------------------------------------------------------------------
    pq_kem_public: str | None = Field(
        default=None, max_length=_PQ_KEM_HEX_LENGTH
    )  # hex ML-KEM-768 public key (1184 bytes)
    pq_sig_public: str | None = Field(
        default=None, max_length=_PQ_SIG_HEX_LENGTH
    )  # hex ML-DSA-44 public key (1312 bytes)
    pq_binding_sig: str | None = Field(
        default=None, max_length=_PQ_SIG_SIG_HEX_LENGTH
    )  # hex ML-DSA-44 signature (2420 bytes)
    protocol_version: int = Field(default=1)  # 1 = classical, 2 = hybrid


class KeyBundleResponse(BaseModel):
    user_id: str
    ik_public: str  # hex — registered Ed25519 auth identity (verifies spk_sig)
    xdh_public: str  # hex — X25519 X3DH identity
    spk_public: str   # hex
    spk_sig: str      # hex
    opk_public: str | None = None  # hex
    pq_kem_public: str | None = None  # hex ML-KEM-768 public key (1184 bytes)
    pq_sig_public: str | None = None  # hex ML-DSA-44 public key (1312 bytes)
    pq_binding_sig: str | None = None  # hex ML-DSA-44 signature (2420 bytes)
    protocol_version: int  # 1 = classical, 2 = hybrid


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
        user_id,
        body.xdh_public,
        body.spk_public,
        body.spk_sig,
        body.opk_public,
        body.pq_kem_public,
        body.pq_sig_public,
        body.pq_binding_sig,
        body.protocol_version,
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
