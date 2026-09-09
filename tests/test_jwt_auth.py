"""JWT creation/verification tests (Phase 6; no external infrastructure).

Covers required claims (sub/iss/iat/exp/jti), enforced issuer, enforced
expiry, pinned algorithm, normalization of the legacy user_id claim, and the
generic 401 error contract.
"""

from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import HTTPException

from server.config import settings
from server.jwt_auth import (
    JWT_ALGORITHM,
    JWT_ISSUER,
    JWT_SECRET,
    create_access_token,
    verify_access_token,
)


def _signed(payload: dict) -> str:
    now = int(time.time())
    claims = {
        "sub": "alice",
        "iss": JWT_ISSUER,
        "iat": now,
        "exp": now + 3600,
        "jti": "token-id-1",
        **payload,
    }
    return jwt.encode(claims, JWT_SECRET, algorithm=JWT_ALGORITHM)


def _assert_401(token: str) -> HTTPException:
    with pytest.raises(HTTPException) as excinfo:
        verify_access_token(token)
    assert excinfo.value.status_code == 401
    return excinfo.value


# ---------------------------------------------------------------------------
# Required claims
# ---------------------------------------------------------------------------


def test_created_token_contains_required_claims():
    claims = verify_access_token(create_access_token("alice"))
    assert claims["sub"] == "alice"
    assert claims["iss"] == JWT_ISSUER
    assert isinstance(claims["iat"], int) and claims["iat"] > 0
    assert isinstance(claims["exp"], int) and claims["exp"] > claims["iat"]
    assert isinstance(claims["jti"], str) and claims["jti"]
    assert claims["user_id"] == "alice"


def test_jti_is_unique_per_token():
    assert create_access_token("alice") != create_access_token("alice")
    a = verify_access_token(create_access_token("alice"))["jti"]
    b = verify_access_token(create_access_token("alice"))["jti"]
    assert a != b


def test_expiry_matches_configuration():
    payload = jwt.decode(create_access_token("alice"), JWT_SECRET, algorithms=[JWT_ALGORITHM])
    lifetime = datetime.fromtimestamp(payload["exp"], tz=timezone.utc) - datetime.fromtimestamp(
        payload["iat"], tz=timezone.utc
    )
    assert lifetime == timedelta(hours=settings.jwt_expiry_hours)


# ---------------------------------------------------------------------------
# Signature / algorithm
# ---------------------------------------------------------------------------


def test_tampered_token_rejected():
    token = create_access_token("alice")
    tampered = token[:-4] + ("X" if token[-4] != "X" else "Y") + token[-3:]
    _assert_401(tampered)


def test_wrong_secret_rejected():
    other = jwt.encode(
        {"sub": "alice", "iss": JWT_ISSUER, "iat": int(time.time()), "exp": int(time.time()) + 3600, "jti": "x"},
        "some-other-secret-please",
        algorithm=JWT_ALGORITHM,
    )
    _assert_401(other)


@pytest.mark.parametrize("alg", ["none", "HS512", "RS256"])
def test_unsupported_algorithm_rejected(alg):
    now = int(time.time())
    claims = {"sub": "alice", "iss": JWT_ISSUER, "iat": now, "exp": now + 3600, "jti": "x"}
    if alg == "none":
        token = jwt.encode(claims, None, algorithm="none")
    elif alg == "RS256":
        rsa_private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        pem = rsa_private.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        token = jwt.encode(claims, pem, algorithm="RS256")
    else:
        token = jwt.encode(claims, JWT_SECRET, algorithm=alg)
    _assert_401(token)


# ---------------------------------------------------------------------------
# Issuer validation
# ---------------------------------------------------------------------------


def test_wrong_issuer_rejected():
    _assert_401(_signed({"iss": "evil-issuer"}))


def test_missing_issuer_rejected():
    _assert_401(_signed({"iss": None}))


# ---------------------------------------------------------------------------
# Expiry / required claims
# ---------------------------------------------------------------------------


def _base_claims(exp: int) -> dict:
    return {
        "sub": "alice",
        "iss": JWT_ISSUER,
        "iat": int(time.time()),
        "exp": exp,
        "jti": "token-id-1",
    }


def test_expired_token_rejected():
    past = int(time.time()) - 7200
    token = jwt.encode(_base_claims(past), JWT_SECRET, algorithm=JWT_ALGORITHM)
    exc = _assert_401(token)
    assert exc.detail == "Token expired"


@pytest.mark.parametrize("missing", ["jti", "sub", "iat", "exp", "iss"])
def test_missing_required_claim_rejected(missing):
    full = _base_claims(int(time.time()) + 3600)
    del full[missing]
    _assert_401(jwt.encode(full, JWT_SECRET, algorithm=JWT_ALGORITHM))


def test_non_string_subject_rejected():
    now = int(time.time())
    token = jwt.encode(
        {"sub": 12345, "iss": JWT_ISSUER, "iat": now, "exp": now + 3600, "jti": "x"},
        JWT_SECRET,
        algorithm=JWT_ALGORITHM,
    )
    _assert_401(token)


# ---------------------------------------------------------------------------
# user_id normalization
# ---------------------------------------------------------------------------


def test_legacy_user_id_claim_is_authoritative_subject():
    now = int(time.time())
    token = jwt.encode(
        {"sub": "bob", "user_id": "EVE", "iss": JWT_ISSUER, "iat": now, "exp": now + 3600, "jti": "x"},
        JWT_SECRET,
        algorithm=JWT_ALGORITHM,
    )
    assert verify_access_token(token)["user_id"] == "bob"
