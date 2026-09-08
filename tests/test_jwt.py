"""JWT helper tests (no external infrastructure)."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import jwt
import pytest
from fastapi import HTTPException

from server.config import settings
from server.middleware import JWT_ALGORITHM, JWT_SECRET, create_token, decode_token


def _past_token() -> str:
    now = datetime.now(timezone.utc)
    payload = {"user_id": "alice", "iat": now - timedelta(days=2), "exp": now - timedelta(hours=1)}
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


def test_create_and_decode_round_trip():
    token = create_token("alice")
    payload = decode_token(token)
    assert payload["user_id"] == "alice"
    assert "iat" in payload and "exp" in payload


def test_token_lifetime_matches_settings():
    token = create_token("alice")
    payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
    lifetime = datetime.fromtimestamp(payload["exp"], tz=timezone.utc) - datetime.fromtimestamp(
        payload["iat"], tz=timezone.utc
    )
    assert lifetime == timedelta(hours=settings.jwt_expiry_hours)


def test_expired_token_rejected():
    with pytest.raises(HTTPException) as excinfo:
        decode_token(_past_token())
    assert excinfo.value.status_code == 401
    assert excinfo.value.detail == "Token expired"


def test_tampered_token_rejected():
    token = create_token("alice")
    tampered = token[:-4] + ("X" if token[-4] != "X" else "Y") + token[-3:]
    with pytest.raises(HTTPException) as excinfo:
        decode_token(tampered)
    assert excinfo.value.status_code == 401
    assert excinfo.value.detail == "Invalid token"


def test_token_signed_with_wrong_secret_rejected():
    token = jwt.encode({"user_id": "alice"}, "some-other-secret", algorithm=JWT_ALGORITHM)
    with pytest.raises(HTTPException) as excinfo:
        decode_token(token)
    assert excinfo.value.status_code == 401
    assert excinfo.value.detail == "Invalid token"


def test_wrong_algorithm_rejected():
    token = jwt.encode({"user_id": "alice"}, JWT_SECRET, algorithm="HS512")
    with pytest.raises(HTTPException) as excinfo:
        decode_token(token)
    assert excinfo.value.status_code == 401
    assert excinfo.value.detail == "Invalid token"
