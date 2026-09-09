"""ws_auth unit tests (no infrastructure required)."""

from __future__ import annotations

import asyncio
import json
import time
from types import SimpleNamespace

import pytest
from fastapi import HTTPException

import server.ws_auth as wa

# Patchable module reference so unit tests control the public helper without
# touching the shared Settings singleton.
_PATCHED_SETTINGS = SimpleNamespace(
    ws_auth_timeout_seconds=0.05,
    ws_presence_ttl_seconds=300,
    ws_connect_rate_per_minute=60,
    ws_message_rate_per_minute=120,
)


class _EventWS:
    """WebSocket stub whose receive() returns a canned ASGI message."""

    def __init__(self, event):
        self._event = event

    async def receive(self):
        return self._event


def _text(text: str) -> dict:
    return {"type": "websocket.receive", "text": text}


def _bytes(payload: bytes) -> dict:
    return {"type": "websocket.receive", "bytes": payload}


def _disconnect(code: int = 1000) -> dict:
    return {"type": "websocket.disconnect", "code": code}


def _auth_frame(token: str) -> str:
    return json.dumps({"type": "auth", "token": token})


# ---------------------------------------------------------------------------
# receive_ws_event
# ---------------------------------------------------------------------------


async def test_receive_ws_event_text():
    assert await wa.receive_ws_event(_EventWS(_text("hi"))) == ("text", "hi")


async def test_receive_ws_event_bytes():
    payload = b"\x00\x01"
    kind, value = await wa.receive_ws_event(_EventWS(_bytes(payload)))
    assert kind == "bytes"
    assert value == payload


async def test_receive_ws_event_disconnect():
    assert await wa.receive_ws_event(_EventWS(_disconnect(1001))) == (
        "disconnect",
        1001,
    )


async def test_receive_ws_event_unexpected_type_is_none():
    assert await wa.receive_ws_event(_EventWS({"type": "websocket.connect"})) is None


# ---------------------------------------------------------------------------
# parse_auth_frame
# ---------------------------------------------------------------------------


def test_parse_auth_frame_valid():
    assert wa.parse_auth_frame(_auth_frame("jwt-abc")) == "jwt-abc"


@pytest.mark.parametrize(
    "raw",
    [
        "not-json",
        "42",
        json.dumps({"type": "hello", "token": "x"}),
        json.dumps({"type": "auth"}),
        json.dumps({"type": "auth", "token": ""}),
        json.dumps({"type": "auth", "token": 123}),
    ],
)
def test_parse_auth_frame_rejects(raw):
    with pytest.raises(wa.WsAuthError) as exc:
        wa.parse_auth_frame(raw)
    assert exc.value.code == wa.WS_AUTH_REQUIRED
    assert exc.value.reason == wa.REASON_AUTH_FAILED


# ---------------------------------------------------------------------------
# receive_auth_token
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "event",
    [
        _text("not-json"),
        _text(json.dumps({"type": "hello"})),
        _text(json.dumps({"token": "x"})),
    ],
)
async def test_receive_auth_token_rejects_bad_frames(event, monkeypatch):
    monkeypatch.setattr(wa, "settings", _PATCHED_SETTINGS)
    with pytest.raises(wa.WsAuthError) as exc:
        await wa.receive_auth_token(_EventWS(event))
    assert exc.value.code == wa.WS_AUTH_REQUIRED


async def test_receive_auth_token_accepts_valid_frame(monkeypatch):
    monkeypatch.setattr(wa, "settings", _PATCHED_SETTINGS)
    token = await wa.receive_auth_token(_EventWS(_text(_auth_frame("jwt-abc"))))
    assert token == "jwt-abc"


async def test_receive_auth_token_returns_none_on_early_disconnect(monkeypatch):
    monkeypatch.setattr(wa, "settings", _PATCHED_SETTINGS)
    assert await wa.receive_auth_token(_EventWS(_disconnect())) is None


async def test_receive_auth_token_rejects_binary_first_frame(monkeypatch):
    monkeypatch.setattr(wa, "settings", _PATCHED_SETTINGS)
    with pytest.raises(wa.WsAuthError) as exc:
        await wa.receive_auth_token(_EventWS(_bytes(b"\x00")))
    assert exc.value.code == wa.WS_POLICY_VIOLATION
    assert exc.value.reason == wa.REASON_POLICY


async def test_receive_auth_token_times_out(monkeypatch):
    monkeypatch.setattr(wa, "settings", _PATCHED_SETTINGS)

    class _SilentWS:
        async def receive(self):
            await asyncio.Event().wait()
            raise AssertionError("unreachable")

    with pytest.raises(wa.WsAuthError) as exc:
        await wa.receive_auth_token(_SilentWS())
    assert exc.value.code == wa.WS_AUTH_REQUIRED
    assert exc.value.reason == wa.REASON_AUTH_TIMEOUT


# ---------------------------------------------------------------------------
# verify_ws_token
# ---------------------------------------------------------------------------

_CLAIMS = {
    "sub": "alice",
    "user_id": "alice",
    "iss": "secure-messaging-api",
    "iat": 1,
    "exp": 4102444800,
    "jti": "test-jti",
}


async def test_verify_ws_token_ok(monkeypatch):
    monkeypatch.setattr(wa, "verify_access_token", lambda token: dict(_CLAIMS))
    monkeypatch.setattr(wa, "is_token_revoked", _async_false)

    assert await wa.verify_ws_token("jwt-abc") == _CLAIMS


async def test_verify_ws_token_rejects_invalid(monkeypatch):
    def _raise(token):
        raise HTTPException(status_code=401, detail="Invalid token")

    monkeypatch.setattr(wa, "verify_access_token", _raise)

    with pytest.raises(wa.WsAuthError) as exc:
        await wa.verify_ws_token("bad")
    assert exc.value.code == wa.WS_AUTH_REQUIRED
    assert exc.value.reason == wa.REASON_AUTH_FAILED


async def test_verify_ws_token_rejects_revoked(monkeypatch):
    monkeypatch.setattr(wa, "verify_access_token", lambda token: dict(_CLAIMS))
    monkeypatch.setattr(wa, "is_token_revoked", _async_true)

    with pytest.raises(wa.WsAuthError) as exc:
        await wa.verify_ws_token("jwt-abc")
    assert exc.value.code == wa.WS_AUTH_REQUIRED
    assert exc.value.reason == wa.REASON_SESSION_EXPIRED


async def test_verify_ws_token_fails_closed_when_revocation_unknown(monkeypatch):
    monkeypatch.setattr(wa, "verify_access_token", lambda token: dict(_CLAIMS))

    async def _raise(jti):
        raise RuntimeError("redis down")

    monkeypatch.setattr(wa, "is_token_revoked", _raise)

    with pytest.raises(wa.WsAuthError) as exc:
        await wa.verify_ws_token("jwt-abc")
    assert exc.value.code == wa.WS_AUTH_REQUIRED
    assert exc.value.reason == wa.REASON_AUTH_FAILED


# ---------------------------------------------------------------------------
# Token lifetime watcher
# ---------------------------------------------------------------------------


async def _collect_close(closed):
    async def fake_close(ws, code, reason):
        closed.append((code, reason))

    return fake_close


async def test_watcher_closes_on_expired_token(monkeypatch):
    closed: list[tuple[int, str]] = []
    monkeypatch.setattr(wa, "close_websocket", await _collect_close(closed))
    await wa._watch_token_lifetime(object(), {"exp": 12345})
    assert closed == [(wa.WS_AUTH_REQUIRED, wa.REASON_SESSION_EXPIRED)]


async def test_watcher_closes_when_token_gets_revoked(monkeypatch):
    closed: list[tuple[int, str]] = []
    monkeypatch.setattr(wa, "close_websocket", await _collect_close(closed))
    calls = {"n": 0}

    async def _revoked_after_wake(jti):
        calls["n"] += 1
        return calls["n"] >= 2

    async def _no_sleep(seconds):
        return None

    monkeypatch.setattr(wa, "is_token_revoked", _revoked_after_wake)
    monkeypatch.setattr(wa, "_sleep", _no_sleep)

    await wa._watch_token_lifetime(
        object(), {"exp": int(time.time()) + 1000, "jti": "test-jti"}
    )
    assert closed == [(wa.WS_AUTH_REQUIRED, wa.REASON_SESSION_EXPIRED)]
    assert calls["n"] == 2


async def test_watcher_fails_closed_when_revocation_unknown(monkeypatch):
    closed: list[tuple[int, str]] = []
    monkeypatch.setattr(wa, "close_websocket", await _collect_close(closed))

    async def _raise(jti):
        raise RuntimeError("redis down")

    monkeypatch.setattr(wa, "is_token_revoked", _raise)

    await wa._watch_token_lifetime(
        object(), {"exp": int(time.time()) + 1000, "jti": "test-jti"}
    )
    assert closed == [(wa.WS_AUTH_REQUIRED, wa.REASON_SESSION_EXPIRED)]


# ---------------------------------------------------------------------------
# Rate gates (degrade open on Redis failures)
# ---------------------------------------------------------------------------


async def test_allow_ws_connect_within_limit(monkeypatch):
    async def _under(identity, category):
        return None

    monkeypatch.setattr(wa, "check_rate_limit_for", _under)
    assert await wa.allow_ws_connect("1.2.3.4") is True


async def test_allow_ws_connect_over_limit(monkeypatch):
    async def _over(identity, category):
        raise HTTPException(status_code=429, detail="limit")

    monkeypatch.setattr(wa, "check_rate_limit_for", _over)
    assert await wa.allow_ws_connect("1.2.3.4") is False


async def test_allow_ws_connect_degrades_open_on_redis_error(monkeypatch, caplog):
    async def _boom(identity, category):
        raise RuntimeError("redis down")

    monkeypatch.setattr(wa, "check_rate_limit_for", _boom)
    with caplog.at_level("WARNING", logger="server.ws_auth"):
        assert await wa.allow_ws_connect("1.2.3.4") is True


async def test_allow_ws_message_uses_user_identity(monkeypatch):
    seen: list[tuple[str, str]] = []

    async def _recorder(identity, category):
        seen.append((identity, category))

    monkeypatch.setattr(wa, "check_rate_limit_for", _recorder)
    assert await wa.allow_ws_message("alice") is True
    assert seen == [("alice", "ws_message")]


async def test_allow_ws_message_over_limit(monkeypatch):
    async def _over(identity, category):
        raise HTTPException(status_code=429, detail="limit")

    monkeypatch.setattr(wa, "check_rate_limit_for", _over)
    assert await wa.allow_ws_message("alice") is False


async def test_allow_ws_message_degrades_open_on_redis_error(monkeypatch):
    async def _boom(identity, category):
        raise RuntimeError("redis down")

    monkeypatch.setattr(wa, "check_rate_limit_for", _boom)
    assert await wa.allow_ws_message("alice") is True


def test_new_connection_id_is_hex_and_unique():
    a = wa.new_connection_id()
    b = wa.new_connection_id()
    assert len(a) == 16
    assert a != b


async def _async_false(jti):
    return False


async def _async_true(jti):
    return True
