"""WebSocket handshake and lifecycle tests (no external infrastructure).

Phase 7 replaced the query-string JWT with a first-frame auth message
``{"type": "auth", "token": "<JWT>"}``. These tests drive the real route via
the infraless TestClient; the Redis-touching helpers are stubbed so nothing
connects to real services.

The real :func:`server.ws_auth.verify_ws_token` runs in every test; the
fixture stubs the primitives underneath it (``verify_access_token`` and
``is_token_revoked``) and individual tests restore the real JWT verifier for
the specific invalid/expired/wrong-issuer cases.

Close codes asserted:
  4001 auth failure/timeout/revoked, 4003 binary-first-frame policy,
  4000 takeover of a replaced connection, 1009 oversized frame, 1013 server
  at capacity.
"""

from __future__ import annotations

import json
import logging
from types import SimpleNamespace

import jwt as pyjwt
import pytest
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from server import ws_auth
from server.config import settings

_CLAIMS = {
    "sub": "alice",
    "user_id": "alice",
    "iss": "secure-messaging-api",
    "iat": 1,
    "exp": 4102444800,
    "jti": "test-jti",
}


def _auth(token: str) -> str:
    return json.dumps({"type": "auth", "token": token})


def _msg(
    to: str, data: str, *, mid: str | None = None, mtype: str = "text"
) -> str:
    from server.message_id import new_message_id

    return json.dumps(
        {
            "id": mid or new_message_id(),
            "type": mtype,
            "recipient": to,
            "data": data,
        }
    )


def _envelope(*, mid: str, mtype: str, sender: str, recipient: str, data: str):
    """Build the server-authoritative envelope a client would receive."""
    return {
        "version": 1,
        "id": mid,
        "type": mtype,
        "sender": sender,
        "recipient": recipient,
        "data": data,
    }


def _assert_relayed(received: dict, sender: str, recipient: str, data: str) -> str:
    parsed = dict(received)
    timestamp = parsed.pop("timestamp")
    mid = parsed.pop("id")
    assert parsed == {
        "version": 1,
        "type": "text",
        "sender": sender,
        "recipient": recipient,
        "data": data,
    }
    assert isinstance(timestamp, int)
    return mid


def _signed(payload: dict) -> str:
    return pyjwt.encode(payload, settings.jwt_secret, algorithm=settings.jwt_algorithm)


@pytest.fixture
def ws_env(monkeypatch):
    """Stub every Redis/rate/presence touchpoint of the /ws route.

    ``verify_access_token`` is stubbed (claims -> alice) so the real
    ``verify_ws_token`` flow works without valid development JWTs; revocation
    reads return not-revoked. Tests needing genuine JWT verification restore
    the real verifier themselves.

    The route delegates presence/queue work to ``presence_service`` and
    ``message_service``, which hold the repository singletons by default; so
    the fixture stubs the singleton *instances* (set_online etc.) and every
    path to real Redis is inert for the whole test.
    """
    from server import ws_registry
    from server.repositories.message_repository import message_repository
    from server.repositories.presence_repository import presence_repository
    from server.ws_registry import WsRegistry

    monkeypatch.setattr(ws_auth, "settings", SimpleNamespace(
        ws_auth_timeout_seconds=10.0,
        ws_presence_ttl_seconds=300,
        ws_idle_timeout_seconds=180.0,
        ws_keepalive_seconds=60.0,
    ))
    monkeypatch.setattr(ws_registry, "registry", WsRegistry(20, max_connections_per_ip=20))

    async def _allow(*args, **kwargs):
        return True

    async def _not_revoked(jti):
        return False

    async def _noop(*args, **kwargs):
        return None

    async def _empty(user_id):
        return []

    async def _online_true(user_id):
        return True

    monkeypatch.setattr(ws_auth, "allow_ws_connect", _allow)
    monkeypatch.setattr(ws_auth, "allow_ws_message", _allow)
    monkeypatch.setattr(ws_auth, "verify_access_token", lambda token: dict(_CLAIMS))
    monkeypatch.setattr(ws_auth, "is_token_revoked", _not_revoked)
    monkeypatch.setattr(presence_repository, "set_online", _noop)
    monkeypatch.setattr(presence_repository, "register_connection", _noop)
    monkeypatch.setattr(presence_repository, "set_offline", _noop)
    monkeypatch.setattr(presence_repository, "remove_connection", _noop)
    monkeypatch.setattr(presence_repository, "is_online", _online_true)
    monkeypatch.setattr(message_repository, "enqueue_message", _noop)
    monkeypatch.setattr(message_repository, "dequeue_all_messages", _empty)


def _use_real_jwt_verifier(monkeypatch):
    from server.jwt_auth import verify_access_token as real

    monkeypatch.setattr(ws_auth, "verify_access_token", real)


# ---------------------------------------------------------------------------
# Handshake
# ---------------------------------------------------------------------------


def test_ws_rejects_non_auth_first_frame(client: TestClient, ws_env):
    with pytest.raises(WebSocketDisconnect) as exc:
        with client.websocket_connect("/ws") as ws:
            ws.send_text("{}")
            ws.receive_text()
    assert exc.value.code == 4001


def test_ws_rejects_malformed_first_frame(client: TestClient, ws_env):
    with pytest.raises(WebSocketDisconnect) as exc:
        with client.websocket_connect("/ws") as ws:
            ws.send_text("not-json")
            ws.receive_text()
    assert exc.value.code == 4001
    assert exc.value.reason == "Authentication failed"


def test_ws_rejects_invalid_token(client: TestClient, ws_env, monkeypatch):
    _use_real_jwt_verifier(monkeypatch)
    with pytest.raises(WebSocketDisconnect) as exc:
        with client.websocket_connect("/ws") as ws:
            ws.send_text(_auth("not-a-valid-token"))
            ws.receive_text()
    assert exc.value.code == 4001


def test_ws_rejects_expired_token(client: TestClient, ws_env, monkeypatch):
    _use_real_jwt_verifier(monkeypatch)
    token = _signed({
        "sub": "alice",
        "iss": settings.jwt_issuer,
        "iat": 1,
        "exp": 2,
        "jti": "j1",
    })
    with pytest.raises(WebSocketDisconnect) as exc:
        with client.websocket_connect("/ws") as ws:
            ws.send_text(_auth(token))
            ws.receive_text()
    assert exc.value.code == 4001


def test_ws_rejects_wrong_issuer_token(client: TestClient, ws_env, monkeypatch):
    _use_real_jwt_verifier(monkeypatch)
    token = _signed({
        "sub": "alice",
        "iss": "wrong-issuer",
        "iat": 1,
        "exp": 4102444800,
        "jti": "j2",
    })
    with pytest.raises(WebSocketDisconnect) as exc:
        with client.websocket_connect("/ws") as ws:
            ws.send_text(_auth(token))
            ws.receive_text()
    assert exc.value.code == 4001


def test_ws_rejects_revoked_token(client: TestClient, ws_env, monkeypatch):
    async def _revoked(jti):
        return True

    monkeypatch.setattr(ws_auth, "is_token_revoked", _revoked)
    with pytest.raises(WebSocketDisconnect) as exc:
        with client.websocket_connect("/ws") as ws:
            ws.send_text(_auth("anything"))
            ws.receive_text()
    assert exc.value.code == 4001
    assert exc.value.reason == "Session expired"


def test_ws_rejects_when_revocation_check_fails(client: TestClient, ws_env, monkeypatch):
    from server import ws_registry
    from server.repositories.presence_repository import presence_repository

    async def _boom(jti):
        raise RuntimeError("redis down")

    async def _must_not_set_online(user_id):
        raise AssertionError("presence must not be created on failed auth")

    async def _must_not_register(user_id, conn_id):
        raise AssertionError("connection must not be registered on failed auth")

    monkeypatch.setattr(ws_auth, "is_token_revoked", _boom)
    monkeypatch.setattr(presence_repository, "set_online", _must_not_set_online)
    monkeypatch.setattr(presence_repository, "register_connection", _must_not_register)

    with pytest.raises(WebSocketDisconnect) as exc:
        with client.websocket_connect("/ws") as ws:
            ws.send_text(_auth("anything"))
            ws.receive_text()
    assert exc.value.code == 4001
    assert exc.value.reason == "Authentication failed"
    # Fail-closed: no authenticated session may exist after the failed auth.
    assert ws_registry.registry.get("alice") is None


def test_ws_times_out_waiting_for_auth(client: TestClient, ws_env, monkeypatch):
    monkeypatch.setattr(ws_auth, "settings", SimpleNamespace(
        ws_auth_timeout_seconds=0.05,
        ws_presence_ttl_seconds=300,
    ))
    with pytest.raises(WebSocketDisconnect) as exc:
        with client.websocket_connect("/ws") as ws:
            ws.receive_text()  # no auth frame ever sent
    assert exc.value.code == 4001
    assert exc.value.reason == "Authentication timed out"


def test_ws_rejects_binary_first_frame(client: TestClient, ws_env):
    with pytest.raises(WebSocketDisconnect) as exc:
        with client.websocket_connect("/ws") as ws:
            ws.send_bytes(b"\x00")
            ws.receive_text()
    assert exc.value.code == 4003


def test_ws_close_reason_is_generic(client: TestClient, ws_env, monkeypatch):
    _use_real_jwt_verifier(monkeypatch)
    with pytest.raises(WebSocketDisconnect) as exc:
        with client.websocket_connect("/ws") as ws:
            ws.send_text(_auth("bad-token"))
            ws.receive_text()
    assert exc.value.code == 4001
    assert exc.value.reason == "Authentication failed"


# ---------------------------------------------------------------------------
# Authenticated message flow
# ---------------------------------------------------------------------------


def test_ws_ignores_query_string_token(client: TestClient, ws_env):
    with client.websocket_connect("/ws?token=stale-token") as ws:
        ws.send_text(_auth("any-token"))
        ws.send_text(_msg("alice", "blob"))
        _assert_relayed(json.loads(ws.receive_text()), "alice", "alice", "blob")


def test_ws_authenticates_and_relays(client: TestClient, ws_env):
    with client.websocket_connect("/ws") as ws:
        ws.send_text(_auth("jwt-abc"))
        ws.send_text(_msg("alice", "blob"))
        _assert_relayed(json.loads(ws.receive_text()), "alice", "alice", "blob")


def test_ws_flushes_pending_messages_on_connect(client: TestClient, ws_env, monkeypatch):
    from server.repositories.message_repository import message_repository

    async def _pending(user_id):
        return [
            json.dumps(
                _envelope(
                    mid="0" * 26,
                    mtype="text",
                    sender="bob",
                    recipient="alice",
                    data="queued",
                )
                | {"timestamp": 1750000000000}
            )
        ]

    monkeypatch.setattr(message_repository, "dequeue_all_messages", _pending)
    with client.websocket_connect("/ws") as ws:
        ws.send_text(_auth("jwt-abc"))
        env = json.loads(ws.receive_text())
        assert env["sender"] == "bob"
        assert env["recipient"] == "alice"
        assert env["data"] == "queued"


def test_ws_queues_message_when_recipient_offline(client: TestClient, ws_env, monkeypatch):
    from server.repositories.message_repository import message_repository
    from server.repositories.presence_repository import presence_repository

    queued: list[tuple[str, str]] = []

    async def _offline(user_id):
        return False

    async def _enqueue(user_id, payload):
        queued.append((user_id, payload))

    monkeypatch.setattr(presence_repository, "is_online", _offline)
    monkeypatch.setattr(message_repository, "enqueue_message", _enqueue)
    with client.websocket_connect("/ws") as ws:
        ws.send_text(_auth("jwt-abc"))
        ws.send_text(_msg("bob", "blob-1"))
        ws.send_text(_msg("bob", "blob-2"))

    assert [q[0] for q in queued] == ["bob", "bob"]
    datas = [json.loads(payload)["data"] for _, payload in queued]
    assert datas == ["blob-1", "blob-2"]
    for _, payload in queued:
        env = json.loads(payload)
        _assert_relayed(env, "alice", "bob", env["data"])


def test_ws_marks_user_online_after_auth(client: TestClient, ws_env, monkeypatch):
    from server.repositories.presence_repository import presence_repository

    events: list[tuple] = []

    async def _set_online(user_id):
        events.append(("online", user_id))

    async def _register(user_id, conn_id):
        events.append(("register", user_id, conn_id))

    monkeypatch.setattr(presence_repository, "set_online", _set_online)
    monkeypatch.setattr(presence_repository, "register_connection", _register)

    with client.websocket_connect("/ws") as ws:
        ws.send_text(_auth("jwt-abc"))
        ws.send_text(_msg("alice", "blob"))
        ws.receive_text()

    assert ("online", "alice") in events
    assert any(e[0] == "register" and e[1] == "alice" for e in events)


def test_ws_drops_binary_messages_after_auth(client: TestClient, ws_env):
    with client.websocket_connect("/ws") as ws:
        ws.send_text(_auth("jwt-abc"))
        ws.send_bytes(b"\x00\x01")
        ws.send_text(_msg("alice", "ok"))
        _assert_relayed(json.loads(ws.receive_text()), "alice", "alice", "ok")


def test_ws_closes_oversized_message(client: TestClient, ws_env):
    with client.websocket_connect("/ws") as ws:
        ws.send_text(_auth("jwt-abc"))
        ws.send_text(json.dumps({"to": "alice", "data": "x" * 70000}))
        with pytest.raises(WebSocketDisconnect) as exc:
            ws.receive_text()
        assert exc.value.code == 1009
        assert exc.value.reason == "Message too large"


def test_ws_drops_rate_limited_messages(client: TestClient, ws_env, monkeypatch):
    calls = {"n": 0}

    async def _limited(user_id):
        calls["n"] += 1
        # 1 -> allow, 2 -> drop, 3 -> allow
        return calls["n"] != 2

    monkeypatch.setattr(ws_auth, "allow_ws_message", _limited)
    with client.websocket_connect("/ws") as ws:
        ws.send_text(_auth("jwt-abc"))
        ws.send_text(_msg("alice", "one"))
        _assert_relayed(json.loads(ws.receive_text()), "alice", "alice", "one")
        ws.send_text(_msg("alice", "two"))  # dropped
        ws.send_text(_msg("alice", "three"))
        _assert_relayed(json.loads(ws.receive_text()), "alice", "alice", "three")


# ---------------------------------------------------------------------------
# Lifecycle: takeover, capacity, non-repudiation
# ---------------------------------------------------------------------------


def test_ws_takeover_closes_previous_connection(client: TestClient, ws_env):
    with client.websocket_connect("/ws") as ws1:
        ws1.send_text(_auth("jwt-abc"))
        with client.websocket_connect("/ws") as ws2:
            ws2.send_text(_auth("jwt-abc"))
            with pytest.raises(WebSocketDisconnect) as exc:
                ws1.receive_text()
            assert exc.value.code == 4000
            assert exc.value.reason == "Replaced by new connection"
            # The replacement is fully functional.
            ws2.send_text(_msg("alice", "blob"))
            _assert_relayed(json.loads(ws2.receive_text()), "alice", "alice", "blob")


def test_ws_takeover_does_not_clear_presence_of_replacement(
    client: TestClient, ws_env, monkeypatch
):
    from server import ws_registry
    from server.repositories.presence_repository import presence_repository

    offline: list[str] = []

    async def _set_offline(user_id):
        offline.append(user_id)

    monkeypatch.setattr(presence_repository, "set_offline", _set_offline)

    old_cm = client.websocket_connect("/ws")
    old = old_cm.__enter__()
    old.send_text(_auth("jwt-abc"))

    with client.websocket_connect("/ws") as new:
        new.send_text(_auth("jwt-abc"))
        with pytest.raises(WebSocketDisconnect) as exc:
            old.receive_text()
        assert exc.value.code == 4000
        assert ws_registry.registry.get("alice") is not None

        # Exit the replaced connection while the replacement is still alive;
        # its cleanup must not remove or clear the replacement's presence.
        old_cm.__exit__(None, None, None)
        assert ws_registry.registry.get("alice") is not None
        assert offline == []


def test_ws_refuses_rate_limited_connect(client: TestClient, ws_env, monkeypatch):
    async def _deny(identity):
        return False

    monkeypatch.setattr(ws_auth, "allow_ws_connect", _deny)
    with pytest.raises(WebSocketDisconnect) as exc:
        with client.websocket_connect("/ws"):
            pass  # refused before accept
    assert exc.value.code == 1013
    assert exc.value.reason == "Rate limit exceeded"


def test_ws_refuses_at_capacity(client: TestClient, ws_env, monkeypatch):
    from server import ws_registry
    from server.ws_registry import WsRegistry

    monkeypatch.setattr(ws_registry, "registry", WsRegistry(1))
    with client.websocket_connect("/ws") as ws1:
        with pytest.raises(WebSocketDisconnect) as exc:
            with client.websocket_connect("/ws"):
                pass  # refused before accept
        assert exc.value.code == 1013
        assert exc.value.reason == "Server at capacity"
        # ws1 is still usable after the refusal.
        ws1.send_text(_auth("jwt-abc"))
        ws1.send_text(_msg("alice", "solo"))
        _assert_relayed(json.loads(ws1.receive_text()), "alice", "alice", "solo")


# ---------------------------------------------------------------------------
# Phase 12: idle timeout + per-IP connection budget
# ---------------------------------------------------------------------------


def test_ws_closes_idle_connection(client: TestClient, ws_env, monkeypatch):
    monkeypatch.setattr(ws_auth, "settings", SimpleNamespace(
        ws_auth_timeout_seconds=10.0,
        ws_presence_ttl_seconds=300,
        ws_idle_timeout_seconds=0.05,
    ))
    with pytest.raises(WebSocketDisconnect) as exc:
        with client.websocket_connect("/ws") as ws:
            ws.send_text(_auth("jwt-abc"))
            ws.receive_text()  # never sends an application frame again
    assert exc.value.code == 4008
    assert exc.value.reason == "Idle timeout"


def test_ws_active_connection_survives_idle_timeout(client: TestClient, ws_env, monkeypatch):
    monkeypatch.setattr(ws_auth, "settings", SimpleNamespace(
        ws_auth_timeout_seconds=10.0,
        ws_presence_ttl_seconds=300,
        ws_idle_timeout_seconds=0.05,
    ))
    with client.websocket_connect("/ws") as ws:
        ws.send_text(_auth("jwt-abc"))
        ws.send_text(_msg("alice", "ping-1"))
        _assert_relayed(json.loads(ws.receive_text()), "alice", "alice", "ping-1")
        ws.send_text(_msg("alice", "ping-2"))
        _assert_relayed(json.loads(ws.receive_text()), "alice", "alice", "ping-2")


def test_ws_refuses_beyond_per_ip_cap(client: TestClient, ws_env, monkeypatch):
    from server import ws_registry
    from server.ws_registry import WsRegistry

    monkeypatch.setattr(ws_registry, "registry", WsRegistry(100, max_connections_per_ip=1))
    with client.websocket_connect("/ws") as ws1:
        ws1.send_text(_auth("jwt-abc"))
        with pytest.raises(WebSocketDisconnect) as exc:
            with client.websocket_connect("/ws"):
                pass  # same address, cap already reached
        assert exc.value.code == 1013
        assert exc.value.reason == "Server at capacity"
        ws1.send_text(_msg("alice", "still-alive"))
        _assert_relayed(json.loads(ws1.receive_text()), "alice", "alice", "still-alive")


def test_ws_never_logs_token_or_payload(client: TestClient, ws_env, caplog):
    secret_token = "super-secret-token-value-12345"
    with caplog.at_level(logging.INFO, logger="server"):
        with client.websocket_connect("/ws") as ws:
            ws.send_text(_auth(secret_token))
            ws.send_text(_msg("alice", "super-secret-plaintext-999"))
            env = json.loads(ws.receive_text())
            assert env["sender"] == "alice"
            assert env["data"] == "super-secret-plaintext-999"

    combined = "\n".join(r.getMessage() for r in caplog.records)
    assert secret_token not in combined
    assert "super-secret-plaintext-999" not in combined
