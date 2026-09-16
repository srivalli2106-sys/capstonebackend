"""Phase 11 envelope / message-id protocol unit tests (no infra required)."""

from __future__ import annotations

import json
import time

import pytest

from server.envelope import (
    MAX_DATA_CHARS,
    MAX_USER_ID_LENGTH,
    MESSAGE_TYPE_NAMES,
    MessageType,
    normalize_envelope,
)
from server.message_id import (
    is_valid_message_id,
    message_timestamp_ms,
    new_message_id,
)

_VALID_ID = new_message_id()


def _frame(**overrides) -> str:
    body = {
        "id": _VALID_ID,
        "type": "text",
        "recipient": "bob",
        "data": "opaque-blob",
    }
    body.update(overrides)
    return json.dumps(body)


# ---------------------------------------------------------------------------
# Message id (ULID) generation/validation
# ---------------------------------------------------------------------------


def test_message_id_shape_and_alphabet():
    mid = new_message_id()
    assert len(mid) == 26
    assert is_valid_message_id(mid)


def test_message_id_is_unique_across_many_draws():
    ids = {new_message_id() for _ in range(2000)}
    assert len(ids) == 2000


def test_message_id_is_monotonic_non_decreasing():
    ids = [new_message_id() for _ in range(500)]
    stamps = [message_timestamp_ms(mid) for mid in ids]
    assert all(a <= b for a, b in zip(stamps, stamps[1:], strict=False))


def test_message_id_timestamp_is_plausible_epoch_ms():
    stamps = [message_timestamp_ms(new_message_id()) for _ in range(3)]
    now = int(time.time() * 1000)
    assert all(abs(now - stamp) < 5000 for stamp in stamps)


@pytest.mark.parametrize(
    "bad",
    [
        "",
        "x",
        "short",
        "0" * 25,
        "0" * 27,
        "AAAAAAAAAAAAAAAAAAAAAAAAA_",
        "abcdefghijklmnopqrstuv90",
        "0O0O0O0O0O0O0O0O0O0O0O0O0O",
    ],
)
def test_is_valid_message_id_rejects(bad):
    assert is_valid_message_id(bad) is False


def test_is_valid_message_id_non_string():
    assert is_valid_message_id(None) is False
    assert is_valid_message_id(123456) is False


def test_message_id_lowercase_accepted():
    assert is_valid_message_id(new_message_id().lower())


# ---------------------------------------------------------------------------
# Message type registry
# ---------------------------------------------------------------------------


def test_registered_types_are_expected_catalog():
    assert MESSAGE_TYPE_NAMES == (
        "text",
        "file",
        "session_init",
        "session_accept",
        "delivery_receipt",
        "read_receipt",
        "typing",
    )


def test_every_enum_value_is_a_string():
    for member in MessageType:
        assert isinstance(member.value, str)


# ---------------------------------------------------------------------------
# normalize_envelope
# ---------------------------------------------------------------------------


def test_valid_frame_becomes_authoritative_envelope():
    env = normalize_envelope(_frame(), "alice")
    assert env["version"] == 1
    assert env["id"] == _VALID_ID
    assert env["type"] == "text"
    assert env["sender"] == "alice"
    assert env["recipient"] == "bob"
    assert env["data"] == "opaque-blob"
    assert isinstance(env["timestamp"], int)


def test_timestamp_uses_injected_clock():
    env = normalize_envelope(_frame(), "alice", now_ms=lambda: 42)
    assert env["timestamp"] == 42


def test_injected_clock_must_return_int():
    with pytest.raises(TypeError):
        normalize_envelope(_frame(), "alice", now_ms=lambda: "not-a-number")


def test_sender_claim_is_overwritten():
    # A client cannot set its own sender: the server decides identity.
    env = normalize_envelope(_frame(sender="mallory"), "alice")
    assert env["sender"] == "alice"


def test_version_claim_is_ignored():
    # The server is authoritative over the envelope version.
    env = normalize_envelope(_frame(version=99), "alice")
    assert env["version"] == 1


@pytest.mark.parametrize(
    "frame",
    [
        "not-json",
        "[]",
        "42",
        '"text"',
        _frame(id="bad-id"),
        _frame(id=""),
        _frame(id="0" * 26 + "extra"),
        _frame(id=None),
        _frame(type="unknown_type"),
        _frame(type=None),
        _frame(recipient=""),
        _frame(recipient="r" * (MAX_USER_ID_LENGTH + 1)),
        _frame(recipient=None),
        _frame(data=""),
        _frame(data=None),
    ],
)
def test_invalid_frames_are_dropped(frame):
    assert normalize_envelope(frame, "alice") is None


def test_oversized_data_frame_is_dropped():
    # Built inside the test: a ~65 KB fixture must never appear as a pytest
    # node id (Windows caps environment variable values at 32767 chars).
    frame = _frame(data="x" * (MAX_DATA_CHARS + 1))
    assert normalize_envelope(frame, "alice") is None


def test_non_string_data_is_dropped():
    assert normalize_envelope(_frame(data=12345), "alice") is None


def test_serialize_envelope_round_trips():
    from server.envelope import serialize_envelope

    env = normalize_envelope(_frame(), "alice")
    assert json.loads(serialize_envelope(env)) == env


def test_data_just_under_limit_is_accepted():
    env = normalize_envelope(_frame(data="x" * MAX_DATA_CHARS), "alice")
    assert env is not None
    assert len(env["data"]) == MAX_DATA_CHARS
