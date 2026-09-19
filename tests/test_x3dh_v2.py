"""x3dh v2 (hybrid) wire-format tests."""

from __future__ import annotations

import pytest

from protocol.x3dh import (
    INIT_VERSION_V1,
    INIT_VERSION_V2,
    ML_KEM_768_CIPHERTEXT_BYTES,
    ML_KEM_768_PUBLIC_KEY_BYTES,
    X3DHError,
    pack_init_message_v2,
    unpack_init_message_v2,
    unpack_init_message,
)


def test_v2_pack_then_unpack_round_trip():
    ik_x = bytes(range(32))
    kem_ct = bytes((i + 7) & 0xFF for i in range(ML_KEM_768_CIPHERTEXT_BYTES))
    alice_pq_kem = bytes((i + 13) & 0xFF for i in range(ML_KEM_768_PUBLIC_KEY_BYTES))
    ek = bytes(range(32, 64))
    payload = pack_init_message_v2(ik_x, kem_ct, alice_pq_kem, ek, opk_index=0)
    assert payload[0] == INIT_VERSION_V2
    parsed = unpack_init_message_v2(payload)
    assert parsed["version"] == INIT_VERSION_V2
    assert parsed["ik_x_public"] == ik_x
    assert parsed["kem_ciphertext"] == kem_ct
    assert parsed["alice_pq_kem_public"] == alice_pq_kem
    assert parsed["ek_public"] == ek
    assert parsed["opk_index"] == 0


def test_v2_pack_rejects_wrong_kem_ciphertext_length():
    ik_x = bytes(32)
    bad_kem = bytes(ML_KEM_768_CIPHERTEXT_BYTES - 1)
    alice_pq_kem = bytes(ML_KEM_768_PUBLIC_KEY_BYTES)
    ek = bytes(32)
    with pytest.raises(X3DHError, match="kem_ciphertext"):
        pack_init_message_v2(ik_x, bad_kem, alice_pq_kem, ek, opk_index=None)


def test_v2_pack_rejects_wrong_alice_pq_kem_pub_length():
    ik_x = bytes(32)
    kem_ct = bytes(ML_KEM_768_CIPHERTEXT_BYTES)
    bad_alice_pq = bytes(ML_KEM_768_PUBLIC_KEY_BYTES - 1)
    ek = bytes(32)
    with pytest.raises(X3DHError, match="alice_pq_kem_public"):
        pack_init_message_v2(ik_x, kem_ct, bad_alice_pq, ek, opk_index=None)


def test_v2_unpack_rejects_wrong_total_length():
    too_short = bytes(ML_KEM_768_CIPHERTEXT_BYTES + ML_KEM_768_PUBLIC_KEY_BYTES)
    with pytest.raises(X3DHError, match="v2 init"):
        unpack_init_message_v2(too_short)


def test_unpack_dispatcher_routes_v1_to_v1():
    payload = bytes([INIT_VERSION_V1]) + bytes(32) + bytes(32) + bytes([0xFF])
    parsed = unpack_init_message(payload)
    assert parsed["version"] == INIT_VERSION_V1
    assert "kem_ciphertext" not in parsed


def test_unpack_dispatcher_routes_v2_to_v2():
    payload = (
        bytes([INIT_VERSION_V2])
        + bytes(32)
        + bytes(ML_KEM_768_CIPHERTEXT_BYTES)
        + bytes(ML_KEM_768_PUBLIC_KEY_BYTES)
        + bytes(32)
        + bytes([0xFF])
    )
    parsed = unpack_init_message(payload)
    assert parsed["version"] == INIT_VERSION_V2
    assert len(parsed["kem_ciphertext"]) == ML_KEM_768_CIPHERTEXT_BYTES
    assert len(parsed["alice_pq_kem_public"]) == ML_KEM_768_PUBLIC_KEY_BYTES


def test_unpack_dispatcher_rejects_unknown_version():
    payload = bytes([99]) + bytes(100)
    with pytest.raises(X3DHError, match="unsupported"):
        unpack_init_message(payload)


def test_v2_opk_index_none_uses_sentinel():
    ik_x = bytes(32)
    kem_ct = bytes(ML_KEM_768_CIPHERTEXT_BYTES)
    alice_pq_kem = bytes(ML_KEM_768_PUBLIC_KEY_BYTES)
    ek = bytes(32)
    payload = pack_init_message_v2(ik_x, kem_ct, alice_pq_kem, ek, opk_index=None)
    parsed = unpack_init_message_v2(payload)
    assert parsed["opk_index"] is None


def test_v2_wire_size_is_exactly_one_byte_per_field():
    expected = (
        1                              # version
        + 32                           # ik_x_public
        + ML_KEM_768_CIPHERTEXT_BYTES  # kem_ciphertext
        + ML_KEM_768_PUBLIC_KEY_BYTES  # alice_pq_kem_public
        + 32                           # ek_public
        + 1                            # opk_index
    )
    assert expected == 2338
