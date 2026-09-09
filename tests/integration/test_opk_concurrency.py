"""
Atomic OPK consumption concurrency test (requires MongoDB).

Proves the Phase 4 guarantee that matching a bundle with
``find_one_and_update`` keyed on an unconsumed OPK is atomic: of many
concurrent consumers, exactly one receives the OPK and no two consumers can
receive the same key.
"""

from __future__ import annotations

import asyncio
from uuid import uuid4

import pytest

from server.db import get_db
from server.repositories.key_repository import key_repository

pytestmark = pytest.mark.integration


async def test_concurrent_opk_consumption_is_atomic():
    db = get_db()
    uid = f"opk_{uuid4().hex[:8]}"
    opk = b"\x77" * 32

    await db["key_bundles"].insert_one(
        {
            "user_id": uid,
            "spk_public": b"\x61" * 32,
            "spk_sig": b"\x62" * 32,
            "opk_public": opk,
            "version": 1,
        }
    )

    results = await asyncio.gather(*[key_repository.consume_opk(uid) for _ in range(8)])

    consumed = [r for r in results if r is not None]
    assert len(consumed) == 1
    assert consumed[0] == opk

    doc = await db["key_bundles"].find_one({"user_id": uid})
    assert doc is not None
    assert doc["opk_public"] is None
