"""UserService registration business-rule tests (no infra required).

The repo is a fake implementing the ``UserRepository`` protocol; all
validation order and error-message assertions pin the pre-refactor HTTP
contract.
"""

from __future__ import annotations

import pytest

from server.exceptions import Conflict, InvalidRequest
from server.services.user_service import UserService

_IK = ("ab" * 32)  # 32-byte identity key as hex


class _Users:
    def __init__(self, registered: set[str] | None = None):
        self.registered = set(registered or ())
        self.calls: list[tuple] = []
        self.return_false = False

    async def register_user(self, user_id: str, ik_public: bytes) -> bool:
        self.calls.append((user_id, ik_public))
        if self.return_false or user_id in self.registered:
            return False
        self.registered.add(user_id)
        return True

    async def get_user(self, user_id: str) -> dict | None:
        return {"user_id": user_id} if user_id in self.registered else None


async def test_register_success_returns_user_id():
    users = _Users()
    svc = UserService(users=users)

    result = await svc.register("alice", _IK)

    assert result == "alice"
    assert users.calls == [("alice", b"\xab" * 32)]


async def test_register_rejects_short_user_id():
    svc = UserService(users=_Users())
    with pytest.raises(InvalidRequest) as exc:
        await svc.register("ab", _IK)
    assert exc.value.message == "user_id too short"


async def test_register_rejects_short_user_id_empty():
    svc = UserService(users=_Users())
    with pytest.raises(InvalidRequest):
        await svc.register("", _IK)


async def test_register_rejects_non_hex_identity_key():
    svc = UserService(users=_Users())
    with pytest.raises(InvalidRequest) as exc:
        await svc.register("alice", "zz")
    assert exc.value.message == "ik_public must be hex"


async def test_register_rejects_wrong_length_identity_key():
    svc = UserService(users=_Users())
    with pytest.raises(InvalidRequest) as exc:
        await svc.register("alice", "ab" * 31)
    assert exc.value.message == "ik_public must be 32 bytes"


async def test_register_duplicate_raises_conflict():
    svc = UserService(users=_Users(registered={"alice"}))
    with pytest.raises(Conflict) as exc:
        await svc.register("alice", _IK)
    assert "already registered" in exc.value.message


async def test_register_duplicate_reported_by_repo_raises_conflict():
    users = _Users()
    users.return_false = True
    svc = UserService(users=users)
    with pytest.raises(Conflict):
        await svc.register("bob", _IK)
