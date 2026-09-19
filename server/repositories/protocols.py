"""Repository contracts used by services (Protocols, no implementation).

Small structural interfaces so a service can be constructed with a real
repository (from the module-level singletons) in production and with a fake
in unit tests — without importing any MongoDB/Redis machinery. Nothing here
is instantiated; the concrete classes in the sibling modules implement these
shapes.
"""

from __future__ import annotations

from typing import Protocol


class UserRepository(Protocol):
    async def register_user(self, user_id: str, ik_public: bytes) -> bool: ...

    async def get_user(self, user_id: str) -> dict | None: ...


class KeyRepository(Protocol):
    async def upsert_key_bundle(
        self,
        user_id: str,
        xdh_public: bytes,
        spk_public: bytes,
        spk_sig: bytes,
        opk_public: bytes | None,
        pq_kem_public: bytes | None = ...,
        pq_sig_public: bytes | None = ...,
        pq_binding_sig: bytes | None = ...,
        protocol_version: int = ...,
    ) -> None: ...

    async def get_key_bundle(self, user_id: str) -> dict | None: ...

    async def consume_opk(self, user_id: str) -> bytes | None: ...


class PresenceRepository(Protocol):
    async def set_online(self, user_id: str) -> None: ...

    async def is_online(self, user_id: str) -> bool: ...

    async def set_offline(self, user_id: str) -> None: ...

    async def register_connection(self, user_id: str, connection_id: str) -> None: ...

    async def get_connection(self, user_id: str) -> str | None: ...

    async def remove_connection(self, user_id: str) -> None: ...


class MessageRepository(Protocol):
    async def enqueue_message(self, user_id: str, payload: str) -> None: ...

    async def dequeue_all_messages(self, user_id: str) -> list[str]: ...
