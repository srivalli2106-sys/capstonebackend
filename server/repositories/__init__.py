"""Data-access layer: persistence mechanics only, no business decisions.

Repositories translate between application types and the underlying
MongoDB (``server.repositories.user_repository``,
``server.repositories.key_repository``) and Redis
(``server.repositories.presence_repository``,
``server.repositories.message_repository``) stores. Connection/client
lifecycle stays in :mod:`server.db` and :mod:`server.redis_client`.

Each repository exposes a small class (with a module-level singleton) so
services can depend on it explicitly and unit tests can substitute a fake
implementation without touching MongoDB or Redis.
"""
