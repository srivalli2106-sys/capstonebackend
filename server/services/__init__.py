"""Application services: business decisions, no persistence mechanics.

Services depend on repositories (injected via constructor, defaulting to the
module-level singletons) so the same business logic runs against real
MongoDB/Redis in production and against fakes in unit tests.

  * :mod:`server.services.user_service`    — registration business rules
  * :mod:`server.services.key_service`     — key-bundle business rules
  * :mod:`server.services.presence_service` — presence lifecycle decisions
  * :mod:`server.services.message_service` — message delivery/queue decisions

Routes (HTTP + WebSocket) are thin transport adapters over these services.
"""
