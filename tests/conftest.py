"""
Shared pytest fixtures/config.

- Forces APP_ENV=test before any server module is imported so the module-level
  Settings singleton is created in test mode.
- Overrides ALLOWED_HOSTS and CORS_ORIGINS with permissive test values so a
  locally-present .env (which may contain production-like placeholders that
  the developer is iterating on) cannot poison the module-level Settings
  and cause the host-header middleware to reject the TestClient's
  "testserver" Host. Process env wins over .env in pydantic-settings.
- Provides an infra-free TestClient (lifespan / MongoDB init is NOT run).
- Automatically skips integration-marked tests unless RUN_INTEGRATION=1.
"""

from __future__ import annotations

import os

# Must be set before server.config is imported. Process env values win over
# any locally-present .env file (pydantic-settings priority: env > .env).
os.environ.setdefault("APP_ENV", "test")
os.environ.setdefault("ALLOWED_HOSTS", "*")
os.environ.setdefault("CORS_ORIGINS", "*")
os.environ.setdefault("SECURE_TRANSPORT", "false")
os.environ.setdefault("JWT_SECRET", "test-only-jwt-secret-must-be-long-enough")
os.environ.setdefault("MONGODB_URI", "mongodb://localhost:27017")

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from server.app import app  # noqa: E402


def pytest_runtest_setup(item: pytest.Item) -> None:
    """Skip integration tests unless explicitly requested."""
    if "integration" in item.keywords and os.getenv("RUN_INTEGRATION") != "1":
        pytest.skip(
            "integration test requires RUN_INTEGRATION=1 and running "
            "MongoDB + Redis"
        )


@pytest.fixture
def client() -> TestClient:
    """HTTP client against the FastAPI app WITHOUT running the lifespan.

    The lifespan (init_db / MongoDB index creation) still fails on machines
    without MongoDB, so unit tests intentionally avoid it.
    """
    return TestClient(app)
