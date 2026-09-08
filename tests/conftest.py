"""
Shared pytest fixtures/config.

- Forces APP_ENV=test before any server module is imported so the module-level
  Settings singleton is created in test mode.
- Provides an infra-free TestClient (lifespan / MongoDB init is NOT run).
- Automatically skips integration-marked tests unless RUN_INTEGRATION=1.
"""

from __future__ import annotations

import os

# Must be set before server.config is imported.
os.environ.setdefault("APP_ENV", "test")

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
