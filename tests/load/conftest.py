"""Load test conftest: re-use the shared client fixture from e2e."""
from __future__ import annotations

# Re-export the shared client fixture so pytest discovers it for tests in this directory.
from tests.e2e.conftest import client  # noqa: F401
