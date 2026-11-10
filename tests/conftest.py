from pathlib import Path

import pytest


@pytest.fixture
def sample_zeek_logs() -> Path:
    """Return the deterministic, synthetic Zeek ASCII log fixture directory."""
    return Path(__file__).parent / "fixtures" / "zeek"
