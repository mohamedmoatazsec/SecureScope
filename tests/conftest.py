import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))

from webserver import Profile, TestServer  # noqa: E402


@pytest.fixture
def http_server():
    """Start a configurable local HTTP server: `with http_server(Profile(...)) as server:`."""

    def factory(profile: Profile, tls: bool = False) -> TestServer:
        return TestServer(profile, tls=tls)

    return factory
