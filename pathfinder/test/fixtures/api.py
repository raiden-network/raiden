from unittest.mock import Mock

import pytest

from pathfinder.api.rest import ServiceApi
from pathfinder.config import API_DEFAULT_PORT, API_PATH


@pytest.fixture(scope='session')
def api_schema() -> str:
    return 'http'


@pytest.fixture(scope='session')
def api_port() -> int:
    return API_DEFAULT_PORT


@pytest.fixture(scope='session')
def api_url(api_schema: str, api_port: int) -> str:
    return '{}://localhost:{}{}'.format(api_schema, api_port, API_PATH)


@pytest.fixture
def api_sut() -> ServiceApi:
    api = ServiceApi(Mock())
    api.run()
    return api
