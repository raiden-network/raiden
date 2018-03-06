import pytest

from pathfinder.api.rest import ServiceApi
from pathfinder.config import API_DEFAULT_PORT, API_PATH
from pathfinder.pathfinding_service import PathfindingService


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
def api_sut(pathfinding_service: PathfindingService) -> ServiceApi:
    api = ServiceApi(pathfinding_service)
    api.run()
    return api
