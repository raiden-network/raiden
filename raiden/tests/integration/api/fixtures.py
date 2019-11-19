# pylint: disable=too-many-arguments,redefined-outer-name
import pytest

from raiden.api.rest import APIServer
from raiden.app import App
from raiden.tests.integration.api.utils import create_api_server
from raiden.utils.typing import Iterable, List


# TODO: Figure out why this fixture can't work as session scoped
#       What happens is that after one test is done, in the next one
#       the server is no longer running even though the teardown has not
#       been invoked.
@pytest.fixture
def api_server_test_instance(
    raiden_network: List[App], rest_api_port_number: int
) -> Iterable[APIServer]:
    api_server = create_api_server(raiden_network[0], rest_api_port_number)

    yield api_server

    if api_server:
        api_server.stop()
