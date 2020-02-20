import pytest

from raiden.api.rest import APIServer
from raiden.app import App
from raiden.tests.integration.api.utils import prepare_api_server
from raiden.utils.typing import List


# TODO: Figure out why this fixture can't work as session scoped
#       What happens is that after one test is done, in the next one
#       the server is no longer running even though the teardown has not
#       been invoked.
@pytest.fixture
def api_server_test_instance(raiden_network: List[App]) -> APIServer:
    api_server = prepare_api_server(raiden_network[0])

    return api_server
