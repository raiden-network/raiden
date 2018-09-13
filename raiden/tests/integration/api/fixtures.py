# pylint: disable=too-many-arguments,redefined-outer-name
import pytest

from raiden.tests.integration.api.utils import create_api_server


# TODO: Figure out why this fixture can't work as session scoped
#       What happens is that after one test is done, in the next one
#       the server is no longer running even though the teardown has not
#       been invoked.
@pytest.fixture
def test_api_server(raiden_network, rest_api_port_number):
    api_server = create_api_server(raiden_network[0], rest_api_port_number)

    yield api_server

    if api_server:
        api_server.stop()
