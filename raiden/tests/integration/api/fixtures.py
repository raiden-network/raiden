import pytest
import os

from raiden.api.rest import APIServer
from raiden.raiden_service import RaidenService
from raiden.tests.integration.api.utils import prepare_api_server
from raiden.utils.typing import List


# TODO: Figure out why this fixture can't work as session scoped
#       What happens is that after one test is done, in the next one
#       the server is no longer running even though the teardown has not
#       been invoked.
@pytest.fixture
def api_server_test_instance(raiden_network: List[RaidenService]) -> APIServer:
    print("-" * 200)
    print("testing")
    print("-" * 200)

    api_server = prepare_api_server(raiden_network[0])

    yield api_server


@pytest.fixture
def client(api_server_test_instance):
    with api_server_test_instance.test_client() as client:
        with api_server_test_instance.app_context():
            api_server_test_instance.init_db()
        yield client

    os.unlink(api_server_test_instance.config["DATABASE"])
