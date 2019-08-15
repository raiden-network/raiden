import json
from unittest.mock import Mock, patch

import pytest
import requests
from eth_utils import to_canonical_address

from raiden.exceptions import ServiceRequestFailed
from raiden.network.pathfinding import PFSInfo, get_pfs_info

# We first test the correct handling of the pfs info endpoint. The info endpoint provides
# the Raiden Client with price and information about the token network registry.
# The client should handle incorrect information and formatting

pfs_test_default_registry_address = "0xB9633dd9a9a71F22C933bF121d7a22008f66B908"
pfs_test_default_payment_address = "0x2222222222222222222222222222222222222222"


# this test tests the correct handling of the success case
def test_get_pfs_info_success():

    info_data = {
        "price_info": 5,
        "network_info": {"chain_id": 42, "registry_address": pfs_test_default_registry_address},
        "version": "0.0.3",
        "operator": "John Doe",
        "message": "This is your favorite pathfinding service",
        "payment_address": pfs_test_default_payment_address,
    }

    response = Mock()
    response.configure_mock(status_code=200, content=json.dumps(info_data))

    with patch.object(requests, "get", return_value=response):
        pfs_info = get_pfs_info("url")

        req_registry_address = to_canonical_address(pfs_test_default_registry_address)

        assert isinstance(pfs_info, PFSInfo)
        assert pfs_info.price == 5
        assert pfs_info.chain_id == 42
        assert pfs_info.token_network_registry_address == req_registry_address
        assert pfs_info.message == "This is your favorite pathfinding service"
        assert pfs_info.operator == "John Doe"
        assert pfs_info.version == "0.0.3"


# This test tests the correct handling of the 3 error cases of get_pfs_info
# - JSONDecodeError, RequestException and KeyError
def test_get_pfs_info_error():

    # test JSONDecodeError with correct data but formatted as a string

    incorrect_json_info_data = {
        "price_info": 5,
        "network_info": {"chain_id": 42, "registry_address": pfs_test_default_registry_address},
        "version": "0.0.3",
        "operator": "John Doe",
        "message": "This is your favorite pathfinding service",
        "payment_address": pfs_test_default_payment_address,
    }

    response = Mock()
    response.configure_mock(status_code=200, content=str(incorrect_json_info_data))

    with patch.object(requests, "get", return_value=response):
        with pytest.raises(ServiceRequestFailed) as error:
            get_pfs_info("url")

        assert "Expecting property name enclosed in double quotes:" in str(error.value)

    # test RequestException
    with patch.object(requests, "get", side_effect=requests.RequestException()):
        with pytest.raises(ServiceRequestFailed) as error:
            get_pfs_info("url")

    # test KeyError with missing key 'price_info' and formatted as json

    incorrect_info_data = {
        "network_info": {"chain_id": 42, "registry_address": pfs_test_default_registry_address},
        "version": "0.0.3",
        "operator": "John Doe",
        "message": "This is your favorite pathfinding service",
        "payment_address": pfs_test_default_payment_address,
    }

    response.configure_mock(status_code=200, content=json.dumps(incorrect_info_data))
    with patch.object(requests, "get", return_value=response):
        with pytest.raises(ServiceRequestFailed) as error:
            get_pfs_info("url")

        assert "'price_info'" in str(error.value)
