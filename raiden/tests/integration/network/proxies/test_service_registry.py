from unittest.mock import Mock, patch

import pytest
import requests
from eth_utils import (
    is_canonical_address,
    is_same_address,
    to_canonical_address,
    to_checksum_address,
)

from raiden.constants import RoutingMode
from raiden.exceptions import BrokenPreconditionError
from raiden.network.pathfinding import configure_pfs_or_exit, get_random_pfs, get_valid_pfs_url
from raiden.settings import DEFAULT_PATHFINDING_MAX_FEE
from raiden.tests.utils.factories import HOP1
from raiden.tests.utils.mocks import mocked_failed_response, mocked_json_response
from raiden.tests.utils.smartcontracts import deploy_service_registry_and_set_urls
from raiden.utils import privatekey_to_address
from raiden.utils.typing import ChainID, FeeAmount, PaymentNetworkAddress

token_network_registry_address_test_default = PaymentNetworkAddress(
    to_canonical_address("0xB9633dd9a9a71F22C933bF121d7a22008f66B908")
)


def test_service_registry_set_url(service_registry_address, private_keys, web3, contract_manager):
    c1_service_proxy, _ = deploy_service_registry_and_set_urls(
        private_keys=private_keys,
        web3=web3,
        contract_manager=contract_manager,
        service_registry_address=service_registry_address,
    )
    with pytest.raises(BrokenPreconditionError):
        c1_service_proxy.set_url("")

    with pytest.raises(BrokenPreconditionError):
        c1_service_proxy.set_url("raiden-network.com")


def test_service_registry_random_pfs(
    service_registry_address, private_keys, web3, contract_manager
):
    addresses = [privatekey_to_address(key) for key in private_keys]
    c1_service_proxy, urls = deploy_service_registry_and_set_urls(
        private_keys=private_keys,
        web3=web3,
        contract_manager=contract_manager,
        service_registry_address=service_registry_address,
    )
    assert c1_service_proxy.ever_made_deposits_len("latest") == 3

    # Test that getting the url for each service address works
    for idx, address in enumerate(addresses):
        assert c1_service_proxy.get_service_url("latest", address) == urls[idx]
    # Test that getting the url for a non-existing service address returns None
    assert c1_service_proxy.get_service_url("latest", to_checksum_address(HOP1)) is None

    # Test that get_service_address by index works
    for idx, address in enumerate(addresses):
        assert c1_service_proxy.ever_made_deposits("latest", idx) == address

    # Test that getting the address for an index out of bounds returns None
    assert not c1_service_proxy.ever_made_deposits("latest", 9999)

    mock_get_pfs_info = Mock()
    mock_get_pfs_info.return_value.price = 100
    with patch("raiden.network.pathfinding.get_pfs_info", mock_get_pfs_info):
        # Make sure that too expensive PFSes are not considered valid
        assert not get_valid_pfs_url(
            c1_service_proxy, 0, "latest", pathfinding_max_fee=FeeAmount(99)
        )

        # ...but ones with the expected price are fine
        assert (
            get_valid_pfs_url(c1_service_proxy, 0, "latest", pathfinding_max_fee=FeeAmount(100))
            == urls[0]
        )

        # Test that getting a random service from the proxy works
        assert (
            get_random_pfs(c1_service_proxy, "latest", pathfinding_max_fee=FeeAmount(100)) in urls
        )


def test_configure_pfs(service_registry_address, private_keys, web3, contract_manager):
    chain_id = ChainID(int(web3.net.version))
    service_proxy, urls = deploy_service_registry_and_set_urls(
        private_keys=private_keys,
        web3=web3,
        contract_manager=contract_manager,
        service_registry_address=service_registry_address,
    )
    json_data = {
        "price_info": 0,
        "network_info": {
            "chain_id": chain_id,
            "registry_address": to_checksum_address(token_network_registry_address_test_default),
        },
        "message": "This is your favorite pathfinding service",
        "operator": "John Doe",
        "version": "0.0.1",
        "payment_address": "0x2222222222222222222222222222222222222222",
    }

    response = mocked_json_response(response_data=json_data)

    # With local routing configure pfs should raise assertion
    with pytest.raises(AssertionError):
        _ = configure_pfs_or_exit(
            pfs_url="",
            routing_mode=RoutingMode.LOCAL,
            service_registry=service_proxy,
            node_network_id=chain_id,
            token_network_registry_address=token_network_registry_address_test_default,
            pathfinding_max_fee=DEFAULT_PATHFINDING_MAX_FEE,
        )

    # With private routing configure pfs should raise assertion
    with pytest.raises(AssertionError):
        _ = configure_pfs_or_exit(
            pfs_url="",
            routing_mode=RoutingMode.PRIVATE,
            service_registry=service_proxy,
            node_network_id=chain_id,
            token_network_registry_address=token_network_registry_address_test_default,
            pathfinding_max_fee=DEFAULT_PATHFINDING_MAX_FEE,
        )

    # Asking for auto address
    with patch.object(requests, "get", return_value=response):
        config = configure_pfs_or_exit(
            pfs_url="auto",
            routing_mode=RoutingMode.PFS,
            service_registry=service_proxy,
            node_network_id=chain_id,
            token_network_registry_address=token_network_registry_address_test_default,
            pathfinding_max_fee=DEFAULT_PATHFINDING_MAX_FEE,
        )
    assert config.url in urls
    assert is_canonical_address(config.payment_address)

    # Configuring a given address
    given_address = "http://ourgivenaddress"
    with patch.object(requests, "get", return_value=response):
        config = configure_pfs_or_exit(
            pfs_url=given_address,
            routing_mode=RoutingMode.PFS,
            service_registry=service_proxy,
            node_network_id=chain_id,
            token_network_registry_address=token_network_registry_address_test_default,
            pathfinding_max_fee=DEFAULT_PATHFINDING_MAX_FEE,
        )
    assert config.url == given_address
    assert is_same_address(config.payment_address, json_data["payment_address"])
    assert config.price == json_data["price_info"]

    # Bad address, should exit the program
    response = mocked_failed_response(error=requests.RequestException(), status_code=400)
    bad_address = "http://badaddress"
    with pytest.raises(SystemExit):
        with patch.object(requests, "get", side_effect=requests.RequestException()):
            # Configuring a given address
            _ = configure_pfs_or_exit(
                pfs_url=bad_address,
                routing_mode=RoutingMode.PFS,
                service_registry=service_proxy,
                node_network_id=chain_id,
                token_network_registry_address=token_network_registry_address_test_default,
                pathfinding_max_fee=DEFAULT_PATHFINDING_MAX_FEE,
            )

    # Addresses of token network registries of pfs and client conflict, should exit the client
    response = mocked_json_response(response_data=json_data)

    with pytest.raises(SystemExit):
        with patch.object(requests, "get", return_value=response):
            _ = configure_pfs_or_exit(
                pfs_url="adad",
                routing_mode=RoutingMode.PFS,
                service_registry=Mock(),
                node_network_id=chain_id,
                token_network_registry_address=PaymentNetworkAddress(
                    to_canonical_address("0x2222222222222222222222222222222222222221")
                ),
                pathfinding_max_fee=DEFAULT_PATHFINDING_MAX_FEE,
            )

    # ChainIDs of pfs and client conflict, should exit the client
    response = mocked_json_response(response_data=json_data)

    with pytest.raises(SystemExit):
        with patch.object(requests, "get", return_value=response):
            configure_pfs_or_exit(
                pfs_url="adad",
                routing_mode=RoutingMode.PFS,
                service_registry=Mock(),
                node_network_id=ChainID(chain_id + 1),
                token_network_registry_address=PaymentNetworkAddress(
                    to_canonical_address("0x2222222222222222222222222222222222222221")
                ),
                pathfinding_max_fee=DEFAULT_PATHFINDING_MAX_FEE,
            )
