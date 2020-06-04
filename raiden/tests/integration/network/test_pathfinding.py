from unittest.mock import patch

import pytest
import requests
from eth_utils import (
    is_canonical_address,
    is_same_address,
    to_canonical_address,
    to_checksum_address,
)

from raiden.constants import MATRIX_AUTO_SELECT_SERVER, RoutingMode
from raiden.exceptions import RaidenError
from raiden.network.pathfinding import PFSInfo, check_pfs_for_production, configure_pfs_or_exit
from raiden.settings import DEFAULT_PATHFINDING_MAX_FEE
from raiden.tests.utils.mocks import mocked_json_response
from raiden.tests.utils.smartcontracts import deploy_service_registry_and_set_urls
from raiden.utils.keys import privatekey_to_address
from raiden.utils.typing import BlockNumber, ChainID, TokenAmount, TokenNetworkRegistryAddress

token_network_registry_address_test_default = TokenNetworkRegistryAddress(
    to_canonical_address("0xB9633dd9a9a71F22C933bF121d7a22008f66B908")
)


def test_configure_pfs(service_registry_address, private_keys, web3, contract_manager):
    chain_id = ChainID(int(web3.net.version))
    service_registry, urls = deploy_service_registry_and_set_urls(
        private_keys=private_keys,
        web3=web3,
        contract_manager=contract_manager,
        service_registry_address=service_registry_address,
    )
    json_data = {
        "price_info": 0,
        "network_info": {
            "chain_id": chain_id,
            "token_network_registry_address": to_checksum_address(
                token_network_registry_address_test_default
            ),
            "user_deposit_address": to_checksum_address(privatekey_to_address(private_keys[1])),
            "confirmed_block": {"number": 10},
        },
        "message": "This is your favorite pathfinding service",
        "operator": "John Doe",
        "version": "0.0.1",
        "payment_address": to_checksum_address(privatekey_to_address(private_keys[0])),
        "matrix_server": "http://matrix.example.com",
    }

    response = mocked_json_response(response_data=json_data)

    # With local routing configure_pfs should raise assertion
    with pytest.raises(AssertionError):
        _ = configure_pfs_or_exit(
            pfs_url="",
            routing_mode=RoutingMode.LOCAL,
            service_registry=service_registry,
            node_network_id=chain_id,
            token_network_registry_address=token_network_registry_address_test_default,
            pathfinding_max_fee=DEFAULT_PATHFINDING_MAX_FEE,
            matrix_servers=["http://matrix.example.com"],
        )

    # With private routing configure_pfs should raise assertion
    with pytest.raises(AssertionError):
        _ = configure_pfs_or_exit(
            pfs_url="",
            routing_mode=RoutingMode.PRIVATE,
            service_registry=service_registry,
            node_network_id=chain_id,
            token_network_registry_address=token_network_registry_address_test_default,
            pathfinding_max_fee=DEFAULT_PATHFINDING_MAX_FEE,
            matrix_servers=["http://matrix.example.com"],
        )

    # Asking for auto address
    # To make this deterministic we need to patch the random selection function
    patch_random = patch("raiden.network.pathfinding.get_random_pfs", return_value="http://foo")
    with patch.object(requests, "get", return_value=response), patch_random:
        config = configure_pfs_or_exit(
            pfs_url=MATRIX_AUTO_SELECT_SERVER,
            routing_mode=RoutingMode.PFS,
            service_registry=service_registry,
            node_network_id=chain_id,
            token_network_registry_address=token_network_registry_address_test_default,
            pathfinding_max_fee=DEFAULT_PATHFINDING_MAX_FEE,
            matrix_servers=["matrix.example.com"],
        )
    assert config.url in urls
    assert is_canonical_address(config.payment_address)

    # Configuring a valid given address
    given_address = "http://foo"
    with patch.object(requests, "get", return_value=response):
        config = configure_pfs_or_exit(
            pfs_url=given_address,
            routing_mode=RoutingMode.PFS,
            service_registry=service_registry,
            node_network_id=chain_id,
            token_network_registry_address=token_network_registry_address_test_default,
            pathfinding_max_fee=DEFAULT_PATHFINDING_MAX_FEE,
            matrix_servers=["matrix.example.com"],
        )
    assert config.url == given_address
    assert is_same_address(config.payment_address, json_data["payment_address"])
    assert config.price == json_data["price_info"]

    # Bad address, should exit the program
    bad_address = "http://badaddress"
    with pytest.raises(RaidenError):
        with patch.object(requests, "get", side_effect=requests.RequestException()):
            # Configuring a given address
            _ = configure_pfs_or_exit(
                pfs_url=bad_address,
                routing_mode=RoutingMode.PFS,
                service_registry=service_registry,
                node_network_id=chain_id,
                token_network_registry_address=token_network_registry_address_test_default,
                pathfinding_max_fee=DEFAULT_PATHFINDING_MAX_FEE,
                matrix_servers=["http://matrix.example.com"],
            )

    # Addresses of token network registries of pfs and client conflict, should exit the client
    response = mocked_json_response(response_data=json_data)
    with pytest.raises(RaidenError):
        with patch.object(requests, "get", return_value=response):
            _ = configure_pfs_or_exit(
                pfs_url="http://foo",
                routing_mode=RoutingMode.PFS,
                service_registry=service_registry,
                node_network_id=chain_id,
                token_network_registry_address=TokenNetworkRegistryAddress(
                    to_canonical_address("0x2222222222222222222222222222222222222221")
                ),
                pathfinding_max_fee=DEFAULT_PATHFINDING_MAX_FEE,
                matrix_servers=["http://matrix.example.com"],
            )

    # ChainIDs of pfs and client conflict, should exit the client
    response = mocked_json_response(response_data=json_data)
    with pytest.raises(RaidenError):
        with patch.object(requests, "get", return_value=response):
            configure_pfs_or_exit(
                pfs_url="http://foo",
                routing_mode=RoutingMode.PFS,
                service_registry=service_registry,
                node_network_id=ChainID(chain_id + 1),
                token_network_registry_address=token_network_registry_address_test_default,
                pathfinding_max_fee=DEFAULT_PATHFINDING_MAX_FEE,
                matrix_servers=["http://matrix.example.com"],
            )

    # Wrong matrix server
    response = mocked_json_response(response_data=json_data)
    with pytest.raises(RaidenError, match="matrix server"):
        with patch.object(requests, "get", return_value=response):
            configure_pfs_or_exit(
                pfs_url="http://foo",
                routing_mode=RoutingMode.PFS,
                service_registry=service_registry,
                node_network_id=ChainID(chain_id),
                token_network_registry_address=token_network_registry_address_test_default,
                pathfinding_max_fee=DEFAULT_PATHFINDING_MAX_FEE,
                matrix_servers=["matrix.doesnotexist.com"],
            )


def test_check_pfs_for_production(
    service_registry_address, private_keys, web3, contract_manager
) -> None:
    chain_id = ChainID(int(web3.net.version))
    service_registry, _ = deploy_service_registry_and_set_urls(
        private_keys=private_keys,
        web3=web3,
        contract_manager=contract_manager,
        service_registry_address=service_registry_address,
    )

    # Configuring an address that doesn't match the registered url should error
    pfs_info = PFSInfo(
        url="http://ourgivenaddress",
        price=TokenAmount(0),
        chain_id=chain_id,
        token_network_registry_address=token_network_registry_address_test_default,
        payment_address=privatekey_to_address(private_keys[0]),
        message="",
        operator="",
        version="",
        user_deposit_address=privatekey_to_address(private_keys[1]),
        confirmed_block_number=BlockNumber(10),
        matrix_server="http://matrix.example.com",
    )
    with pytest.raises(RaidenError):
        check_pfs_for_production(service_registry=service_registry, pfs_info=pfs_info)

    # Configuring an pfs payment address that isn't registered should error
    pfs_info = PFSInfo(
        url="http://foo",
        price=TokenAmount(0),
        chain_id=chain_id,
        token_network_registry_address=token_network_registry_address_test_default,
        payment_address=to_canonical_address("0x2222222222222222222222222222222222222221"),
        message="",
        operator="",
        version="",
        user_deposit_address=privatekey_to_address(private_keys[1]),
        confirmed_block_number=BlockNumber(10),
        matrix_server="http://matrix.example.com",
    )
    with pytest.raises(RaidenError):
        check_pfs_for_production(service_registry=service_registry, pfs_info=pfs_info)
