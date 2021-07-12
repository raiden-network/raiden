import json
from unittest.mock import patch

import pytest
from eth_utils import (
    is_canonical_address,
    is_same_address,
    to_canonical_address,
    to_checksum_address,
)
from requests.exceptions import RequestException

from raiden.constants import MATRIX_AUTO_SELECT_SERVER, RoutingMode
from raiden.exceptions import PFSReturnedError, RaidenError, ServiceRequestFailed
from raiden.network.pathfinding import (
    PFSConfig,
    PFSInfo,
    PFSProxy,
    check_pfs_for_production,
    configure_pfs_or_exit,
    session,
)
from raiden.settings import DEFAULT_PATHFINDING_MAX_FEE
from raiden.tests.unit.test_pfs_integration import make_address_metadata
from raiden.tests.utils.factories import UNIT_CHAIN_ID, make_address, make_signer
from raiden.tests.utils.mocks import mocked_json_response
from raiden.tests.utils.smartcontracts import deploy_service_registry_and_set_urls
from raiden.utils.keys import privatekey_to_address
from raiden.utils.typing import (
    BlockNumber,
    BlockTimeout,
    ChainID,
    TokenAmount,
    TokenNetworkRegistryAddress,
)

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
        "matrix_room_id": "!room-id:matrix.example.com",
    }

    response = mocked_json_response(response_data=json_data)

    # With private routing configure_pfs should raise assertion
    with pytest.raises(AssertionError):
        _ = configure_pfs_or_exit(
            pfs_url="",
            routing_mode=RoutingMode.PRIVATE,
            service_registry=service_registry,
            node_chain_id=chain_id,
            token_network_registry_address=token_network_registry_address_test_default,
            pathfinding_max_fee=DEFAULT_PATHFINDING_MAX_FEE,
        )

    # Asking for auto address
    # To make this deterministic we need to patch the random selection function
    patch_random = patch("raiden.network.pathfinding.get_random_pfs", return_value="http://foo")
    with patch.object(session, "get", return_value=response), patch_random:
        config = configure_pfs_or_exit(
            pfs_url=MATRIX_AUTO_SELECT_SERVER,
            routing_mode=RoutingMode.PFS,
            service_registry=service_registry,
            node_chain_id=chain_id,
            token_network_registry_address=token_network_registry_address_test_default,
            pathfinding_max_fee=DEFAULT_PATHFINDING_MAX_FEE,
        )
    assert config.url in urls
    assert is_canonical_address(config.payment_address)

    # Configuring a valid given address
    given_address = "http://foo"
    with patch.object(session, "get", return_value=response):
        config = configure_pfs_or_exit(
            pfs_url=given_address,
            routing_mode=RoutingMode.PFS,
            service_registry=service_registry,
            node_chain_id=chain_id,
            token_network_registry_address=token_network_registry_address_test_default,
            pathfinding_max_fee=DEFAULT_PATHFINDING_MAX_FEE,
        )
    assert config.url == given_address
    assert is_same_address(config.payment_address, json_data["payment_address"])
    assert config.price == json_data["price_info"]

    # Bad address, should exit the program
    bad_address = "http://badaddress"
    with pytest.raises(RaidenError):
        with patch.object(session, "get", side_effect=RequestException()):
            # Configuring a given address
            _ = configure_pfs_or_exit(
                pfs_url=bad_address,
                routing_mode=RoutingMode.PFS,
                service_registry=service_registry,
                node_chain_id=chain_id,
                token_network_registry_address=token_network_registry_address_test_default,
                pathfinding_max_fee=DEFAULT_PATHFINDING_MAX_FEE,
            )

    # Addresses of token network registries of pfs and client conflict, should exit the client
    response = mocked_json_response(response_data=json_data)
    with pytest.raises(RaidenError):
        with patch.object(session, "get", return_value=response):
            _ = configure_pfs_or_exit(
                pfs_url="http://foo",
                routing_mode=RoutingMode.PFS,
                service_registry=service_registry,
                node_chain_id=chain_id,
                token_network_registry_address=TokenNetworkRegistryAddress(
                    to_canonical_address("0x2222222222222222222222222222222222222221")
                ),
                pathfinding_max_fee=DEFAULT_PATHFINDING_MAX_FEE,
            )

    # ChainIDs of pfs and client conflict, should exit the client
    response = mocked_json_response(response_data=json_data)
    with pytest.raises(RaidenError):
        with patch.object(session, "get", return_value=response):
            configure_pfs_or_exit(
                pfs_url="http://foo",
                routing_mode=RoutingMode.PFS,
                service_registry=service_registry,
                node_chain_id=ChainID(chain_id + 1),
                token_network_registry_address=token_network_registry_address_test_default,
                pathfinding_max_fee=DEFAULT_PATHFINDING_MAX_FEE,
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


def test_query_user():
    signer = make_signer()
    address = signer.address
    metadata_dict = make_address_metadata(signer)
    matrix_user_id = metadata_dict["user_id"]
    capabilities = metadata_dict["capabilities"]
    pfs_config = PFSConfig(
        info=PFSInfo(
            url="mock-address",
            chain_id=UNIT_CHAIN_ID,
            token_network_registry_address=TokenNetworkRegistryAddress(make_address()),
            user_deposit_address=make_address(),
            payment_address=make_address(),
            confirmed_block_number=BlockNumber(100),
            message="",
            operator="",
            version="",
            price=TokenAmount(0),
            matrix_server="http://matrix.example.com",
        ),
        maximum_fee=TokenAmount(100),
        iou_timeout=BlockTimeout(100),
        max_paths=5,
    )

    pfs_proxy = PFSProxy(pfs_config)
    with patch("raiden.network.pathfinding.session") as session_mock:
        # success
        response = session_mock.get.return_value
        response.status_code = 200
        response.content = json.dumps(metadata_dict)
        return_metadata = pfs_proxy.query_address_metadata(address)
        assert return_metadata.get("user_id") == matrix_user_id
        assert return_metadata["capabilities"] == capabilities

        # invalid signature
        displayname = metadata_dict["displayname"]
        metadata_dict["displayname"] = "invalid_signature"
        response.content = json.dumps(metadata_dict)
        with pytest.raises(ServiceRequestFailed):
            pfs_proxy.query_address_metadata(address)
        metadata_dict["displayname"] = displayname
        response.content = json.dumps(metadata_dict)

        # malformed response
        response = session_mock.get.return_value
        response.status_code = 200
        response.content = "{wrong"
        with pytest.raises(ServiceRequestFailed):
            pfs_proxy.query_address_metadata(address)

        # error response
        response = session_mock.get.return_value
        response.status_code = 400
        response.content = json.dumps({"error_code": 123})
        with pytest.raises(PFSReturnedError) as exc_info:
            pfs_proxy.query_address_metadata(address)
            assert exc_info.value["error_code"] == 123
