from http import HTTPStatus

import grequests
import pytest
from eth_typing import Address
from eth_utils import is_checksum_address, to_canonical_address, to_checksum_address

from raiden.api.rest import APIServer
from raiden.constants import Environment
from raiden.settings import DEFAULT_NUMBER_OF_BLOCK_CONFIRMATIONS
from raiden.tests.integration.api.rest.utils import (
    api_url_for,
    assert_proper_response,
    assert_response_with_error,
    get_json_response,
)
from raiden.tests.utils.client import burn_eth
from raiden.tests.utils.detect_failure import raise_on_failure
from raiden.waiting import wait_for_block
from raiden_contracts.constants import CONTRACT_HUMAN_STANDARD_TOKEN


@raise_on_failure
@pytest.mark.parametrize("number_of_tokens", [0])
@pytest.mark.parametrize("number_of_nodes", [1])
@pytest.mark.parametrize("channels_per_node", [0])
@pytest.mark.parametrize("environment_type", [Environment.PRODUCTION])
@pytest.mark.parametrize("enable_rest_api", [True])
def test_register_token_mainnet(
    api_server_test_instance: APIServer, token_amount, raiden_network, contract_manager
):
    app0 = raiden_network[0]
    contract_proxy, _ = app0.raiden.rpc_client.deploy_single_contract(
        contract_name=CONTRACT_HUMAN_STANDARD_TOKEN,
        contract=contract_manager.get_contract(CONTRACT_HUMAN_STANDARD_TOKEN),
        constructor_parameters=(token_amount, 2, "raiden", "Rd"),
    )
    new_token_address = Address(to_canonical_address(contract_proxy.address))
    register_request = grequests.put(
        api_url_for(
            api_server_test_instance,
            "registertokenresource",
            token_address=to_checksum_address(new_token_address),
        )
    )
    response = register_request.send().response
    assert response is not None and response.status_code == HTTPStatus.NOT_IMPLEMENTED


@raise_on_failure
@pytest.mark.parametrize("number_of_tokens", [0])
@pytest.mark.parametrize("number_of_nodes", [1])
@pytest.mark.parametrize("channels_per_node", [0])
@pytest.mark.parametrize("max_token_networks", [1])
@pytest.mark.parametrize("environment_type", [Environment.DEVELOPMENT])
@pytest.mark.parametrize("register_tokens", [False])
@pytest.mark.parametrize("enable_rest_api", [True])
def test_register_token(
    api_server_test_instance, token_amount, raiden_network, contract_manager, retry_timeout
):
    app0 = raiden_network[0]
    contract_proxy, _ = app0.raiden.rpc_client.deploy_single_contract(
        contract_name=CONTRACT_HUMAN_STANDARD_TOKEN,
        contract=contract_manager.get_contract(CONTRACT_HUMAN_STANDARD_TOKEN),
        constructor_parameters=(token_amount, 2, "raiden", "Rd1"),
    )
    new_token_address = Address(to_canonical_address(contract_proxy.address))
    contract_proxy, _ = app0.raiden.rpc_client.deploy_single_contract(
        contract_name=CONTRACT_HUMAN_STANDARD_TOKEN,
        contract=contract_manager.get_contract(CONTRACT_HUMAN_STANDARD_TOKEN),
        constructor_parameters=(token_amount, 2, "raiden", "Rd2"),
    )
    other_token_address = Address(to_canonical_address(contract_proxy.address))

    # Wait until Raiden can start using the token contract.
    # Here, the block at which the contract was deployed should be confirmed by Raiden.
    # Therefore, until that block is received.
    wait_for_block(
        raiden=app0.raiden,
        block_number=app0.raiden.get_block_number() + DEFAULT_NUMBER_OF_BLOCK_CONFIRMATIONS + 1,
        retry_timeout=retry_timeout,
    )
    wait_for_block(
        raiden=app0.raiden,
        block_number=app0.raiden.get_block_number() + DEFAULT_NUMBER_OF_BLOCK_CONFIRMATIONS + 1,
        retry_timeout=retry_timeout,
    )

    register_request = grequests.put(
        api_url_for(
            api_server_test_instance,
            "registertokenresource",
            token_address=to_checksum_address(new_token_address),
        )
    )
    register_response = register_request.send().response
    assert_proper_response(register_response, status_code=HTTPStatus.CREATED)
    response_json = get_json_response(register_response)
    assert "token_network_address" in response_json
    assert is_checksum_address(response_json["token_network_address"])

    # now try to reregister it and get the error
    conflict_request = grequests.put(
        api_url_for(
            api_server_test_instance,
            "registertokenresource",
            token_address=to_checksum_address(new_token_address),
        )
    )
    conflict_response = conflict_request.send().response
    assert_response_with_error(conflict_response, HTTPStatus.CONFLICT)

    # Test that adding a second token throws a forbidden error
    forbidden_request = grequests.put(
        api_url_for(
            api_server_test_instance,
            "registertokenresource",
            token_address=to_checksum_address(other_token_address),
        )
    )
    forbidden_response = forbidden_request.send().response
    assert_response_with_error(forbidden_response, HTTPStatus.FORBIDDEN)
    response_json = get_json_response(forbidden_response)
    assert "Number of token networks will exceed the maximum of" in response_json["errors"]


@raise_on_failure
@pytest.mark.parametrize("number_of_tokens", [0])
@pytest.mark.parametrize("number_of_nodes", [1])
@pytest.mark.parametrize("channels_per_node", [0])
@pytest.mark.parametrize("environment_type", [Environment.DEVELOPMENT])
@pytest.mark.parametrize("enable_rest_api", [True])
def test_register_token_without_balance(
    api_server_test_instance, token_amount, raiden_network, contract_manager, retry_timeout
):
    app0 = raiden_network[0]
    contract_proxy, _ = app0.raiden.rpc_client.deploy_single_contract(
        contract_name=CONTRACT_HUMAN_STANDARD_TOKEN,
        contract=contract_manager.get_contract(CONTRACT_HUMAN_STANDARD_TOKEN),
        constructor_parameters=(token_amount, 2, "raiden", "Rd2"),
    )
    new_token_address = Address(to_canonical_address(contract_proxy.address))

    # Wait until Raiden can start using the token contract.
    # Here, the block at which the contract was deployed should be confirmed by Raiden.
    # Therefore, until that block is received.
    wait_for_block(
        raiden=app0.raiden,
        block_number=app0.raiden.get_block_number() + DEFAULT_NUMBER_OF_BLOCK_CONFIRMATIONS + 1,
        retry_timeout=retry_timeout,
    )

    # Burn all the eth and then make sure we get the appropriate API error
    burn_eth(app0.raiden.rpc_client)
    poor_request = grequests.put(
        api_url_for(
            api_server_test_instance,
            "registertokenresource",
            token_address=to_checksum_address(new_token_address),
        )
    )
    poor_response = poor_request.send().response
    assert_response_with_error(poor_response, HTTPStatus.PAYMENT_REQUIRED)
