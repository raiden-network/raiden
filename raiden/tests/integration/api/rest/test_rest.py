import datetime
import json
from http import HTTPStatus

import gevent
import grequests
import pytest
from eth_utils import is_checksum_address, to_checksum_address, to_hex
from flask import url_for

from raiden.api.rest import APIServer
from raiden.constants import GENESIS_BLOCK_NUMBER, Environment
from raiden.messages.transfers import LockedTransfer, Unlock
from raiden.settings import (
    DEFAULT_NUMBER_OF_BLOCK_CONFIRMATIONS,
    INTERNAL_ROUTING_DEFAULT_FEE_PERC,
)
from raiden.tests.integration.api.rest.utils import (
    api_url_for,
    assert_no_content_response,
    assert_proper_response,
    assert_response_with_code,
    assert_response_with_error,
    get_json_response,
)
from raiden.tests.integration.api.utils import prepare_api_server
from raiden.tests.integration.fixtures.smartcontracts import RED_EYES_PER_CHANNEL_PARTICIPANT_LIMIT
from raiden.tests.utils import factories
from raiden.tests.utils.client import burn_eth
from raiden.tests.utils.detect_failure import expect_failure, raise_on_failure
from raiden.tests.utils.events import must_have_event, must_have_events
from raiden.tests.utils.network import CHAIN
from raiden.tests.utils.protocol import WaitForMessage
from raiden.tests.utils.transfer import block_offset_timeout, watch_for_unlock_failures
from raiden.transfer import views
from raiden.transfer.mediated_transfer.initiator import calculate_fee_margin
from raiden.transfer.state import ChannelState
from raiden.utils.secrethash import sha256_secrethash
from raiden.utils.system import get_system_spec
from raiden.utils.typing import FeeAmount, PaymentAmount, PaymentID
from raiden.waiting import (
    TransferWaitResult,
    wait_for_block,
    wait_for_received_transfer_result,
    wait_for_token_network,
)
from raiden_contracts.constants import CONTRACT_CUSTOM_TOKEN, CONTRACTS_VERSION

# pylint: disable=too-many-locals,unused-argument,too-many-lines

# Makes sure the node will have enough deposit to test the overlimit deposit
DEPOSIT_FOR_TEST_API_DEPOSIT_LIMIT = RED_EYES_PER_CHANNEL_PARTICIPANT_LIMIT + 2


class CustomException(Exception):
    pass


@raise_on_failure
@pytest.mark.parametrize("number_of_nodes", [1])
@pytest.mark.parametrize("channels_per_node", [0])
@pytest.mark.parametrize("enable_rest_api", [True])
def test_payload_with_invalid_addresses(api_server_test_instance: APIServer):
    """ Addresses require leading 0x in the payload. """
    invalid_address = "61c808d82a3ac53231750dadc13c777b59310bd9"
    channel_data_obj = {
        "partner_address": invalid_address,
        "token_address": "0xEA674fdDe714fd979de3EdF0F56AA9716B898ec8",
        "settle_timeout": "10",
    }
    request = grequests.put(
        api_url_for(api_server_test_instance, "channelsresource"), json=channel_data_obj
    )
    response = request.send().response
    assert_response_with_error(response, HTTPStatus.BAD_REQUEST)

    url_without_prefix = (
        "http://localhost:{port}/api/v1/channels/ea674fdde714fd979de3edf0f56aa9716b898ec8"
    ).format(port=api_server_test_instance.config.port)

    request = grequests.patch(
        url_without_prefix, json=dict(state=ChannelState.STATE_SETTLED.value)
    )
    response = request.send().response

    assert_response_with_code(response, HTTPStatus.NOT_FOUND)


@pytest.mark.xfail(
    strict=True, reason="Crashed app also crashes on teardown", raises=CustomException
)
@expect_failure
@pytest.mark.parametrize("number_of_nodes", [1])
@pytest.mark.parametrize("channels_per_node", [0])
@pytest.mark.parametrize("enable_rest_api", [True])
def test_crash_on_unhandled_exception(api_server_test_instance: APIServer) -> None:
    """ Crash when an unhandled exception happens on APIServer. """

    # as we should not have unhandled exceptions in our endpoints, create one to test
    @api_server_test_instance.flask_app.route("/error_endpoint", methods=["GET"])
    def error_endpoint():  # pylint: disable=unused-variable
        raise CustomException("This is an unhandled error")

    with api_server_test_instance.flask_app.app_context():
        url = url_for("error_endpoint")
    request = grequests.get(url)
    request.send()
    api_server_test_instance.greenlet.get(timeout=10)


@raise_on_failure
@pytest.mark.parametrize("number_of_nodes", [1])
@pytest.mark.parametrize("channels_per_node", [0])
@pytest.mark.parametrize("enable_rest_api", [True])
def test_payload_with_address_invalid_chars(api_server_test_instance: APIServer):
    """ Addresses cannot have invalid characters in it. """
    invalid_address = "0x61c808d82a3ac53231750dadc13c777b59310bdg"  # g at the end is invalid
    channel_data_obj = {
        "partner_address": invalid_address,
        "token_address": "0xEA674fdDe714fd979de3EdF0F56AA9716B898ec8",
        "settle_timeout": "10",
    }
    request = grequests.put(
        api_url_for(api_server_test_instance, "channelsresource"), json=channel_data_obj
    )
    response = request.send().response
    assert_response_with_error(response, HTTPStatus.BAD_REQUEST)


@raise_on_failure
@pytest.mark.parametrize("number_of_nodes", [1])
@pytest.mark.parametrize("channels_per_node", [0])
@pytest.mark.parametrize("enable_rest_api", [True])
def test_payload_with_address_invalid_length(api_server_test_instance: APIServer):
    """ Encoded addresses must have the right length. """
    invalid_address = "0x61c808d82a3ac53231750dadc13c777b59310b"  # one char short
    channel_data_obj = {
        "partner_address": invalid_address,
        "token_address": "0xEA674fdDe714fd979de3EdF0F56AA9716B898ec8",
        "settle_timeout": "10",
    }
    request = grequests.put(
        api_url_for(api_server_test_instance, "channelsresource"), json=channel_data_obj
    )
    response = request.send().response
    assert_response_with_error(response, HTTPStatus.BAD_REQUEST)


@raise_on_failure
@pytest.mark.parametrize("number_of_nodes", [1])
@pytest.mark.parametrize("channels_per_node", [0])
@pytest.mark.parametrize("enable_rest_api", [True])
def test_payload_with_address_not_eip55(api_server_test_instance: APIServer):
    """ Provided addresses must be EIP55 encoded. """
    invalid_address = "0xf696209d2ca35e6c88e5b99b7cda3abf316bed69"
    channel_data_obj = {
        "partner_address": invalid_address,
        "token_address": "0xEA674fdDe714fd979de3EdF0F56AA9716B898ec8",
        "settle_timeout": "90",
    }
    request = grequests.put(
        api_url_for(api_server_test_instance, "channelsresource"), json=channel_data_obj
    )
    response = request.send().response
    assert_response_with_error(response, HTTPStatus.BAD_REQUEST)


@raise_on_failure
@pytest.mark.parametrize("number_of_nodes", [1])
@pytest.mark.parametrize("channels_per_node", [0])
@pytest.mark.parametrize("enable_rest_api", [True])
def test_api_query_our_address(api_server_test_instance: APIServer):
    request = grequests.get(api_url_for(api_server_test_instance, "addressresource"))
    response = request.send().response
    assert_proper_response(response)

    our_address = api_server_test_instance.rest_api.raiden_api.address
    assert get_json_response(response) == {"our_address": to_checksum_address(our_address)}


@raise_on_failure
@pytest.mark.parametrize("enable_rest_api", [True])
def test_api_get_raiden_version(api_server_test_instance: APIServer):
    request = grequests.get(api_url_for(api_server_test_instance, "versionresource"))
    response = request.send().response
    assert_proper_response(response)

    raiden_version = get_system_spec()["raiden"]

    assert get_json_response(response) == {"version": raiden_version}


@raise_on_failure
@pytest.mark.parametrize("enable_rest_api", [True])
def test_api_get_contract_infos(api_server_test_instance: APIServer):
    request = grequests.get(api_url_for(api_server_test_instance, "contractsresource"))
    response = request.send().response
    assert_proper_response(response)

    json = get_json_response(response)

    assert json["contracts_version"] == CONTRACTS_VERSION
    for contract_name in [
        "token_network_registry_address",
        "secret_registry_address",
        "service_registry_address",
        "user_deposit_address",
        "monitoring_service_address",
        "one_to_n_address",
    ]:
        address = json[contract_name]
        if address != "":
            assert is_checksum_address(address)


@raise_on_failure
@pytest.mark.parametrize("number_of_nodes", [1])
@pytest.mark.parametrize("channels_per_node", [0])
@pytest.mark.parametrize("enable_rest_api", [True])
def test_api_get_channel_list(
    api_server_test_instance: APIServer, token_addresses, reveal_timeout
):
    partner_address = "0x61C808D82A3Ac53231750daDc13c777b59310bD9"

    request = grequests.get(api_url_for(api_server_test_instance, "channelsresource"))
    response = request.send().response
    assert_proper_response(response, HTTPStatus.OK)

    json_response = get_json_response(response)
    assert json_response == []

    # let's create a new channel
    token_address = token_addresses[0]
    settle_timeout = 1650
    channel_data_obj = {
        "partner_address": partner_address,
        "token_address": to_checksum_address(token_address),
        "settle_timeout": str(settle_timeout),
        "reveal_timeout": str(reveal_timeout),
    }

    request = grequests.put(
        api_url_for(api_server_test_instance, "channelsresource"), json=channel_data_obj
    )
    response = request.send().response

    assert_proper_response(response, HTTPStatus.CREATED)

    request = grequests.get(api_url_for(api_server_test_instance, "channelsresource"))
    response = request.send().response
    assert_proper_response(response, HTTPStatus.OK)
    json_response = get_json_response(response)
    channel_info = json_response[0]
    assert channel_info["partner_address"] == partner_address
    assert channel_info["token_address"] == to_checksum_address(token_address)
    assert channel_info["total_deposit"] == "0"
    assert "token_network_address" in channel_info


@raise_on_failure
@pytest.mark.parametrize("number_of_nodes", [1])
@pytest.mark.parametrize("channels_per_node", [0])
@pytest.mark.parametrize("number_of_tokens", [2])
@pytest.mark.parametrize("environment_type", [Environment.PRODUCTION])
@pytest.mark.parametrize("enable_rest_api", [True])
def test_api_tokens(api_server_test_instance: APIServer, blockchain_services, token_addresses):
    partner_address = "0x61C808D82A3Ac53231750daDc13c777b59310bD9"
    token_address1 = token_addresses[0]
    token_address2 = token_addresses[1]
    settle_timeout = 1650

    channel_data_obj = {
        "partner_address": partner_address,
        "token_address": to_checksum_address(token_address1),
        "settle_timeout": str(settle_timeout),
    }
    request = grequests.put(
        api_url_for(api_server_test_instance, "channelsresource"), json=channel_data_obj
    )
    response = request.send().response
    assert_proper_response(response, HTTPStatus.CREATED)

    settle_timeout = 1650
    channel_data_obj = {
        "partner_address": partner_address,
        "token_address": to_checksum_address(token_address2),
        "settle_timeout": str(settle_timeout),
    }
    request = grequests.put(
        api_url_for(api_server_test_instance, "channelsresource"), json=channel_data_obj
    )
    response = request.send().response
    assert_proper_response(response, HTTPStatus.CREATED)

    # and now let's get the token list
    request = grequests.get(api_url_for(api_server_test_instance, "tokensresource"))
    response = request.send().response
    assert_proper_response(response)
    json_response = get_json_response(response)
    expected_response = [to_checksum_address(token_address1), to_checksum_address(token_address2)]
    assert set(json_response) == set(expected_response)


@raise_on_failure
@pytest.mark.parametrize("number_of_nodes", [1])
@pytest.mark.parametrize("channels_per_node", [0])
@pytest.mark.parametrize("enable_rest_api", [True])
def test_query_partners_by_token(
    api_server_test_instance: APIServer, blockchain_services, token_addresses
):
    first_partner_address = "0x61C808D82A3Ac53231750daDc13c777b59310bD9"
    second_partner_address = "0x29FA6cf0Cce24582a9B20DB94Be4B6E017896038"
    token_address = token_addresses[0]
    settle_timeout = 1650
    channel_data_obj = {
        "partner_address": first_partner_address,
        "token_address": to_checksum_address(token_address),
        "settle_timeout": str(settle_timeout),
    }
    request = grequests.put(
        api_url_for(api_server_test_instance, "channelsresource"), json=channel_data_obj
    )
    response = request.send().response
    assert_proper_response(response, HTTPStatus.CREATED)
    json_response = get_json_response(response)

    channel_data_obj["partner_address"] = second_partner_address
    request = grequests.put(
        api_url_for(api_server_test_instance, "channelsresource"), json=channel_data_obj
    )
    response = request.send().response
    assert_proper_response(response, HTTPStatus.CREATED)
    json_response = get_json_response(response)

    # and a channel for another token
    channel_data_obj["partner_address"] = "0xb07937AbA15304FBBB0Bf6454a9377a76E3dD39E"
    channel_data_obj["token_address"] = to_checksum_address(token_address)
    request = grequests.put(
        api_url_for(api_server_test_instance, "channelsresource"), json=channel_data_obj
    )
    response = request.send().response
    assert_proper_response(response, HTTPStatus.CREATED)

    # and now let's query our partners per token for the first token
    request = grequests.get(
        api_url_for(
            api_server_test_instance,
            "partnersresourcebytokenaddress",
            token_address=to_checksum_address(token_address),
        )
    )
    response = request.send().response
    assert_proper_response(response)
    json_response = get_json_response(response)
    expected_response = [
        {
            "partner_address": first_partner_address,
            "channel": "/api/v1/channels/{}/{}".format(
                to_checksum_address(token_address), to_checksum_address(first_partner_address)
            ),
        },
        {
            "partner_address": second_partner_address,
            "channel": "/api/v1/channels/{}/{}".format(
                to_checksum_address(token_address), to_checksum_address(second_partner_address)
            ),
        },
    ]
    assert all(r in json_response for r in expected_response)


@raise_on_failure
@pytest.mark.parametrize("number_of_nodes", [2])
@pytest.mark.parametrize("enable_rest_api", [True])
def test_api_timestamp_format(
    api_server_test_instance: APIServer, raiden_network, token_addresses
):
    _, app1 = raiden_network
    amount = 200
    identifier = 42
    token_address = token_addresses[0]
    target_address = app1.raiden.address

    payment_url = api_url_for(
        api_server_test_instance,
        "token_target_paymentresource",
        token_address=to_checksum_address(token_address),
        target_address=to_checksum_address(target_address),
    )

    # Make payment
    grequests.post(payment_url, json={"amount": str(amount), "identifier": str(identifier)}).send()

    json_response = get_json_response(grequests.get(payment_url).send().response)

    assert len(json_response) == 1, "payment response had no event record"
    event_data = json_response[0]
    assert "log_time" in event_data, "missing log_time attribute from event record"
    log_timestamp = event_data["log_time"]

    # python (and javascript) can parse strings with either space or T as a separator of date
    # and time and still treat it as a ISO8601 string
    log_date = datetime.datetime.fromisoformat(log_timestamp)

    log_timestamp_iso = log_date.isoformat()

    assert log_timestamp_iso == log_timestamp, "log_time is not a valid ISO8601 string"


@raise_on_failure
@pytest.mark.parametrize("number_of_tokens", [0])
@pytest.mark.parametrize("number_of_nodes", [1])
@pytest.mark.parametrize("channels_per_node", [0])
@pytest.mark.parametrize("environment_type", [Environment.DEVELOPMENT])
@pytest.mark.parametrize("enable_rest_api", [True])
def test_get_token_network_for_token(
    api_server_test_instance,
    token_amount,
    token_addresses,
    raiden_network,
    contract_manager,
    retry_timeout,
    unregistered_token,
):
    app0 = raiden_network[0]
    new_token_address = unregistered_token

    # Wait until Raiden can start using the token contract.
    # Here, the block at which the contract was deployed should be confirmed by Raiden.
    # Therefore, until that block is received.
    wait_for_block(
        raiden=app0.raiden,
        block_number=app0.raiden.get_block_number() + DEFAULT_NUMBER_OF_BLOCK_CONFIRMATIONS + 1,
        retry_timeout=retry_timeout,
    )

    # unregistered token returns 404
    token_request = grequests.get(
        api_url_for(
            api_server_test_instance,
            "registertokenresource",
            token_address=to_checksum_address(new_token_address),
        )
    )
    token_response = token_request.send().response
    assert_proper_response(token_response, status_code=HTTPStatus.NOT_FOUND)

    # register token
    register_request = grequests.put(
        api_url_for(
            api_server_test_instance,
            "registertokenresource",
            token_address=to_checksum_address(new_token_address),
        )
    )
    register_response = register_request.send().response
    assert_proper_response(register_response, status_code=HTTPStatus.CREATED)
    token_network_address = get_json_response(register_response)["token_network_address"]

    wait_for_token_network(
        app0.raiden, app0.raiden.default_registry.address, new_token_address, 0.1
    )

    # now it should return the token address
    token_request = grequests.get(
        api_url_for(
            api_server_test_instance,
            "registertokenresource",
            token_address=to_checksum_address(new_token_address),
        )
    )
    token_response = token_request.send().response
    assert_proper_response(token_response, status_code=HTTPStatus.OK)
    assert token_network_address == get_json_response(token_response)


@raise_on_failure
@pytest.mark.parametrize("number_of_nodes", [1])
@pytest.mark.parametrize("channels_per_node", [0])
@pytest.mark.parametrize("number_of_tokens", [1])
@pytest.mark.parametrize("enable_rest_api", [True])
# For non-red eyes mainnet code set number_of_tokens to 2 and uncomment the code
# at the end of this test
def test_get_connection_managers_info(api_server_test_instance: APIServer, token_addresses):
    # check that there are no registered tokens
    request = grequests.get(api_url_for(api_server_test_instance, "connectionsinforesource"))
    response = request.send().response
    result = get_json_response(response)
    assert len(result) == 0

    funds = 100
    token_address1 = to_checksum_address(token_addresses[0])
    connect_data_obj = {"funds": funds}
    request = grequests.put(
        api_url_for(api_server_test_instance, "connectionsresource", token_address=token_address1),
        json=connect_data_obj,
    )
    response = request.send().response
    assert_no_content_response(response)

    # check that there now is one registered channel manager
    request = grequests.get(api_url_for(api_server_test_instance, "connectionsinforesource"))
    response = request.send().response
    result = get_json_response(response)
    assert isinstance(result, dict) and len(result.keys()) == 1
    assert token_address1 in result
    assert isinstance(result[token_address1], dict)
    assert set(result[token_address1].keys()) == {"funds", "sum_deposits", "channels"}

    # funds = 100
    # token_address2 = to_checksum_address(token_addresses[1])
    # connect_data_obj = {
    #     'funds': funds,
    # }
    # request = grequests.put(
    #     api_url_for(
    #         api_server_test_instance,
    #         'connectionsresource',
    #         token_address=token_address2,
    #     ),
    #     json=connect_data_obj,
    # )
    # response = request.send().response
    # assert_no_content_response(response)

    # # check that there now are two registered channel managers
    # request = grequests.get(
    #     api_url_for(api_server_test_instance, 'connectionsinforesource'),
    # )
    # response = request.send().response
    # result = response.json()
    # assert isinstance(result, dict) and len(result.keys()) == 2
    # assert token_address2 in result
    # assert isinstance(result[token_address2], dict)
    # assert set(result[token_address2].keys()) == {'funds', 'sum_deposits', 'channels'}


@raise_on_failure
@pytest.mark.parametrize("number_of_nodes", [1])
@pytest.mark.parametrize("channels_per_node", [0])
@pytest.mark.parametrize("number_of_tokens", [1])
@pytest.mark.parametrize("enable_rest_api", [True])
def test_connect_insufficient_reserve(api_server_test_instance: APIServer, token_addresses):

    # Burn all eth and then try to connect to a token network
    burn_eth(api_server_test_instance.rest_api.raiden_api.raiden.rpc_client)
    funds = 100
    token_address1 = to_checksum_address(token_addresses[0])
    connect_data_obj = {"funds": funds}
    request = grequests.put(
        api_url_for(api_server_test_instance, "connectionsresource", token_address=token_address1),
        json=connect_data_obj,
    )
    response = request.send().response
    assert_proper_response(response, HTTPStatus.PAYMENT_REQUIRED)
    json_response = get_json_response(response)
    assert "The account balance is below the estimated amount" in json_response["errors"]


@raise_on_failure
@pytest.mark.parametrize("number_of_nodes", [1])
@pytest.mark.parametrize("channels_per_node", [0])
@pytest.mark.parametrize("enable_rest_api", [True])
def test_network_events(api_server_test_instance: APIServer, token_addresses):
    # let's create a new channel
    partner_address = "0x61C808D82A3Ac53231750daDc13c777b59310bD9"
    token_address = token_addresses[0]
    settle_timeout = 1650
    channel_data_obj = {
        "partner_address": partner_address,
        "token_address": to_checksum_address(token_address),
        "settle_timeout": str(settle_timeout),
    }
    request = grequests.put(
        api_url_for(api_server_test_instance, "channelsresource"), json=channel_data_obj
    )
    response = request.send().response

    assert_proper_response(response, status_code=HTTPStatus.CREATED)

    request = grequests.get(
        api_url_for(
            api_server_test_instance,
            "blockchaineventsnetworkresource",
            from_block=GENESIS_BLOCK_NUMBER,
        )
    )
    response = request.send().response
    assert_proper_response(response, status_code=HTTPStatus.OK)
    assert len(get_json_response(response)) > 0


@raise_on_failure
@pytest.mark.parametrize("number_of_nodes", [1])
@pytest.mark.parametrize("channels_per_node", [0])
@pytest.mark.parametrize("enable_rest_api", [True])
def test_token_events(api_server_test_instance: APIServer, token_addresses):
    # let's create a new channel
    partner_address = "0x61C808D82A3Ac53231750daDc13c777b59310bD9"
    token_address = token_addresses[0]
    settle_timeout = 1650
    channel_data_obj = {
        "partner_address": partner_address,
        "token_address": to_checksum_address(token_address),
        "settle_timeout": str(settle_timeout),
    }
    request = grequests.put(
        api_url_for(api_server_test_instance, "channelsresource"), json=channel_data_obj
    )
    response = request.send().response

    assert_proper_response(response, status_code=HTTPStatus.CREATED)

    request = grequests.get(
        api_url_for(
            api_server_test_instance,
            "blockchaineventstokenresource",
            token_address=token_address,
            from_block=GENESIS_BLOCK_NUMBER,
        )
    )
    response = request.send().response
    assert_proper_response(response, status_code=HTTPStatus.OK)
    assert len(get_json_response(response)) > 0


@raise_on_failure
@pytest.mark.parametrize("number_of_nodes", [1])
@pytest.mark.parametrize("channels_per_node", [0])
@pytest.mark.parametrize("enable_rest_api", [True])
def test_channel_events(api_server_test_instance: APIServer, token_addresses):
    # let's create a new channel
    partner_address = "0x61C808D82A3Ac53231750daDc13c777b59310bD9"
    token_address = token_addresses[0]
    settle_timeout = 1650
    channel_data_obj = {
        "partner_address": partner_address,
        "token_address": to_checksum_address(token_address),
        "settle_timeout": str(settle_timeout),
    }
    request = grequests.put(
        api_url_for(api_server_test_instance, "channelsresource"), json=channel_data_obj
    )
    response = request.send().response

    assert_proper_response(response, status_code=HTTPStatus.CREATED)

    request = grequests.get(
        api_url_for(
            api_server_test_instance,
            "tokenchanneleventsresourceblockchain",
            token_address=token_address,
            from_block=str(GENESIS_BLOCK_NUMBER),
        )
    )
    response = request.send().response
    assert_proper_response(response, status_code=HTTPStatus.OK)
    assert len(get_json_response(response)) > 0


@raise_on_failure
@pytest.mark.parametrize("number_of_nodes", [1])
@pytest.mark.parametrize("channels_per_node", [0])
@pytest.mark.parametrize("enable_rest_api", [True])
def test_token_events_errors_for_unregistered_token(api_server_test_instance):
    request = grequests.get(
        api_url_for(
            api_server_test_instance,
            "tokenchanneleventsresourceblockchain",
            token_address="0x61C808D82A3Ac53231750daDc13c777b59310bD9",
            from_block="5",
            to_block="20",
        )
    )
    response = request.send().response
    assert_response_with_error(response, status_code=HTTPStatus.NOT_FOUND)

    request = grequests.get(
        api_url_for(
            api_server_test_instance,
            "channelblockchaineventsresource",
            token_address="0x61C808D82A3Ac53231750daDc13c777b59310bD9",
            partner_address="0x61C808D82A3Ac53231750daDc13c777b59313bD9",
            from_block="5",
            to_block="20",
        )
    )
    response = request.send().response
    assert_response_with_error(response, status_code=HTTPStatus.NOT_FOUND)


@raise_on_failure
@pytest.mark.parametrize("number_of_nodes", [3])
@pytest.mark.parametrize("enable_rest_api", [True])
@pytest.mark.parametrize("number_of_tokens", [2])
def test_payment_events_endpoints(
    api_server_test_instance: APIServer, raiden_network, token_addresses
):
    app0, app1, app2 = raiden_network

    token_address0 = token_addresses[0]
    token_address2 = token_addresses[1]

    app0_address = app0.raiden.address
    app1_address = app1.raiden.address
    app2_address = app2.raiden.address

    app0_server = api_server_test_instance
    app1_server = prepare_api_server(app1)
    app2_server = prepare_api_server(app2)

    # Payment 1: app0 is sending tokens of token1 to app1
    identifier1 = PaymentID(10)
    amount1 = PaymentAmount(10)
    secret1, secrethash1 = factories.make_secret_with_hash()
    request = grequests.post(
        api_url_for(
            app0_server,
            "token_target_paymentresource",
            token_address=to_checksum_address(token_address0),
            target_address=to_checksum_address(app1_address),
        ),
        json={"amount": str(amount1), "identifier": str(identifier1), "secret": to_hex(secret1)},
    )
    request.send()

    # Payment 2: app0 is sending some tokens of token2 to app2
    identifier2 = PaymentID(20)
    amount2 = PaymentAmount(10)
    secret2, secrethash2 = factories.make_secret_with_hash()
    request = grequests.post(
        api_url_for(
            app0_server,
            "token_target_paymentresource",
            token_address=to_checksum_address(token_address2),
            target_address=to_checksum_address(app2_address),
        ),
        json={"amount": str(amount2), "identifier": str(identifier2), "secret": to_hex(secret2)},
    )
    request.send()

    # Payment 3: app0 is sending some tokens of token1 to app2
    identifier3 = PaymentID(30)
    amount3 = PaymentAmount(17)
    secret3, secrethash3 = factories.make_secret_with_hash()
    request = grequests.post(
        api_url_for(
            app0_server,
            "token_target_paymentresource",
            token_address=to_checksum_address(token_address0),
            target_address=to_checksum_address(app1_address),
        ),
        json={"amount": str(amount3), "identifier": str(identifier3), "secret": to_hex(secret3)},
    )
    request.send()

    # Payment 4: app1 also sends some tokens to app2
    identifier4 = PaymentID(40)
    amount4 = PaymentAmount(5)
    secret4, secrethash4 = factories.make_secret_with_hash()
    request = grequests.post(
        api_url_for(
            app1_server,
            "token_target_paymentresource",
            token_address=to_checksum_address(token_address0),
            target_address=to_checksum_address(app2_address),
        ),
        json={"amount": str(amount4), "identifier": str(identifier4), "secret": to_hex(secret4)},
    )
    request.send()

    timeout = block_offset_timeout(
        app2.raiden, "Waiting for transfer received success in the WAL timed out"
    )
    with watch_for_unlock_failures(*raiden_network), timeout:
        result = wait_for_received_transfer_result(
            app1.raiden, identifier1, amount1, app1.raiden.alarm.sleep_time, secrethash1
        )
        msg = f"Unexpected transfer result: {str(result)}"
        assert result == TransferWaitResult.UNLOCKED, msg
        result = wait_for_received_transfer_result(
            app2.raiden, identifier2, amount2, app2.raiden.alarm.sleep_time, secrethash2
        )
        msg = f"Unexpected transfer result: {str(result)}"
        assert result == TransferWaitResult.UNLOCKED, msg
        result = wait_for_received_transfer_result(
            app1.raiden, identifier3, amount3, app1.raiden.alarm.sleep_time, secrethash3
        )
        msg = f"Unexpected transfer result: {str(result)}"
        assert result == TransferWaitResult.UNLOCKED, msg
        result = wait_for_received_transfer_result(
            app2.raiden, identifier4, amount4, app2.raiden.alarm.sleep_time, secrethash4
        )
        msg = f"Unexpected transfer result: {str(result)}"
        assert result == TransferWaitResult.UNLOCKED, msg

    # predefine events for later use in assertions
    event_sent_1 = {
        "event": "EventPaymentSentSuccess",
        "identifier": str(identifier1),
        "target": to_checksum_address(app1_address),
        "token_address": to_checksum_address(token_address0),
    }
    event_sent_2 = {
        "event": "EventPaymentSentSuccess",
        "identifier": str(identifier2),
        "target": to_checksum_address(app2_address),
        "token_address": to_checksum_address(token_address2),
    }
    event_sent_3 = {
        "event": "EventPaymentSentSuccess",
        "identifier": str(identifier3),
        "target": to_checksum_address(app1_address),
        "token_address": to_checksum_address(token_address0),
    }
    event_sent_4 = {
        "event": "EventPaymentSentSuccess",
        "identifier": str(identifier4),
        "target": to_checksum_address(app2_address),
        "token_address": to_checksum_address(token_address0),
    }
    event_received_1 = {
        "event": "EventPaymentReceivedSuccess",
        "identifier": str(identifier1),
        "initiator": to_checksum_address(app0_address),
        "token_address": to_checksum_address(token_address0),
    }
    event_received_2 = {
        "event": "EventPaymentReceivedSuccess",
        "identifier": str(identifier2),
        "initiator": to_checksum_address(app0_address),
        "token_address": to_checksum_address(token_address2),
    }
    event_received_3 = {
        "event": "EventPaymentReceivedSuccess",
        "identifier": str(identifier3),
        "initiator": to_checksum_address(app0_address),
        "token_address": to_checksum_address(token_address0),
    }
    event_received_4 = {
        "event": "EventPaymentReceivedSuccess",
        "identifier": str(identifier4),
        "initiator": to_checksum_address(app1_address),
        "token_address": to_checksum_address(token_address0),
    }

    # test app0 endpoint without (partner and token) for sender
    request = grequests.get(api_url_for(app0_server, "paymentresource"))
    with watch_for_unlock_failures(*raiden_network):
        response = request.send().response
    assert_proper_response(response, HTTPStatus.OK)
    json_response = get_json_response(response)

    assert must_have_event(json_response, event_sent_1)
    assert must_have_event(json_response, event_sent_2)
    assert must_have_event(json_response, event_sent_3)

    # test endpoint without (partner and token) for target1
    request = grequests.get(api_url_for(app1_server, "paymentresource"))
    response = request.send().response
    assert_proper_response(response, HTTPStatus.OK)
    json_response = get_json_response(response)
    assert must_have_event(json_response, event_received_1)
    assert must_have_event(json_response, event_received_3)
    assert must_have_event(json_response, event_sent_4)
    # test endpoint without (partner and token) for target2
    request = grequests.get(api_url_for(app2_server, "paymentresource"))
    response = request.send().response
    assert_proper_response(response, HTTPStatus.OK)
    json_response = get_json_response(response)
    assert must_have_event(json_response, event_received_2)
    assert must_have_event(json_response, event_received_4)

    # test endpoint without partner for app0
    request = grequests.get(
        api_url_for(app0_server, "token_paymentresource", token_address=token_address0)
    )
    response = request.send().response
    assert_proper_response(response, HTTPStatus.OK)
    json_response = get_json_response(response)

    assert must_have_event(json_response, event_sent_1)
    assert must_have_event(json_response, event_sent_3)

    # test endpoint without partner for app0 but with limit/offset to get only first
    request = grequests.get(
        api_url_for(
            app0_server, "token_paymentresource", token_address=token_address0, limit=1, offset=0,
        )
    )
    response = request.send().response
    assert_proper_response(response, HTTPStatus.OK)
    json_response = get_json_response(response)

    assert must_have_event(json_response, event_sent_1)
    assert len(json_response) == 1

    # test endpoint without partner for app0 but with limit/offset
    # to get only second transfer of token_address
    request = grequests.get(
        api_url_for(
            app0_server, "token_paymentresource", token_address=token_address0, limit=1, offset=1,
        )
    )
    response = request.send().response
    assert_proper_response(response, HTTPStatus.OK)
    json_response = get_json_response(response)

    # this should return only payment 3, since payment 1 is offset
    # and payment 2 is of another token address
    assert len(json_response) == 1
    assert must_have_event(json_response, event_sent_3)

    # test endpoint of app1 without partner for token_address
    request = grequests.get(
        api_url_for(app1_server, "token_paymentresource", token_address=token_address0)
    )
    response = request.send().response
    assert_proper_response(response, HTTPStatus.OK)
    json_response = get_json_response(response)
    assert must_have_events(json_response, event_received_1)
    assert must_have_events(json_response, event_received_3)
    assert must_have_events(json_response, event_sent_4)

    # test endpoint of app2 without partner for token_address
    request = grequests.get(
        api_url_for(app2_server, "token_paymentresource", token_address=token_address0)
    )
    response = request.send().response
    assert_proper_response(response, HTTPStatus.OK)
    json_response = get_json_response(response)
    assert must_have_events(json_response, event_received_4)

    # test endpoint of app2 without partner for token_address2
    request = grequests.get(
        api_url_for(app2_server, "token_paymentresource", token_address=token_address2)
    )
    response = request.send().response
    assert_proper_response(response, HTTPStatus.OK)
    json_response = get_json_response(response)
    assert must_have_events(json_response, event_received_2)

    # test endpoint for token_address0 and partner for app0
    request = grequests.get(
        api_url_for(
            app0_server,
            "token_target_paymentresource",
            token_address=token_address0,
            target_address=app1_address,
        )
    )
    response = request.send().response
    assert_proper_response(response, HTTPStatus.OK)
    json_response = get_json_response(response)
    assert len(json_response) == 2
    assert must_have_event(json_response, event_sent_1)
    assert must_have_event(json_response, event_sent_3)

    request = grequests.get(
        api_url_for(
            app0_server,
            "token_target_paymentresource",
            token_address=token_address2,
            target_address=app2_address,
        )
    )
    response = request.send().response
    assert_proper_response(response, HTTPStatus.OK)
    json_response = get_json_response(response)
    assert len(json_response) == 1
    assert must_have_event(json_response, event_sent_2)

    # test endpoint for token_address0 and partner for app1. Check both partners
    # to see that filtering works correctly
    request = grequests.get(
        api_url_for(
            app1_server,
            "token_target_paymentresource",
            token_address=token_address0,
            target_address=app2_address,
        )
    )
    response = request.send().response
    assert_proper_response(response, HTTPStatus.OK)
    json_response = get_json_response(response)
    assert len(json_response) == 1
    assert must_have_event(json_response, event_sent_4)

    request = grequests.get(
        api_url_for(
            app1_server,
            "token_target_paymentresource",
            token_address=token_address0,
            target_address=app0_address,
        )
    )
    response = request.send().response
    assert_proper_response(response, HTTPStatus.OK)
    json_response = get_json_response(response)
    assert len(json_response) == 2
    assert must_have_event(json_response, event_received_1)
    assert must_have_event(json_response, event_received_3)

    # test app1 checking payments to himself
    request = grequests.get(
        api_url_for(
            app1_server,
            "token_target_paymentresource",
            token_address=token_address0,
            target_address=app1_address,
        )
    )
    response = request.send().response
    assert_proper_response(response, HTTPStatus.OK)
    json_response = get_json_response(response)
    assert len(json_response) == 0

    # test endpoint for token and partner for app2
    request = grequests.get(
        api_url_for(
            app2_server,
            "token_target_paymentresource",
            token_address=token_address0,
            target_address=app0_address,
        )
    )
    response = request.send().response
    assert_proper_response(response, HTTPStatus.OK)
    json_response = get_json_response(response)
    # Since app2 has no payment with app0 in token_address
    assert len(json_response) == 0

    # test endpoint for token2 and partner for app2
    request = grequests.get(
        api_url_for(
            app2_server,
            "token_target_paymentresource",
            token_address=token_address2,
            target_address=app0_address,
        )
    )
    response = request.send().response
    assert_proper_response(response, HTTPStatus.OK)
    json_response = get_json_response(response)

    # app2 has one payment with app0 in token_address2
    assert len(json_response) == 1
    assert must_have_events(json_response, event_received_2)

    request = grequests.get(
        api_url_for(
            app2_server,
            "token_target_paymentresource",
            token_address=token_address0,
            target_address=app1_address,
        )
    )
    response = request.send().response
    assert_proper_response(response, HTTPStatus.OK)
    json_response = get_json_response(response)
    assert must_have_events(json_response, event_received_4)
    assert not must_have_event(json_response, event_received_2)

    # also add a test for filtering by wrong token address
    request = grequests.get(
        api_url_for(
            app2_server,
            "token_target_paymentresource",
            token_address=app1_address,
            target_address=app1_address,
        )
    )
    response = request.send().response
    assert_proper_response(response, HTTPStatus.BAD_REQUEST)

    app1_server.stop()
    app2_server.stop()


@raise_on_failure
@pytest.mark.parametrize("number_of_nodes", [2])
@pytest.mark.parametrize("enable_rest_api", [True])
def test_channel_events_raiden(
    api_server_test_instance: APIServer, raiden_network, token_addresses
):
    _, app1 = raiden_network
    amount = 100
    identifier = 42
    token_address = token_addresses[0]
    target_address = app1.raiden.address

    request = grequests.post(
        api_url_for(
            api_server_test_instance,
            "token_target_paymentresource",
            token_address=to_checksum_address(token_address),
            target_address=to_checksum_address(target_address),
        ),
        json={"amount": str(amount), "identifier": str(identifier)},
    )
    response = request.send().response
    assert_proper_response(response)


@raise_on_failure
@pytest.mark.parametrize("number_of_nodes", [3])
@pytest.mark.parametrize("channels_per_node", [CHAIN])
@pytest.mark.parametrize("enable_rest_api", [True])
def test_pending_transfers_endpoint(raiden_network, token_addresses):
    initiator, mediator, target = raiden_network
    token_address = token_addresses[0]
    token_network_address = views.get_token_network_address_by_token_address(
        views.state_from_app(mediator), mediator.raiden.default_registry.address, token_address
    )
    assert token_network_address

    amount_to_send = PaymentAmount(150)
    # Remove when https://github.com/raiden-network/raiden/issues/4982 is tackled
    expected_fee = FeeAmount(int(amount_to_send * INTERNAL_ROUTING_DEFAULT_FEE_PERC))
    fee_margin = calculate_fee_margin(amount_to_send, expected_fee)
    # This is 0,4% of ~150, so ~1.2 which gets rounded to 1
    actual_fee = 1
    identifier = 42

    initiator_server = prepare_api_server(initiator)
    mediator_server = prepare_api_server(mediator)
    target_server = prepare_api_server(target)

    target.raiden.message_handler = target_wait = WaitForMessage()
    mediator.raiden.message_handler = mediator_wait = WaitForMessage()

    secret = factories.make_secret()
    secrethash = sha256_secrethash(secret)

    request = grequests.get(
        api_url_for(
            mediator_server, "pending_transfers_resource_by_token", token_address=token_address
        )
    )
    response = request.send().response
    assert response.status_code == 200 and response.content == b"[]"

    target_hold = target.raiden.raiden_event_handler
    target_hold.hold_secretrequest_for(secrethash=secrethash)

    initiator.raiden.start_mediated_transfer_with_secret(
        token_network_address=token_network_address,
        amount=PaymentAmount(amount_to_send - expected_fee - fee_margin),
        target=target.raiden.address,
        identifier=identifier,
        secret=secret,
    )

    transfer_arrived = target_wait.wait_for_message(LockedTransfer, {"payment_identifier": 42})
    transfer_arrived.wait(timeout=30.0)

    for server in (initiator_server, mediator_server, target_server):
        request = grequests.get(api_url_for(server, "pending_transfers_resource"))
        response = request.send().response
        assert response.status_code == 200
        content = json.loads(response.content)
        assert len(content) == 1
        assert content[0]["payment_identifier"] == str(identifier)
        if server == target_server:
            assert content[0]["locked_amount"] == str(amount_to_send - actual_fee)
        else:
            assert content[0]["locked_amount"] == str(amount_to_send)
        assert content[0]["token_address"] == to_checksum_address(token_address)
        assert content[0]["token_network_address"] == to_checksum_address(token_network_address)

    mediator_unlock = mediator_wait.wait_for_message(Unlock, {})
    target_unlock = target_wait.wait_for_message(Unlock, {})
    target_hold.release_secretrequest_for(target.raiden, secrethash)
    gevent.joinall({mediator_unlock, target_unlock}, raise_error=True)

    for server in (initiator_server, mediator_server, target_server):
        request = grequests.get(api_url_for(server, "pending_transfers_resource"))
        response = request.send().response
        assert response.status_code == 200 and response.content == b"[]"

    request = grequests.get(
        api_url_for(
            initiator_server,
            "pending_transfers_resource_by_token",
            token_address=to_hex(b"notaregisteredtokenn"),
        )
    )
    response = request.send().response
    assert response.status_code == 404 and b"Token" in response.content

    request = grequests.get(
        api_url_for(
            target_server,
            "pending_transfers_resource_by_token_and_partner",
            token_address=token_address,
            partner_address=to_hex(b"~nonexistingchannel~"),
        )
    )
    response = request.send().response
    assert response.status_code == 404 and b"Channel" in response.content


@raise_on_failure
@pytest.mark.parametrize("number_of_nodes", [1])
@pytest.mark.parametrize("channels_per_node", [0])
@pytest.mark.parametrize("number_of_tokens", [1])
@pytest.mark.parametrize("token_contract_name", [CONTRACT_CUSTOM_TOKEN])
@pytest.mark.parametrize("enable_rest_api", [True])
def test_api_testnet_token_mint(api_server_test_instance: APIServer, token_addresses):
    user_address = factories.make_checksum_address()
    token_address = token_addresses[0]
    url = api_url_for(api_server_test_instance, "tokensmintresource", token_address=token_address)
    request = grequests.post(url, json=dict(to=user_address, value=1))
    response = request.send().response
    assert_response_with_code(response, HTTPStatus.OK)

    # mint method defaults to mintFor
    request = grequests.post(url, json=dict(to=user_address, value=10))
    response = request.send().response
    assert_response_with_code(response, HTTPStatus.OK)

    # invalid due to negative value
    request = grequests.post(url, json=dict(to=user_address, value=-1))
    response = request.send().response
    assert_response_with_error(response, HTTPStatus.BAD_REQUEST)

    # invalid due to invalid address
    request = grequests.post(url, json=dict(to=user_address[:-2], value=10))
    response = request.send().response
    assert_response_with_error(response, HTTPStatus.BAD_REQUEST)

    # trying to mint with no ETH
    burn_eth(api_server_test_instance.rest_api.raiden_api.raiden.rpc_client)
    request = grequests.post(url, json=dict(to=user_address, value=1))
    response = request.send().response
    assert_response_with_code(response, HTTPStatus.PAYMENT_REQUIRED)


@raise_on_failure
@pytest.mark.parametrize("number_of_nodes", [1])
@pytest.mark.parametrize("channels_per_node", [0])
@pytest.mark.parametrize("enable_rest_api", [True])
def test_shutdown(api_server_test_instance: APIServer):
    """ Node must stop after shutdown is called """
    url = ("http://localhost:{port}/api/v1/shutdown").format(
        port=api_server_test_instance.config.port
    )
    response = grequests.post(url).send().response

    assert_response_with_code(response, HTTPStatus.OK)
    finished = gevent.joinall({api_server_test_instance}, timeout=10, raise_error=True)
    assert finished, "The Raiden node did not shut down!"
