import datetime
import json
from hashlib import sha256
from http import HTTPStatus

import gevent
import grequests
import pytest
from eth_utils import (
    is_checksum_address,
    to_bytes,
    to_canonical_address,
    to_checksum_address,
    to_hex,
)
from flask import url_for

from raiden.api.rest import APIServer
from raiden.api.v1.encoding import AddressField, HexAddressConverter
from raiden.constants import GENESIS_BLOCK_NUMBER, NULL_ADDRESS_HEX, SECRET_LENGTH, Environment
from raiden.messages.transfers import LockedTransfer, Unlock
from raiden.settings import (
    DEFAULT_NUMBER_OF_BLOCK_CONFIRMATIONS,
    INTERNAL_ROUTING_DEFAULT_FEE_PERC,
)
from raiden.tests.integration.api.utils import create_api_server
from raiden.tests.integration.fixtures.smartcontracts import RED_EYES_PER_CHANNEL_PARTICIPANT_LIMIT
from raiden.tests.utils import factories
from raiden.tests.utils.client import burn_eth
from raiden.tests.utils.events import check_dict_nested_attrs, must_have_event, must_have_events
from raiden.tests.utils.network import CHAIN
from raiden.tests.utils.protocol import WaitForMessage
from raiden.tests.utils.smartcontracts import deploy_contract_web3
from raiden.tests.utils.transfer import watch_for_unlock_failures
from raiden.transfer import views
from raiden.transfer.mediated_transfer.initiator import calculate_fee_margin
from raiden.transfer.state import ChannelState
from raiden.utils import get_system_spec
from raiden.utils.secrethash import sha256_secrethash
from raiden.utils.typing import FeeAmount, PaymentAmount, PaymentID, TokenAmount
from raiden.waiting import (
    TransferWaitResult,
    wait_for_block,
    wait_for_participant_deposit,
    wait_for_received_transfer_result,
    wait_for_token_network,
)
from raiden_contracts.constants import (
    CONTRACT_CUSTOM_TOKEN,
    CONTRACT_HUMAN_STANDARD_TOKEN,
    TEST_SETTLE_TIMEOUT_MAX,
    TEST_SETTLE_TIMEOUT_MIN,
)

# pylint: disable=too-many-locals,unused-argument,too-many-lines

# Makes sure the node will have enough deposit to test the overlimit deposit
DEPOSIT_FOR_TEST_API_DEPOSIT_LIMIT = RED_EYES_PER_CHANNEL_PARTICIPANT_LIMIT + 2


class CustomException(Exception):
    pass


def get_json_response(response):
    """
    Utility function to deal with JSON responses.
    requests's `.json` can fail when simplejson is installed. See
    https://github.com/raiden-network/raiden/issues/4174
    """
    return json.loads(response.content)


def assert_no_content_response(response):
    assert (
        response is not None
        and response.text == ""
        and response.status_code == HTTPStatus.NO_CONTENT
    )


def assert_response_with_code(response, status_code):
    assert response is not None and response.status_code == status_code


def assert_response_with_error(response, status_code):
    json_response = get_json_response(response)
    assert (
        response is not None
        and response.status_code == status_code
        and "errors" in json_response
        and json_response["errors"] != ""
    )


def assert_proper_response(response, status_code=HTTPStatus.OK):
    assert (
        response is not None
        and response.status_code == status_code
        and response.headers["Content-Type"] == "application/json"
    )


def api_url_for(api_server, endpoint, **kwargs):
    # url_for() expects binary address so we have to convert here
    for key, val in kwargs.items():
        if isinstance(val, str) and val.startswith("0x"):
            kwargs[key] = to_canonical_address(val)
    with api_server.flask_app.app_context():
        return url_for(f"v1_resources.{endpoint}", **kwargs)


def test_hex_converter():
    converter = HexAddressConverter(map=None)

    # invalid hex data
    with pytest.raises(Exception):
        converter.to_python("-")

    # invalid address, too short
    with pytest.raises(Exception):
        converter.to_python("0x1234")

    # missing prefix 0x
    with pytest.raises(Exception):
        converter.to_python("414d72a6f6e28f4950117696081450d63d56c354")

    address = b"AMr\xa6\xf6\xe2\x8fIP\x11v\x96\x08\x14P\xd6=V\xc3T"
    assert converter.to_python("0x414D72a6f6E28F4950117696081450d63D56C354") == address


def test_address_field():
    # pylint: disable=protected-access
    field = AddressField()
    attr = "test"
    data = object()

    # invalid hex data
    with pytest.raises(Exception):
        field._deserialize("-", attr, data)

    # invalid address, too short
    with pytest.raises(Exception):
        field._deserialize("0x1234", attr, data)

    # missing prefix 0x
    with pytest.raises(Exception):
        field._deserialize("414d72a6f6e28f4950117696081450d63d56c354", attr, data)

    address = b"AMr\xa6\xf6\xe2\x8fIP\x11v\x96\x08\x14P\xd6=V\xc3T"
    assert field._deserialize("0x414D72a6f6E28F4950117696081450d63D56C354", attr, data) == address


@pytest.mark.parametrize("number_of_nodes", [1])
@pytest.mark.parametrize("channels_per_node", [0])
def test_payload_with_invalid_addresses(api_server_test_instance: APIServer, rest_api_port_number):
    """ Addresses require leading 0x in the payload. """
    invalid_address = "61c808d82a3ac53231750dadc13c777b59310bd9"
    channel_data_obj = {
        "partner_address": invalid_address,
        "token_address": "0xEA674fdDe714fd979de3EdF0F56AA9716B898ec8",
        "settle_timeout": 10,
    }
    request = grequests.put(
        api_url_for(api_server_test_instance, "channelsresource"), json=channel_data_obj
    )
    response = request.send().response
    assert_response_with_error(response, HTTPStatus.BAD_REQUEST)

    url_without_prefix = (
        "http://localhost:{port}/api/v1/channels/ea674fdde714fd979de3edf0f56aa9716b898ec8"
    ).format(port=rest_api_port_number)

    request = grequests.patch(
        url_without_prefix, json=dict(state=ChannelState.STATE_SETTLED.value)
    )
    response = request.send().response

    assert_response_with_code(response, HTTPStatus.NOT_FOUND)


@pytest.mark.xfail(
    strict=True, reason="Crashed app also crashes on teardown", raises=CustomException
)
@pytest.mark.parametrize("number_of_nodes", [1])
@pytest.mark.parametrize("channels_per_node", [0])
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


@pytest.mark.parametrize("number_of_nodes", [1])
@pytest.mark.parametrize("channels_per_node", [0])
def test_payload_with_address_invalid_chars(api_server_test_instance: APIServer):
    """ Addresses cannot have invalid characters in it. """
    invalid_address = "0x61c808d82a3ac53231750dadc13c777b59310bdg"  # g at the end is invalid
    channel_data_obj = {
        "partner_address": invalid_address,
        "token_address": "0xEA674fdDe714fd979de3EdF0F56AA9716B898ec8",
        "settle_timeout": 10,
    }
    request = grequests.put(
        api_url_for(api_server_test_instance, "channelsresource"), json=channel_data_obj
    )
    response = request.send().response
    assert_response_with_error(response, HTTPStatus.BAD_REQUEST)


@pytest.mark.parametrize("number_of_nodes", [1])
@pytest.mark.parametrize("channels_per_node", [0])
def test_payload_with_address_invalid_length(api_server_test_instance: APIServer):
    """ Encoded addresses must have the right length. """
    invalid_address = "0x61c808d82a3ac53231750dadc13c777b59310b"  # g at the end is invalid
    channel_data_obj = {
        "partner_address": invalid_address,
        "token_address": "0xEA674fdDe714fd979de3EdF0F56AA9716B898ec8",
        "settle_timeout": 10,
    }
    request = grequests.put(
        api_url_for(api_server_test_instance, "channelsresource"), json=channel_data_obj
    )
    response = request.send().response
    assert_response_with_error(response, HTTPStatus.BAD_REQUEST)


@pytest.mark.parametrize("number_of_nodes", [1])
@pytest.mark.parametrize("channels_per_node", [0])
def test_payload_with_address_not_eip55(api_server_test_instance: APIServer):
    """ Provided addresses must be EIP55 encoded. """
    invalid_address = "0xf696209d2ca35e6c88e5b99b7cda3abf316bed69"
    channel_data_obj = {
        "partner_address": invalid_address,
        "token_address": "0xEA674fdDe714fd979de3EdF0F56AA9716B898ec8",
        "settle_timeout": 90,
    }
    request = grequests.put(
        api_url_for(api_server_test_instance, "channelsresource"), json=channel_data_obj
    )
    response = request.send().response
    assert_response_with_error(response, HTTPStatus.BAD_REQUEST)


@pytest.mark.parametrize("number_of_nodes", [1])
@pytest.mark.parametrize("channels_per_node", [0])
def test_api_query_our_address(api_server_test_instance: APIServer):
    request = grequests.get(api_url_for(api_server_test_instance, "addressresource"))
    response = request.send().response
    assert_proper_response(response)

    our_address = api_server_test_instance.rest_api.raiden_api.address
    assert get_json_response(response) == {"our_address": to_checksum_address(our_address)}


def test_api_get_raiden_version(api_server_test_instance: APIServer):
    request = grequests.get(api_url_for(api_server_test_instance, "versionresource"))
    response = request.send().response
    assert_proper_response(response)

    raiden_version = get_system_spec()["raiden"]

    assert get_json_response(response) == {"version": raiden_version}


@pytest.mark.parametrize("number_of_nodes", [1])
@pytest.mark.parametrize("channels_per_node", [0])
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
        "settle_timeout": settle_timeout,
        "reveal_timeout": reveal_timeout,
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
    assert channel_info["total_deposit"] == 0
    assert "token_network_address" in channel_info


@pytest.mark.parametrize("number_of_nodes", [1])
@pytest.mark.parametrize("channels_per_node", [0])
def test_api_channel_status_channel_nonexistant(
    api_server_test_instance: APIServer, token_addresses
):
    partner_address = "0x61C808D82A3Ac53231750daDc13c777b59310bD9"
    token_address = token_addresses[0]

    request = grequests.get(
        api_url_for(
            api_server_test_instance,
            "channelsresourcebytokenandpartneraddress",
            token_address=token_address,
            partner_address=partner_address,
        )
    )
    response = request.send().response
    assert_proper_response(response, HTTPStatus.NOT_FOUND)
    assert get_json_response(response)["errors"] == (
        "Channel with partner '{}' for token '{}' could not be found.".format(
            to_checksum_address(partner_address), to_checksum_address(token_address)
        )
    )


@pytest.mark.parametrize("number_of_nodes", [1])
@pytest.mark.parametrize("channels_per_node", [0])
def test_api_open_and_deposit_channel(
    api_server_test_instance: APIServer, token_addresses, reveal_timeout
):

    first_partner_address = "0x61C808D82A3Ac53231750daDc13c777b59310bD9"
    token_address = token_addresses[0]
    token_address_hex = to_checksum_address(token_address)
    settle_timeout = 1650
    channel_data_obj = {
        "partner_address": first_partner_address,
        "token_address": token_address_hex,
        "settle_timeout": settle_timeout,
        "reveal_timeout": reveal_timeout,
    }
    # First let's try to create channel with the null address and see error is handled
    channel_data_obj["partner_address"] = NULL_ADDRESS_HEX
    request = grequests.put(
        api_url_for(api_server_test_instance, "channelsresource"), json=channel_data_obj
    )
    response = request.send().response
    assert_response_with_error(response, status_code=HTTPStatus.BAD_REQUEST)
    # now let's really create a new channel
    channel_data_obj["partner_address"] = first_partner_address
    request = grequests.put(
        api_url_for(api_server_test_instance, "channelsresource"), json=channel_data_obj
    )
    response = request.send().response

    assert_proper_response(response, HTTPStatus.CREATED)
    first_channel_id = 1
    json_response = get_json_response(response)
    expected_response = channel_data_obj.copy()
    expected_response.update(
        {
            "balance": 0,
            "state": ChannelState.STATE_OPENED.value,
            "channel_identifier": 1,
            "total_deposit": 0,
        }
    )
    assert check_dict_nested_attrs(json_response, expected_response)
    token_network_address = json_response["token_network_address"]

    # Now let's try to open the same channel again and see that a proper error is returned
    request = grequests.put(
        api_url_for(api_server_test_instance, "channelsresource"), json=channel_data_obj
    )
    response = request.send().response
    assert_proper_response(response, HTTPStatus.CONFLICT)
    json_response = get_json_response(response)
    assert first_partner_address in json_response["errors"]
    assert token_address_hex in json_response["errors"]
    assert "b'" not in json_response["errors"]

    # now let's open a channel and make a deposit too
    second_partner_address = "0x29FA6cf0Cce24582a9B20DB94Be4B6E017896038"
    total_deposit = 100
    channel_data_obj = {
        "partner_address": second_partner_address,
        "token_address": to_checksum_address(token_address),
        "settle_timeout": settle_timeout,
        "reveal_timeout": reveal_timeout,
        "total_deposit": total_deposit,
    }
    request = grequests.put(
        api_url_for(api_server_test_instance, "channelsresource"), json=channel_data_obj
    )
    response = request.send().response

    assert_proper_response(response, HTTPStatus.CREATED)
    second_channel_id = 2
    json_response = get_json_response(response)
    expected_response = channel_data_obj.copy()
    expected_response.update(
        {
            "balance": total_deposit,
            "state": ChannelState.STATE_OPENED.value,
            "channel_identifier": second_channel_id,
            "token_network_address": token_network_address,
            "total_deposit": total_deposit,
        }
    )
    assert check_dict_nested_attrs(json_response, expected_response)

    # assert depositing again with less than the initial deposit returns 409
    request = grequests.patch(
        api_url_for(
            api_server_test_instance,
            "channelsresourcebytokenandpartneraddress",
            token_address=token_address,
            partner_address=second_partner_address,
        ),
        json={"total_deposit": 99},
    )
    response = request.send().response
    assert_proper_response(response, HTTPStatus.CONFLICT)

    # assert depositing negative amount fails
    request = grequests.patch(
        api_url_for(
            api_server_test_instance,
            "channelsresourcebytokenandpartneraddress",
            token_address=token_address,
            partner_address=first_partner_address,
        ),
        json={"total_deposit": -1000},
    )
    response = request.send().response
    assert_proper_response(response, HTTPStatus.CONFLICT)

    # let's deposit on the first channel
    request = grequests.patch(
        api_url_for(
            api_server_test_instance,
            "channelsresourcebytokenandpartneraddress",
            token_address=token_address,
            partner_address=first_partner_address,
        ),
        json={"total_deposit": total_deposit},
    )
    response = request.send().response
    assert_proper_response(response)
    json_response = get_json_response(response)
    expected_response = {
        "channel_identifier": first_channel_id,
        "partner_address": first_partner_address,
        "token_address": to_checksum_address(token_address),
        "settle_timeout": settle_timeout,
        "reveal_timeout": reveal_timeout,
        "state": ChannelState.STATE_OPENED.value,
        "balance": total_deposit,
        "total_deposit": total_deposit,
        "token_network_address": token_network_address,
    }
    assert check_dict_nested_attrs(json_response, expected_response)

    # let's try querying for the second channel
    request = grequests.get(
        api_url_for(
            api_server_test_instance,
            "channelsresourcebytokenandpartneraddress",
            token_address=token_address,
            partner_address=second_partner_address,
        )
    )

    response = request.send().response
    assert_proper_response(response)
    json_response = get_json_response(response)
    expected_response = {
        "channel_identifier": second_channel_id,
        "partner_address": second_partner_address,
        "token_address": to_checksum_address(token_address),
        "settle_timeout": settle_timeout,
        "reveal_timeout": reveal_timeout,
        "state": ChannelState.STATE_OPENED.value,
        "balance": total_deposit,
        "total_deposit": total_deposit,
        "token_network_address": token_network_address,
    }
    assert check_dict_nested_attrs(json_response, expected_response)

    # finally let's burn all eth and try to open another channel
    burn_eth(api_server_test_instance.rest_api.raiden_api.raiden.rpc_client)
    channel_data_obj = {
        "partner_address": "0xf3AF96F89b3d7CdcBE0C083690A28185Feb0b3CE",
        "token_address": to_checksum_address(token_address),
        "settle_timeout": settle_timeout,
        "reveal_timeout": reveal_timeout,
        "balance": 1,
    }
    request = grequests.put(
        api_url_for(api_server_test_instance, "channelsresource"), json=channel_data_obj
    )
    response = request.send().response
    assert_proper_response(response, HTTPStatus.PAYMENT_REQUIRED)
    json_response = get_json_response(response)
    assert "The account balance is below the estimated amount" in json_response["errors"]


@pytest.mark.parametrize("number_of_nodes", [1])
@pytest.mark.parametrize("channels_per_node", [0])
def test_api_open_and_deposit_race(
    api_server_test_instance: APIServer,
    raiden_network,
    token_addresses,
    reveal_timeout,
    token_network_registry_address,
    retry_timeout,
):
    """Tests that a race for the same deposit from the API is handled properly

    The proxy's set_total_deposit is raising a RaidenRecoverableError in case of
    races. That needs to be properly handled and not allowed to bubble out of
    the greenlet.

    Regression test for https://github.com/raiden-network/raiden/issues/4937
    """
    app0 = raiden_network[0]
    # let's create a new channel
    first_partner_address = "0x61C808D82A3Ac53231750daDc13c777b59310bD9"
    token_address = token_addresses[0]
    settle_timeout = 1650
    channel_data_obj = {
        "partner_address": first_partner_address,
        "token_address": to_checksum_address(token_address),
        "settle_timeout": settle_timeout,
        "reveal_timeout": reveal_timeout,
    }

    request = grequests.put(
        api_url_for(api_server_test_instance, "channelsresource"), json=channel_data_obj
    )
    response = request.send().response

    assert_proper_response(response, HTTPStatus.CREATED)
    json_response = get_json_response(response)
    expected_response = channel_data_obj.copy()
    expected_response.update(
        {
            "balance": 0,
            "state": ChannelState.STATE_OPENED.value,
            "channel_identifier": 1,
            "total_deposit": 0,
        }
    )
    assert check_dict_nested_attrs(json_response, expected_response)

    # Prepare the deposit api call
    deposit_amount = TokenAmount(99)
    request = grequests.patch(
        api_url_for(
            api_server_test_instance,
            "channelsresourcebytokenandpartneraddress",
            token_address=token_address,
            partner_address=first_partner_address,
        ),
        json={"total_deposit": deposit_amount},
    )

    # Spawn two greenlets doing the same deposit request
    greenlets = [gevent.spawn(request.send), gevent.spawn(request.send)]
    gevent.joinall(set(greenlets), raise_error=True)
    # Make sure that both responses are fine
    g1_response = greenlets[0].get().response
    assert_proper_response(g1_response, HTTPStatus.OK)
    json_response = get_json_response(g1_response)
    expected_response.update({"total_deposit": deposit_amount, "balance": deposit_amount})
    assert check_dict_nested_attrs(json_response, expected_response)
    g2_response = greenlets[0].get().response
    assert_proper_response(g2_response, HTTPStatus.OK)
    json_response = get_json_response(g2_response)
    assert check_dict_nested_attrs(json_response, expected_response)

    # Wait for the deposit to be seen
    timeout_seconds = 20
    exception = Exception(f"Expected deposit not seen within {timeout_seconds}")
    with gevent.Timeout(seconds=timeout_seconds, exception=exception):
        wait_for_participant_deposit(
            raiden=app0.raiden,
            token_network_registry_address=token_network_registry_address,
            token_address=token_address,
            partner_address=to_canonical_address(first_partner_address),
            target_address=app0.raiden.address,
            target_balance=deposit_amount,
            retry_timeout=retry_timeout,
        )

    request = grequests.get(api_url_for(api_server_test_instance, "channelsresource"))
    response = request.send().response
    assert_proper_response(response, HTTPStatus.OK)
    json_response = get_json_response(response)
    channel_info = json_response[0]
    assert channel_info["token_address"] == to_checksum_address(token_address)
    assert channel_info["total_deposit"] == deposit_amount


@pytest.mark.parametrize("number_of_nodes", [1])
@pytest.mark.parametrize("channels_per_node", [0])
def test_api_open_close_and_settle_channel(
    api_server_test_instance: APIServer, token_addresses, reveal_timeout
):
    # let's create a new channel
    partner_address = "0x61C808D82A3Ac53231750daDc13c777b59310bD9"
    token_address = token_addresses[0]
    settle_timeout = 1650
    channel_data_obj = {
        "partner_address": partner_address,
        "token_address": to_checksum_address(token_address),
        "settle_timeout": settle_timeout,
    }
    request = grequests.put(
        api_url_for(api_server_test_instance, "channelsresource"), json=channel_data_obj
    )
    response = request.send().response

    balance = 0
    assert_proper_response(response, status_code=HTTPStatus.CREATED)
    channel_identifier = 1
    json_response = get_json_response(response)
    expected_response = channel_data_obj.copy()
    expected_response.update(
        {
            "balance": balance,
            "state": ChannelState.STATE_OPENED.value,
            "reveal_timeout": reveal_timeout,
            "channel_identifier": channel_identifier,
            "total_deposit": 0,
        }
    )
    assert check_dict_nested_attrs(json_response, expected_response)

    token_network_address = json_response["token_network_address"]

    # let's close the channel
    request = grequests.patch(
        api_url_for(
            api_server_test_instance,
            "channelsresourcebytokenandpartneraddress",
            token_address=token_address,
            partner_address=partner_address,
        ),
        json={"state": ChannelState.STATE_CLOSED.value},
    )
    response = request.send().response
    assert_proper_response(response)
    expected_response = {
        "token_network_address": token_network_address,
        "channel_identifier": channel_identifier,
        "partner_address": partner_address,
        "token_address": to_checksum_address(token_address),
        "settle_timeout": settle_timeout,
        "reveal_timeout": reveal_timeout,
        "state": ChannelState.STATE_CLOSED.value,
        "balance": balance,
        "total_deposit": balance,
    }
    assert check_dict_nested_attrs(get_json_response(response), expected_response)

    # try closing the channel again
    request = grequests.patch(
        api_url_for(
            api_server_test_instance,
            "channelsresourcebytokenandpartneraddress",
            token_address=token_address,
            partner_address=partner_address,
        ),
        json={"state": ChannelState.STATE_CLOSED.value},
    )
    # Closing the channel again should not work
    response = request.send().response
    assert_proper_response(response, HTTPStatus.CONFLICT)

    # Try sending a payment when channel is closed
    request = grequests.post(
        api_url_for(
            api_server_test_instance,
            "token_target_paymentresource",
            token_address=to_checksum_address(token_address),
            target_address=to_checksum_address(partner_address),
        ),
        json={"amount": 1},
    )
    # Payment should not work since channel is closing
    response = request.send().response
    assert_proper_response(response, HTTPStatus.CONFLICT)

    # Try to create channel with the same partner again before previous channnel settles
    request = grequests.put(
        api_url_for(api_server_test_instance, "channelsresource"), json=channel_data_obj
    )
    # Channel exists and is currently being settled so API request to open channel should fail
    response = request.send().response
    assert_proper_response(response, HTTPStatus.CONFLICT)


@pytest.mark.parametrize("number_of_nodes", [2])
@pytest.mark.parametrize("channels_per_node", [0])
def test_api_close_insufficient_eth(
    api_server_test_instance: APIServer, token_addresses, reveal_timeout
):

    # let's create a new channel
    partner_address = "0x61C808D82A3Ac53231750daDc13c777b59310bD9"
    token_address = token_addresses[0]
    settle_timeout = 1650
    channel_data_obj = {
        "partner_address": partner_address,
        "token_address": to_checksum_address(token_address),
        "settle_timeout": settle_timeout,
    }
    request = grequests.put(
        api_url_for(api_server_test_instance, "channelsresource"), json=channel_data_obj
    )
    response = request.send().response

    balance = 0
    assert_proper_response(response, status_code=HTTPStatus.CREATED)
    channel_identifier = 1
    json_response = get_json_response(response)
    expected_response = channel_data_obj.copy()
    expected_response.update(
        {
            "balance": balance,
            "state": ChannelState.STATE_OPENED.value,
            "reveal_timeout": reveal_timeout,
            "channel_identifier": channel_identifier,
            "total_deposit": 0,
        }
    )
    assert check_dict_nested_attrs(json_response, expected_response)

    # let's burn all eth and try to close the channel
    burn_eth(api_server_test_instance.rest_api.raiden_api.raiden.rpc_client)
    request = grequests.patch(
        api_url_for(
            api_server_test_instance,
            "channelsresourcebytokenandpartneraddress",
            token_address=token_address,
            partner_address=partner_address,
        ),
        json={"state": ChannelState.STATE_CLOSED.value},
    )
    response = request.send().response
    assert_proper_response(response, HTTPStatus.PAYMENT_REQUIRED)
    json_response = get_json_response(response)
    assert "insufficient ETH" in json_response["errors"]


@pytest.mark.parametrize("number_of_nodes", [1])
@pytest.mark.parametrize("channels_per_node", [0])
def test_api_open_channel_invalid_input(
    api_server_test_instance: APIServer, token_addresses, reveal_timeout
):
    partner_address = "0x61C808D82A3Ac53231750daDc13c777b59310bD9"
    token_address = token_addresses[0]
    settle_timeout = TEST_SETTLE_TIMEOUT_MIN - 1
    channel_data_obj = {
        "partner_address": partner_address,
        "token_address": to_checksum_address(token_address),
        "settle_timeout": settle_timeout,
        "reveal_timeout": reveal_timeout,
    }
    request = grequests.put(
        api_url_for(api_server_test_instance, "channelsresource"), json=channel_data_obj
    )
    response = request.send().response
    assert_response_with_error(response, status_code=HTTPStatus.CONFLICT)

    channel_data_obj["settle_timeout"] = TEST_SETTLE_TIMEOUT_MAX + 1
    request = grequests.put(
        api_url_for(api_server_test_instance, "channelsresource"), json=channel_data_obj
    )
    response = request.send().response
    assert_response_with_error(response, status_code=HTTPStatus.CONFLICT)

    channel_data_obj["settle_timeout"] = TEST_SETTLE_TIMEOUT_MAX - 1
    channel_data_obj["token_address"] = to_checksum_address(factories.make_address())
    request = grequests.put(
        api_url_for(api_server_test_instance, "channelsresource"), json=channel_data_obj
    )
    response = request.send().response
    assert_response_with_error(response, status_code=HTTPStatus.CONFLICT)


@pytest.mark.parametrize("number_of_nodes", [1])
@pytest.mark.parametrize("channels_per_node", [0])
def test_api_channel_state_change_errors(
    api_server_test_instance: APIServer, token_addresses, reveal_timeout
):
    partner_address = "0x61C808D82A3Ac53231750daDc13c777b59310bD9"
    token_address = token_addresses[0]
    settle_timeout = 1650
    channel_data_obj = {
        "partner_address": partner_address,
        "token_address": to_checksum_address(token_address),
        "settle_timeout": settle_timeout,
        "reveal_timeout": reveal_timeout,
    }
    request = grequests.put(
        api_url_for(api_server_test_instance, "channelsresource"), json=channel_data_obj
    )
    response = request.send().response
    assert_proper_response(response, HTTPStatus.CREATED)

    # let's try to set a random state
    request = grequests.patch(
        api_url_for(
            api_server_test_instance,
            "channelsresourcebytokenandpartneraddress",
            token_address=token_address,
            partner_address=partner_address,
        ),
        json=dict(state="inlimbo"),
    )
    response = request.send().response
    assert_response_with_error(response, HTTPStatus.BAD_REQUEST)

    # let's try to set both new state and total_deposit
    request = grequests.patch(
        api_url_for(
            api_server_test_instance,
            "channelsresourcebytokenandpartneraddress",
            token_address=token_address,
            partner_address=partner_address,
        ),
        json=dict(state=ChannelState.STATE_CLOSED.value, total_deposit=200),
    )
    response = request.send().response
    assert_response_with_error(response, HTTPStatus.CONFLICT)

    # let's try to set both new state and total_withdraw
    request = grequests.patch(
        api_url_for(
            api_server_test_instance,
            "channelsresourcebytokenandpartneraddress",
            token_address=token_address,
            partner_address=partner_address,
        ),
        json=dict(state=ChannelState.STATE_CLOSED.value, total_withdraw=200),
    )
    response = request.send().response
    assert_response_with_error(response, HTTPStatus.CONFLICT)

    # let's try to set both total deposit and total_withdraw
    request = grequests.patch(
        api_url_for(
            api_server_test_instance,
            "channelsresourcebytokenandpartneraddress",
            token_address=token_address,
            partner_address=partner_address,
        ),
        json=dict(total_deposit=500, total_withdraw=200),
    )
    response = request.send().response
    assert_response_with_error(response, HTTPStatus.CONFLICT)

    # let's try to set both new state and reveal_timeout
    request = grequests.patch(
        api_url_for(
            api_server_test_instance,
            "channelsresourcebytokenandpartneraddress",
            token_address=token_address,
            partner_address=partner_address,
        ),
        json=dict(state=ChannelState.STATE_CLOSED.value, reveal_timeout=50),
    )
    response = request.send().response
    assert_response_with_error(response, HTTPStatus.CONFLICT)

    # let's try to set both total_deposit and reveal_timeout
    request = grequests.patch(
        api_url_for(
            api_server_test_instance,
            "channelsresourcebytokenandpartneraddress",
            token_address=token_address,
            partner_address=partner_address,
        ),
        json=dict(total_deposit=500, reveal_timeout=50),
    )
    response = request.send().response
    assert_response_with_error(response, HTTPStatus.CONFLICT)

    # let's try to set both total_withdraw and reveal_timeout
    request = grequests.patch(
        api_url_for(
            api_server_test_instance,
            "channelsresourcebytokenandpartneraddress",
            token_address=token_address,
            partner_address=partner_address,
        ),
        json=dict(total_withdraw=500, reveal_timeout=50),
    )
    response = request.send().response
    assert_response_with_error(response, HTTPStatus.CONFLICT)

    # let's try to patch with no arguments
    request = grequests.patch(
        api_url_for(
            api_server_test_instance,
            "channelsresourcebytokenandpartneraddress",
            token_address=token_address,
            partner_address=partner_address,
        )
    )
    response = request.send().response
    assert_response_with_error(response, HTTPStatus.BAD_REQUEST)

    # ok now let's close and settle for real
    request = grequests.patch(
        api_url_for(
            api_server_test_instance,
            "channelsresourcebytokenandpartneraddress",
            token_address=token_address,
            partner_address=partner_address,
        ),
        json=dict(state=ChannelState.STATE_CLOSED.value),
    )
    response = request.send().response
    assert_proper_response(response)

    # let's try to deposit to a settled channel
    request = grequests.patch(
        api_url_for(
            api_server_test_instance,
            "channelsresourcebytokenandpartneraddress",
            token_address=token_address,
            partner_address=partner_address,
        ),
        json=dict(total_deposit=500),
    )
    response = request.send().response
    assert_response_with_error(response, HTTPStatus.CONFLICT)


@pytest.mark.parametrize("number_of_nodes", [1])
@pytest.mark.parametrize("channels_per_node", [0])
@pytest.mark.parametrize("number_of_tokens", [2])
@pytest.mark.parametrize("environment_type", [Environment.DEVELOPMENT])
def test_api_tokens(api_server_test_instance: APIServer, blockchain_services, token_addresses):
    partner_address = "0x61C808D82A3Ac53231750daDc13c777b59310bD9"
    token_address1 = token_addresses[0]
    token_address2 = token_addresses[1]
    settle_timeout = 1650

    channel_data_obj = {
        "partner_address": partner_address,
        "token_address": to_checksum_address(token_address1),
        "settle_timeout": settle_timeout,
    }
    request = grequests.put(
        api_url_for(api_server_test_instance, "channelsresource"), json=channel_data_obj
    )
    response = request.send().response
    assert_proper_response(response, HTTPStatus.CREATED)

    partner_address = "0x61C808D82A3Ac53231750daDc13c777b59310bD9"
    settle_timeout = 1650
    channel_data_obj = {
        "partner_address": partner_address,
        "token_address": to_checksum_address(token_address2),
        "settle_timeout": settle_timeout,
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


@pytest.mark.parametrize("number_of_nodes", [1])
@pytest.mark.parametrize("channels_per_node", [0])
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
        "settle_timeout": settle_timeout,
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


@pytest.mark.parametrize("number_of_nodes", [2])
def test_api_payments_target_error(
    api_server_test_instance: APIServer, raiden_network, token_addresses
):
    _, app1 = raiden_network
    amount = 200
    identifier = 42
    token_address = token_addresses[0]
    target_address = app1.raiden.address

    # stop app1 to force an error
    app1.stop()

    request = grequests.post(
        api_url_for(
            api_server_test_instance,
            "token_target_paymentresource",
            token_address=to_checksum_address(token_address),
            target_address=to_checksum_address(target_address),
        ),
        json={"amount": amount, "identifier": identifier},
    )
    response = request.send().response
    assert_proper_response(response, status_code=HTTPStatus.CONFLICT)
    app1.start()


@pytest.mark.parametrize("number_of_nodes", [2])
def test_api_payments(
    api_server_test_instance: APIServer, raiden_network, token_addresses, deposit
):
    _, app1 = raiden_network
    amount = 100
    identifier = 42
    token_address = token_addresses[0]
    target_address = app1.raiden.address

    our_address = api_server_test_instance.rest_api.raiden_api.address

    payment = {
        "initiator_address": to_checksum_address(our_address),
        "target_address": to_checksum_address(target_address),
        "token_address": to_checksum_address(token_address),
        "amount": amount,
        "identifier": identifier,
    }

    # Test a normal payment
    request = grequests.post(
        api_url_for(
            api_server_test_instance,
            "token_target_paymentresource",
            token_address=to_checksum_address(token_address),
            target_address=to_checksum_address(target_address),
        ),
        json={"amount": amount, "identifier": identifier},
    )
    with watch_for_unlock_failures(*raiden_network):
        response = request.send().response
    assert_proper_response(response)
    json_response = get_json_response(response)
    assert_payment_secret_and_hash(json_response, payment)

    # Test a payment without providing an identifier
    payment["amount"] = 1
    request = grequests.post(
        api_url_for(
            api_server_test_instance,
            "token_target_paymentresource",
            token_address=to_checksum_address(token_address),
            target_address=to_checksum_address(target_address),
        ),
        json={"amount": 1},
    )
    with watch_for_unlock_failures(*raiden_network):
        response = request.send().response
    assert_proper_response(response)
    json_response = get_json_response(response)
    assert_payment_secret_and_hash(json_response, payment)

    # Test that trying out a payment with an amount higher than what is available returns an error
    payment["amount"] = deposit
    request = grequests.post(
        api_url_for(
            api_server_test_instance,
            "token_target_paymentresource",
            token_address=to_checksum_address(token_address),
            target_address=to_checksum_address(target_address),
        ),
        json={"amount": deposit},
    )
    response = request.send().response
    assert_proper_response(response, status_code=HTTPStatus.CONFLICT)


@pytest.mark.parametrize("number_of_nodes", [2])
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
    grequests.post(payment_url, json={"amount": amount, "identifier": identifier}).send()

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


@pytest.mark.parametrize("number_of_nodes", [2])
def test_api_payments_secret_hash_errors(
    api_server_test_instance: APIServer, raiden_network, token_addresses
):
    _, app1 = raiden_network
    amount = 200
    identifier = 42
    token_address = token_addresses[0]
    target_address = app1.raiden.address
    secret = to_hex(factories.make_secret())
    bad_secret = "Not Hex String. 0x78c8d676e2f2399aa2a015f3433a2083c55003591a0f3f33"
    bad_secret_hash = "Not Hex String. 0x78c8d676e2f2399aa2a015f3433a2083c55003591a0f3f33"
    short_secret = "0x123"
    short_secret_hash = "Short secret hash"

    request = grequests.post(
        api_url_for(
            api_server_test_instance,
            "token_target_paymentresource",
            token_address=to_checksum_address(token_address),
            target_address=to_checksum_address(target_address),
        ),
        json={"amount": amount, "identifier": identifier, "secret": short_secret},
    )
    response = request.send().response
    assert_proper_response(response, status_code=HTTPStatus.BAD_REQUEST)

    request = grequests.post(
        api_url_for(
            api_server_test_instance,
            "token_target_paymentresource",
            token_address=to_checksum_address(token_address),
            target_address=to_checksum_address(target_address),
        ),
        json={"amount": amount, "identifier": identifier, "secret": bad_secret},
    )
    response = request.send().response
    assert_proper_response(response, status_code=HTTPStatus.BAD_REQUEST)

    request = grequests.post(
        api_url_for(
            api_server_test_instance,
            "token_target_paymentresource",
            token_address=to_checksum_address(token_address),
            target_address=to_checksum_address(target_address),
        ),
        json={"amount": amount, "identifier": identifier, "secret_hash": short_secret_hash},
    )
    response = request.send().response
    assert_proper_response(response, status_code=HTTPStatus.BAD_REQUEST)

    request = grequests.post(
        api_url_for(
            api_server_test_instance,
            "token_target_paymentresource",
            token_address=to_checksum_address(token_address),
            target_address=to_checksum_address(target_address),
        ),
        json={"amount": amount, "identifier": identifier, "secret_hash": bad_secret_hash},
    )
    response = request.send().response
    assert_proper_response(response, status_code=HTTPStatus.BAD_REQUEST)

    request = grequests.post(
        api_url_for(
            api_server_test_instance,
            "token_target_paymentresource",
            token_address=to_checksum_address(token_address),
            target_address=to_checksum_address(target_address),
        ),
        json={"amount": amount, "identifier": identifier, "secret": secret, "secret_hash": secret},
    )
    response = request.send().response
    assert_proper_response(response, status_code=HTTPStatus.CONFLICT)


@pytest.mark.parametrize("number_of_nodes", [2])
def test_api_payments_with_secret_no_hash(
    api_server_test_instance: APIServer, raiden_network, token_addresses
):
    _, app1 = raiden_network
    amount = 100
    identifier = 42
    token_address = token_addresses[0]
    target_address = app1.raiden.address
    secret = to_hex(factories.make_secret())

    our_address = api_server_test_instance.rest_api.raiden_api.address

    payment = {
        "initiator_address": to_checksum_address(our_address),
        "target_address": to_checksum_address(target_address),
        "token_address": to_checksum_address(token_address),
        "amount": amount,
        "identifier": identifier,
    }

    request = grequests.post(
        api_url_for(
            api_server_test_instance,
            "token_target_paymentresource",
            token_address=to_checksum_address(token_address),
            target_address=to_checksum_address(target_address),
        ),
        json={"amount": amount, "identifier": identifier, "secret": secret},
    )
    with watch_for_unlock_failures(*raiden_network):
        response = request.send().response
    assert_proper_response(response)
    json_response = get_json_response(response)
    assert_payment_secret_and_hash(json_response, payment)
    assert secret == json_response["secret"]


@pytest.mark.parametrize("number_of_nodes", [2])
def test_api_payments_with_hash_no_secret(
    api_server_test_instance, raiden_network, token_addresses
):
    _, app1 = raiden_network
    amount = 200
    identifier = 42
    token_address = token_addresses[0]
    target_address = app1.raiden.address
    secret = to_hex(factories.make_secret())
    secret_hash = to_hex(sha256(to_bytes(hexstr=secret)).digest())

    our_address = api_server_test_instance.rest_api.raiden_api.address

    payment = {
        "initiator_address": to_checksum_address(our_address),
        "target_address": to_checksum_address(target_address),
        "token_address": to_checksum_address(token_address),
        "amount": amount,
        "identifier": identifier,
    }

    request = grequests.post(
        api_url_for(
            api_server_test_instance,
            "token_target_paymentresource",
            token_address=to_checksum_address(token_address),
            target_address=to_checksum_address(target_address),
        ),
        json={"amount": amount, "identifier": identifier, "secret_hash": secret_hash},
    )
    with watch_for_unlock_failures(*raiden_network):
        response = request.send().response
    assert_proper_response(response, status_code=HTTPStatus.CONFLICT)
    assert payment == payment


@pytest.mark.parametrize("number_of_nodes", [2])
@pytest.mark.parametrize("resolver_ports", [[None, 8000]])
def test_api_payments_with_resolver(
    api_server_test_instance: APIServer, raiden_network, token_addresses, resolvers
):

    _, app1 = raiden_network
    amount = 100
    identifier = 42
    token_address = token_addresses[0]
    target_address = app1.raiden.address
    secret = to_hex(factories.make_secret())
    secret_hash = to_hex(sha256(to_bytes(hexstr=secret)).digest())

    our_address = api_server_test_instance.rest_api.raiden_api.address

    payment = {
        "initiator_address": to_checksum_address(our_address),
        "target_address": to_checksum_address(target_address),
        "token_address": to_checksum_address(token_address),
        "amount": amount,
        "identifier": identifier,
    }

    # payment with secret_hash when both resolver and initiator don't have the secret

    request = grequests.post(
        api_url_for(
            api_server_test_instance,
            "token_target_paymentresource",
            token_address=to_checksum_address(token_address),
            target_address=to_checksum_address(target_address),
        ),
        json={"amount": amount, "identifier": identifier, "secret_hash": secret_hash},
    )
    response = request.send().response
    assert_proper_response(response, status_code=HTTPStatus.CONFLICT)
    assert payment == payment

    # payment with secret where the resolver doesn't have the secret. Should work.

    request = grequests.post(
        api_url_for(
            api_server_test_instance,
            "token_target_paymentresource",
            token_address=to_checksum_address(token_address),
            target_address=to_checksum_address(target_address),
        ),
        json={"amount": amount, "identifier": identifier, "secret": secret},
    )
    with watch_for_unlock_failures(*raiden_network):
        response = request.send().response
    assert_proper_response(response, status_code=HTTPStatus.OK)
    assert payment == payment

    # payment with secret_hash where the resolver has the secret. Should work.

    secret = "0x2ff886d47b156de00d4cad5d8c332706692b5b572adfe35e6d2f65e92906806e"
    secret_hash = to_hex(sha256(to_bytes(hexstr=secret)).digest())

    request = grequests.post(
        api_url_for(
            api_server_test_instance,
            "token_target_paymentresource",
            token_address=to_checksum_address(token_address),
            target_address=to_checksum_address(target_address),
        ),
        json={"amount": amount, "identifier": identifier, "secret_hash": secret_hash},
    )
    with watch_for_unlock_failures(*raiden_network):
        response = request.send().response
    assert_proper_response(response, status_code=HTTPStatus.OK)
    assert payment == payment


@pytest.mark.parametrize("number_of_nodes", [2])
def test_api_payments_with_secret_and_hash(
    api_server_test_instance: APIServer, raiden_network, token_addresses
):
    _, app1 = raiden_network
    amount = 100
    identifier = 42
    token_address = token_addresses[0]
    target_address = app1.raiden.address
    secret = to_hex(factories.make_secret())
    secret_hash = to_hex(sha256(to_bytes(hexstr=secret)).digest())

    our_address = api_server_test_instance.rest_api.raiden_api.address

    payment = {
        "initiator_address": to_checksum_address(our_address),
        "target_address": to_checksum_address(target_address),
        "token_address": to_checksum_address(token_address),
        "amount": amount,
        "identifier": identifier,
    }

    request = grequests.post(
        api_url_for(
            api_server_test_instance,
            "token_target_paymentresource",
            token_address=to_checksum_address(token_address),
            target_address=to_checksum_address(target_address),
        ),
        json={
            "amount": amount,
            "identifier": identifier,
            "secret": secret,
            "secret_hash": secret_hash,
        },
    )
    with watch_for_unlock_failures(*raiden_network):
        response = request.send().response
    assert_proper_response(response)
    json_response = get_json_response(response)
    assert_payment_secret_and_hash(json_response, payment)
    assert secret == json_response["secret"]
    assert secret_hash == json_response["secret_hash"]


def assert_payment_secret_and_hash(response, payment):
    # make sure that payment key/values are part of the response.
    assert len(response) == 7
    assert "secret" in response
    assert "secret_hash" in response

    secret = to_bytes(hexstr=response["secret"])
    assert len(secret) == SECRET_LENGTH
    assert payment["amount"] == response["amount"]

    assert to_bytes(hexstr=response["secret_hash"]) == sha256_secrethash(secret)


def assert_payment_conflict(responses):
    assert all(response is not None for response in responses)
    assert any(
        resp.status_code == HTTPStatus.CONFLICT
        and get_json_response(resp)["errors"] == "Another payment with the same id is in flight"
        for resp in responses
    )


@pytest.mark.parametrize("number_of_nodes", [2])
def test_api_payments_conflicts(
    api_server_test_instance: APIServer, raiden_network, token_addresses
):
    _, app1 = raiden_network
    token_address = token_addresses[0]
    target_address = app1.raiden.address

    payment_url = api_url_for(
        api_server_test_instance,
        "token_target_paymentresource",
        token_address=to_checksum_address(token_address),
        target_address=to_checksum_address(target_address),
    )

    # two different transfers (different amounts) with same identifier at the same time:
    # payment conflict
    responses = grequests.map(
        [
            grequests.post(payment_url, json={"amount": 10, "identifier": 11}),
            grequests.post(payment_url, json={"amount": 11, "identifier": 11}),
        ]
    )
    assert_payment_conflict(responses)

    # same request sent twice, e. g. when it is retried: no conflict
    responses = grequests.map(
        [
            grequests.post(payment_url, json={"amount": 10, "identifier": 73}),
            grequests.post(payment_url, json={"amount": 10, "identifier": 73}),
        ]
    )
    assert all(response.status_code == HTTPStatus.OK for response in responses)


@pytest.mark.parametrize("number_of_tokens", [0])
@pytest.mark.parametrize("number_of_nodes", [1])
@pytest.mark.parametrize("channels_per_node", [0])
@pytest.mark.parametrize("environment_type", [Environment.PRODUCTION])
def test_register_token_mainnet(
    api_server_test_instance: APIServer,
    token_amount,
    token_addresses,
    raiden_network,
    contract_manager,
):
    app0 = raiden_network[0]
    new_token_address = deploy_contract_web3(
        CONTRACT_HUMAN_STANDARD_TOKEN,
        app0.raiden.rpc_client,
        contract_manager=contract_manager,
        constructor_arguments=(token_amount, 2, "raiden", "Rd"),
    )
    register_request = grequests.put(
        api_url_for(
            api_server_test_instance,
            "registertokenresource",
            token_address=to_checksum_address(new_token_address),
        )
    )
    response = register_request.send().response
    assert response is not None and response.status_code == HTTPStatus.NOT_IMPLEMENTED


@pytest.mark.parametrize("number_of_tokens", [0])
@pytest.mark.parametrize("number_of_nodes", [1])
@pytest.mark.parametrize("channels_per_node", [0])
@pytest.mark.parametrize("environment_type", [Environment.DEVELOPMENT])
def test_register_token(
    api_server_test_instance,
    token_amount,
    token_addresses,
    raiden_network,
    contract_manager,
    retry_timeout,
):
    app0 = raiden_network[0]
    new_token_address = deploy_contract_web3(
        CONTRACT_HUMAN_STANDARD_TOKEN,
        app0.raiden.rpc_client,
        contract_manager=contract_manager,
        constructor_arguments=(token_amount, 2, "raiden", "Rd"),
    )
    other_token_address = deploy_contract_web3(
        CONTRACT_HUMAN_STANDARD_TOKEN,
        app0.raiden.rpc_client,
        contract_manager=contract_manager,
        constructor_arguments=(token_amount, 2, "raiden", "Rd"),
    )

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

    # Burn all the eth and then make sure we get the appropriate API error
    burn_eth(app0.raiden.rpc_client)
    poor_request = grequests.put(
        api_url_for(
            api_server_test_instance,
            "registertokenresource",
            token_address=to_checksum_address(other_token_address),
        )
    )
    poor_response = poor_request.send().response
    assert_response_with_error(poor_response, HTTPStatus.PAYMENT_REQUIRED)


@pytest.mark.parametrize("number_of_tokens", [0])
@pytest.mark.parametrize("number_of_nodes", [1])
@pytest.mark.parametrize("channels_per_node", [0])
@pytest.mark.parametrize("environment_type", [Environment.DEVELOPMENT])
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


@pytest.mark.parametrize("number_of_nodes", [1])
@pytest.mark.parametrize("channels_per_node", [0])
@pytest.mark.parametrize("number_of_tokens", [1])
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


@pytest.mark.parametrize("number_of_nodes", [1])
@pytest.mark.parametrize("channels_per_node", [0])
@pytest.mark.parametrize("number_of_tokens", [1])
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


@pytest.mark.parametrize("number_of_nodes", [1])
@pytest.mark.parametrize("channels_per_node", [0])
def test_network_events(api_server_test_instance: APIServer, token_addresses):
    # let's create a new channel
    partner_address = "0x61C808D82A3Ac53231750daDc13c777b59310bD9"
    token_address = token_addresses[0]
    settle_timeout = 1650
    channel_data_obj = {
        "partner_address": partner_address,
        "token_address": to_checksum_address(token_address),
        "settle_timeout": settle_timeout,
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


@pytest.mark.parametrize("number_of_nodes", [1])
@pytest.mark.parametrize("channels_per_node", [0])
def test_token_events(api_server_test_instance: APIServer, token_addresses):
    # let's create a new channel
    partner_address = "0x61C808D82A3Ac53231750daDc13c777b59310bD9"
    token_address = token_addresses[0]
    settle_timeout = 1650
    channel_data_obj = {
        "partner_address": partner_address,
        "token_address": to_checksum_address(token_address),
        "settle_timeout": settle_timeout,
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


@pytest.mark.parametrize("number_of_nodes", [1])
@pytest.mark.parametrize("channels_per_node", [0])
def test_channel_events(api_server_test_instance: APIServer, token_addresses):
    # let's create a new channel
    partner_address = "0x61C808D82A3Ac53231750daDc13c777b59310bD9"
    token_address = token_addresses[0]
    settle_timeout = 1650
    channel_data_obj = {
        "partner_address": partner_address,
        "token_address": to_checksum_address(token_address),
        "settle_timeout": settle_timeout,
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
            partner_address=partner_address,
            token_address=token_address,
            from_block=GENESIS_BLOCK_NUMBER,
        )
    )
    response = request.send().response
    assert_proper_response(response, status_code=HTTPStatus.OK)
    assert len(get_json_response(response)) > 0


@pytest.mark.parametrize("number_of_nodes", [1])
@pytest.mark.parametrize("channels_per_node", [0])
def test_token_events_errors_for_unregistered_token(api_server_test_instance):
    request = grequests.get(
        api_url_for(
            api_server_test_instance,
            "tokenchanneleventsresourceblockchain",
            token_address="0x61C808D82A3Ac53231750daDc13c777b59310bD9",
            from_block=5,
            to_block=20,
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
            from_block=5,
            to_block=20,
        )
    )
    response = request.send().response
    assert_response_with_error(response, status_code=HTTPStatus.NOT_FOUND)


@pytest.mark.parametrize("number_of_nodes", [1])
@pytest.mark.parametrize("channels_per_node", [0])
@pytest.mark.parametrize("deposit", [DEPOSIT_FOR_TEST_API_DEPOSIT_LIMIT])
def test_api_deposit_limit(
    api_server_test_instance,
    proxy_manager,
    token_network_registry_address,
    token_addresses,
    reveal_timeout,
):
    token_address = token_addresses[0]

    registry = proxy_manager.token_network_registry(token_network_registry_address)
    token_network_address = registry.get_token_network(token_address, "latest")
    token_network = proxy_manager.token_network(token_network_address)
    deposit_limit = token_network.channel_participant_deposit_limit("latest")

    # let's create a new channel and deposit exactly the limit amount
    first_partner_address = "0x61C808D82A3Ac53231750daDc13c777b59310bD9"
    settle_timeout = 1650
    channel_data_obj = {
        "partner_address": first_partner_address,
        "token_address": to_checksum_address(token_address),
        "settle_timeout": settle_timeout,
        "reveal_timeout": reveal_timeout,
        "total_deposit": deposit_limit,
    }

    request = grequests.put(
        api_url_for(api_server_test_instance, "channelsresource"), json=channel_data_obj
    )
    response = request.send().response

    assert_proper_response(response, HTTPStatus.CREATED)
    first_channel_identifier = 1
    json_response = get_json_response(response)
    expected_response = channel_data_obj.copy()
    expected_response.update(
        {
            "balance": deposit_limit,
            "state": ChannelState.STATE_OPENED.value,
            "channel_identifier": first_channel_identifier,
            "total_deposit": deposit_limit,
        }
    )
    assert check_dict_nested_attrs(json_response, expected_response)

    # now let's open a channel and deposit a bit more than the limit
    second_partner_address = "0x29FA6cf0Cce24582a9B20DB94Be4B6E017896038"
    balance_failing = deposit_limit + 1  # token has two digits
    channel_data_obj = {
        "partner_address": second_partner_address,
        "token_address": to_checksum_address(token_address),
        "settle_timeout": settle_timeout,
        "reveal_timeout": reveal_timeout,
        "total_deposit": balance_failing,
    }
    request = grequests.put(
        api_url_for(api_server_test_instance, "channelsresource"), json=channel_data_obj
    )
    response = request.send().response

    assert_proper_response(response, HTTPStatus.CONFLICT)
    json_response = get_json_response(response)
    assert (
        json_response["errors"]
        == "Deposit of 75000000000000001 is larger than the channel participant deposit limit"
    )


@pytest.mark.parametrize("number_of_nodes", [3])
def test_payment_events_endpoints(
    api_server_test_instance: APIServer, raiden_network, token_addresses
):
    app0, app1, app2 = raiden_network
    amount1 = PaymentAmount(10)
    identifier1 = PaymentID(42)
    secret1, secrethash1 = factories.make_secret_with_hash()
    token_address = token_addresses[0]

    app0_address = app0.raiden.address
    target1_address = app1.raiden.address
    target2_address = app2.raiden.address

    app1_server = create_api_server(app1, 8575)
    app2_server = create_api_server(app2, 8576)

    # app0 is sending tokens to target 1
    request = grequests.post(
        api_url_for(
            api_server_test_instance,
            "token_target_paymentresource",
            token_address=to_checksum_address(token_address),
            target_address=to_checksum_address(target1_address),
        ),
        json={"amount": amount1, "identifier": identifier1, "secret": to_hex(secret1)},
    )
    request.send()

    # app0 is sending some tokens to target 2
    identifier2 = PaymentID(43)
    amount2 = PaymentAmount(10)
    secret2, secrethash2 = factories.make_secret_with_hash()
    request = grequests.post(
        api_url_for(
            api_server_test_instance,
            "token_target_paymentresource",
            token_address=to_checksum_address(token_address),
            target_address=to_checksum_address(target2_address),
        ),
        json={"amount": amount2, "identifier": identifier2, "secret": to_hex(secret2)},
    )
    request.send()

    # target1 also sends some tokens to target 2
    identifier3 = PaymentID(44)
    amount3 = PaymentAmount(5)
    secret3, secrethash3 = factories.make_secret_with_hash()
    request = grequests.post(
        api_url_for(
            app1_server,
            "token_target_paymentresource",
            token_address=to_checksum_address(token_address),
            target_address=to_checksum_address(target2_address),
        ),
        json={"amount": amount3, "identifier": identifier3, "secret": to_hex(secret3)},
    )
    request.send()

    exception = ValueError("Waiting for transfer received success in the WAL timed out")
    with watch_for_unlock_failures(*raiden_network), gevent.Timeout(
        seconds=60, exception=exception
    ):
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
            app2.raiden, identifier3, amount3, app2.raiden.alarm.sleep_time, secrethash3
        )
        msg = f"Unexpected transfer result: {str(result)}"
        assert result == TransferWaitResult.UNLOCKED, msg

    # test endpoint without (partner and token) for sender
    request = grequests.get(api_url_for(api_server_test_instance, "paymentresource"))
    with watch_for_unlock_failures(*raiden_network):
        response = request.send().response
    assert_proper_response(response, HTTPStatus.OK)
    json_response = get_json_response(response)
    assert must_have_event(
        json_response,
        {
            "event": "EventPaymentSentSuccess",
            "identifier": identifier1,
            "target": to_checksum_address(target1_address),
        },
    )
    assert must_have_event(
        json_response,
        {
            "event": "EventPaymentSentSuccess",
            "identifier": identifier2,
            "target": to_checksum_address(target2_address),
        },
    )

    # test endpoint without (partner and token) for target1
    request = grequests.get(api_url_for(app1_server, "paymentresource"))
    response = request.send().response
    assert_proper_response(response, HTTPStatus.OK)
    json_response = get_json_response(response)
    assert must_have_event(
        json_response, {"event": "EventPaymentReceivedSuccess", "identifier": identifier1}
    )
    assert must_have_event(
        json_response, {"event": "EventPaymentSentSuccess", "identifier": identifier3}
    )
    # test endpoint without (partner and token) for target2
    request = grequests.get(api_url_for(app2_server, "paymentresource"))
    response = request.send().response
    assert_proper_response(response, HTTPStatus.OK)
    json_response = get_json_response(response)
    assert must_have_event(
        json_response, {"event": "EventPaymentReceivedSuccess", "identifier": identifier2}
    )
    assert must_have_event(
        json_response, {"event": "EventPaymentReceivedSuccess", "identifier": identifier3}
    )

    # test endpoint without partner for app0
    request = grequests.get(
        api_url_for(api_server_test_instance, "token_paymentresource", token_address=token_address)
    )
    response = request.send().response
    assert_proper_response(response, HTTPStatus.OK)
    json_response = get_json_response(response)
    assert must_have_event(
        json_response,
        {
            "event": "EventPaymentSentSuccess",
            "identifier": identifier1,
            "target": to_checksum_address(target1_address),
        },
    )
    assert must_have_event(
        json_response,
        {
            "event": "EventPaymentSentSuccess",
            "identifier": identifier2,
            "target": to_checksum_address(target2_address),
        },
    )

    # test endpoint without partner for app0 but with limit/offset to get only first
    request = grequests.get(
        api_url_for(
            api_server_test_instance,
            "token_paymentresource",
            token_address=token_address,
            limit=1,
            offset=0,
        )
    )
    response = request.send().response
    assert_proper_response(response, HTTPStatus.OK)
    json_response = get_json_response(response)

    assert must_have_event(
        json_response,
        {
            "event": "EventPaymentSentSuccess",
            "identifier": identifier1,
            "target": to_checksum_address(target1_address),
        },
    )
    assert len(json_response) == 1
    # test endpoint without partner for app0 but with limit/offset to get only second
    request = grequests.get(
        api_url_for(
            api_server_test_instance,
            "token_paymentresource",
            token_address=token_address,
            limit=1,
            offset=1,
        )
    )
    response = request.send().response
    assert_proper_response(response, HTTPStatus.OK)
    json_response = get_json_response(response)
    assert must_have_event(
        json_response,
        {
            "event": "EventPaymentSentSuccess",
            "identifier": identifier2,
            "target": to_checksum_address(target2_address),
        },
    )

    # test endpoint without partner for target1
    request = grequests.get(
        api_url_for(app1_server, "token_paymentresource", token_address=token_address)
    )
    response = request.send().response
    assert_proper_response(response, HTTPStatus.OK)
    json_response = get_json_response(response)
    assert must_have_events(
        json_response,
        {"event": "EventPaymentReceivedSuccess", "identifier": identifier1},
        {
            "event": "EventPaymentSentSuccess",
            "identifier": identifier3,
            "target": to_checksum_address(target2_address),
        },
    )
    # test endpoint without partner for target2
    request = grequests.get(
        api_url_for(app2_server, "token_paymentresource", token_address=token_address)
    )
    response = request.send().response
    assert_proper_response(response, HTTPStatus.OK)
    json_response = get_json_response(response)
    assert must_have_events(
        json_response,
        {"event": "EventPaymentReceivedSuccess", "identifier": identifier2},
        {"event": "EventPaymentReceivedSuccess", "identifier": identifier3},
    )

    # test endpoint for token and partner for app0
    request = grequests.get(
        api_url_for(
            api_server_test_instance,
            "token_target_paymentresource",
            token_address=token_address,
            target_address=target1_address,
        )
    )
    response = request.send().response
    assert_proper_response(response, HTTPStatus.OK)
    json_response = get_json_response(response)
    assert must_have_event(
        json_response,
        {
            "event": "EventPaymentSentSuccess",
            "identifier": identifier1,
            "target": to_checksum_address(target1_address),
        },
    )
    assert not must_have_event(
        json_response,
        {
            "event": "EventPaymentSentSuccess",
            "identifier": identifier2,
            "target": to_checksum_address(target2_address),
        },
    )
    # test endpoint for token and partner for target1. Check both partners
    # to see that filtering works correctly
    request = grequests.get(
        api_url_for(
            app1_server,
            "token_target_paymentresource",
            token_address=token_address,
            target_address=target2_address,
        )
    )
    response = request.send().response
    assert_proper_response(response, HTTPStatus.OK)
    json_response = get_json_response(response)
    assert must_have_event(
        json_response,
        {
            "event": "EventPaymentSentSuccess",
            "identifier": identifier3,
            "target": to_checksum_address(target2_address),
        },
    )
    assert not must_have_event(
        response, {"event": "EventPaymentReceivedSuccess", "identifier": identifier1}
    )
    request = grequests.get(
        api_url_for(
            app1_server,
            "token_target_paymentresource",
            token_address=token_address,
            target_address=target1_address,
        )
    )
    response = request.send().response
    assert_proper_response(response, HTTPStatus.OK)
    json_response = get_json_response(response)
    assert len(json_response) == 0
    # test endpoint for token and partner for target2
    request = grequests.get(
        api_url_for(
            app2_server,
            "token_target_paymentresource",
            token_address=token_address,
            target_address=app0_address,
        )
    )
    response = request.send().response
    assert_proper_response(response, HTTPStatus.OK)
    json_response = get_json_response(response)
    assert must_have_events(
        json_response, {"event": "EventPaymentReceivedSuccess", "identifier": identifier2}
    )
    assert not must_have_event(
        json_response, {"event": "EventPaymentReceivedSuccess", "identifier": identifier1}
    )
    assert not must_have_event(
        json_response, {"event": "EventPaymentReceivedSuccess", "identifier": identifier3}
    )
    request = grequests.get(
        api_url_for(
            app2_server,
            "token_target_paymentresource",
            token_address=token_address,
            target_address=target1_address,
        )
    )
    response = request.send().response
    assert_proper_response(response, HTTPStatus.OK)
    json_response = get_json_response(response)
    assert must_have_events(
        json_response, {"event": "EventPaymentReceivedSuccess", "identifier": identifier3}
    )
    assert not must_have_event(
        json_response, {"event": "EventPaymentReceivedSuccess", "identifier": identifier2}
    )
    assert not must_have_event(
        json_response, {"event": "EventPaymentReceivedSuccess", "identifier": identifier1}
    )

    app1_server.stop()
    app2_server.stop()


@pytest.mark.parametrize("number_of_nodes", [2])
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
        json={"amount": amount, "identifier": identifier},
    )
    response = request.send().response
    assert_proper_response(response)


@pytest.mark.parametrize("number_of_nodes", [3])
@pytest.mark.parametrize("channels_per_node", [CHAIN])
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

    initiator_server = create_api_server(initiator, 8575)
    mediator_server = create_api_server(mediator, 8576)
    target_server = create_api_server(target, 8577)

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
    gevent.wait((mediator_unlock, target_unlock))

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


@pytest.mark.parametrize("number_of_nodes", [2])
@pytest.mark.parametrize("deposit", [1000])
def test_api_withdraw(api_server_test_instance: APIServer, raiden_network, token_addresses):
    _, app1 = raiden_network
    token_address = token_addresses[0]
    partner_address = app1.raiden.address

    # Withdraw a 0 amount
    request = grequests.patch(
        api_url_for(
            api_server_test_instance,
            "channelsresourcebytokenandpartneraddress",
            token_address=token_address,
            partner_address=partner_address,
        ),
        json=dict(total_withdraw=0),
    )
    response = request.send().response
    assert_response_with_error(response, HTTPStatus.CONFLICT)

    # Withdraw an amount larger than balance
    request = grequests.patch(
        api_url_for(
            api_server_test_instance,
            "channelsresourcebytokenandpartneraddress",
            token_address=token_address,
            partner_address=partner_address,
        ),
        json=dict(total_withdraw=1500),
    )
    response = request.send().response
    assert_response_with_error(response, HTTPStatus.CONFLICT)

    # Withdraw a valid amount
    request = grequests.patch(
        api_url_for(
            api_server_test_instance,
            "channelsresourcebytokenandpartneraddress",
            token_address=token_address,
            partner_address=partner_address,
        ),
        json=dict(total_withdraw=750),
    )
    response = request.send().response
    assert_response_with_code(response, HTTPStatus.OK)

    # Withdraw same amount as before which would sum up to more than the balance
    request = grequests.patch(
        api_url_for(
            api_server_test_instance,
            "channelsresourcebytokenandpartneraddress",
            token_address=token_address,
            partner_address=partner_address,
        ),
        json=dict(total_withdraw=750),
    )
    response = request.send().response
    assert_response_with_error(response, HTTPStatus.CONFLICT)


@pytest.mark.parametrize("number_of_nodes", [1])
@pytest.mark.parametrize("channels_per_node", [0])
@pytest.mark.parametrize("number_of_tokens", [1])
@pytest.mark.parametrize("token_contract_name", [CONTRACT_CUSTOM_TOKEN])
def test_api_testnet_token_mint(api_server_test_instance: APIServer, token_addresses):
    user_address = factories.make_checksum_address()
    token_address = token_addresses[0]
    url = api_url_for(api_server_test_instance, "tokensmintresource", token_address=token_address)

    request = grequests.post(url, json=dict(to=user_address, value=1, contract_method="mintFor"))
    response = request.send().response
    assert_response_with_code(response, HTTPStatus.OK)

    # mint method defaults to mintFor
    request = grequests.post(url, json=dict(to=user_address, value=10))
    response = request.send().response
    assert_response_with_code(response, HTTPStatus.OK)

    # fails because requested mint method is not there
    request = grequests.post(url, json=dict(to=user_address, value=10, contract_method="mint"))
    response = request.send().response
    assert_response_with_error(response, HTTPStatus.BAD_REQUEST)

    # fails because of invalid choice of mint method
    request = grequests.post(
        url, json=dict(to=user_address, value=10, contract_method="unknownMethod")
    )
    response = request.send().response
    assert_response_with_error(response, HTTPStatus.BAD_REQUEST)

    # invalid due to negative value
    request = grequests.post(url, json=dict(to=user_address, value=-1))
    response = request.send().response
    assert_response_with_error(response, HTTPStatus.BAD_REQUEST)

    # invalid due to invalid address
    request = grequests.post(url, json=dict(to=user_address[:-2], value=10))
    response = request.send().response
    assert_response_with_error(response, HTTPStatus.BAD_REQUEST)


@pytest.mark.parametrize("number_of_nodes", [2])
def test_api_payments_with_lock_timeout(
    api_server_test_instance: APIServer, raiden_network, token_addresses
):
    _, app1 = raiden_network
    amount = 100
    identifier = 42
    token_address = token_addresses[0]
    target_address = app1.raiden.address
    number_of_nodes = 2
    reveal_timeout = number_of_nodes * 4 + DEFAULT_NUMBER_OF_BLOCK_CONFIRMATIONS
    settle_timeout = 39

    # try lock_timeout = reveal_timeout - should not work
    request = grequests.post(
        api_url_for(
            api_server_test_instance,
            "token_target_paymentresource",
            token_address=to_checksum_address(token_address),
            target_address=to_checksum_address(target_address),
        ),
        json={"amount": amount, "identifier": identifier, "lock_timeout": reveal_timeout},
    )
    response = request.send().response
    assert_response_with_error(response, status_code=HTTPStatus.CONFLICT)

    # try lock_timeout = reveal_timeout * 2  - should  work.
    request = grequests.post(
        api_url_for(
            api_server_test_instance,
            "token_target_paymentresource",
            token_address=to_checksum_address(token_address),
            target_address=to_checksum_address(target_address),
        ),
        json={"amount": amount, "identifier": identifier, "lock_timeout": 2 * reveal_timeout},
    )
    with watch_for_unlock_failures(*raiden_network):
        response = request.send().response
    assert_proper_response(response, status_code=HTTPStatus.OK)

    # try lock_timeout = settle_timeout - should work.
    request = grequests.post(
        api_url_for(
            api_server_test_instance,
            "token_target_paymentresource",
            token_address=to_checksum_address(token_address),
            target_address=to_checksum_address(target_address),
        ),
        json={"amount": amount, "identifier": identifier, "lock_timeout": settle_timeout},
    )
    response = request.send().response
    assert_proper_response(response, status_code=HTTPStatus.OK)

    # try lock_timeout = settle_timeout+1 - should not work.
    request = grequests.post(
        api_url_for(
            api_server_test_instance,
            "token_target_paymentresource",
            token_address=to_checksum_address(token_address),
            target_address=to_checksum_address(target_address),
        ),
        json={"amount": amount, "identifier": identifier, "lock_timeout": settle_timeout + 1},
    )
    response = request.send().response
    assert_response_with_error(response, status_code=HTTPStatus.CONFLICT)


@pytest.mark.parametrize("number_of_nodes", [2])
@pytest.mark.parametrize("deposit", [0])
def test_api_set_reveal_timeout(
    api_server_test_instance: APIServer, raiden_network, token_addresses, settle_timeout
):
    app0, app1 = raiden_network
    token_address = token_addresses[0]
    partner_address = app1.raiden.address

    request = grequests.patch(
        api_url_for(
            api_server_test_instance,
            "channelsresourcebytokenandpartneraddress",
            token_address=token_address,
            partner_address=partner_address,
        ),
        json=dict(reveal_timeout=0),
    )
    response = request.send().response
    assert_response_with_error(response, HTTPStatus.CONFLICT)

    request = grequests.patch(
        api_url_for(
            api_server_test_instance,
            "channelsresourcebytokenandpartneraddress",
            token_address=token_address,
            partner_address=partner_address,
        ),
        json=dict(reveal_timeout=settle_timeout + 1),
    )
    response = request.send().response
    assert_response_with_error(response, HTTPStatus.CONFLICT)

    reveal_timeout = int(settle_timeout / 2)
    request = grequests.patch(
        api_url_for(
            api_server_test_instance,
            "channelsresourcebytokenandpartneraddress",
            token_address=token_address,
            partner_address=partner_address,
        ),
        json=dict(reveal_timeout=reveal_timeout),
    )
    response = request.send().response
    assert_response_with_code(response, HTTPStatus.OK)

    token_network_address = views.get_token_network_address_by_token_address(
        views.state_from_app(app0), app0.raiden.default_registry.address, token_address
    )
    assert token_network_address
    channel_state = views.get_channelstate_by_token_network_and_partner(
        chain_state=views.state_from_raiden(app0.raiden),
        token_network_address=token_network_address,
        partner_address=app1.raiden.address,
    )
    assert channel_state

    assert channel_state.reveal_timeout == reveal_timeout
