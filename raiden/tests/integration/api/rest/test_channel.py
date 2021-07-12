from http import HTTPStatus

import gevent
import grequests
import pytest
from eth_utils import to_canonical_address, to_checksum_address

from raiden.api.rest import APIServer
from raiden.constants import BLOCK_ID_LATEST, NULL_ADDRESS_HEX
from raiden.raiden_service import RaidenService
from raiden.tests.integration.api.rest.test_rest import DEPOSIT_FOR_TEST_API_DEPOSIT_LIMIT
from raiden.tests.integration.api.rest.utils import (
    api_url_for,
    assert_proper_response,
    assert_response_with_code,
    assert_response_with_error,
    get_json_response,
)
from raiden.tests.utils import factories
from raiden.tests.utils.client import burn_eth
from raiden.tests.utils.detect_failure import raise_on_failure
from raiden.tests.utils.events import check_dict_nested_attrs
from raiden.transfer import views
from raiden.transfer.state import ChannelState
from raiden.utils.typing import List, TokenAmount
from raiden.waiting import wait_for_participant_deposit
from raiden_contracts.constants import TEST_SETTLE_TIMEOUT_MAX, TEST_SETTLE_TIMEOUT_MIN


@raise_on_failure
@pytest.mark.parametrize("number_of_nodes", [1])
@pytest.mark.parametrize("channels_per_node", [0])
@pytest.mark.parametrize("enable_rest_api", [True])
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


@raise_on_failure
@pytest.mark.parametrize("number_of_nodes", [1])
@pytest.mark.parametrize("channels_per_node", [0])
@pytest.mark.parametrize("enable_rest_api", [True])
def test_api_channel_open_and_deposit(
    api_server_test_instance: APIServer, token_addresses, reveal_timeout
):

    first_partner_address = "0x61C808D82A3Ac53231750daDc13c777b59310bD9"
    token_address = token_addresses[0]
    token_address_hex = to_checksum_address(token_address)
    settle_timeout = 1650
    channel_data_obj = {
        "partner_address": first_partner_address,
        "token_address": token_address_hex,
        "settle_timeout": str(settle_timeout),
        "reveal_timeout": str(reveal_timeout),
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
            "balance": "0",
            "state": ChannelState.STATE_OPENED.value,
            "channel_identifier": "1",
            "total_deposit": "0",
        }
    )
    assert check_dict_nested_attrs(json_response, expected_response)
    token_network_address = json_response["token_network_address"]

    # Now let's try to open the same channel again, because it is possible for
    # the participants to race on the channel creation, this is not considered
    # an error.
    request = grequests.put(
        api_url_for(api_server_test_instance, "channelsresource"), json=channel_data_obj
    )
    response = request.send().response
    assert_proper_response(response, HTTPStatus.OK)
    json_response = get_json_response(response)
    assert check_dict_nested_attrs(json_response, expected_response)

    # now let's open a channel and make a deposit too
    second_partner_address = "0x29FA6cf0Cce24582a9B20DB94Be4B6E017896038"
    total_deposit = 100
    channel_data_obj = {
        "partner_address": second_partner_address,
        "token_address": to_checksum_address(token_address),
        "settle_timeout": str(settle_timeout),
        "reveal_timeout": str(reveal_timeout),
        "total_deposit": str(total_deposit),
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
            "balance": str(total_deposit),
            "state": ChannelState.STATE_OPENED.value,
            "channel_identifier": str(second_channel_id),
            "token_network_address": token_network_address,
            "total_deposit": str(total_deposit),
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
        json={"total_deposit": "99"},
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
        json={"total_deposit": "-1000"},
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
        json={"total_deposit": str(total_deposit)},
    )
    response = request.send().response
    assert_proper_response(response)
    json_response = get_json_response(response)
    expected_response = {
        "channel_identifier": str(first_channel_id),
        "partner_address": first_partner_address,
        "token_address": to_checksum_address(token_address),
        "settle_timeout": str(settle_timeout),
        "reveal_timeout": str(reveal_timeout),
        "state": ChannelState.STATE_OPENED.value,
        "balance": str(total_deposit),
        "total_deposit": str(total_deposit),
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
        "channel_identifier": str(second_channel_id),
        "partner_address": second_partner_address,
        "token_address": to_checksum_address(token_address),
        "settle_timeout": str(settle_timeout),
        "reveal_timeout": str(reveal_timeout),
        "state": ChannelState.STATE_OPENED.value,
        "balance": str(total_deposit),
        "total_deposit": str(total_deposit),
        "token_network_address": token_network_address,
    }
    assert check_dict_nested_attrs(json_response, expected_response)

    # finally let's burn all eth and try to open another channel
    burn_eth(api_server_test_instance.rest_api.raiden_api.raiden.rpc_client)
    channel_data_obj = {
        "partner_address": "0xf3AF96F89b3d7CdcBE0C083690A28185Feb0b3CE",
        "token_address": to_checksum_address(token_address),
        "settle_timeout": str(settle_timeout),
        "reveal_timeout": str(reveal_timeout),
    }
    request = grequests.put(
        api_url_for(api_server_test_instance, "channelsresource"), json=channel_data_obj
    )
    response = request.send().response
    assert_proper_response(response, HTTPStatus.PAYMENT_REQUIRED)
    json_response = get_json_response(response)
    assert "The account balance is below the estimated amount" in json_response["errors"]


@raise_on_failure
@pytest.mark.parametrize("number_of_nodes", [1])
@pytest.mark.parametrize("channels_per_node", [0])
@pytest.mark.parametrize("enable_rest_api", [True])
def test_api_channel_open_and_deposit_race(
    api_server_test_instance: APIServer,
    raiden_network: List[RaidenService],
    token_addresses,
    reveal_timeout,
    token_network_registry_address,
    retry_timeout,
):
    """Tests that a race for the same deposit from the API is handled properly

    The proxy's approve_and_set_total_deposit is raising a
    RaidenRecoverableError in case of races. That needs to be properly handled
    and not allowed to bubble out of the greenlet.

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
        "settle_timeout": str(settle_timeout),
        "reveal_timeout": str(reveal_timeout),
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
            "balance": "0",
            "state": ChannelState.STATE_OPENED.value,
            "channel_identifier": "1",
            "total_deposit": "0",
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
        json={"total_deposit": str(deposit_amount)},
    )

    # Spawn two greenlets doing the same deposit request
    greenlets = [gevent.spawn(request.send), gevent.spawn(request.send)]
    gevent.joinall(set(greenlets), raise_error=True)
    # Make sure that both responses are fine
    g1_response = greenlets[0].get().response
    assert_proper_response(g1_response, HTTPStatus.OK)
    json_response = get_json_response(g1_response)
    expected_response.update(
        {"total_deposit": str(deposit_amount), "balance": str(deposit_amount)}
    )
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
            raiden=app0,
            token_network_registry_address=token_network_registry_address,
            token_address=token_address,
            partner_address=to_canonical_address(first_partner_address),
            target_address=app0.address,
            target_balance=deposit_amount,
            retry_timeout=retry_timeout,
        )

    request = grequests.get(api_url_for(api_server_test_instance, "channelsresource"))
    response = request.send().response
    assert_proper_response(response, HTTPStatus.OK)
    json_response = get_json_response(response)
    channel_info = json_response[0]
    assert channel_info["token_address"] == to_checksum_address(token_address)
    assert channel_info["total_deposit"] == str(deposit_amount)


@raise_on_failure
@pytest.mark.parametrize("number_of_nodes", [1])
@pytest.mark.parametrize("channels_per_node", [0])
@pytest.mark.parametrize("enable_rest_api", [True])
def test_api_channel_open_close_and_settle(
    api_server_test_instance: APIServer,
    token_addresses,
    reveal_timeout,
):
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

    balance = 0
    assert_proper_response(response, status_code=HTTPStatus.CREATED)
    channel_identifier = 1
    json_response = get_json_response(response)
    expected_response = channel_data_obj.copy()
    expected_response.update(
        {
            "balance": str(balance),
            "state": ChannelState.STATE_OPENED.value,
            "reveal_timeout": str(reveal_timeout),
            "channel_identifier": str(channel_identifier),
            "total_deposit": "0",
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
        "channel_identifier": str(channel_identifier),
        "partner_address": partner_address,
        "token_address": to_checksum_address(token_address),
        "settle_timeout": str(settle_timeout),
        "reveal_timeout": str(reveal_timeout),
        "state": ChannelState.STATE_CLOSED.value,
        "balance": str(balance),
        "total_deposit": str(balance),
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
        json={"amount": "1"},
    )
    # Payment should not work since channel is closing
    response = request.send().response
    assert_proper_response(response, HTTPStatus.CONFLICT)

    # Try to create channel with the same partner again before previous channel settles
    request = grequests.put(
        api_url_for(api_server_test_instance, "channelsresource"), json=channel_data_obj
    )
    # Channel exists and is currently being settled so API request to open channel should fail
    response = request.send().response
    assert_proper_response(response, HTTPStatus.CONFLICT)


@raise_on_failure
@pytest.mark.parametrize("number_of_nodes", [2])
@pytest.mark.parametrize("channels_per_node", [0])
@pytest.mark.parametrize("enable_rest_api", [True])
def test_api_channel_close_insufficient_eth(
    api_server_test_instance: APIServer, token_addresses, reveal_timeout
):

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

    balance = 0
    assert_proper_response(response, status_code=HTTPStatus.CREATED)
    channel_identifier = 1
    json_response = get_json_response(response)
    expected_response = channel_data_obj.copy()
    expected_response.update(
        {
            "balance": str(balance),
            "state": ChannelState.STATE_OPENED.value,
            "reveal_timeout": str(reveal_timeout),
            "channel_identifier": str(channel_identifier),
            "total_deposit": "0",
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


@raise_on_failure
@pytest.mark.parametrize("number_of_nodes", [1])
@pytest.mark.parametrize("channels_per_node", [0])
@pytest.mark.parametrize("enable_rest_api", [True])
def test_api_channel_open_channel_invalid_input(
    api_server_test_instance: APIServer, token_addresses, reveal_timeout
):
    partner_address = "0x61C808D82A3Ac53231750daDc13c777b59310bD9"
    token_address = token_addresses[0]
    settle_timeout = TEST_SETTLE_TIMEOUT_MIN - 1
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
    assert_response_with_error(response, status_code=HTTPStatus.CONFLICT)

    channel_data_obj["settle_timeout"] = str(TEST_SETTLE_TIMEOUT_MAX + 1)
    request = grequests.put(
        api_url_for(api_server_test_instance, "channelsresource"), json=channel_data_obj
    )
    response = request.send().response
    assert_response_with_error(response, status_code=HTTPStatus.CONFLICT)

    channel_data_obj["settle_timeout"] = str(TEST_SETTLE_TIMEOUT_MAX - 1)
    channel_data_obj["token_address"] = to_checksum_address(factories.make_address())
    request = grequests.put(
        api_url_for(api_server_test_instance, "channelsresource"), json=channel_data_obj
    )
    response = request.send().response
    assert_response_with_error(response, status_code=HTTPStatus.CONFLICT)


@raise_on_failure
@pytest.mark.parametrize("number_of_nodes", [1])
@pytest.mark.parametrize("channels_per_node", [0])
@pytest.mark.parametrize("enable_rest_api", [True])
def test_api_channel_state_change_errors(
    api_server_test_instance: APIServer, token_addresses, reveal_timeout
):
    partner_address = "0x61C808D82A3Ac53231750daDc13c777b59310bD9"
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
        json=dict(state=ChannelState.STATE_CLOSED.value, total_deposit="200"),
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
        json=dict(state=ChannelState.STATE_CLOSED.value, total_withdraw="200"),
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
        json=dict(total_deposit="500", total_withdraw="200"),
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
        json=dict(state=ChannelState.STATE_CLOSED.value, reveal_timeout="50"),
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
        json=dict(total_deposit="500", reveal_timeout="50"),
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
        json=dict(total_withdraw="500", reveal_timeout="50"),
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
        json=dict(total_deposit="500"),
    )
    response = request.send().response
    assert_response_with_error(response, HTTPStatus.CONFLICT)


@raise_on_failure
@pytest.mark.parametrize("number_of_nodes", [2])
@pytest.mark.parametrize("deposit", [1000])
@pytest.mark.parametrize("enable_rest_api", [True])
def test_api_channel_withdraw(
    api_server_test_instance: APIServer,
    raiden_network: List[RaidenService],
    token_addresses,
    pfs_mock,
):
    _, app1 = raiden_network
    pfs_mock.add_apps(raiden_network)

    token_address = token_addresses[0]
    partner_address = app1.address

    # Withdraw a 0 amount
    request = grequests.patch(
        api_url_for(
            api_server_test_instance,
            "channelsresourcebytokenandpartneraddress",
            token_address=token_address,
            partner_address=partner_address,
        ),
        json=dict(total_withdraw="0"),
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
        json=dict(total_withdraw="1500"),
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
        json=dict(total_withdraw="750"),
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
        json=dict(total_withdraw="750"),
    )
    response = request.send().response
    assert_response_with_error(response, HTTPStatus.CONFLICT)


@raise_on_failure
@pytest.mark.parametrize("number_of_nodes", [2])
@pytest.mark.parametrize("deposit", [1000])
@pytest.mark.parametrize("enable_rest_api", [True])
def test_api_channel_withdraw_with_offline_partner(
    api_server_test_instance: APIServer,
    raiden_network: List[RaidenService],
    token_addresses,
):
    app0, app1 = raiden_network
    app0.pfs_proxy.set_services((app0,))  # type: ignore

    token_address = token_addresses[0]
    partner_address = app1.address

    # Withdraw when the partner node is offline
    request = grequests.patch(
        api_url_for(
            api_server_test_instance,
            "channelsresourcebytokenandpartneraddress",
            token_address=token_address,
            partner_address=partner_address,
        ),
        json=dict(total_withdraw="500"),
    )
    response = request.send().response
    assert_response_with_error(response, HTTPStatus.CONFLICT)


@raise_on_failure
@pytest.mark.parametrize("number_of_nodes", [2])
@pytest.mark.parametrize("deposit", [0])
@pytest.mark.parametrize("enable_rest_api", [True])
def test_api_channel_set_reveal_timeout(
    api_server_test_instance: APIServer,
    raiden_network: List[RaidenService],
    token_addresses,
    settle_timeout,
):
    app0, app1 = raiden_network
    token_address = token_addresses[0]
    partner_address = app1.address

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
        views.state_from_raiden(app0), app0.default_registry.address, token_address
    )
    assert token_network_address
    channel_state = views.get_channelstate_by_token_network_and_partner(
        chain_state=views.state_from_raiden(app0),
        token_network_address=token_network_address,
        partner_address=app1.address,
    )
    assert channel_state

    assert channel_state.reveal_timeout == reveal_timeout


@raise_on_failure
@pytest.mark.parametrize("number_of_nodes", [1])
@pytest.mark.parametrize("channels_per_node", [0])
@pytest.mark.parametrize("deposit", [DEPOSIT_FOR_TEST_API_DEPOSIT_LIMIT])
@pytest.mark.parametrize("enable_rest_api", [True])
def test_api_channel_deposit_limit(
    api_server_test_instance,
    proxy_manager,
    token_network_registry_address,
    token_addresses,
    reveal_timeout,
):
    token_address = token_addresses[0]

    registry = proxy_manager.token_network_registry(
        token_network_registry_address, BLOCK_ID_LATEST
    )
    token_network_address = registry.get_token_network(token_address, BLOCK_ID_LATEST)
    token_network = proxy_manager.token_network(token_network_address, BLOCK_ID_LATEST)
    deposit_limit = token_network.channel_participant_deposit_limit(BLOCK_ID_LATEST)

    # let's create a new channel and deposit exactly the limit amount
    first_partner_address = "0x61C808D82A3Ac53231750daDc13c777b59310bD9"
    settle_timeout = 1650
    channel_data_obj = {
        "partner_address": first_partner_address,
        "token_address": to_checksum_address(token_address),
        "settle_timeout": str(settle_timeout),
        "reveal_timeout": str(reveal_timeout),
        "total_deposit": str(deposit_limit),
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
            "balance": str(deposit_limit),
            "state": ChannelState.STATE_OPENED.value,
            "channel_identifier": str(first_channel_identifier),
            "total_deposit": str(deposit_limit),
        }
    )
    assert check_dict_nested_attrs(json_response, expected_response)

    # now let's open a channel and deposit a bit more than the limit
    second_partner_address = "0x29FA6cf0Cce24582a9B20DB94Be4B6E017896038"
    balance_failing = deposit_limit + 1  # token has two digits
    channel_data_obj = {
        "partner_address": second_partner_address,
        "token_address": to_checksum_address(token_address),
        "settle_timeout": str(settle_timeout),
        "reveal_timeout": str(reveal_timeout),
        "total_deposit": str(balance_failing),
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
