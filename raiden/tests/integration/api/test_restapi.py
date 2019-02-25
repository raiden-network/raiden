import json
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

from raiden.api.v1.encoding import AddressField, HexAddressConverter
from raiden.constants import (
    GENESIS_BLOCK_NUMBER,
    SECRET_HASH_HEXSTRING_LENGTH,
    SECRET_HEXSTRING_LENGTH,
    Environment,
)
from raiden.messages import LockedTransfer, Unlock
from raiden.tests.fixtures.variables import RED_EYES_PER_CHANNEL_PARTICIPANT_LIMIT
from raiden.tests.integration.api.utils import create_api_server
from raiden.tests.utils import factories
from raiden.tests.utils.client import burn_eth
from raiden.tests.utils.events import check_dict_nested_attrs, must_have_event, must_have_events
from raiden.tests.utils.network import CHAIN
from raiden.tests.utils.protocol import HoldRaidenEvent, WaitForMessage
from raiden.tests.utils.smartcontracts import deploy_contract_web3
from raiden.transfer import views
from raiden.transfer.state import CHANNEL_STATE_CLOSED, CHANNEL_STATE_OPENED
from raiden.utils import sha3
from raiden.waiting import wait_for_transfer_success
from raiden_contracts.constants import (
    CONTRACT_HUMAN_STANDARD_TOKEN,
    TEST_SETTLE_TIMEOUT_MAX,
    TEST_SETTLE_TIMEOUT_MIN,
)

# pylint: disable=too-many-locals,unused-argument,too-many-lines


class CustomException(Exception):
    pass


def assert_no_content_response(response):
    assert(
        response is not None and
        response.text == '' and
        response.status_code == HTTPStatus.NO_CONTENT
    )


def assert_response_with_code(response, status_code):
    assert (
        response is not None and
        response.status_code == status_code
    )


def assert_response_with_error(response, status_code):
    assert (
        response is not None and
        response.status_code == status_code and
        'errors' in response.json() and
        response.json()['errors'] != ''
    )


def assert_proper_response(response, status_code=HTTPStatus.OK):
    assert (
        response is not None and
        response.status_code == status_code and
        response.headers['Content-Type'] == 'application/json'
    )


def api_url_for(api_server, endpoint, **kwargs):
    # url_for() expects binary address so we have to convert here
    for key, val in kwargs.items():
        if isinstance(val, str) and val.startswith('0x'):
            kwargs[key] = to_canonical_address(val)
    with api_server.flask_app.app_context():
        return url_for('v1_resources.{}'.format(endpoint), **kwargs)


def test_hex_converter():
    converter = HexAddressConverter(map=None)

    # invalid hex data
    with pytest.raises(Exception):
        converter.to_python('-')

    # invalid address, too short
    with pytest.raises(Exception):
        converter.to_python('0x1234')

    # missing prefix 0x
    with pytest.raises(Exception):
        converter.to_python('414d72a6f6e28f4950117696081450d63d56c354')

    address = b'AMr\xa6\xf6\xe2\x8fIP\x11v\x96\x08\x14P\xd6=V\xc3T'
    assert converter.to_python('0x414D72a6f6E28F4950117696081450d63D56C354') == address


def test_address_field():
    # pylint: disable=protected-access
    field = AddressField()
    attr = 'test'
    data = object()

    # invalid hex data
    with pytest.raises(Exception):
        field._deserialize('-', attr, data)

    # invalid address, too short
    with pytest.raises(Exception):
        field._deserialize('0x1234', attr, data)

    # missing prefix 0x
    with pytest.raises(Exception):
        field._deserialize('414d72a6f6e28f4950117696081450d63d56c354', attr, data)

    address = b'AMr\xa6\xf6\xe2\x8fIP\x11v\x96\x08\x14P\xd6=V\xc3T'
    assert field._deserialize('0x414D72a6f6E28F4950117696081450d63D56C354', attr, data) == address


@pytest.mark.parametrize('number_of_nodes', [1])
@pytest.mark.parametrize('channels_per_node', [0])
def test_payload_with_invalid_addresses(api_server_test_instance, rest_api_port_number):
    """ Addresses require leading 0x in the payload. """
    invalid_address = '61c808d82a3ac53231750dadc13c777b59310bd9'
    channel_data_obj = {
        'partner_address': invalid_address,
        'token_address': '0xEA674fdDe714fd979de3EdF0F56AA9716B898ec8',
        'settle_timeout': 10,
    }
    request = grequests.put(
        api_url_for(
            api_server_test_instance,
            'channelsresource',
        ),
        json=channel_data_obj,
    )
    response = request.send().response
    assert_response_with_error(response, HTTPStatus.BAD_REQUEST)

    url_without_prefix = (
        'http://localhost:{port}/api/v1/'
        'channels/ea674fdde714fd979de3edf0f56aa9716b898ec8'
    ).format(port=rest_api_port_number)

    request = grequests.patch(
        url_without_prefix,
        json=dict(state='CHANNEL_STATE_SETTLED'),
    )
    response = request.send().response

    assert_response_with_code(response, HTTPStatus.NOT_FOUND)


@pytest.mark.xfail(
    strict=True,
    reason='Crashed app also crashes on teardown',
    raises=CustomException,
)
@pytest.mark.parametrize('number_of_nodes', [1])
@pytest.mark.parametrize('channels_per_node', [0])
def test_crash_on_unhandled_exception(api_server_test_instance):
    """ Crash when an unhandled exception happens on APIServer. """

    # as we should not have unhandled exceptions in our endpoints, create one to test
    @api_server_test_instance.flask_app.route('/error_endpoint', methods=['GET'])
    def error_endpoint():  # pylint: disable=unused-variable
        raise CustomException('This is an unhandled error')

    with api_server_test_instance.flask_app.app_context():
        url = url_for('error_endpoint')
    request = grequests.get(url)
    request.send()
    api_server_test_instance.get(timeout=10)


@pytest.mark.parametrize('number_of_nodes', [1])
@pytest.mark.parametrize('channels_per_node', [0])
def test_payload_with_address_invalid_chars(api_server_test_instance):
    """ Addresses cannot have invalid characters in it. """
    invalid_address = '0x61c808d82a3ac53231750dadc13c777b59310bdg'  # g at the end is invalid
    channel_data_obj = {
        'partner_address': invalid_address,
        'token_address': '0xEA674fdDe714fd979de3EdF0F56AA9716B898ec8',
        'settle_timeout': 10,
    }
    request = grequests.put(
        api_url_for(
            api_server_test_instance,
            'channelsresource',
        ),
        json=channel_data_obj,
    )
    response = request.send().response
    assert_response_with_error(response, HTTPStatus.BAD_REQUEST)


@pytest.mark.parametrize('number_of_nodes', [1])
@pytest.mark.parametrize('channels_per_node', [0])
def test_payload_with_address_invalid_length(api_server_test_instance):
    """ Encoded addresses must have the right length. """
    invalid_address = '0x61c808d82a3ac53231750dadc13c777b59310b'  # g at the end is invalid
    channel_data_obj = {
        'partner_address': invalid_address,
        'token_address': '0xEA674fdDe714fd979de3EdF0F56AA9716B898ec8',
        'settle_timeout': 10,
    }
    request = grequests.put(
        api_url_for(
            api_server_test_instance,
            'channelsresource',
        ),
        json=channel_data_obj,
    )
    response = request.send().response
    assert_response_with_error(response, HTTPStatus.BAD_REQUEST)


@pytest.mark.parametrize('number_of_nodes', [1])
@pytest.mark.parametrize('channels_per_node', [0])
def test_payload_with_address_not_eip55(api_server_test_instance):
    """ Provided addresses must be EIP55 encoded. """
    invalid_address = '0xf696209d2ca35e6c88e5b99b7cda3abf316bed69'
    channel_data_obj = {
        'partner_address': invalid_address,
        'token_address': '0xEA674fdDe714fd979de3EdF0F56AA9716B898ec8',
        'settle_timeout': 90,
    }
    request = grequests.put(
        api_url_for(
            api_server_test_instance,
            'channelsresource',
        ),
        json=channel_data_obj,
    )
    response = request.send().response
    assert_response_with_error(response, HTTPStatus.BAD_REQUEST)


@pytest.mark.parametrize('number_of_nodes', [1])
@pytest.mark.parametrize('channels_per_node', [0])
def test_api_query_our_address(api_server_test_instance):
    request = grequests.get(
        api_url_for(api_server_test_instance, 'addressresource'),
    )
    response = request.send().response
    assert_proper_response(response)

    our_address = api_server_test_instance.rest_api.raiden_api.address
    assert response.json() == {'our_address': to_checksum_address(our_address)}


@pytest.mark.parametrize('number_of_nodes', [1])
@pytest.mark.parametrize('channels_per_node', [0])
def test_api_get_channel_list(
        api_server_test_instance,
        token_addresses,
        reveal_timeout,
):
    partner_address = '0x61C808D82A3Ac53231750daDc13c777b59310bD9'

    request = grequests.get(
        api_url_for(
            api_server_test_instance,
            'channelsresource',
        ),
    )
    response = request.send().response
    assert_proper_response(response, HTTPStatus.OK)
    assert response.json() == []

    # let's create a new channel
    token_address = token_addresses[0]
    settle_timeout = 1650
    channel_data_obj = {
        'partner_address': partner_address,
        'token_address': to_checksum_address(token_address),
        'settle_timeout': settle_timeout,
        'reveal_timeout': reveal_timeout,
    }

    request = grequests.put(
        api_url_for(
            api_server_test_instance,
            'channelsresource',
        ),
        json=channel_data_obj,
    )
    response = request.send().response

    assert_proper_response(response, HTTPStatus.CREATED)

    request = grequests.get(
        api_url_for(
            api_server_test_instance,
            'channelsresource',
        ),
    )
    response = request.send().response
    assert_proper_response(response, HTTPStatus.OK)
    channel_info = response.json()[0]
    assert channel_info['partner_address'] == partner_address
    assert channel_info['token_address'] == to_checksum_address(token_address)
    assert channel_info['total_deposit'] == 0
    assert 'token_network_identifier' in channel_info


@pytest.mark.parametrize('number_of_nodes', [1])
@pytest.mark.parametrize('channels_per_node', [0])
def test_api_channel_status_channel_nonexistant(
        api_server_test_instance,
        token_addresses,
):
    partner_address = '0x61C808D82A3Ac53231750daDc13c777b59310bD9'
    token_address = token_addresses[0]

    request = grequests.get(
        api_url_for(
            api_server_test_instance,
            'channelsresourcebytokenandpartneraddress',
            token_address=token_address,
            partner_address=partner_address,
        ),
    )
    response = request.send().response
    assert_proper_response(response, HTTPStatus.NOT_FOUND)
    assert response.json()['errors'] == (
        "Channel with partner '{}' for token '{}' could not be found.".format(
            to_checksum_address(partner_address),
            to_checksum_address(token_address),
        )
    )


@pytest.mark.parametrize('number_of_nodes', [1])
@pytest.mark.parametrize('channels_per_node', [0])
def test_api_open_and_deposit_channel(
        api_server_test_instance,
        token_addresses,
        reveal_timeout,
):
    # let's create a new channel
    first_partner_address = '0x61C808D82A3Ac53231750daDc13c777b59310bD9'
    token_address = token_addresses[0]
    settle_timeout = 1650
    channel_data_obj = {
        'partner_address': first_partner_address,
        'token_address': to_checksum_address(token_address),
        'settle_timeout': settle_timeout,
        'reveal_timeout': reveal_timeout,
    }

    request = grequests.put(
        api_url_for(
            api_server_test_instance,
            'channelsresource',
        ),
        json=channel_data_obj,
    )
    response = request.send().response

    assert_proper_response(response, HTTPStatus.CREATED)
    first_channel_id = 1
    response = response.json()
    expected_response = channel_data_obj.copy()
    expected_response.update({
        'balance': 0,
        'state': CHANNEL_STATE_OPENED,
        'channel_identifier': 1,
        'total_deposit': 0,
    })
    assert check_dict_nested_attrs(response, expected_response)

    token_network_identifier = response['token_network_identifier']

    # now let's open a channel and make a deposit too
    second_partner_address = '0x29FA6cf0Cce24582a9B20DB94Be4B6E017896038'
    total_deposit = 100
    channel_data_obj = {
        'partner_address': second_partner_address,
        'token_address': to_checksum_address(token_address),
        'settle_timeout': settle_timeout,
        'reveal_timeout': reveal_timeout,
        'total_deposit': total_deposit,
    }
    request = grequests.put(
        api_url_for(
            api_server_test_instance,
            'channelsresource',
        ),
        json=channel_data_obj,
    )
    response = request.send().response

    assert_proper_response(response, HTTPStatus.CREATED)
    second_channel_id = 2
    response = response.json()
    expected_response = channel_data_obj.copy()
    expected_response.update({
        'balance': total_deposit,
        'state': CHANNEL_STATE_OPENED,
        'channel_identifier': second_channel_id,
        'token_network_identifier': token_network_identifier,
        'total_deposit': total_deposit,
    })
    assert check_dict_nested_attrs(response, expected_response)

    # assert depositing again with less than the initial deposit returns 409
    request = grequests.patch(
        api_url_for(
            api_server_test_instance,
            'channelsresourcebytokenandpartneraddress',
            token_address=token_address,
            partner_address=second_partner_address,
        ),
        json={'total_deposit': 99},
    )
    response = request.send().response
    assert_proper_response(response, HTTPStatus.CONFLICT)

    # assert depositing negative amount fails
    request = grequests.patch(
        api_url_for(
            api_server_test_instance,
            'channelsresourcebytokenandpartneraddress',
            token_address=token_address,
            partner_address=first_partner_address,
        ),
        json={'total_deposit': -1000},
    )
    response = request.send().response
    assert_proper_response(response, HTTPStatus.CONFLICT)

    # let's deposit on the first channel
    request = grequests.patch(
        api_url_for(
            api_server_test_instance,
            'channelsresourcebytokenandpartneraddress',
            token_address=token_address,
            partner_address=first_partner_address,
        ),
        json={'total_deposit': total_deposit},
    )
    response = request.send().response
    assert_proper_response(response)
    response = response.json()
    expected_response = {
        'channel_identifier': first_channel_id,
        'partner_address': first_partner_address,
        'token_address': to_checksum_address(token_address),
        'settle_timeout': settle_timeout,
        'reveal_timeout': reveal_timeout,
        'state': CHANNEL_STATE_OPENED,
        'balance': total_deposit,
        'total_deposit': total_deposit,
        'token_network_identifier': token_network_identifier,
    }
    assert check_dict_nested_attrs(response, expected_response)

    # let's try querying for the second channel
    request = grequests.get(
        api_url_for(
            api_server_test_instance,
            'channelsresourcebytokenandpartneraddress',
            token_address=token_address,
            partner_address=second_partner_address,
        ),
    )

    response = request.send().response
    assert_proper_response(response)
    response = response.json()
    expected_response = {
        'channel_identifier': second_channel_id,
        'partner_address': second_partner_address,
        'token_address': to_checksum_address(token_address),
        'settle_timeout': settle_timeout,
        'reveal_timeout': reveal_timeout,
        'state': CHANNEL_STATE_OPENED,
        'balance': total_deposit,
        'total_deposit': total_deposit,
        'token_network_identifier': token_network_identifier,
    }
    assert check_dict_nested_attrs(response, expected_response)

    # finally let's burn all eth and try to open another channel
    burn_eth(api_server_test_instance.rest_api.raiden_api.raiden)
    channel_data_obj = {
        'partner_address': '0xf3AF96F89b3d7CdcBE0C083690A28185Feb0b3CE',
        'token_address': to_checksum_address(token_address),
        'settle_timeout': settle_timeout,
        'reveal_timeout': reveal_timeout,
        'balance': 1,
    }
    request = grequests.put(
        api_url_for(
            api_server_test_instance,
            'channelsresource',
        ),
        json=channel_data_obj,
    )
    response = request.send().response
    assert_proper_response(response, HTTPStatus.PAYMENT_REQUIRED)
    response = response.json()
    assert 'The account balance is below the estimated amount' in response['errors']


@pytest.mark.parametrize('number_of_nodes', [1])
@pytest.mark.parametrize('channels_per_node', [0])
def test_api_open_close_and_settle_channel(
        api_server_test_instance,
        token_addresses,
        reveal_timeout,
):
    # let's create a new channel
    partner_address = '0x61C808D82A3Ac53231750daDc13c777b59310bD9'
    token_address = token_addresses[0]
    settle_timeout = 1650
    channel_data_obj = {
        'partner_address': partner_address,
        'token_address': to_checksum_address(token_address),
        'settle_timeout': settle_timeout,
    }
    request = grequests.put(
        api_url_for(
            api_server_test_instance,
            'channelsresource',
        ),
        json=channel_data_obj,
    )
    response = request.send().response

    balance = 0
    assert_proper_response(response, status_code=HTTPStatus.CREATED)
    channel_identifier = 1
    response = response.json()
    expected_response = channel_data_obj.copy()
    expected_response.update({
        'balance': balance,
        'state': CHANNEL_STATE_OPENED,
        'reveal_timeout': reveal_timeout,
        'channel_identifier': channel_identifier,
        'total_deposit': 0,
    })
    assert check_dict_nested_attrs(response, expected_response)

    token_network_identifier = response['token_network_identifier']

    # let's close the channel
    request = grequests.patch(
        api_url_for(
            api_server_test_instance,
            'channelsresourcebytokenandpartneraddress',
            token_address=token_address,
            partner_address=partner_address,
        ),
        json={'state': CHANNEL_STATE_CLOSED},
    )
    response = request.send().response
    assert_proper_response(response)
    expected_response = {
        'token_network_identifier': token_network_identifier,
        'channel_identifier': channel_identifier,
        'partner_address': partner_address,
        'token_address': to_checksum_address(token_address),
        'settle_timeout': settle_timeout,
        'reveal_timeout': reveal_timeout,
        'state': CHANNEL_STATE_CLOSED,
        'balance': balance,
        'total_deposit': balance,
    }
    assert check_dict_nested_attrs(response.json(), expected_response)


@pytest.mark.parametrize('number_of_nodes', [2])
@pytest.mark.parametrize('channels_per_node', [0])
def test_api_close_insufficient_eth(
        api_server_test_instance,
        token_addresses,
        reveal_timeout,
        skip_if_parity,
):
    # FIXME parity version of this test fails:
    # parity reports 'insufficient funds' correctly but raiden does not recognize it.

    # let's create a new channel
    partner_address = '0x61C808D82A3Ac53231750daDc13c777b59310bD9'
    token_address = token_addresses[0]
    settle_timeout = 1650
    channel_data_obj = {
        'partner_address': partner_address,
        'token_address': to_checksum_address(token_address),
        'settle_timeout': settle_timeout,
    }
    request = grequests.put(
        api_url_for(
            api_server_test_instance,
            'channelsresource',
        ),
        json=channel_data_obj,
    )
    response = request.send().response

    balance = 0
    assert_proper_response(response, status_code=HTTPStatus.CREATED)
    channel_identifier = 1
    response = response.json()
    expected_response = channel_data_obj.copy()
    expected_response.update({
        'balance': balance,
        'state': CHANNEL_STATE_OPENED,
        'reveal_timeout': reveal_timeout,
        'channel_identifier': channel_identifier,
        'total_deposit': 0,
    })
    assert check_dict_nested_attrs(response, expected_response)

    # let's burn all eth and try to close the channel
    burn_eth(api_server_test_instance.rest_api.raiden_api.raiden)
    request = grequests.patch(
        api_url_for(
            api_server_test_instance,
            'channelsresourcebytokenandpartneraddress',
            token_address=token_address,
            partner_address=partner_address,
        ),
        json={'state': CHANNEL_STATE_CLOSED},
    )
    response = request.send().response
    assert_proper_response(response, HTTPStatus.PAYMENT_REQUIRED)
    response = response.json()
    assert 'Insufficient ETH' in response['errors']


@pytest.mark.parametrize('number_of_nodes', [1])
@pytest.mark.parametrize('channels_per_node', [0])
def test_api_open_channel_invalid_input(
        api_server_test_instance,
        token_addresses,
        reveal_timeout,
):
    partner_address = '0x61C808D82A3Ac53231750daDc13c777b59310bD9'
    token_address = token_addresses[0]
    settle_timeout = TEST_SETTLE_TIMEOUT_MIN - 1
    channel_data_obj = {
        'partner_address': partner_address,
        'token_address': to_checksum_address(token_address),
        'settle_timeout': settle_timeout,
        'reveal_timeout': reveal_timeout,
    }
    request = grequests.put(
        api_url_for(
            api_server_test_instance,
            'channelsresource',
        ),
        json=channel_data_obj,
    )
    response = request.send().response
    assert_response_with_error(response, status_code=HTTPStatus.CONFLICT)

    channel_data_obj['settle_timeout'] = TEST_SETTLE_TIMEOUT_MAX + 1
    request = grequests.put(
        api_url_for(
            api_server_test_instance,
            'channelsresource',
        ),
        json=channel_data_obj,
    )
    response = request.send().response
    assert_response_with_error(response, status_code=HTTPStatus.CONFLICT)

    channel_data_obj['settle_timeout'] = TEST_SETTLE_TIMEOUT_MAX - 1
    channel_data_obj['token_address'] = to_checksum_address(factories.make_address())
    request = grequests.put(
        api_url_for(
            api_server_test_instance,
            'channelsresource',
        ),
        json=channel_data_obj,
    )
    response = request.send().response
    assert_response_with_error(response, status_code=HTTPStatus.CONFLICT)


@pytest.mark.parametrize('number_of_nodes', [1])
@pytest.mark.parametrize('channels_per_node', [0])
def test_api_channel_state_change_errors(
        api_server_test_instance,
        token_addresses,
        reveal_timeout,
):
    partner_address = '0x61C808D82A3Ac53231750daDc13c777b59310bD9'
    token_address = token_addresses[0]
    settle_timeout = 1650
    channel_data_obj = {
        'partner_address': partner_address,
        'token_address': to_checksum_address(token_address),
        'settle_timeout': settle_timeout,
        'reveal_timeout': reveal_timeout,
    }
    request = grequests.put(
        api_url_for(
            api_server_test_instance,
            'channelsresource',
        ),
        json=channel_data_obj,
    )
    response = request.send().response
    assert_proper_response(response, HTTPStatus.CREATED)

    # let's try to set a random state
    request = grequests.patch(
        api_url_for(
            api_server_test_instance,
            'channelsresourcebytokenandpartneraddress',
            token_address=token_address,
            partner_address=partner_address,
        ),
        json=dict(state='inlimbo'),
    )
    response = request.send().response
    assert_response_with_error(response, HTTPStatus.BAD_REQUEST)
    # let's try to set both new state and balance
    request = grequests.patch(
        api_url_for(
            api_server_test_instance,
            'channelsresourcebytokenandpartneraddress',
            token_address=token_address,
            partner_address=partner_address,
        ),
        json=dict(state=CHANNEL_STATE_CLOSED, total_deposit=200),
    )
    response = request.send().response
    assert_response_with_error(response, HTTPStatus.CONFLICT)
    # let's try to patch with no arguments
    request = grequests.patch(
        api_url_for(
            api_server_test_instance,
            'channelsresourcebytokenandpartneraddress',
            token_address=token_address,
            partner_address=partner_address,
        ),
    )
    response = request.send().response
    assert_response_with_error(response, HTTPStatus.BAD_REQUEST)

    # ok now let's close and settle for real
    request = grequests.patch(
        api_url_for(
            api_server_test_instance,
            'channelsresourcebytokenandpartneraddress',
            token_address=token_address,
            partner_address=partner_address,
        ),
        json=dict(state=CHANNEL_STATE_CLOSED),
    )
    response = request.send().response
    assert_proper_response(response)

    # let's try to deposit to a settled channel
    request = grequests.patch(
        api_url_for(
            api_server_test_instance,
            'channelsresourcebytokenandpartneraddress',
            token_address=token_address,
            partner_address=partner_address,
        ),
        json=dict(total_deposit=500),
    )
    response = request.send().response
    assert_response_with_error(response, HTTPStatus.CONFLICT)


@pytest.mark.parametrize('number_of_nodes', [1])
@pytest.mark.parametrize('channels_per_node', [0])
@pytest.mark.parametrize('number_of_tokens', [2])
@pytest.mark.parametrize('environment_type', [Environment.DEVELOPMENT])
def test_api_tokens(api_server_test_instance, blockchain_services, token_addresses):
    partner_address = '0x61C808D82A3Ac53231750daDc13c777b59310bD9'
    token_address1 = token_addresses[0]
    token_address2 = token_addresses[1]
    settle_timeout = 1650

    channel_data_obj = {
        'partner_address': partner_address,
        'token_address': to_checksum_address(token_address1),
        'settle_timeout': settle_timeout,
    }
    request = grequests.put(
        api_url_for(
            api_server_test_instance,
            'channelsresource',
        ),
        json=channel_data_obj,
    )
    response = request.send().response
    assert_proper_response(response, HTTPStatus.CREATED)

    partner_address = '0x61C808D82A3Ac53231750daDc13c777b59310bD9'
    settle_timeout = 1650
    channel_data_obj = {
        'partner_address': partner_address,
        'token_address': to_checksum_address(token_address2),
        'settle_timeout': settle_timeout,
    }
    request = grequests.put(
        api_url_for(
            api_server_test_instance,
            'channelsresource',
        ),
        json=channel_data_obj,
    )
    response = request.send().response
    assert_proper_response(response, HTTPStatus.CREATED)

    # and now let's get the token list
    request = grequests.get(
        api_url_for(
            api_server_test_instance,
            'tokensresource',
        ),
    )
    response = request.send().response
    assert_proper_response(response)
    response = response.json()
    expected_response = [
        to_checksum_address(token_address1),
        to_checksum_address(token_address2),
    ]
    assert set(response) == set(expected_response)


@pytest.mark.parametrize('number_of_nodes', [1])
@pytest.mark.parametrize('channels_per_node', [0])
def test_query_partners_by_token(api_server_test_instance, blockchain_services, token_addresses):
    first_partner_address = '0x61C808D82A3Ac53231750daDc13c777b59310bD9'
    second_partner_address = '0x29FA6cf0Cce24582a9B20DB94Be4B6E017896038'
    token_address = token_addresses[0]
    settle_timeout = 1650
    channel_data_obj = {
        'partner_address': first_partner_address,
        'token_address': to_checksum_address(token_address),
        'settle_timeout': settle_timeout,
    }
    request = grequests.put(
        api_url_for(
            api_server_test_instance,
            'channelsresource',
        ),
        json=channel_data_obj,
    )
    response = request.send().response
    assert_proper_response(response, HTTPStatus.CREATED)
    response = response.json()

    channel_data_obj['partner_address'] = second_partner_address
    request = grequests.put(
        api_url_for(
            api_server_test_instance,
            'channelsresource',
        ),
        json=channel_data_obj,
    )
    response = request.send().response
    assert_proper_response(response, HTTPStatus.CREATED)
    response = response.json()

    # and a channel for another token
    channel_data_obj['partner_address'] = '0xb07937AbA15304FBBB0Bf6454a9377a76E3dD39E'
    channel_data_obj['token_address'] = to_checksum_address(token_address)
    request = grequests.put(
        api_url_for(
            api_server_test_instance,
            'channelsresource',
        ),
        json=channel_data_obj,
    )
    response = request.send().response
    assert_proper_response(response, HTTPStatus.CREATED)

    # and now let's query our partners per token for the first token
    request = grequests.get(
        api_url_for(
            api_server_test_instance,
            'partnersresourcebytokenaddress',
            token_address=to_checksum_address(token_address),
        ),
    )
    response = request.send().response
    assert_proper_response(response)
    response = response.json()
    expected_response = [
        {
            'partner_address': first_partner_address,
            'channel': '/api/v1/channels/{}/{}'.format(
                to_checksum_address(token_address),
                to_checksum_address(first_partner_address),
            ),
        }, {
            'partner_address': second_partner_address,
            'channel': '/api/v1/channels/{}/{}'.format(
                to_checksum_address(token_address),
                to_checksum_address(second_partner_address),
            ),
        },
    ]
    assert all(r in response for r in expected_response)


@pytest.mark.parametrize('number_of_nodes', [2])
def test_api_payments_target_error(api_server_test_instance, raiden_network, token_addresses):
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
            'token_target_paymentresource',
            token_address=to_checksum_address(token_address),
            target_address=to_checksum_address(target_address),
        ),
        json={'amount': amount, 'identifier': identifier},
    )
    response = request.send().response
    assert_proper_response(response, status_code=HTTPStatus.CONFLICT)
    app1.start()


@pytest.mark.parametrize('number_of_nodes', [2])
def test_api_payments(api_server_test_instance, raiden_network, token_addresses):
    _, app1 = raiden_network
    amount = 200
    identifier = 42
    token_address = token_addresses[0]
    target_address = app1.raiden.address

    our_address = api_server_test_instance.rest_api.raiden_api.address

    payment = {
        'initiator_address': to_checksum_address(our_address),
        'target_address': to_checksum_address(target_address),
        'token_address': to_checksum_address(token_address),
        'amount': amount,
        'identifier': identifier,
    }

    request = grequests.post(
        api_url_for(
            api_server_test_instance,
            'token_target_paymentresource',
            token_address=to_checksum_address(token_address),
            target_address=to_checksum_address(target_address),
        ),
        json={'amount': amount, 'identifier': identifier},
    )
    response = request.send().response
    assert_proper_response(response)
    response = response.json()
    assert_payment_secret_and_hash(response, payment)


@pytest.mark.parametrize('number_of_nodes', [2])
def test_api_payments_secret_hash_errors(
        api_server_test_instance,
        raiden_network,
        token_addresses,
):
    _, app1 = raiden_network
    amount = 200
    identifier = 42
    token_address = token_addresses[0]
    target_address = app1.raiden.address
    secret = '0x78c8d676e2f2399aa2a015f3433a2083c55003591a0f3f3349b6e50fc9ca44f1'
    secret_hash = to_hex(sha3(to_bytes(hexstr=secret)))
    bad_secret = 'Not Hex String. 0x78c8d676e2f2399aa2a015f3433a2083c55003591a0f3f33'
    bad_secret_hash = 'Not Hex String. 0x78c8d676e2f2399aa2a015f3433a2083c55003591a0f3f33'
    short_secret = '0x123'
    short_secret_hash = 'Short secret hash'

    request = grequests.post(
        api_url_for(
            api_server_test_instance,
            'token_target_paymentresource',
            token_address=to_checksum_address(token_address),
            target_address=to_checksum_address(target_address),
        ),
        json={
            'amount': amount,
            'identifier': identifier,
            'secret': short_secret,
        },
    )
    response = request.send().response
    assert_proper_response(response, status_code=HTTPStatus.CONFLICT)

    request = grequests.post(
        api_url_for(
            api_server_test_instance,
            'token_target_paymentresource',
            token_address=to_checksum_address(token_address),
            target_address=to_checksum_address(target_address),
        ),
        json={
            'amount': amount,
            'identifier': identifier,
            'secret': bad_secret,
        },
    )
    response = request.send().response
    assert_proper_response(response, status_code=HTTPStatus.CONFLICT)

    request = grequests.post(
        api_url_for(
            api_server_test_instance,
            'token_target_paymentresource',
            token_address=to_checksum_address(token_address),
            target_address=to_checksum_address(target_address),
        ),
        json={
            'amount': amount,
            'identifier': identifier,
            'secret_hash': short_secret_hash,
        },
    )
    response = request.send().response
    assert_proper_response(response, status_code=HTTPStatus.CONFLICT)

    request = grequests.post(
        api_url_for(
            api_server_test_instance,
            'token_target_paymentresource',
            token_address=to_checksum_address(token_address),
            target_address=to_checksum_address(target_address),
        ),
        json={
            'amount': amount,
            'identifier': identifier,
            'secret_hash': bad_secret_hash,
        },
    )
    response = request.send().response
    assert_proper_response(response, status_code=HTTPStatus.CONFLICT)

    request = grequests.post(
        api_url_for(
            api_server_test_instance,
            'token_target_paymentresource',
            token_address=to_checksum_address(token_address),
            target_address=to_checksum_address(target_address),
        ),
        json={
            'amount': amount,
            'identifier': identifier,
            'secret_hash': secret_hash,
        },
    )
    response = request.send().response
    assert_proper_response(response, status_code=HTTPStatus.CONFLICT)

    request = grequests.post(
        api_url_for(
            api_server_test_instance,
            'token_target_paymentresource',
            token_address=to_checksum_address(token_address),
            target_address=to_checksum_address(target_address),
        ),
        json={
            'amount': amount,
            'identifier': identifier,
            'secret': secret,
            'secret_hash': secret,
        },
    )
    response = request.send().response
    assert_proper_response(response, status_code=HTTPStatus.CONFLICT)


@pytest.mark.parametrize('number_of_nodes', [2])
def test_api_payments_with_secret_no_hash(
        api_server_test_instance,
        raiden_network,
        token_addresses,
):
    _, app1 = raiden_network
    amount = 200
    identifier = 42
    token_address = token_addresses[0]
    target_address = app1.raiden.address
    secret = '0x78c8d676e2f2399aa2a015f3433a2083c55003591a0f3f3349b6e50fc9ca44f1'

    our_address = api_server_test_instance.rest_api.raiden_api.address

    payment = {
        'initiator_address': to_checksum_address(our_address),
        'target_address': to_checksum_address(target_address),
        'token_address': to_checksum_address(token_address),
        'amount': amount,
        'identifier': identifier,
    }

    request = grequests.post(
        api_url_for(
            api_server_test_instance,
            'token_target_paymentresource',
            token_address=to_checksum_address(token_address),
            target_address=to_checksum_address(target_address),
        ),
        json={
            'amount': amount,
            'identifier': identifier,
            'secret': secret,
        },
    )
    response = request.send().response
    assert_proper_response(response)
    response = response.json()
    assert_payment_secret_and_hash(response, payment)
    assert secret == response['secret']


@pytest.mark.parametrize('number_of_nodes', [2])
def test_api_payments_with_secret_and_hash(
        api_server_test_instance,
        raiden_network,
        token_addresses,
):
    _, app1 = raiden_network
    amount = 200
    identifier = 42
    token_address = token_addresses[0]
    target_address = app1.raiden.address
    secret = '0x78c8d676e2f2399aa2a015f3433a2083c55003591a0f3f3349b6e50fc9ca44f1'
    secret_hash = to_hex(sha3(to_bytes(hexstr=secret)))

    our_address = api_server_test_instance.rest_api.raiden_api.address

    payment = {
        'initiator_address': to_checksum_address(our_address),
        'target_address': to_checksum_address(target_address),
        'token_address': to_checksum_address(token_address),
        'amount': amount,
        'identifier': identifier,
    }

    request = grequests.post(
        api_url_for(
            api_server_test_instance,
            'token_target_paymentresource',
            token_address=to_checksum_address(token_address),
            target_address=to_checksum_address(target_address),
        ),
        json={
            'amount': amount,
            'identifier': identifier,
            'secret': secret,
            'secret_hash': secret_hash,
        },
    )
    response = request.send().response
    assert_proper_response(response)
    response = response.json()
    assert_payment_secret_and_hash(response, payment)
    assert secret == response['secret']
    assert secret_hash == response['secret_hash']


def assert_payment_secret_and_hash(response, payment):
    # make sure that payment key/values are part of the response.
    assert response.items() >= payment.items()
    assert 'secret' in response
    assert 'secret_hash' in response
    assert len(response['secret']) == SECRET_HEXSTRING_LENGTH
    assert len(response['secret_hash']) == SECRET_HASH_HEXSTRING_LENGTH

    generated_secret_hash = to_hex(sha3(to_bytes(hexstr=response['secret'])))
    assert generated_secret_hash == response['secret_hash']


def assert_payment_conflict(responses):
    assert all(response is not None for response in responses)
    assert any(
        response.status_code == HTTPStatus.CONFLICT and
        response.json()['errors'] == 'Another payment with the same id is in flight'
        for response in responses
    )


@pytest.mark.parametrize('number_of_nodes', [2])
def test_api_payments_conflicts(api_server_test_instance, raiden_network, token_addresses):
    _, app1 = raiden_network
    token_address = token_addresses[0]
    target_address = app1.raiden.address

    payment_url = api_url_for(
        api_server_test_instance,
        'token_target_paymentresource',
        token_address=to_checksum_address(token_address),
        target_address=to_checksum_address(target_address),
    )

    # two different transfers (different amounts) with same identifier at the same time:
    # payment conflict
    responses = grequests.map([
        grequests.post(payment_url, json={'amount': 10, 'identifier': 11}),
        grequests.post(payment_url, json={'amount': 11, 'identifier': 11}),
    ])
    assert_payment_conflict(responses)

    # same request sent twice, e. g. when it is retried: no conflict
    responses = grequests.map([
        grequests.post(payment_url, json={'amount': 10, 'identifier': 73}),
        grequests.post(payment_url, json={'amount': 10, 'identifier': 73}),
    ])
    assert all(response.status_code == HTTPStatus.OK for response in responses)


@pytest.mark.parametrize('number_of_tokens', [0])
@pytest.mark.parametrize('number_of_nodes', [1])
@pytest.mark.parametrize('channels_per_node', [0])
@pytest.mark.parametrize('environment_type', [Environment.PRODUCTION])
def test_register_token_mainnet(
        api_server_test_instance,
        token_amount,
        token_addresses,
        raiden_network,
        contract_manager,
):
    app0 = raiden_network[0]
    new_token_address = deploy_contract_web3(
        CONTRACT_HUMAN_STANDARD_TOKEN,
        app0.raiden.chain.client,
        contract_manager=contract_manager,
        constructor_arguments=(
            token_amount,
            2,
            'raiden',
            'Rd',
        ),
    )
    register_request = grequests.put(api_url_for(
        api_server_test_instance,
        'registertokenresource',
        token_address=to_checksum_address(new_token_address),
    ))
    response = register_request.send().response
    assert(
        response is not None and
        response.status_code == HTTPStatus.NOT_IMPLEMENTED
    )


@pytest.mark.parametrize('number_of_tokens', [0])
@pytest.mark.parametrize('number_of_nodes', [1])
@pytest.mark.parametrize('channels_per_node', [0])
@pytest.mark.parametrize('environment_type', [Environment.DEVELOPMENT])
def test_register_token(
        api_server_test_instance,
        token_amount,
        token_addresses,
        raiden_network,
        contract_manager,
        skip_if_parity,
):
    app0 = raiden_network[0]
    new_token_address = deploy_contract_web3(
        CONTRACT_HUMAN_STANDARD_TOKEN,
        app0.raiden.chain.client,
        contract_manager=contract_manager,
        constructor_arguments=(
            token_amount,
            2,
            'raiden',
            'Rd',
        ),
    )
    other_token_address = deploy_contract_web3(
        CONTRACT_HUMAN_STANDARD_TOKEN,
        app0.raiden.chain.client,
        contract_manager=contract_manager,
        constructor_arguments=(
            token_amount,
            2,
            'raiden',
            'Rd',
        ),
    )

    register_request = grequests.put(api_url_for(
        api_server_test_instance,
        'registertokenresource',
        token_address=to_checksum_address(new_token_address),
    ))
    register_response = register_request.send().response
    assert_proper_response(register_response, status_code=HTTPStatus.CREATED)
    response_json = register_response.json()
    assert 'token_network_address' in response_json
    assert is_checksum_address(response_json['token_network_address'])

    # now try to reregister it and get the error
    conflict_request = grequests.put(api_url_for(
        api_server_test_instance,
        'registertokenresource',
        token_address=to_checksum_address(new_token_address),
    ))
    conflict_response = conflict_request.send().response
    assert_response_with_error(conflict_response, HTTPStatus.CONFLICT)

    # Burn all the eth and then make sure we get the appropriate API error
    burn_eth(app0.raiden)
    poor_request = grequests.put(api_url_for(
        api_server_test_instance,
        'registertokenresource',
        token_address=to_checksum_address(other_token_address),
    ))
    poor_response = poor_request.send().response
    assert_response_with_error(poor_response, HTTPStatus.PAYMENT_REQUIRED)


@pytest.mark.parametrize('number_of_tokens', [0])
@pytest.mark.parametrize('number_of_nodes', [1])
@pytest.mark.parametrize('channels_per_node', [0])
@pytest.mark.parametrize('environment_type', [Environment.DEVELOPMENT])
def test_get_token_network_for_token(
        api_server_test_instance,
        token_amount,
        token_addresses,
        raiden_network,
        contract_manager,
        skip_if_parity,
):
    app0 = raiden_network[0]

    new_token_address = deploy_contract_web3(
        CONTRACT_HUMAN_STANDARD_TOKEN,
        app0.raiden.chain.client,
        contract_manager=contract_manager,
        constructor_arguments=(
            token_amount,
            2,
            'raiden',
            'Rd',
        ),
    )

    # unregistered token returns 404
    token_request = grequests.get(api_url_for(
        api_server_test_instance,
        'registertokenresource',
        token_address=to_checksum_address(new_token_address),
    ))
    token_response = token_request.send().response
    assert_proper_response(token_response, status_code=HTTPStatus.NOT_FOUND)

    # register token
    register_request = grequests.put(api_url_for(
        api_server_test_instance,
        'registertokenresource',
        token_address=to_checksum_address(new_token_address),
    ))
    register_response = register_request.send().response
    assert_proper_response(register_response, status_code=HTTPStatus.CREATED)
    token_network_address = register_response.json()['token_network_address']

    gevent.sleep(app0.raiden.alarm.sleep_time * 10)

    # now it should return the token address
    token_request = grequests.get(api_url_for(
        api_server_test_instance,
        'registertokenresource',
        token_address=to_checksum_address(new_token_address),
    ))
    token_response = token_request.send().response
    assert_proper_response(token_response, status_code=HTTPStatus.OK)
    assert token_network_address == token_response.json()


@pytest.mark.parametrize('number_of_nodes', [1])
@pytest.mark.parametrize('channels_per_node', [0])
@pytest.mark.parametrize('number_of_tokens', [1])
# For non-red eyes mainnet code set number_of_tokens to 2 and uncomment the code
# at the end of this test
def test_get_connection_managers_info(api_server_test_instance, token_addresses):
    # check that there are no registered tokens
    request = grequests.get(
        api_url_for(api_server_test_instance, 'connectionsinforesource'),
    )
    response = request.send().response
    result = response.json()
    assert len(result) == 0

    funds = 100
    token_address1 = to_checksum_address(token_addresses[0])
    connect_data_obj = {
        'funds': funds,
    }
    request = grequests.put(
        api_url_for(
            api_server_test_instance,
            'connectionsresource',
            token_address=token_address1,
        ),
        json=connect_data_obj,
    )
    response = request.send().response
    assert_no_content_response(response)

    # check that there now is one registered channel manager
    request = grequests.get(
        api_url_for(api_server_test_instance, 'connectionsinforesource'),
    )
    response = request.send().response
    result = response.json()
    assert isinstance(result, dict) and len(result.keys()) == 1
    assert token_address1 in result
    assert isinstance(result[token_address1], dict)
    assert set(result[token_address1].keys()) == {'funds', 'sum_deposits', 'channels'}

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


@pytest.mark.parametrize('number_of_nodes', [1])
@pytest.mark.parametrize('channels_per_node', [0])
@pytest.mark.parametrize('number_of_tokens', [1])
def test_connect_insufficient_reserve(api_server_test_instance, token_addresses):

    # Burn all eth and then try to connect to a token network
    burn_eth(api_server_test_instance.rest_api.raiden_api.raiden)
    funds = 100
    token_address1 = to_checksum_address(token_addresses[0])
    connect_data_obj = {
        'funds': funds,
    }
    request = grequests.put(
        api_url_for(
            api_server_test_instance,
            'connectionsresource',
            token_address=token_address1,
        ),
        json=connect_data_obj,
    )
    response = request.send().response
    assert_proper_response(response, HTTPStatus.PAYMENT_REQUIRED)
    response = response.json()
    assert 'The account balance is below the estimated amount' in response['errors']


@pytest.mark.parametrize('number_of_nodes', [1])
@pytest.mark.parametrize('channels_per_node', [0])
def test_network_events(api_server_test_instance, token_addresses):
    # let's create a new channel
    partner_address = '0x61C808D82A3Ac53231750daDc13c777b59310bD9'
    token_address = token_addresses[0]
    settle_timeout = 1650
    channel_data_obj = {
        'partner_address': partner_address,
        'token_address': to_checksum_address(token_address),
        'settle_timeout': settle_timeout,
    }
    request = grequests.put(
        api_url_for(
            api_server_test_instance,
            'channelsresource',
        ),
        json=channel_data_obj,
    )
    response = request.send().response

    assert_proper_response(response, status_code=HTTPStatus.CREATED)

    request = grequests.get(
        api_url_for(
            api_server_test_instance,
            'blockchaineventsnetworkresource',
            from_block=GENESIS_BLOCK_NUMBER,
        ),
    )
    response = request.send().response
    assert_proper_response(response, status_code=HTTPStatus.OK)
    assert len(response.json()) > 0


@pytest.mark.parametrize('number_of_nodes', [1])
@pytest.mark.parametrize('channels_per_node', [0])
def test_token_events(api_server_test_instance, token_addresses):
    # let's create a new channel
    partner_address = '0x61C808D82A3Ac53231750daDc13c777b59310bD9'
    token_address = token_addresses[0]
    settle_timeout = 1650
    channel_data_obj = {
        'partner_address': partner_address,
        'token_address': to_checksum_address(token_address),
        'settle_timeout': settle_timeout,
    }
    request = grequests.put(
        api_url_for(
            api_server_test_instance,
            'channelsresource',
        ),
        json=channel_data_obj,
    )
    response = request.send().response

    assert_proper_response(response, status_code=HTTPStatus.CREATED)

    request = grequests.get(
        api_url_for(
            api_server_test_instance,
            'blockchaineventstokenresource',
            token_address=token_address,
            from_block=GENESIS_BLOCK_NUMBER,
        ),
    )
    response = request.send().response
    assert_proper_response(response, status_code=HTTPStatus.OK)
    assert len(response.json()) > 0


@pytest.mark.parametrize('number_of_nodes', [1])
@pytest.mark.parametrize('channels_per_node', [0])
def test_channel_events(api_server_test_instance, token_addresses):
    # let's create a new channel
    partner_address = '0x61C808D82A3Ac53231750daDc13c777b59310bD9'
    token_address = token_addresses[0]
    settle_timeout = 1650
    channel_data_obj = {
        'partner_address': partner_address,
        'token_address': to_checksum_address(token_address),
        'settle_timeout': settle_timeout,
    }
    request = grequests.put(
        api_url_for(
            api_server_test_instance,
            'channelsresource',
        ),
        json=channel_data_obj,
    )
    response = request.send().response

    assert_proper_response(response, status_code=HTTPStatus.CREATED)

    request = grequests.get(
        api_url_for(
            api_server_test_instance,
            'tokenchanneleventsresourceblockchain',
            partner_address=partner_address,
            token_address=token_address,
            from_block=GENESIS_BLOCK_NUMBER,
        ),
    )
    response = request.send().response
    assert_proper_response(response, status_code=HTTPStatus.OK)
    assert len(response.json()) > 0


@pytest.mark.parametrize('number_of_nodes', [1])
@pytest.mark.parametrize('channels_per_node', [0])
def test_token_events_errors_for_unregistered_token(api_server_test_instance):
    request = grequests.get(
        api_url_for(
            api_server_test_instance,
            'tokenchanneleventsresourceblockchain',
            token_address='0x61C808D82A3Ac53231750daDc13c777b59310bD9',
            from_block=5,
            to_block=20,
        ),
    )
    response = request.send().response
    assert_response_with_error(response, status_code=HTTPStatus.NOT_FOUND)

    request = grequests.get(
        api_url_for(
            api_server_test_instance,
            'channelblockchaineventsresource',
            token_address='0x61C808D82A3Ac53231750daDc13c777b59310bD9',
            partner_address='0x61C808D82A3Ac53231750daDc13c777b59313bD9',
            from_block=5,
            to_block=20,
        ),
    )
    response = request.send().response
    assert_response_with_error(response, status_code=HTTPStatus.NOT_FOUND)


@pytest.mark.parametrize('number_of_nodes', [1])
@pytest.mark.parametrize('channels_per_node', [0])
@pytest.mark.parametrize('deposit', [50000])
def test_api_deposit_limit(
        api_server_test_instance,
        token_addresses,
        reveal_timeout,
):
    # let's create a new channel and deposit exactly the limit amount
    first_partner_address = '0x61C808D82A3Ac53231750daDc13c777b59310bD9'
    token_address = token_addresses[0]
    settle_timeout = 1650
    balance_working = RED_EYES_PER_CHANNEL_PARTICIPANT_LIMIT
    channel_data_obj = {
        'partner_address': first_partner_address,
        'token_address': to_checksum_address(token_address),
        'settle_timeout': settle_timeout,
        'reveal_timeout': reveal_timeout,
        'total_deposit': balance_working,
    }

    request = grequests.put(
        api_url_for(
            api_server_test_instance,
            'channelsresource',
        ),
        json=channel_data_obj,
    )
    response = request.send().response

    assert_proper_response(response, HTTPStatus.CREATED)
    first_channel_identifier = 1
    response = response.json()
    expected_response = channel_data_obj.copy()
    expected_response.update({
        'balance': balance_working,
        'state': CHANNEL_STATE_OPENED,
        'channel_identifier': first_channel_identifier,
        'total_deposit': balance_working,
    })
    assert check_dict_nested_attrs(response, expected_response)

    # now let's open a channel and deposit a bit more than the limit
    second_partner_address = '0x29FA6cf0Cce24582a9B20DB94Be4B6E017896038'
    balance_failing = balance_working + 1  # token has two digits
    channel_data_obj = {
        'partner_address': second_partner_address,
        'token_address': to_checksum_address(token_address),
        'settle_timeout': settle_timeout,
        'reveal_timeout': reveal_timeout,
        'total_deposit': balance_failing,
    }
    request = grequests.put(
        api_url_for(
            api_server_test_instance,
            'channelsresource',
        ),
        json=channel_data_obj,
    )
    response = request.send().response

    assert_proper_response(response, HTTPStatus.CONFLICT)
    response = response.json()
    assert (
        response['errors'] ==
        'The deposit of 75000000000000001 is bigger than the current limit of 75000000000000000'
    )


@pytest.mark.parametrize('number_of_nodes', [3])
def test_payment_events_endpoints(api_server_test_instance, raiden_network, token_addresses):
    app0, app1, app2 = raiden_network
    amount1 = 200
    identifier1 = 42
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
            'token_target_paymentresource',
            token_address=to_checksum_address(token_address),
            target_address=to_checksum_address(target1_address),
        ),
        json={'amount': amount1, 'identifier': identifier1},
    )
    request.send()

    # app0 is sending some tokens to target 2
    identifier2 = 43
    amount2 = 123
    request = grequests.post(
        api_url_for(
            api_server_test_instance,
            'token_target_paymentresource',
            token_address=to_checksum_address(token_address),
            target_address=to_checksum_address(target2_address),
        ),
        json={'amount': amount2, 'identifier': identifier2},
    )
    request.send()

    # target1 also sends some tokens to target 2
    identifier3 = 44
    amount3 = 5
    request = grequests.post(
        api_url_for(
            app1_server,
            'token_target_paymentresource',
            token_address=to_checksum_address(token_address),
            target_address=to_checksum_address(target2_address),
        ),
        json={'amount': amount3, 'identifier': identifier3},
    )
    request.send()

    exception = ValueError('Waiting for transfer received success in the WAL timed out')
    with gevent.Timeout(seconds=60, exception=exception):
        wait_for_transfer_success(
            app1.raiden,
            identifier1,
            amount1,
            app1.raiden.alarm.sleep_time,
        )
        wait_for_transfer_success(
            app2.raiden,
            identifier2,
            amount2,
            app2.raiden.alarm.sleep_time,
        )
        wait_for_transfer_success(
            app2.raiden,
            identifier3,
            amount3,
            app2.raiden.alarm.sleep_time,
        )

    # test endpoint without (partner and token) for sender
    request = grequests.get(
        api_url_for(
            api_server_test_instance,
            'paymentresource',
        ),
    )
    response = request.send().response
    assert_proper_response(response, HTTPStatus.OK)
    response = response.json()
    assert must_have_event(
        response,
        {
            'event': 'EventPaymentSentSuccess',
            'identifier': identifier1,
            'target': to_checksum_address(target1_address),
        },
    )
    assert must_have_event(
        response,
        {
            'event': 'EventPaymentSentSuccess',
            'identifier': identifier2,
            'target': to_checksum_address(target2_address),
        },
    )

    # test endpoint without (partner and token) for target1
    request = grequests.get(
        api_url_for(
            app1_server,
            'paymentresource',
        ),
    )
    response = request.send().response
    assert_proper_response(response, HTTPStatus.OK)
    response = response.json()
    assert must_have_event(
        response,
        {
            'event': 'EventPaymentReceivedSuccess',
            'identifier': identifier1,
        },
    )
    assert must_have_event(
        response,
        {
            'event': 'EventPaymentSentSuccess',
            'identifier': identifier3,
        },
    )
    # test endpoint without (partner and token) for target2
    request = grequests.get(
        api_url_for(
            app2_server,
            'paymentresource',
        ),
    )
    response = request.send().response
    assert_proper_response(response, HTTPStatus.OK)
    response = response.json()
    assert must_have_event(
        response,
        {
            'event': 'EventPaymentReceivedSuccess',
            'identifier': identifier2,
        },
    )
    assert must_have_event(
        response,
        {
            'event': 'EventPaymentReceivedSuccess',
            'identifier': identifier3,
        },
    )

    # test endpoint without partner for app0
    request = grequests.get(
        api_url_for(
            api_server_test_instance,
            'token_paymentresource',
            token_address=token_address,
        ),
    )
    response = request.send().response
    assert_proper_response(response, HTTPStatus.OK)
    response = response.json()
    assert must_have_event(
        response,
        {
            'event': 'EventPaymentSentSuccess',
            'identifier': identifier1,
            'target': to_checksum_address(target1_address),
        },
    )
    assert must_have_event(
        response,
        {
            'event': 'EventPaymentSentSuccess',
            'identifier': identifier2,
            'target': to_checksum_address(target2_address),
        },
    )
    # test endpoint without partner for target1
    request = grequests.get(
        api_url_for(
            app1_server,
            'token_paymentresource',
            token_address=token_address,
        ),
    )
    response = request.send().response
    assert_proper_response(response, HTTPStatus.OK)
    response = response.json()
    assert must_have_events(
        response,
        {
            'event': 'EventPaymentReceivedSuccess',
            'identifier': identifier1,
        }, {
            'event': 'EventPaymentSentSuccess',
            'identifier': identifier3,
            'target': to_checksum_address(target2_address),
        },
    )
    # test endpoint without partner for target2
    request = grequests.get(
        api_url_for(
            app2_server,
            'token_paymentresource',
            token_address=token_address,
        ),
    )
    response = request.send().response
    assert_proper_response(response, HTTPStatus.OK)
    response = response.json()
    assert must_have_events(
        response,
        {
            'event': 'EventPaymentReceivedSuccess',
            'identifier': identifier2,
        }, {
            'event': 'EventPaymentReceivedSuccess',
            'identifier': identifier3,
        },
    )

    # test endpoint for token and partner for app0
    request = grequests.get(
        api_url_for(
            api_server_test_instance,
            'token_target_paymentresource',
            token_address=token_address,
            target_address=target1_address,
        ),
    )
    response = request.send().response
    assert_proper_response(response, HTTPStatus.OK)
    response = response.json()
    assert must_have_event(
        response,
        {
            'event': 'EventPaymentSentSuccess',
            'identifier': identifier1,
            'target': to_checksum_address(target1_address),
        },
    )
    assert not must_have_event(
        response,
        {
            'event': 'EventPaymentSentSuccess',
            'identifier': identifier2,
            'target': to_checksum_address(target2_address),
        },
    )
    # test endpoint for token and partner for target1. Check both partners
    # to see that filtering works correctly
    request = grequests.get(
        api_url_for(
            app1_server,
            'token_target_paymentresource',
            token_address=token_address,
            target_address=target2_address,
        ),
    )
    response = request.send().response
    assert_proper_response(response, HTTPStatus.OK)
    response = response.json()
    assert must_have_event(
        response,
        {
            'event': 'EventPaymentSentSuccess',
            'identifier': identifier3,
            'target': to_checksum_address(target2_address),
        },
    )
    assert not must_have_event(
        response,
        {
            'event': 'EventPaymentReceivedSuccess',
            'identifier': identifier1,
        },
    )
    request = grequests.get(
        api_url_for(
            app1_server,
            'token_target_paymentresource',
            token_address=token_address,
            target_address=target1_address,
        ),
    )
    response = request.send().response
    assert_proper_response(response, HTTPStatus.OK)
    response = response.json()
    assert len(response) == 0
    # test endpoint for token and partner for target2
    request = grequests.get(
        api_url_for(
            app2_server,
            'token_target_paymentresource',
            token_address=token_address,
            target_address=app0_address,
        ),
    )
    response = request.send().response
    assert_proper_response(response, HTTPStatus.OK)
    response = response.json()
    assert must_have_events(
        response,
        {
            'event': 'EventPaymentReceivedSuccess',
            'identifier': identifier2,
        },
    )
    assert not must_have_event(
        response,
        {
            'event': 'EventPaymentReceivedSuccess',
            'identifier': identifier1,
        },
    )
    assert not must_have_event(
        response,
        {
            'event': 'EventPaymentReceivedSuccess',
            'identifier': identifier3,
        },
    )
    request = grequests.get(
        api_url_for(
            app2_server,
            'token_target_paymentresource',
            token_address=token_address,
            target_address=target1_address,
        ),
    )
    response = request.send().response
    assert_proper_response(response, HTTPStatus.OK)
    response = response.json()
    assert must_have_events(
        response,
        {
            'event': 'EventPaymentReceivedSuccess',
            'identifier': identifier3,
        },
    )
    assert not must_have_event(
        response,
        {
            'event': 'EventPaymentReceivedSuccess',
            'identifier': identifier2,
        },
    )
    assert not must_have_event(
        response,
        {
            'event': 'EventPaymentReceivedSuccess',
            'identifier': identifier1,
        },
    )

    app1_server.stop()
    app2_server.stop()


@pytest.mark.parametrize('number_of_nodes', [2])
def test_channel_events_raiden(api_server_test_instance, raiden_network, token_addresses):
    _, app1 = raiden_network
    amount = 200
    identifier = 42
    token_address = token_addresses[0]
    target_address = app1.raiden.address

    request = grequests.post(
        api_url_for(
            api_server_test_instance,
            'token_target_paymentresource',
            token_address=to_checksum_address(token_address),
            target_address=to_checksum_address(target_address),
        ),
        json={'amount': amount, 'identifier': identifier},
    )
    response = request.send().response
    assert_proper_response(response)


@pytest.mark.parametrize('number_of_nodes', [3])
@pytest.mark.parametrize('channels_per_node', [CHAIN])
def test_pending_transfers_endpoint(raiden_network, token_addresses):
    initiator, mediator, target = raiden_network
    amount = 200
    identifier = 42

    token_address = token_addresses[0]
    token_network_id = views.get_token_network_identifier_by_token_address(
        views.state_from_app(mediator),
        mediator.raiden.default_registry.address,
        token_address,
    )

    initiator_server = create_api_server(initiator, 8575)
    mediator_server = create_api_server(mediator, 8576)
    target_server = create_api_server(target, 8577)

    target.raiden.raiden_event_handler = target_hold = HoldRaidenEvent()
    target.raiden.message_handler = target_wait = WaitForMessage()
    mediator.raiden.message_handler = mediator_wait = WaitForMessage()

    secret = factories.make_secret()
    secrethash = sha3(secret)

    request = grequests.get(api_url_for(
        mediator_server,
        'pending_transfers_resource_by_token',
        token_address=token_address,
    ))
    response = request.send().response
    assert response.status_code == 200 and response.content == b'[]'

    target_hold.hold_secretrequest_for(secrethash=secrethash)

    initiator.raiden.start_mediated_transfer_with_secret(
        token_network_identifier=token_network_id,
        amount=amount,
        target=target.raiden.address,
        identifier=identifier,
        secret=secret,
    )

    transfer_arrived = target_wait.wait_for_message(LockedTransfer, {'payment_identifier': 42})
    transfer_arrived.wait()

    for server in (initiator_server, mediator_server, target_server):
        request = grequests.get(api_url_for(server, 'pending_transfers_resource'))
        response = request.send().response
        assert response.status_code == 200
        content = json.loads(response.content)
        assert len(content) == 1
        assert content[0]['payment_identifier'] == str(identifier)
        assert content[0]['locked_amount'] == str(amount)
        assert content[0]['token_address'] == to_checksum_address(token_address)
        assert content[0]['token_network_identifier'] == to_checksum_address(token_network_id)

    mediator_unlock = mediator_wait.wait_for_message(Unlock, {})
    target_unlock = target_wait.wait_for_message(Unlock, {})
    target_hold.release_secretrequest_for(target.raiden, secrethash)
    gevent.wait((mediator_unlock, target_unlock))

    for server in (initiator_server, mediator_server, target_server):
        request = grequests.get(api_url_for(server, 'pending_transfers_resource'))
        response = request.send().response
        assert response.status_code == 200 and response.content == b'[]'

    request = grequests.get(api_url_for(
        initiator_server,
        'pending_transfers_resource_by_token',
        token_address=to_hex(b'notaregisteredtokenn'),
    ))
    response = request.send().response
    assert response.status_code == 404 and b'Token' in response.content

    request = grequests.get(api_url_for(
        target_server,
        'pending_transfers_resource_by_token_and_partner',
        token_address=token_address,
        partner_address=to_hex(b'~nonexistingchannel~'),
    ))
    response = request.send().response
    assert response.status_code == 404 and b'Channel' in response.content
