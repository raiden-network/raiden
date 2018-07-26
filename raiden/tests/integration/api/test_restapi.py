from http import HTTPStatus

import pytest
import grequests
from flask import url_for
from eth_utils import (
    to_checksum_address,
    to_canonical_address,
    is_checksum_address,
)
from raiden_contracts.constants import (
    CONTRACT_HUMAN_STANDARD_TOKEN,
    MAX_TOKENS_DEPLOY,
    TEST_SETTLE_TIMEOUT_MIN,
    TEST_SETTLE_TIMEOUT_MAX,
)

from raiden.api.v1.encoding import (
    AddressField,
    HexAddressConverter,
)
from raiden.transfer.state import (
    CHANNEL_STATE_OPENED,
    CHANNEL_STATE_CLOSED,
)
from raiden.tests.utils import assert_dicts_are_equal
from raiden.tests.utils.client import burn_all_eth
from raiden.tests.utils.smartcontracts import deploy_contract_web3

# pylint: disable=too-many-locals,unused-argument,too-many-lines


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


def api_url_for(api_backend, endpoint, **kwargs):
    api_server, _ = api_backend
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


def test_url_with_invalid_address(rest_api_port_number, api_backend):
    """ Addresses require the leading 0x in the urls. """

    url_without_prefix = (
        'http://localhost:{port}/api/1/'
        'channels/ea674fdde714fd979de3edf0f56aa9716b898ec8'
    ).format(port=rest_api_port_number)

    request = grequests.patch(
        url_without_prefix,
        json=dict(state='CHANNEL_STATE_SETTLED'),
    )
    response = request.send().response

    assert_response_with_code(response, HTTPStatus.NOT_FOUND)


@pytest.mark.parametrize('number_of_nodes', [1])
@pytest.mark.parametrize('channels_per_node', [0])
def test_payload_with_address_without_prefix(api_backend):
    """ Addresses require leading 0x in the payload. """
    invalid_address = '61c808d82a3ac53231750dadc13c777b59310bd9'
    channel_data_obj = {
        'partner_address': invalid_address,
        'token_address': '0xEA674fdDe714fd979de3EdF0F56AA9716B898ec8',
        'settle_timeout': 10,
    }
    request = grequests.put(
        api_url_for(
            api_backend,
            'channelsresource',
        ),
        json=channel_data_obj,
    )
    response = request.send().response
    assert_response_with_error(response, HTTPStatus.BAD_REQUEST)


@pytest.mark.parametrize('number_of_nodes', [1])
@pytest.mark.parametrize('channels_per_node', [0])
def test_payload_with_address_invalid_chars(api_backend):
    """ Addresses cannot have invalid characters in it. """
    invalid_address = '0x61c808d82a3ac53231750dadc13c777b59310bdg'  # g at the end is invalid
    channel_data_obj = {
        'partner_address': invalid_address,
        'token_address': '0xEA674fdDe714fd979de3EdF0F56AA9716B898ec8',
        'settle_timeout': 10,
    }
    request = grequests.put(
        api_url_for(
            api_backend,
            'channelsresource',
        ),
        json=channel_data_obj,
    )
    response = request.send().response
    assert_response_with_error(response, HTTPStatus.BAD_REQUEST)


@pytest.mark.parametrize('number_of_nodes', [1])
@pytest.mark.parametrize('channels_per_node', [0])
def test_payload_with_address_invalid_length(api_backend):
    """ Encoded addresses must have the right length. """
    invalid_address = '0x61c808d82a3ac53231750dadc13c777b59310b'  # g at the end is invalid
    channel_data_obj = {
        'partner_address': invalid_address,
        'token_address': '0xEA674fdDe714fd979de3EdF0F56AA9716B898ec8',
        'settle_timeout': 10,
    }
    request = grequests.put(
        api_url_for(
            api_backend,
            'channelsresource',
        ),
        json=channel_data_obj,
    )
    response = request.send().response
    assert_response_with_error(response, HTTPStatus.BAD_REQUEST)


@pytest.mark.parametrize('number_of_nodes', [1])
@pytest.mark.parametrize('channels_per_node', [0])
def test_payload_with_address_not_eip55(api_backend):
    """ Provided addresses must be EIP55 encoded. """
    invalid_address = '0xf696209d2ca35e6c88e5b99b7cda3abf316bed69'
    channel_data_obj = {
        'partner_address': invalid_address,
        'token_address': '0xEA674fdDe714fd979de3EdF0F56AA9716B898ec8',
        'settle_timeout': 90,
    }
    request = grequests.put(
        api_url_for(
            api_backend,
            'channelsresource',
        ),
        json=channel_data_obj,
    )
    response = request.send().response
    assert_response_with_error(response, HTTPStatus.BAD_REQUEST)


@pytest.mark.parametrize('number_of_nodes', [1])
@pytest.mark.parametrize('channels_per_node', [0])
def test_api_query_our_address(api_backend):
    request = grequests.get(
        api_url_for(api_backend, 'addressresource'),
    )
    response = request.send().response
    assert_proper_response(response)

    api_server, _ = api_backend
    our_address = api_server.rest_api.raiden_api.address
    assert response.json() == {'our_address': to_checksum_address(our_address)}


@pytest.mark.parametrize('number_of_nodes', [1])
@pytest.mark.parametrize('channels_per_node', [0])
def test_api_get_channel_list(
        api_backend,
        token_addresses,
        reveal_timeout,
):
    partner_address = '0x61C808D82A3Ac53231750daDc13c777b59310bD9'

    request = grequests.get(
        api_url_for(
            api_backend,
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
            api_backend,
            'channelsresource',
        ),
        json=channel_data_obj,
    )
    response = request.send().response

    assert_proper_response(response, HTTPStatus.CREATED)

    request = grequests.get(
        api_url_for(
            api_backend,
            'channelsresource',
        ),
    )
    response = request.send().response
    assert_proper_response(response, HTTPStatus.OK)
    channel_info = response.json()[0]
    assert channel_info['partner_address'] == partner_address
    assert channel_info['token_address'] == to_checksum_address(token_address)
    assert 'token_network_identifier' in channel_info


@pytest.mark.parametrize('number_of_nodes', [1])
@pytest.mark.parametrize('channels_per_node', [0])
def test_api_channel_status_channel_nonexistant(
        api_backend,
        token_addresses,
):
    partner_address = '0x61C808D82A3Ac53231750daDc13c777b59310bD9'
    token_address = token_addresses[0]

    request = grequests.get(
        api_url_for(
            api_backend,
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
        api_backend,
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
            api_backend,
            'channelsresource',
        ),
        json=channel_data_obj,
    )
    response = request.send().response

    assert_proper_response(response, HTTPStatus.CREATED)
    response = response.json()
    expected_response = channel_data_obj
    expected_response['balance'] = 0
    expected_response['state'] = CHANNEL_STATE_OPENED
    expected_response['channel_identifier'] = assert_dicts_are_equal.IGNORE_VALUE
    expected_response['token_network_identifier'] = assert_dicts_are_equal.IGNORE_VALUE
    assert_dicts_are_equal(response, expected_response)

    token_network_identifier = response['token_network_identifier']

    # now let's open a channel and make a deposit too
    second_partner_address = '0x29FA6cf0Cce24582a9B20DB94Be4B6E017896038'
    balance = 100
    channel_data_obj = {
        'partner_address': second_partner_address,
        'token_address': to_checksum_address(token_address),
        'settle_timeout': settle_timeout,
        'reveal_timeout': reveal_timeout,
        'balance': balance,
    }
    request = grequests.put(
        api_url_for(
            api_backend,
            'channelsresource',
        ),
        json=channel_data_obj,
    )
    response = request.send().response

    assert_proper_response(response, HTTPStatus.CREATED)
    response = response.json()
    expected_response = channel_data_obj
    expected_response['balance'] = balance
    expected_response['state'] = CHANNEL_STATE_OPENED
    expected_response['channel_identifier'] = assert_dicts_are_equal.IGNORE_VALUE
    expected_response['token_network_identifier'] = token_network_identifier
    assert_dicts_are_equal(response, expected_response)

    # let's deposit on the first channel
    request = grequests.patch(
        api_url_for(
            api_backend,
            'channelsresourcebytokenandpartneraddress',
            token_address=token_address,
            partner_address=first_partner_address,
        ),
        json={'total_deposit': balance},
    )
    response = request.send().response
    assert_proper_response(response)
    response = response.json()
    expected_response = {
        'channel_identifier': assert_dicts_are_equal.IGNORE_VALUE,
        'partner_address': first_partner_address,
        'token_address': to_checksum_address(token_address),
        'settle_timeout': settle_timeout,
        'reveal_timeout': reveal_timeout,
        'state': CHANNEL_STATE_OPENED,
        'balance': balance,
        'token_network_identifier': token_network_identifier,
    }
    assert_dicts_are_equal(response, expected_response)

    # let's try querying for the second channel
    request = grequests.get(
        api_url_for(
            api_backend,
            'channelsresourcebytokenandpartneraddress',
            token_address=token_address,
            partner_address=second_partner_address,
        ),
    )

    response = request.send().response
    assert_proper_response(response)
    response = response.json()
    expected_response = {
        'channel_identifier': assert_dicts_are_equal.IGNORE_VALUE,
        'partner_address': second_partner_address,
        'token_address': to_checksum_address(token_address),
        'settle_timeout': settle_timeout,
        'reveal_timeout': reveal_timeout,
        'state': CHANNEL_STATE_OPENED,
        'balance': balance,
        'token_network_identifier': token_network_identifier,
    }
    assert_dicts_are_equal(response, expected_response)

    # finally let's burn all eth and try to open another channel
    api_server, _ = api_backend
    burn_all_eth(api_server.rest_api.raiden_api.raiden)
    channel_data_obj = {
        'partner_address': '0xf3AF96F89b3d7CdcBE0C083690A28185Feb0b3CE',
        'token_address': to_checksum_address(token_address),
        'settle_timeout': settle_timeout,
        'reveal_timeout': reveal_timeout,
        'balance': 1,
    }
    request = grequests.put(
        api_url_for(
            api_backend,
            'channelsresource',
        ),
        json=channel_data_obj,
    )
    response = request.send().response
    assert_proper_response(response, HTTPStatus.PAYMENT_REQUIRED)
    response = response.json()
    assert 'Insufficient ETH' in response['errors']


@pytest.mark.parametrize('number_of_nodes', [1])
@pytest.mark.parametrize('channels_per_node', [0])
def test_api_open_close_and_settle_channel(
        api_backend,
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
            api_backend,
            'channelsresource',
        ),
        json=channel_data_obj,
    )
    response = request.send().response

    balance = 0
    assert_proper_response(response, status_code=HTTPStatus.CREATED)
    response = response.json()
    expected_response = channel_data_obj
    expected_response['balance'] = balance
    expected_response['state'] = CHANNEL_STATE_OPENED
    expected_response['reveal_timeout'] = reveal_timeout
    expected_response['channel_identifier'] = assert_dicts_are_equal.IGNORE_VALUE
    expected_response['token_network_identifier'] = assert_dicts_are_equal.IGNORE_VALUE
    assert_dicts_are_equal(response, expected_response)

    token_network_identifier = response['token_network_identifier']

    # let's close the channel
    request = grequests.patch(
        api_url_for(
            api_backend,
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
        'channel_identifier': assert_dicts_are_equal.IGNORE_VALUE,
        'partner_address': partner_address,
        'token_address': to_checksum_address(token_address),
        'settle_timeout': settle_timeout,
        'reveal_timeout': reveal_timeout,
        'state': CHANNEL_STATE_CLOSED,
        'balance': balance,
    }
    assert_dicts_are_equal(response.json(), expected_response)


def test_api_close_insufficient_eth(
        api_backend,
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
            api_backend,
            'channelsresource',
        ),
        json=channel_data_obj,
    )
    response = request.send().response

    balance = 0
    assert_proper_response(response, status_code=HTTPStatus.CREATED)
    response = response.json()
    expected_response = channel_data_obj
    expected_response['balance'] = balance
    expected_response['state'] = CHANNEL_STATE_OPENED
    expected_response['reveal_timeout'] = reveal_timeout
    expected_response['channel_identifier'] = assert_dicts_are_equal.IGNORE_VALUE
    expected_response['token_network_identifier'] = assert_dicts_are_equal.IGNORE_VALUE
    assert_dicts_are_equal(response, expected_response)

    # let's burn all eth and try to close the channel
    api_server, _ = api_backend
    burn_all_eth(api_server.rest_api.raiden_api.raiden)
    request = grequests.patch(
        api_url_for(
            api_backend,
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
        api_backend,
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
            api_backend,
            'channelsresource',
        ),
        json=channel_data_obj,
    )
    response = request.send().response
    assert_response_with_error(response, status_code=HTTPStatus.CONFLICT)

    channel_data_obj['settle_timeout'] = TEST_SETTLE_TIMEOUT_MAX + 1
    request = grequests.put(
        api_url_for(
            api_backend,
            'channelsresource',
        ),
        json=channel_data_obj,
    )
    response = request.send().response
    assert_response_with_error(response, status_code=HTTPStatus.CONFLICT)


@pytest.mark.parametrize('number_of_nodes', [1])
@pytest.mark.parametrize('channels_per_node', [0])
def test_api_channel_state_change_errors(
        api_backend,
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
            api_backend,
            'channelsresource',
        ),
        json=channel_data_obj,
    )
    response = request.send().response
    assert_proper_response(response, HTTPStatus.CREATED)

    # let's try to set a random state
    request = grequests.patch(
        api_url_for(
            api_backend,
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
            api_backend,
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
            api_backend,
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
            api_backend,
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
            api_backend,
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
def test_api_tokens(api_backend, blockchain_services, token_addresses):
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
            api_backend,
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
            api_backend,
            'channelsresource',
        ),
        json=channel_data_obj,
    )
    response = request.send().response
    assert_proper_response(response, HTTPStatus.CREATED)

    # and now let's get the token list
    request = grequests.get(
        api_url_for(
            api_backend,
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
def test_query_partners_by_token(api_backend, blockchain_services, token_addresses):
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
            api_backend,
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
            api_backend,
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
            api_backend,
            'channelsresource',
        ),
        json=channel_data_obj,
    )
    response = request.send().response
    assert_proper_response(response, HTTPStatus.CREATED)

    # and now let's query our partners per token for the first token
    request = grequests.get(
        api_url_for(
            api_backend,
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
            'channel': '/api/1/channels/{}/{}'.format(
                to_checksum_address(token_address),
                to_checksum_address(first_partner_address),
            ),
        }, {
            'partner_address': second_partner_address,
            'channel': '/api/1/channels/{}/{}'.format(
                to_checksum_address(token_address),
                to_checksum_address(second_partner_address),
            ),
        },
    ]
    assert all(r in response for r in expected_response)


@pytest.mark.parametrize('number_of_nodes', [2])
def test_api_transfers(api_backend, raiden_network, token_addresses):
    _, app1 = raiden_network
    amount = 200
    identifier = 42
    token_address = token_addresses[0]
    target_address = app1.raiden.address

    api_server, _ = api_backend
    our_address = api_server.rest_api.raiden_api.address

    transfer = {
        'initiator_address': to_checksum_address(our_address),
        'target_address': to_checksum_address(target_address),
        'token_address': to_checksum_address(token_address),
        'amount': amount,
        'identifier': identifier,
    }

    request = grequests.post(
        api_url_for(
            api_backend,
            'transfertotargetresource',
            token_address=to_checksum_address(token_address),
            target_address=to_checksum_address(target_address),
        ),
        json={'amount': amount, 'identifier': identifier},
    )
    response = request.send().response
    assert_proper_response(response)
    response = response.json()
    assert response == transfer


@pytest.mark.parametrize('number_of_tokens', [0])
@pytest.mark.parametrize('number_of_nodes', [1])
@pytest.mark.parametrize('channels_per_node', [0])
def test_register_token(api_backend, token_amount, token_addresses, raiden_network):
    app0 = raiden_network[0]
    new_token_address = deploy_contract_web3(
        CONTRACT_HUMAN_STANDARD_TOKEN,
        app0.raiden.chain.client,
        num_confirmations=None,
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
        num_confirmations=None,
        constructor_arguments=(
            token_amount,
            2,
            'raiden',
            'Rd',
        ),
    )

    register_request = grequests.put(api_url_for(
        api_backend,
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
        api_backend,
        'registertokenresource',
        token_address=to_checksum_address(new_token_address),
    ))
    conflict_response = conflict_request.send().response
    assert_response_with_error(conflict_response, HTTPStatus.CONFLICT)

    # Burn all the eth and then make sure we get the appropriate API error
    burn_all_eth(app0.raiden)
    poor_request = grequests.put(api_url_for(
        api_backend,
        'registertokenresource',
        token_address=to_checksum_address(other_token_address),
    ))
    poor_response = poor_request.send().response
    assert_response_with_error(poor_response, HTTPStatus.PAYMENT_REQUIRED)


@pytest.mark.parametrize('number_of_nodes', [1])
@pytest.mark.parametrize('channels_per_node', [0])
@pytest.mark.parametrize('number_of_tokens', [2])
def test_get_connection_managers_info(api_backend, token_addresses):
    # check that there are no registered tokens
    request = grequests.get(
        api_url_for(api_backend, 'connectionsinforesource'),
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
            api_backend,
            'connectionsresource',
            token_address=token_address1,
        ),
        json=connect_data_obj,
    )
    response = request.send().response
    assert_no_content_response(response)

    # check that there now is one registered channel manager
    request = grequests.get(
        api_url_for(api_backend, 'connectionsinforesource'),
    )
    response = request.send().response
    result = response.json()
    assert isinstance(result, dict) and len(result.keys()) == 1
    assert token_address1 in result
    assert isinstance(result[token_address1], dict)
    assert set(result[token_address1].keys()) == {'funds', 'sum_deposits', 'channels'}

    funds = 100
    token_address2 = to_checksum_address(token_addresses[1])
    connect_data_obj = {
        'funds': funds,
    }
    request = grequests.put(
        api_url_for(
            api_backend,
            'connectionsresource',
            token_address=token_address2,
        ),
        json=connect_data_obj,
    )
    response = request.send().response
    assert_no_content_response(response)

    # check that there now are two registered channel managers
    request = grequests.get(
        api_url_for(api_backend, 'connectionsinforesource'),
    )
    response = request.send().response
    result = response.json()
    assert isinstance(result, dict) and len(result.keys()) == 2
    assert token_address2 in result
    assert isinstance(result[token_address2], dict)
    assert set(result[token_address2].keys()) == {'funds', 'sum_deposits', 'channels'}


@pytest.mark.parametrize('number_of_nodes', [1])
@pytest.mark.parametrize('channels_per_node', [0])
@pytest.mark.parametrize('number_of_tokens', [2])
def test_connect_insufficient_eth(api_backend, token_addresses):

    # Burn all eth and then try to connect to a token network
    api_server, _ = api_backend
    burn_all_eth(api_server.rest_api.raiden_api.raiden)
    funds = 100
    token_address1 = to_checksum_address(token_addresses[0])
    connect_data_obj = {
        'funds': funds,
    }
    request = grequests.put(
        api_url_for(
            api_backend,
            'connectionsresource',
            token_address=token_address1,
        ),
        json=connect_data_obj,
    )
    response = request.send().response
    assert_proper_response(response, HTTPStatus.PAYMENT_REQUIRED)
    response = response.json()
    assert 'Insufficient ETH' in response['errors']


@pytest.mark.parametrize('number_of_nodes', [1])
@pytest.mark.parametrize('channels_per_node', [0])
def test_network_events(api_backend, token_addresses):
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
            api_backend,
            'channelsresource',
        ),
        json=channel_data_obj,
    )
    response = request.send().response

    assert_proper_response(response, status_code=HTTPStatus.CREATED)

    request = grequests.get(
        api_url_for(
            api_backend,
            'networkeventsresource',
            from_block=0,
        ),
    )
    response = request.send().response
    assert_proper_response(response, status_code=HTTPStatus.OK)
    assert len(response.json()) > 0


@pytest.mark.parametrize('number_of_nodes', [1])
@pytest.mark.parametrize('channels_per_node', [0])
def test_token_events(api_backend, token_addresses):
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
            api_backend,
            'channelsresource',
        ),
        json=channel_data_obj,
    )
    response = request.send().response

    assert_proper_response(response, status_code=HTTPStatus.CREATED)

    request = grequests.get(
        api_url_for(
            api_backend,
            'tokeneventsresource',
            token_address=token_address,
            from_block=0,
        ),
    )
    response = request.send().response
    assert_proper_response(response, status_code=HTTPStatus.OK)
    assert len(response.json()) > 0


@pytest.mark.parametrize('number_of_nodes', [1])
@pytest.mark.parametrize('channels_per_node', [0])
def test_channel_events(api_backend, token_addresses):
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
            api_backend,
            'channelsresource',
        ),
        json=channel_data_obj,
    )
    response = request.send().response

    assert_proper_response(response, status_code=HTTPStatus.CREATED)

    request = grequests.get(
        api_url_for(
            api_backend,
            'channeleventsresource',
            partner_address=partner_address,
            token_address=token_address,
            from_block=0,
        ),
    )
    response = request.send().response
    assert_proper_response(response, status_code=HTTPStatus.OK)
    assert len(response.json()) > 0


@pytest.mark.parametrize('number_of_nodes', [1])
@pytest.mark.parametrize('channels_per_node', [0])
def test_token_events_errors_for_unregistered_token(api_backend):
    request = grequests.get(
        api_url_for(
            api_backend,
            'tokeneventsresource',
            token_address='0x61C808D82A3Ac53231750daDc13c777b59310bD9',
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
        api_backend,
        token_addresses,
        reveal_timeout,
):
    # let's create a new channel and deposit exactly the limit amount
    first_partner_address = '0x61C808D82A3Ac53231750daDc13c777b59310bD9'
    token_address = token_addresses[0]
    settle_timeout = 1650
    balance_working = MAX_TOKENS_DEPLOY * (10 ** 2)  # token has two digits
    channel_data_obj = {
        'partner_address': first_partner_address,
        'token_address': to_checksum_address(token_address),
        'settle_timeout': settle_timeout,
        'reveal_timeout': reveal_timeout,
        'balance': balance_working,
    }

    request = grequests.put(
        api_url_for(
            api_backend,
            'channelsresource',
        ),
        json=channel_data_obj,
    )
    response = request.send().response

    assert_proper_response(response, HTTPStatus.CREATED)
    response = response.json()
    expected_response = channel_data_obj
    expected_response['balance'] = balance_working
    expected_response['state'] = CHANNEL_STATE_OPENED
    expected_response['channel_identifier'] = assert_dicts_are_equal.IGNORE_VALUE
    expected_response['token_network_identifier'] = assert_dicts_are_equal.IGNORE_VALUE
    assert_dicts_are_equal(response, expected_response)

    # now let's open a channel and deposit a bit more than the limit
    second_partner_address = '0x29FA6cf0Cce24582a9B20DB94Be4B6E017896038'
    balance_failing = balance_working + 1  # token has two digits
    channel_data_obj = {
        'partner_address': second_partner_address,
        'token_address': to_checksum_address(token_address),
        'settle_timeout': settle_timeout,
        'reveal_timeout': reveal_timeout,
        'balance': balance_failing,
    }
    request = grequests.put(
        api_url_for(
            api_backend,
            'channelsresource',
        ),
        json=channel_data_obj,
    )
    response = request.send().response

    assert_proper_response(response, HTTPStatus.CONFLICT)
    response = response.json()
    assert response['errors'] == 'The deposit of 10001 is bigger than the current limit of 10000'
