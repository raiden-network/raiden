from http import HTTPStatus

import pytest
import grequests
from flask import url_for
from eth_utils import to_checksum_address, to_canonical_address

from raiden.api.v1.encoding import (
    AddressField,
    HexAddressConverter,
)
from raiden.constants import NETTINGCHANNEL_SETTLE_TIMEOUT_MIN, NETTINGCHANNEL_SETTLE_TIMEOUT_MAX
from raiden.transfer.state import (
    CHANNEL_STATE_OPENED,
    CHANNEL_STATE_CLOSED,
)
from raiden.utils import get_contract_path

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


def test_api_query_our_address(api_backend):
    request = grequests.get(
        api_url_for(api_backend, 'addressresource'),
    )
    response = request.send().response
    assert_proper_response(response)

    api_server, _ = api_backend
    our_address = api_server.rest_api.raiden_api.address
    assert response.json() == {'our_address': to_checksum_address(our_address)}


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
    # can't know the channel address beforehand but make sure we get one
    assert 'channel_address' in response
    first_channel_address = response['channel_address']
    expected_response['channel_address'] = response['channel_address']
    assert response == expected_response

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
    # can't know the channel address beforehand but make sure we get one
    assert 'channel_address' in response
    expected_response['channel_address'] = response['channel_address']
    second_channel_address = response['channel_address']
    assert response == expected_response

    # let's deposit on the first channel
    request = grequests.patch(
        api_url_for(
            api_backend,
            'channelsresourcebychanneladdress',
            channel_address=first_channel_address,
        ),
        json={'total_deposit': balance},
    )
    response = request.send().response
    assert_proper_response(response)
    response = response.json()
    expected_response = {
        'channel_address': first_channel_address,
        'partner_address': first_partner_address,
        'token_address': to_checksum_address(token_address),
        'settle_timeout': settle_timeout,
        'reveal_timeout': reveal_timeout,
        'state': CHANNEL_STATE_OPENED,
        'balance': balance,
    }
    assert response == expected_response

    # finally let's try querying for the second channel
    request = grequests.get(
        api_url_for(
            api_backend,
            'channelsresourcebychanneladdress',
            channel_address=second_channel_address,
        ),
    )

    response = request.send().response
    assert_proper_response(response)
    response = response.json()
    expected_response = {
        'channel_address': second_channel_address,
        'partner_address': second_partner_address,
        'token_address': to_checksum_address(token_address),
        'settle_timeout': settle_timeout,
        'reveal_timeout': reveal_timeout,
        'state': CHANNEL_STATE_OPENED,
        'balance': balance,
    }
    assert response == expected_response


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
    # can't know the channel address beforehand but make sure we get one
    assert 'channel_address' in response
    channel_address = response['channel_address']
    expected_response['channel_address'] = response['channel_address']
    assert response == expected_response

    # let's close the channel
    request = grequests.patch(
        api_url_for(
            api_backend,
            'channelsresourcebychanneladdress',
            channel_address=channel_address,
        ),
        json={'state': CHANNEL_STATE_CLOSED},
    )
    response = request.send().response
    assert_proper_response(response)
    expected_response = {
        'channel_address': channel_address,
        'partner_address': partner_address,
        'token_address': to_checksum_address(token_address),
        'settle_timeout': settle_timeout,
        'reveal_timeout': reveal_timeout,
        'state': CHANNEL_STATE_CLOSED,
        'balance': balance,
    }
    assert response.json() == expected_response


def test_api_open_channel_invalid_input(
        api_backend,
        token_addresses,
        reveal_timeout,
):
    partner_address = '0x61C808D82A3Ac53231750daDc13c777b59310bD9'
    token_address = token_addresses[0]
    settle_timeout = NETTINGCHANNEL_SETTLE_TIMEOUT_MIN - 1
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

    channel_data_obj['settle_timeout'] = NETTINGCHANNEL_SETTLE_TIMEOUT_MAX + 1
    request = grequests.put(
        api_url_for(
            api_backend,
            'channelsresource',
        ),
        json=channel_data_obj,
    )
    response = request.send().response
    assert_response_with_error(response, status_code=HTTPStatus.CONFLICT)


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
    response = response.json()
    channel_address = response['channel_address']

    # let's try to set a random state
    request = grequests.patch(
        api_url_for(
            api_backend,
            'channelsresourcebychanneladdress',
            channel_address=channel_address,
        ),
        json=dict(state='inlimbo'),
    )
    response = request.send().response
    assert_response_with_error(response, HTTPStatus.BAD_REQUEST)
    # let's try to set both new state and balance
    request = grequests.patch(
        api_url_for(
            api_backend,
            'channelsresourcebychanneladdress',
            channel_address=channel_address,
        ),
        json=dict(state=CHANNEL_STATE_CLOSED, total_deposit=200),
    )
    response = request.send().response
    assert_response_with_error(response, HTTPStatus.CONFLICT)
    # let's try to patch with no arguments
    request = grequests.patch(
        api_url_for(
            api_backend,
            'channelsresourcebychanneladdress',
            channel_address=channel_address,
        ),
    )
    response = request.send().response
    assert_response_with_error(response, HTTPStatus.BAD_REQUEST)

    # ok now let's close and settle for real
    request = grequests.patch(
        api_url_for(
            api_backend,
            'channelsresourcebychanneladdress',
            channel_address=channel_address,
        ),
        json=dict(state=CHANNEL_STATE_CLOSED),
    )
    response = request.send().response
    assert_proper_response(response)

    # let's try to deposit to a settled channel
    request = grequests.patch(
        api_url_for(
            api_backend,
            'channelsresourcebychanneladdress',
            channel_address=channel_address,
        ),
        json=dict(total_deposit=500),
    )
    response = request.send().response
    assert_response_with_error(response, HTTPStatus.CONFLICT)


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
    first_channel_address = response['channel_address']

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
    second_channel_address = response['channel_address']

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
            'channel': '/api/1/channels/{}'.format(
                first_channel_address,
            ),
        }, {
            'partner_address': second_partner_address,
            'channel': '/api/1/channels/{}'.format(
                second_channel_address,
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
    new_token_address = app0.raiden.chain.deploy_contract(
        contract_name='HumanStandardToken',
        contract_path=get_contract_path('HumanStandardToken.sol'),
        constructor_parameters=(token_amount, 'raiden', 2, 'Rd'),
    )

    register_request = grequests.put(api_url_for(
        api_backend,
        'registertokenresource',
        token_address=to_checksum_address(new_token_address),
    ))
    register_response = register_request.send().response
    assert_proper_response(register_response, status_code=HTTPStatus.CREATED)
    assert 'channel_manager_address' in register_response.json()

    # now try to reregister it and get the error
    conflict_request = grequests.put(api_url_for(
        api_backend,
        'registertokenresource',
        token_address=to_checksum_address(new_token_address),
    ))
    conflict_response = conflict_request.send().response
    assert_response_with_error(conflict_response, HTTPStatus.CONFLICT)


@pytest.mark.parametrize('channels_per_node', [0])
@pytest.mark.parametrize('number_of_tokens', [2])
def test_get_connection_managers_info(raiden_network, api_backend, token_addresses):
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
