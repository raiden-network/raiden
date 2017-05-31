# -*- coding: utf-8 -*-
import httplib
import json

import pytest
import grequests
from flask import url_for
from pyethapp.jsonrpc import address_encoder, address_decoder

from raiden.api.v1.encoding import (
    AddressField,
    HexAddressConverter,
)
from raiden.utils import channel_to_api_dict
from raiden.tests.utils.transfer import channel
from raiden.transfer.state import (
    CHANNEL_STATE_OPENED,
    CHANNEL_STATE_CLOSED,
    CHANNEL_STATE_SETTLED,
)
from raiden.settings import (
    DEFAULT_JOINABLE_FUNDS_TARGET,
    DEFAULT_INITIAL_CHANNEL_TARGET,
)


def assert_proper_response(response):
    """ Make sure the API response is of the proper type"""
    assert (
        response and
        response.status_code == httplib.OK and
        response.headers['Content-Type'] == 'application/json'
    )


def api_url_for(api_backend, endpoint, **kwargs):
    api_server, _ = api_backend
    # url_for() expects binary address so we have to convert here
    for key, val in kwargs.iteritems():
        if isinstance(val, basestring) and val.startswith('0x'):
            kwargs[key] = address_decoder(val)
    with api_server.flask_app.app_context():
        return url_for('v1_resources.{}'.format(endpoint), **kwargs)


def test_hex_converter():
    converter = HexAddressConverter(map=None)

    # invalid hex data
    with pytest.raises(Exception):
        converter.to_python('-')

    # invalid address, too short
    with pytest.raises(Exception):
        converter.to_python('1234')

    # missing prefix 0x
    with pytest.raises(Exception):
        converter.to_python('414d72a6f6e28f4950117696081450d63d56c354')

    address = b'AMr\xa6\xf6\xe2\x8fIP\x11v\x96\x08\x14P\xd6=V\xc3T'
    assert converter.to_python('0x414d72a6f6e28f4950117696081450d63d56c354') == address


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
        field._deserialize('1234', attr, data)

    # missing prefix 0x
    with pytest.raises(Exception):
        field._deserialize('414d72a6f6e28f4950117696081450d63d56c354', attr, data)

    address = b'AMr\xa6\xf6\xe2\x8fIP\x11v\x96\x08\x14P\xd6=V\xc3T'
    assert field._deserialize('0x414d72a6f6e28f4950117696081450d63d56c354', attr, data) == address


@pytest.mark.parametrize('blockchain_type', ['geth'])
@pytest.mark.parametrize('number_of_nodes', [2])
def test_channel_to_api_dict(raiden_network, token_addresses, settle_timeout):
    app0, app1 = raiden_network  # pylint: disable=unbalanced-tuple-unpacking
    channel0 = channel(app0, app1, token_addresses[0])

    netting_address = channel0.external_state.netting_channel.address
    netting_channel = app0.raiden.chain.netting_channel(netting_address)

    result = channel_to_api_dict(channel0)
    expected_result = {
        'channel_address': netting_channel.address,
        'token_address': channel0.token_address,
        'partner_address': app1.raiden.address,
        'settle_timeout': settle_timeout,
        'balance': channel0.contract_balance,
        'state': CHANNEL_STATE_OPENED
    }
    assert result == expected_result


def test_url_with_invalid_address(rest_api_port_number, api_backend):
    """ Addresses require the leading 0x in the urls. """

    url_without_prefix = (
        'http://localhost:{port}/api/1/'
        'channels/ea674fdde714fd979de3edf0f56aa9716b898ec8'
    ).format(port=rest_api_port_number)

    request = grequests.patch(
        url_without_prefix,
        json={'state': CHANNEL_STATE_SETTLED}
    )
    response = request.send().response

    assert response.status_code == httplib.NOT_FOUND


def test_payload_with_address_without_prefix(api_backend):
    """ Addresses require leading 0x in the payload. """
    invalid_address = '61c808d82a3ac53231750dadc13c777b59310bd9'
    channel_data_obj = {
        'partner_address': invalid_address,
        'token_address': '0xea674fdde714fd979de3edf0f56aa9716b898ec8',
        'settle_timeout': 10,
    }
    request = grequests.put(
        api_url_for(api_backend, 'channelsresource'),
        json=channel_data_obj
    )
    response = request.send().response
    assert response.status_code == httplib.BAD_REQUEST


def test_payload_with_address_invalid_chars(api_backend):
    """ Addresses cannot have invalid characters in it. """
    invalid_address = '0x61c808d82a3ac53231750dadc13c777b59310bdg'  # g at the end is invalid
    channel_data_obj = {
        'partner_address': invalid_address,
        'token_address': '0xea674fdde714fd979de3edf0f56aa9716b898ec8',
        'settle_timeout': 10,
    }
    request = grequests.put(
        api_url_for(api_backend, 'channelsresource'),
        json=channel_data_obj
    )
    response = request.send().response
    assert response.status_code == httplib.BAD_REQUEST


def test_payload_with_address_invalid_length(api_backend):
    """ Encoded addresses must have the right length. """
    invalid_address = '0x61c808d82a3ac53231750dadc13c777b59310b'  # g at the end is invalid
    channel_data_obj = {
        'partner_address': invalid_address,
        'token_address': '0xea674fdde714fd979de3edf0f56aa9716b898ec8',
        'settle_timeout': 10,
    }
    request = grequests.put(
        api_url_for(api_backend, 'channelsresource'),
        json=channel_data_obj
    )
    response = request.send().response
    assert response.status_code == httplib.BAD_REQUEST


def test_api_query_channels(
        api_backend,
        api_test_context,
        api_raiden_service):

    request = grequests.get(
        api_url_for(api_backend, 'channelsresource')
    )
    response = request.send().response
    assert_proper_response(response)
    assert response.json() == api_test_context.expect_channels()

    api_test_context.make_channel_and_add()
    response = request.send().response
    assert_proper_response(response)
    assert response.json() == api_test_context.expect_channels()


def test_api_open_and_deposit_channel(
        api_backend,
        api_test_context,
        api_raiden_service):
    # let's create a new channel
    first_partner_address = '0x61c808d82a3ac53231750dadc13c777b59310bd9'
    token_address = '0xea674fdde714fd979de3edf0f56aa9716b898ec8'
    settle_timeout = 1650
    channel_data_obj = {
        'partner_address': first_partner_address,
        'token_address': token_address,
        'settle_timeout': settle_timeout
    }
    request = grequests.put(
        api_url_for(api_backend, 'channelsresource'),
        json=channel_data_obj
    )
    response = request.send().response

    assert_proper_response(response)
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
    second_partner_address = '0x29fa6cf0cce24582a9b20db94be4b6e017896038'
    balance = 100
    channel_data_obj = {
        'partner_address': second_partner_address,
        'token_address': token_address,
        'settle_timeout': settle_timeout,
        'balance': balance
    }
    request = grequests.put(
        api_url_for(api_backend, 'channelsresource'),
        json=channel_data_obj
    )
    response = request.send().response

    assert_proper_response(response)
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
            channel_address=first_channel_address
        ),
        json={'balance': balance}
    )
    response = request.send().response
    assert_proper_response(response)
    response = response.json()
    expected_response = {
        'channel_address': first_channel_address,
        'partner_address': first_partner_address,
        'token_address': token_address,
        'settle_timeout': settle_timeout,
        'state': CHANNEL_STATE_OPENED,
        'balance': balance
    }
    assert response == expected_response

    # finally let's try querying for the second channel
    request = grequests.get(
        api_url_for(
            api_backend,
            'channelsresourcebychanneladdress',
            channel_address=second_channel_address
        )
    )

    response = request.send().response
    assert_proper_response(response)
    response = response.json()
    expected_response = {
        'channel_address': second_channel_address,
        'partner_address': second_partner_address,
        'token_address': token_address,
        'settle_timeout': settle_timeout,
        'state': CHANNEL_STATE_OPENED,
        'balance': balance
    }
    assert response == expected_response


def test_api_open_close_and_settle_channel(
        api_backend,
        api_test_context,
        api_raiden_service):
    # let's create a new channel
    partner_address = '0x61c808d82a3ac53231750dadc13c777b59310bd9'
    token_address = '0xea674fdde714fd979de3edf0f56aa9716b898ec8'
    settle_timeout = 1650
    channel_data_obj = {
        'partner_address': partner_address,
        'token_address': token_address,
        'settle_timeout': settle_timeout
    }
    request = grequests.put(
        api_url_for(api_backend, 'channelsresource'),
        json=channel_data_obj
    )
    response = request.send().response

    balance = 0
    assert_proper_response(response)
    response = response.json()
    expected_response = channel_data_obj
    expected_response['balance'] = balance
    expected_response['state'] = CHANNEL_STATE_OPENED
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
            channel_address=channel_address
        ),
        json={'state': CHANNEL_STATE_CLOSED}
    )
    response = request.send().response
    assert_proper_response(response)
    expected_response = {
        'channel_address': channel_address,
        'partner_address': partner_address,
        'token_address': token_address,
        'settle_timeout': settle_timeout,
        'state': CHANNEL_STATE_CLOSED,
        'balance': balance
    }
    assert response.json() == expected_response

    # let's settle the channel
    request = grequests.patch(
        api_url_for(
            api_backend,
            'channelsresourcebychanneladdress',
            channel_address=channel_address
        ),
        json={'state': CHANNEL_STATE_SETTLED}
    )
    response = request.send().response
    assert_proper_response(response)
    expected_response = {
        'channel_address': channel_address,
        'partner_address': partner_address,
        'token_address': token_address,
        'settle_timeout': settle_timeout,
        'state': CHANNEL_STATE_SETTLED,
        'balance': balance
    }
    assert response.json() == expected_response


def test_api_channel_state_change_errors(
        api_backend,
        api_test_context,
        api_raiden_service):
    # let's create a new channel
    partner_address = '0x61c808d82a3ac53231750dadc13c777b59310bd9'
    token_address = '0xea674fdde714fd979de3edf0f56aa9716b898ec8'
    settle_timeout = 1650
    channel_data_obj = {
        'partner_address': partner_address,
        'token_address': token_address,
        'settle_timeout': settle_timeout
    }
    request = grequests.put(
        api_url_for(api_backend, 'channelsresource'),
        json=channel_data_obj
    )
    response = request.send().response
    assert_proper_response(response)
    response = response.json()
    channel_address = response['channel_address']

    # let's try to settle the channel (we are bad!)
    request = grequests.patch(
        api_url_for(
            api_backend,
            'channelsresourcebychanneladdress',
            channel_address=channel_address
        ),
        json={'state': CHANNEL_STATE_SETTLED}
    )
    response = request.send().response
    assert response is not None and response.status_code == httplib.CONFLICT
    # let's try to set a random state
    request = grequests.patch(
        api_url_for(
            api_backend,
            'channelsresourcebychanneladdress',
            channel_address=channel_address
        ),
        json={'state': 'inlimbo'}
    )
    response = request.send().response
    assert response is not None and response.status_code == httplib.BAD_REQUEST
    # let's try to set both new state and balance
    request = grequests.patch(
        api_url_for(
            api_backend,
            'channelsresourcebychanneladdress',
            channel_address=channel_address
        ),
        json={'state': CHANNEL_STATE_CLOSED, 'balance': 200}
    )
    response = request.send().response
    assert response is not None and response.status_code == httplib.CONFLICT
    # let's try to path with no arguments
    request = grequests.patch(
        api_url_for(
            api_backend,
            'channelsresourcebychanneladdress',
            channel_address=channel_address
        ),
    )
    response = request.send().response
    assert response is not None and response.status_code == httplib.BAD_REQUEST

    # ok now let's close and settle for real
    request = grequests.patch(
        api_url_for(
            api_backend,
            'channelsresourcebychanneladdress',
            channel_address=channel_address
        ),
        json={'state': CHANNEL_STATE_CLOSED}
    )
    response = request.send().response
    assert_proper_response(response)
    request = grequests.patch(
        api_url_for(
            api_backend,
            'channelsresourcebychanneladdress',
            channel_address=channel_address
        ),
        json={'state': CHANNEL_STATE_SETTLED}
    )
    response = request.send().response
    assert_proper_response(response)

    # let's try to deposit to a settled channel
    request = grequests.patch(
        api_url_for(
            api_backend,
            'channelsresourcebychanneladdress',
            channel_address=channel_address
        ),
        json={'balance': 500}
    )
    response = request.send().response
    assert response is not None and response.status_code == httplib.CONFLICT

    # and now let's try to settle again
    request = grequests.patch(
        api_url_for(
            api_backend,
            'channelsresourcebychanneladdress',
            channel_address=channel_address
        ),
        json={'state': CHANNEL_STATE_SETTLED}
    )
    response = request.send().response
    assert response is not None and response.status_code == httplib.CONFLICT


def test_api_tokens(
        api_backend,
        api_test_context,
        api_raiden_service):
    # let's create 2 new channels for 2 different tokens
    partner_address = '0x61c808d82a3ac53231750dadc13c777b59310bd9'
    token_address = '0xea674fdde714fd979de3edf0f56aa9716b898ec8'
    settle_timeout = 1650
    channel_data_obj = {
        'partner_address': partner_address,
        'token_address': token_address,
        'settle_timeout': settle_timeout
    }
    request = grequests.put(
        api_url_for(api_backend, 'channelsresource'),
        json=channel_data_obj
    )
    response = request.send().response
    assert_proper_response(response)

    partner_address = '0x61c808d82a3ac53231750dadc13c777b59310bd9'
    token_address = '0x61c808d82a3ac53231750dadc13c777b59310bd9'
    settle_timeout = 1650
    channel_data_obj = {
        'partner_address': partner_address,
        'token_address': token_address,
        'settle_timeout': settle_timeout
    }
    request = grequests.put(
        api_url_for(api_backend, 'channelsresource'),
        json=channel_data_obj
    )
    response = request.send().response
    assert_proper_response(response)

    # and now let's get the token list
    request = grequests.get(
        api_url_for(api_backend, 'tokensresource'),
    )
    response = request.send().response
    assert_proper_response(response)
    response = response.json()
    expected_response = [
        {'address': '0x61c808d82a3ac53231750dadc13c777b59310bd9'},
        {'address': '0xea674fdde714fd979de3edf0f56aa9716b898ec8'},
    ]
    assert all(r in response for r in expected_response)


def test_query_partners_by_token(
        api_backend,
        api_test_context,
        api_raiden_service):
    # let's create 2 new channels for the same token
    first_partner_address = '0x61c808d82a3ac53231750dadc13c777b59310bd9'
    second_partner_address = '0x29fa6cf0cce24582a9b20db94be4b6e017896038'
    token_address = '0xea674fdde714fd979de3edf0f56aa9716b898ec8'
    settle_timeout = 1650
    channel_data_obj = {
        'partner_address': first_partner_address,
        'token_address': token_address,
        'settle_timeout': settle_timeout
    }
    request = grequests.put(
        api_url_for(api_backend, 'channelsresource'),
        json=channel_data_obj
    )
    response = request.send().response
    assert_proper_response(response)
    response = response.json()
    first_channel_address = response['channel_address']

    channel_data_obj['partner_address'] = second_partner_address
    request = grequests.put(
        api_url_for(api_backend, 'channelsresource'),
        json=channel_data_obj,
    )
    response = request.send().response
    assert_proper_response(response)
    response = response.json()
    second_channel_address = response['channel_address']

    # and a channel for another token
    channel_data_obj['partner_address'] = '0xb07937AbA15304FBBB0Bf6454a9377a76E3dD39E'
    channel_data_obj['token_address'] = '0x70faa28A6B8d6829a4b1E649d26eC9a2a39ba413'
    request = grequests.put(
        api_url_for(api_backend, 'channelsresource'),
        json=channel_data_obj
    )
    response = request.send().response
    assert_proper_response(response)

    # and now let's query our partners per token for the first token
    request = grequests.get(
        api_url_for(
            api_backend,
            'partnersresourcebytokenaddress',
            token_address=token_address,
        )
    )
    response = request.send().response
    assert_proper_response(response)
    response = response.json()
    expected_response = [
        {
            'partner_address': first_partner_address,
            'channel': '/api/1/channels/{}'.format(first_channel_address)
        }, {
            'partner_address': second_partner_address,
            'channel': '/api/1/channels/{}'.format(second_channel_address)
        }
    ]
    assert all(r in response for r in expected_response)


def test_query_blockchain_events(
        api_backend,
        api_test_context,
        api_raiden_service):

    # Adding some mock events. Some of these events should not normally contain
    # a block number but for the purposes of making sure block numbers propagate
    # in the API logic I am adding them here and testing for them later.
    api_test_context.add_events([{
        '_event_type': 'TokenAdded',
        'block_number': 1,
        'channel_manager_address': '0x61c808d82a3ac53231750dadc13c777b59310bd9',
        'token_address': '0x61c808d82a3ac53231750dadc13c777b59310bd9'
    }, {
        '_event_type': 'TokenAdded',
        'block_number': 13,
        'channel_manager_address': '0x61c808d82a3ac53231750dadc13c777b59310bd9',
        'token_address': '0xea674fdde714fd979de3edf0f56aa9716b898ec8'
    }, {
        '_event_type': 'ChannelNew',
        'settle_timeout': 10,
        'netting_channel': '0xea674fdde714fd979de3edf0f56aa9716b898ec8',
        'participant1': '0x4894a542053248e0c504e3def2048c08f73e1ca6',
        'participant2': '0x356857Cd22CBEFccDa4e96AF13b408623473237A',
        'block_number': 15,
    }, {
        '_event_type': 'ChannelNew',
        'settle_timeout': 10,
        'netting_channel': '0xa193fb0032c8635d590f8f31be9f70bd12451b1e',
        'participant1': '0xcd111aa492a9c77a367c36e6d6af8e6f212e0c8e',
        'participant2': '0x88bacc4ddc8f8a5987e1b990bb7f9e8430b24f1a',
        'block_number': 100,
    }, {
        '_event_type': 'ChannelNewBalance',
        'token_address': '0x61c808d82a3ac53231750dadc13c777b59310bd9',
        'participant': '0xcd111aa492a9c77a367c36e6d6af8e6f212e0c8e',
        'balance': 200,
        'block_number': 20,
    }, {
        '_event_type': 'ChannelNewBalance',
        'token_address': '0x61c808d82a3ac53231750dadc13c777b59310bd9',
        'participant': '0x00472c1e4275230354dbe5007a5976053f12610a',
        'balance': 650,
        'block_number': 150,
    }, {
        '_event_type': 'ChannelSettled',
        'block_number': 35,
    }, {
        '_event_type': 'ChannelSettled',
        'block_number': 250,
    }])

    # and now let's query the network events for 'TokenAdded' for blocks 1-10
    request = grequests.get(
        api_url_for(
            api_backend,
            'networkeventsresource',
            from_block=0,
            to_block=10
        )
    )
    response = request.send().response
    assert_proper_response(response)
    response = json.loads(response._content)
    assert len(response) == 1
    assert response[0] == {
        'event_type': 'TokenAdded',
        'block_number': 1,
        'channel_manager_address': '0x61c808d82a3ac53231750dadc13c777b59310bd9',
        'token_address': '0x61c808d82a3ac53231750dadc13c777b59310bd9'
    }

    # query ChannelNew event for a token
    api_test_context.specify_token_for_channelnew('0x61c808d82a3ac53231750dadc13c777b59310bd9')
    request = grequests.get(
        api_url_for(
            api_backend,
            'tokeneventsresource',
            token_address='0x61c808d82a3ac53231750dadc13c777b59310bd9',
            from_block=5,
            to_block=20
        )
    )
    response = request.send().response
    assert_proper_response(response)
    response = json.loads(response._content)
    assert len(response) == 1
    assert response[0] == {
        'event_type': 'ChannelNew',
        'settle_timeout': 10,
        'netting_channel': '0xea674fdde714fd979de3edf0f56aa9716b898ec8',
        'participant1': '0x4894a542053248e0c504e3def2048c08f73e1ca6',
        'participant2': '0x356857Cd22CBEFccDa4e96AF13b408623473237A',
        'block_number': 15,
    }

    # finally query for some channel related events
    # Note: No need to test em all since this does not test the implementation
    # of `get_channel_events()` but just makes sure the proper data make it there
    api_test_context.specify_channel_for_events('0xedbaf3c5100302dcdda53269322f3730b1f0416d')
    request = grequests.get(
        api_url_for(
            api_backend,
            'channeleventsresource',
            channel_address='0xedbaf3c5100302dcdda53269322f3730b1f0416d',
            from_block=10,
            to_block=90
        )
    )
    response = request.send().response
    assert_proper_response(response)
    response = json.loads(response._content)
    assert len(response) == 2
    assert response[0] == {
        'event_type': 'ChannelNewBalance',
        'token_address': '0x61c808d82a3ac53231750dadc13c777b59310bd9',
        'participant': '0xcd111aa492a9c77a367c36e6d6af8e6f212e0c8e',
        'balance': 200,
        'block_number': 20,
    }
    assert response[1] == {
        'event_type': 'ChannelSettled',
        'block_number': 35,
    }


def test_break_blockchain_events(
        api_backend,
        api_test_context,
        api_raiden_service,
        rest_api_port_number):

    api_test_context.add_events([{
        '_event_type': 'ChannelNew',
        'settle_timeout': 10,
        'netting_channel': '0xea674fdde714fd979de3edf0f56aa9716b898ec8',
        'participant1': '0x4894a542053248e0c504e3def2048c08f73e1ca6',
        'participant2': '0x356857Cd22CBEFccDa4e96AF13b408623473237A',
        'block_number': 15,
    }, {
        '_event_type': 'ChannelSettled',
        'block_number': 35,
    }])

    # Let's make sure that token_address as a query argument does not override
    # the provided token_address
    api_test_context.specify_token_for_channelnew('0x61c808d82a3ac53231750dadc13c777b59310bd9')
    request = grequests.get(
        'http://localhost:{port}/api/1/events/tokens/0x61c808d82a3ac53231750dadc13c777b59310bd9'
        '?from_block=5&to_block=20'
        '&token_address=0x167a9333bf582556f35bd4d16a7e80e191aa6476'.format(
            port=rest_api_port_number,
        )
    )
    response = request.send().response
    assert_proper_response(response)
    response = json.loads(response._content)
    assert len(response) == 1
    assert response[0] == {
        'event_type': 'ChannelNew',
        'settle_timeout': 10,
        'netting_channel': '0xea674fdde714fd979de3edf0f56aa9716b898ec8',
        'participant1': '0x4894a542053248e0c504e3def2048c08f73e1ca6',
        'participant2': '0x356857Cd22CBEFccDa4e96AF13b408623473237A',
        'block_number': 15,
    }

    # Assert the same for the event/channels endpoint
    api_test_context.specify_channel_for_events('0xedbaf3c5100302dcdda53269322f3730b1f0416d')
    request = grequests.get(
        'http://localhost:{port}/api/1/events/channels/0xedbaf3c5100302dcdda53269322f3730b1f0416d'
        '?from_block=10&to_block=90'
        '&channel_address=0x167A9333BF582556f35Bd4d16A7E80E191aa6476'.format(
            port=rest_api_port_number,
        )
    )
    response = request.send().response
    assert_proper_response(response)
    response = json.loads(response._content)
    assert len(response) == 1
    assert response[0] == {
        'event_type': 'ChannelSettled',
        'block_number': 35,
    }


def test_api_token_swaps(
        api_backend,
        api_test_context,
        api_raiden_service):

    tokenswap_obj = {
        'role': 'maker',
        'sending_amount': 42,
        'sending_token': '0xea674fdde714fd979de3edf0f56aa9716b898ec8',
        'receiving_amount': 76,
        'receiving_token': '0x2a65aca4d5fc5b5c859090a6c34d164135398226'
    }
    target_address = '0x61c808d82a3ac53231750dadc13c777b59310bd9'
    identifier = 1337
    api_test_context.specify_tokenswap_input(
        tokenswap_obj,
        target_address,
        identifier
    )
    request = grequests.put(
        api_url_for(
            api_backend,
            'tokenswapsresource',
            target_address=target_address,
            identifier=identifier
        ),
        json=tokenswap_obj
    )
    response = request.send().response
    assert_proper_response(response)

    tokenswap_obj = {
        'role': 'taker',
        'sending_amount': 76,
        'sending_token': '0x2a65aca4d5fc5b5c859090a6c34d164135398226',
        'receiving_amount': 42,
        'receiving_token': '0xea674fdde714fd979de3edf0f56aa9716b898ec8'
    }
    target_address = '0xbbc5ee8be95683983df67260b0ab033c237bde60'
    api_test_context.specify_tokenswap_input(
        tokenswap_obj,
        target_address,
        identifier
    )
    request = grequests.put(
        api_url_for(
            api_backend,
            'tokenswapsresource',
            target_address=target_address,
            identifier=identifier
        ),
        json=tokenswap_obj
    )
    response = request.send().response
    assert_proper_response(response)


def test_api_transfers(
        api_backend,
        api_test_context,
        api_raiden_service):

    amount = 200
    identifier = 42
    token_address = '0xea674fdde714fd979de3edf0f56aa9716b898ec8'
    target_address = '0x61c808d82a3ac53231750dadc13c777b59310bd9'
    transfer = {
        'initiator_address': address_encoder(api_raiden_service.address),
        'target_address': target_address,
        'token_address': token_address,
        'amount': amount,
        'identifier': identifier
    }

    request = grequests.post(
        api_url_for(
            api_backend,
            'transfertotargetresource',
            token_address=token_address,
            target_address=target_address
        ),
        json={'amount': amount, 'identifier': identifier}
    )
    response = request.send().response
    assert_proper_response(response)
    response = response.json()
    assert response == transfer


def test_connect_and_leave_token_network(
        api_backend,
        api_test_context,
        api_raiden_service):

    # first check we don't have any open channels
    request = grequests.get(
        api_url_for(api_backend, 'channelsresource')
    )
    response = request.send().response
    assert_proper_response(response)
    channels = response.json()
    assert not channels
    assert response.json() == api_test_context.expect_channels()

    funds = 100
    initial_channel_target = DEFAULT_INITIAL_CHANNEL_TARGET
    joinable_funds_target = DEFAULT_JOINABLE_FUNDS_TARGET
    token_address = '0xea674fdde714fd979de3edf0f56aa9716b898ec8'
    connect_data_obj = {
        'funds': funds,
    }
    request = grequests.put(
        api_url_for(api_backend, 'connectionsresource', token_address=token_address),
        json=connect_data_obj,
    )
    response = request.send().response
    assert_proper_response(response)

    # check that channels got created
    request = grequests.get(
        api_url_for(api_backend, 'channelsresource')
    )
    response = request.send().response
    assert_proper_response(response)
    channels = response.json()
    # There should be three channels according to the default initial_channel_target
    assert len(channels) == DEFAULT_INITIAL_CHANNEL_TARGET
    assert response.json() == api_test_context.expect_channels()

    expected_balance = int((funds * joinable_funds_target) / initial_channel_target)
    assert channels[0]['balance'] == expected_balance
    assert channels[1]['balance'] == expected_balance
    assert channels[2]['balance'] == expected_balance
    assert channels[0]['state'] == CHANNEL_STATE_OPENED
    assert channels[1]['state'] == CHANNEL_STATE_OPENED
    assert channels[2]['state'] == CHANNEL_STATE_OPENED

    # Let's leave the token network
    request = grequests.delete(
        api_url_for(api_backend, 'connectionsresource', token_address=token_address),
    )
    response = request.send().response
    assert_proper_response(response)

    # check that all channels were settled after calling `leave`
    request = grequests.get(
        api_url_for(api_backend, 'channelsresource')
    )
    response = request.send().response
    assert_proper_response(response)

    channels = response.json()
    assert channels[0]['state'] == CHANNEL_STATE_SETTLED
    assert channels[1]['state'] == CHANNEL_STATE_SETTLED
    assert channels[2]['state'] == CHANNEL_STATE_SETTLED
