# -*- coding: utf-8 -*-
import pytest
import grequests

from raiden.tests.utils.apitestcontext import decode_response
from raiden.utils import netting_channel_to_api_dict, bytes_to_hexstr
from raiden.tests.utils.transfer import channel


@pytest.mark.parametrize('blockchain_type', ['tester'])
@pytest.mark.parametrize('number_of_nodes', [2])
def test_netting_channel_to_api_dict(raiden_network, tokens_addresses, settle_timeout):
    app0, app1 = raiden_network  # pylint: disable=unbalanced-tuple-unpacking
    channel0 = channel(app0, app1, tokens_addresses[0])

    netting_address = channel0.external_state.netting_channel.address
    netting_channel = app0.raiden.chain.netting_channel(netting_address)

    result = netting_channel_to_api_dict(netting_channel, app0.raiden.address)
    expected_result = {
        "channel_address": bytes_to_hexstr(netting_channel.address),
        "token_address": bytes_to_hexstr(channel0.token_address),
        "partner_address": bytes_to_hexstr(app1.raiden.address),
        "settle_timeout": settle_timeout,
        "balance": channel0.contract_balance,
        "state": "open"
    }
    assert result == expected_result


def test_api_query_channels(api_test_server, api_test_context, api_raiden_service):
    request = grequests.get('http://localhost:5001/api/1/channels')
    response = request.send().response
    assert response and response.status_code == 200
    assert decode_response(response) == api_test_context.expect_channels()

    api_test_context.make_channel_and_add()
    response = request.send().response
    assert response.status_code == 200
    assert decode_response(response) == api_test_context.expect_channels()


def test_api_open_and_deposit_channel(
        api_test_server,
        api_test_context,
        api_raiden_service,
        reveal_timeout):
    # let's create a new channel
    first_partner_address = "0x61c808d82a3ac53231750dadc13c777b59310bd9"
    token_address = "0xea674fdde714fd979de3edf0f56aa9716b898ec8"
    settle_timeout = 1650
    channel_data_obj = {
        "partner_address": first_partner_address,
        "token_address": token_address,
        "settle_timeout": settle_timeout
    }
    request = grequests.put(
        'http://localhost:5001/api/1/channels',
        data=channel_data_obj
    )
    response = request.send().response

    assert response and response.status_code == 200
    response = decode_response(response)
    expected_response = channel_data_obj
    expected_response['reveal_timeout'] = reveal_timeout
    expected_response['balance'] = 0
    expected_response['state'] = 'open'
    # can't know the channel address beforehand but make sure we get one
    assert 'channel_address' in response
    first_channel_address = response['channel_address']
    expected_response['channel_address'] = response['channel_address']
    assert response == expected_response

    # now let's open a channel and make a deposit too
    second_partner_address = '0x29fa6cf0cce24582a9b20db94be4b6e017896038'
    balance = 100
    channel_data_obj = {
        "partner_address": second_partner_address,
        "token_address": token_address,
        "settle_timeout": settle_timeout,
        "balance": balance
    }
    request = grequests.put(
        'http://localhost:5001/api/1/channels',
        data=channel_data_obj
    )
    response = request.send().response

    assert response and response.status_code == 200
    response = decode_response(response)
    expected_response = channel_data_obj
    expected_response['reveal_timeout'] = reveal_timeout
    expected_response['balance'] = balance
    expected_response['state'] = 'open'
    # can't know the channel address beforehand but make sure we get one
    assert 'channel_address' in response
    expected_response['channel_address'] = response['channel_address']
    second_channel_address = response['channel_address']
    assert response == expected_response

    # let's deposit on the first channel
    request = grequests.patch(
        'http://localhost:5001/api/1/channels/{}'.format(first_channel_address),
        data={'balance': balance}
    )
    response = request.send().response
    assert response and response.status_code == 200
    response = decode_response(response)
    expected_response = {
        "channel_address": first_channel_address,
        "partner_address": first_partner_address,
        "token_address": token_address,
        "settle_timeout": settle_timeout,
        "reveal_timeout": reveal_timeout,
        "state": 'open',
        "balance": balance
    }
    assert response == expected_response

    # finall let's try querying for the second channel
    request = grequests.get(
        'http://localhost:5001/api/1/channels/{}'.format(second_channel_address)
    )
    response = request.send().response
    assert response and response.status_code == 200
    response = decode_response(response)
    expected_response = {
        "channel_address": second_channel_address,
        "partner_address": second_partner_address,
        "token_address": token_address,
        "settle_timeout": settle_timeout,
        "reveal_timeout": reveal_timeout,
        "state": 'open',
        "balance": balance
    }
    assert response == expected_response


def test_api_open_close_and_settle_channel(
        api_test_server,
        api_test_context,
        api_raiden_service,
        reveal_timeout):
    # let's create a new channel
    partner_address = "0x61c808d82a3ac53231750dadc13c777b59310bd9"
    token_address = "0xea674fdde714fd979de3edf0f56aa9716b898ec8"
    settle_timeout = 1650
    channel_data_obj = {
        "partner_address": partner_address,
        "token_address": token_address,
        "settle_timeout": settle_timeout
    }
    request = grequests.put(
        'http://localhost:5001/api/1/channels',
        data=channel_data_obj
    )
    response = request.send().response

    balance = 0
    assert response and response.status_code == 200
    response = decode_response(response)
    expected_response = channel_data_obj
    expected_response['reveal_timeout'] = reveal_timeout
    expected_response['balance'] = balance
    expected_response['state'] = 'open'
    # can't know the channel address beforehand but make sure we get one
    assert 'channel_address' in response
    channel_address = response['channel_address']
    expected_response['channel_address'] = response['channel_address']
    assert response == expected_response

    # let's the close the channel
    request = grequests.patch(
        'http://localhost:5001/api/1/channels/{}'.format(channel_address),
        data={'state': 'closed'}
    )
    response = request.send().response
    assert response and response.status_code == 200
    response = decode_response(response)
    expected_response = {
        "channel_address": channel_address,
        "partner_address": partner_address,
        "token_address": token_address,
        "settle_timeout": settle_timeout,
        "reveal_timeout": reveal_timeout,
        "state": 'closed',
        "balance": balance
    }
    assert response == expected_response

    # let's settle the channel
    request = grequests.patch(
        'http://localhost:5001/api/1/channels/{}'.format(channel_address),
        data={'state': 'settled'}
    )
    response = request.send().response
    assert response and response.status_code == 200
    response = decode_response(response)
    expected_response = {
        "channel_address": channel_address,
        "partner_address": partner_address,
        "token_address": token_address,
        "settle_timeout": settle_timeout,
        "reveal_timeout": reveal_timeout,
        "state": 'settled',
        "balance": balance
    }
    assert response == expected_response


def test_api_tokens(
        api_test_server,
        api_test_context,
        api_raiden_service,
        reveal_timeout):
    # let's create 2 new channels for 2 different tokens
    partner_address = "0x61c808d82a3ac53231750dadc13c777b59310bd9"
    token_address = "0xea674fdde714fd979de3edf0f56aa9716b898ec8"
    settle_timeout = 1650
    channel_data_obj = {
        "partner_address": partner_address,
        "token_address": token_address,
        "settle_timeout": settle_timeout
    }
    request = grequests.put(
        'http://localhost:5001/api/1/channels',
        data=channel_data_obj
    )
    response = request.send().response
    assert response and response.status_code == 200

    partner_address = "0x61c808d82a3ac53231750dadc13c777b59310bd9"
    token_address = "0x61c808d82a3ac53231750dadc13c777b59310bd9"
    settle_timeout = 1650
    channel_data_obj = {
        "partner_address": partner_address,
        "token_address": token_address,
        "settle_timeout": settle_timeout
    }
    request = grequests.put(
        'http://localhost:5001/api/1/channels',
        data=channel_data_obj
    )
    response = request.send().response
    assert response and response.status_code == 200

    # and now let's get the token list
    request = grequests.get(
        'http://localhost:5001/api/1/tokens',
    )
    response = request.send().response
    assert response and response.status_code == 200
    response = decode_response(response)
    assert response == [
        {"address": "0x61c808d82a3ac53231750dadc13c777b59310bd9"},
        {"address": "0xea674fdde714fd979de3edf0f56aa9716b898ec8"},
    ]


def test_query_partners_by_token(
        api_test_server,
        api_test_context,
        api_raiden_service,
        reveal_timeout):
    # let's create 2 new channels for the same token
    first_partner_address = "0x61c808d82a3ac53231750dadc13c777b59310bd9"
    second_partner_address = '0x29fa6cf0cce24582a9b20db94be4b6e017896038'
    token_address = "0xea674fdde714fd979de3edf0f56aa9716b898ec8"
    settle_timeout = 1650
    channel_data_obj = {
        "partner_address": first_partner_address,
        "token_address": token_address,
        "settle_timeout": settle_timeout
    }
    request = grequests.put(
        'http://localhost:5001/api/1/channels',
        data=channel_data_obj
    )
    response = request.send().response
    assert response and response.status_code == 200
    response = decode_response(response)
    first_channel_address = response['channel_address']

    channel_data_obj['partner_address'] = second_partner_address
    request = grequests.put(
        'http://localhost:5001/api/1/channels',
        data=channel_data_obj
    )
    response = request.send().response
    assert response and response.status_code == 200
    response = decode_response(response)
    second_channel_address = response['channel_address']

    # and a channel for another token
    channel_data_obj['partner_address'] = '0xb07937AbA15304FBBB0Bf6454a9377a76E3dD39E'
    channel_data_obj['token_address'] = '0x70faa28A6B8d6829a4b1E649d26eC9a2a39ba413'
    request = grequests.put(
        'http://localhost:5001/api/1/channels',
        data=channel_data_obj
    )
    response = request.send().response
    assert response and response.status_code == 200

    # and now let's query our partners per token for the first token
    request = grequests.get(
        'http://localhost:5001/api/1/tokens/0xea674fdde714fd979de3edf0f56aa9716b898ec8/partners',
    )
    response = request.send().response
    assert response and response.status_code == 200
    response = decode_response(response)
    assert response == [
        {
            "partner_address": first_partner_address,
            "channel": "/api/1/channels/{}".format(first_channel_address)
        }, {
            "partner_address": second_partner_address,
            "channel": "/api/1/channels/{}".format(second_channel_address)
        }
    ]
