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
        "status": "open"
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


def test_api_open_channel(api_test_server, api_test_context, api_raiden_service, reveal_timeout):
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
    expected_response = channel_data_obj
    expected_response['reveal_timeout'] = reveal_timeout
    expected_response['balance'] = 0
    expected_response['status'] = 'open'

    assert decode_response(response) == expected_response
