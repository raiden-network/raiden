# -*- coding: utf-8 -*-
import grequests
from gevent import Greenlet
from raiden.api.rest import RestAPI, APIServer
from raiden.tests.utils.apitestcontext import decode_response
from raiden.utils import netting_channel_to_api_dict
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
        "channel_address": '0x' + netting_channel.address.encode('hex'),
        "token_address": '0x' + channel0.token_address.encode('hex'),
        "partner_address": '0x' + app1.raiden.address.encode('hex'),
        "settle_timeout": settle_timeout,
        "balance": channel0.contract_balance,
        "status": "open"
    }
    assert result == expected_result

    responses = grequests.map([grequests.get('http://localhost:5001/api/1/channels')])
    response = responses[0]
    assert response.status_code == 200
    assert decode_response(response) == api_test_context.expect_channels()

    api_test_context.make_channel()
    responses = grequests.map([grequests.get('http://localhost:5001/api/1/channels')])
    response = responses[0]
    assert response.status_code == 200
    assert decode_response(response) == api_test_context.expect_channels()

    g.kill(block=True, timeout=10)
