# -*- coding: utf-8 -*-
import grequests
from gevent import Greenlet
from raiden.api.rest import RestAPI, APIServer
from raiden.tests.utils.apitestcontext import decode_response


def test_api_query_channels(monkeypatch, raiden_service, api_test_context):
    monkeypatch.setattr(
        raiden_service.api,
        'get_channel_list',
        api_test_context.query_channels
    )
    rest_api = RestAPI(raiden_service.api)
    api_server = APIServer(rest_api)
    g = Greenlet.spawn(api_server.run, 5001, debug=False)

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
