# -*- coding: utf-8 -*-
import pytest
import copy
from gevent import Greenlet

from raiden.app import App
from raiden.api.rest import RestAPI, APIServer
from raiden.raiden_service import RaidenService
from raiden.network.discovery import Discovery
from raiden.tests.utils.apitestcontext import ApiTestContext


@pytest.fixture
def api_raiden_service(
        monkeypatch,
        api_test_context,
        blockchain_services,
        transport_class,
        max_unresponsive_time,
        send_ping_time,
        reveal_timeout,
        raiden_udp_ports):
    blockchain = blockchain_services[0]
    config = copy.deepcopy(App.default_config)

    config['port'] = raiden_udp_ports[0]
    config['host'] = '127.0.0.1'
    config['privatekey_hex'] = blockchain.private_key.encode('hex')
    config['send_ping_time'] = send_ping_time
    config['max_unresponsive_time'] = max_unresponsive_time
    config['reveal_timeout'] = reveal_timeout
    raiden_service = RaidenService(
        blockchain,
        blockchain.private_key,
        transport_class,
        Discovery(),
        config
    )
    monkeypatch.setattr(
        raiden_service.api,
        'get_channel_list',
        api_test_context.query_channels
    )
    monkeypatch.setattr(
        raiden_service.api,
        'open',
        api_test_context.open_channel
    )
    return raiden_service


@pytest.fixture
def api_test_context(reveal_timeout):
    return ApiTestContext(reveal_timeout)


@pytest.fixture(scope='session')
def api_test_server():
    # Initializing it without raiden_service.api here since that is a
    # function scope fixture. We will inject it to rest_api object later
    rest_api = RestAPI(None)
    api_server = APIServer(rest_api)
    g = Greenlet.spawn(api_server.run, 5001, debug=False)
    yield rest_api
    # At sessions teardown kill the greenlet
    g.kill(block=True, timeout=10)
