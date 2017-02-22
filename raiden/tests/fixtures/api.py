# -*- coding: utf-8 -*-
import pytest
import copy


from raiden.app import App
from raiden.raiden_service import RaidenService
from raiden.network.discovery import Discovery


# TODO: This fixture could be perhaps be abstracted out and combined partly
#       with what we have in tests/utils/network.py::create_apps()
@pytest.fixture
def raiden_service(
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
    return RaidenService(
        blockchain,
        blockchain.private_key,
        transport_class,
        Discovery(),
        config
    )
