# -*- coding: utf-8 -*-
import pytest

from raiden.tests.integration.fixtures.transport import TransportProtocol
from raiden.transfer import views
from raiden.transfer import state
from raiden.messages import Ping


# We need to use this helper function since `pytest.skipif()` conditions can't access fixtures
def skip_if_not_udp(transport_protocol: TransportProtocol):
    if transport_protocol is not TransportProtocol.UDP:
        pytest.skip(f"Test doesn't apply to {transport_protocol.value} protocol")


@pytest.mark.parametrize('number_of_nodes', [2])
def test_udp_ping_pong(raiden_network, transport_config):
    skip_if_not_udp(transport_config.protocol)

    app0, app1 = raiden_network

    ping_message = Ping(nonce=0)
    app0.raiden.sign(ping_message)
    ping_encoded = ping_message.encode()

    messageid = ('ping', ping_message.nonce, app1.raiden.address)
    async_result = app0.raiden.transport.maybe_sendraw_with_result(
        app1.raiden.address,
        ping_encoded,
        messageid,
    )
    assert async_result.wait(2), 'The message was not processed'

    network_state = views.get_node_network_status(
        views.state_from_app(app0),
        app1.raiden.address,
    )
    assert network_state is state.NODE_NETWORK_REACHABLE


@pytest.mark.parametrize('number_of_nodes', [2])
def test_udp_ping_pong_unreachable_node(raiden_network, transport_config):
    skip_if_not_udp(transport_config.protocol)

    app0, app1 = raiden_network

    app1.raiden.transport.stop_and_wait()

    ping_message = Ping(nonce=0)
    app0.raiden.sign(ping_message)
    ping_encoded = ping_message.encode()

    messageid = ('ping', ping_message.nonce, app1.raiden.address)
    async_result = app0.raiden.transport.maybe_sendraw_with_result(
        app1.raiden.address,
        ping_encoded,
        messageid,
    )

    nat_keepalive_fail = (
        app0.config['transport']['nat_keepalive_timeout'] *
        app0.config['transport']['nat_keepalive_retries'] *
        2  # wait a bit longer to avoid races
    )
    msg = "The message was dropped, it can't be acknowledged"
    assert async_result.wait(nat_keepalive_fail) is None, msg

    network_state = views.get_node_network_status(
        views.state_from_app(app0),
        app1.raiden.address,
    )
    assert network_state is state.NODE_NETWORK_UNREACHABLE
