# -*- coding: utf-8 -*-

import pytest
from gevent import server

from raiden import waiting
from raiden.app import App
from raiden.network.transport.udp.udp_transport import UDPTransport
from raiden.tests.utils.network import CHAIN
from raiden.tests.utils.transfer import (
    assert_synched_channel_state,
    mediated_transfer,
)
from raiden.transfer import views


@pytest.mark.parametrize('in_memory_database', [False])
@pytest.mark.parametrize('deposit', [10])
@pytest.mark.parametrize('channels_per_node', [CHAIN])
@pytest.mark.parametrize('number_of_nodes', [3])
def test_mediated_transfer(
        raiden_network,
        number_of_nodes,
        deposit,
        token_addresses,
        network_wait,
        skip_if_not_udp,
):
    app0, app1, app2 = raiden_network
    token_address = token_addresses[0]
    node_state = views.state_from_app(app0)
    payment_network_id = app0.raiden.default_registry.address
    token_network_identifier = views.get_token_network_identifier_by_token_address(
        node_state,
        payment_network_id,
        token_address,
    )

    # make a ferw transfers from app0 to app2
    amount = 1
    spent_amount = deposit - 2
    for _ in range(spent_amount):
        mediated_transfer(
            app0,
            app2,
            token_network_identifier,
            amount,
            timeout=network_wait * number_of_nodes,
        )

    app0.raiden.stop()
    host_port = (app0.raiden.config['host'], app0.raiden.config['port'])
    socket = server._udp_socket(host_port)

    new_transport = UDPTransport(
        app0.discovery,
        socket,
        app0.raiden.transport.throttle_policy,
        app0.raiden.config['transport'],
    )

    app0_restart = App(
        app0.config,
        app0.raiden.chain,
        app0.raiden.default_registry,
        new_transport,
        app0.raiden.discovery,
    )

    app0.stop()
    del app0  # the app0 object should not be used after it is stopped

    assert_synched_channel_state(
        token_network_identifier,
        app0_restart, deposit - spent_amount, [],
        app1, deposit + spent_amount, [],
    )
    assert_synched_channel_state(
        token_network_identifier,
        app1, deposit - spent_amount, [],
        app2, deposit + spent_amount, [],
    )

    # wait for the nodes' healthcheck to update the network statuses
    waiting.wait_for_healthy(
        app0_restart.raiden,
        app1.raiden.address,
        network_wait,
    )
    waiting.wait_for_healthy(
        app1.raiden,
        app0_restart.raiden.address,
        network_wait,
    )

    mediated_transfer(
        app2,
        app0_restart,
        token_network_identifier,
        amount,
        timeout=network_wait * number_of_nodes * 2,
    )
    mediated_transfer(
        app0_restart,
        app2,
        token_network_identifier,
        amount,
        timeout=network_wait * number_of_nodes * 2,
    )

    assert_synched_channel_state(
        token_network_identifier,
        app0_restart, deposit - spent_amount, [],
        app1, deposit + spent_amount, [],
    )
    assert_synched_channel_state(
        token_network_identifier,
        app1, deposit - spent_amount, [],
        app2, deposit + spent_amount, [],
    )
