# -*- coding: utf-8 -*-
import gevent
import pytest

from raiden.tests.utils.transfer import (
    assert_synched_channel_state,
    direct_transfer,
)


@pytest.mark.parametrize('number_of_nodes', [2])
def test_direct_transfer(raiden_network, token_addresses, deposit, network_wait):
    token_address = token_addresses[0]
    app0, app1 = raiden_network

    amount = 10
    direct_transfer(
        app0,
        app1,
        token_address,
        amount,
        timeout=network_wait,
    )

    assert_synched_channel_state(
        token_address,
        app0, deposit - amount, [],
        app1, deposit + amount, [],
    )


@pytest.mark.parametrize('number_of_nodes', [2])
@pytest.mark.parametrize('channels_per_node', [1])
@pytest.mark.parametrize('number_of_tokens', [1])
def test_direct_transfer_to_offline_node(raiden_network, token_addresses, deposit):
    app0, app1 = raiden_network
    token_address = token_addresses[0]

    # Wait until the initialization of the node is complete and then stop it
    gevent.wait([app1.raiden.start_event])
    app1.raiden.stop()

    amount = 10
    target = app1.raiden.address
    app0.raiden.direct_transfer_async(
        app0.raiden.default_registry.address,
        token_address,
        amount,
        target,
        identifier=1,
    )

    app1.raiden.start()

    gevent.sleep(5)

    no_outstanding_locks = []
    assert_synched_channel_state(
        token_address,
        app0, deposit - amount, no_outstanding_locks,
        app1, deposit + amount, no_outstanding_locks,
    )
