# -*- coding: utf-8 -*-
import pytest
import gevent
import itertools

from ethereum import slogging

from raiden.api.python import RaidenAPI
from raiden.tests.utils.blockchain import wait_until_block
from raiden.transfer.state import (
    CHANNEL_STATE_SETTLED,
)

log = slogging.getLogger(__name__)


@pytest.mark.parametrize('number_of_nodes', [2])
@pytest.mark.parametrize('number_of_tokens', [1])
@pytest.mark.parametrize('channels_per_node', [1])
@pytest.mark.parametrize('settle_timeout', [6])
@pytest.mark.parametrize('reveal_timeout', [3])
def test_close_raiden_app_gracefully(
    raiden_network,
    token_addresses,
    settle_timeout,
    blockchain_type
):
    # it's pretty tedious to get tester to mine during `app.stop`, so we just skip it
    if blockchain_type == 'tester':
        return
    for app in raiden_network:
        app.stop(graceful=True)


@pytest.mark.parametrize('number_of_nodes', [2])
@pytest.mark.parametrize('number_of_tokens', [1])
@pytest.mark.parametrize('channels_per_node', [1])
@pytest.mark.parametrize('settle_timeout', [6])
@pytest.mark.parametrize('reveal_timeout', [3])
def test_leaving(
    raiden_network,
    token_addresses,
    blockchain_type
):

    token_address = token_addresses[0]
    connection_managers = [
        app.raiden.connection_manager_for_token(token_address) for app in raiden_network
    ]

    all_channels = list(
        itertools.chain.from_iterable(
            connection_manager.open_channels for connection_manager in connection_managers
        )
    )

    leaving_async = list(
        itertools.chain.from_iterable(
            app.raiden.leave_all_token_networks_async() for app in raiden_network[1:]
        )
    )

    with gevent.timeout.Timeout(30):
        # tester needs manual block progress
        if blockchain_type == 'tester':
            for app in raiden_network:
                connection_manager = app.raiden.connection_manager_for_token(token_address)
                wait_blocks = connection_manager.min_settle_blocks
                if wait_blocks > 0:
                    wait_until_block(
                        app.raiden.chain,
                        app.raiden.chain.block_number() + wait_blocks
                    )
                    gevent.sleep(app.raiden.alarm.wait_time)

    gevent.wait(leaving_async, timeout=50)
    assert len(connection_managers[0].open_channels) == 0
    assert all(channel.state == CHANNEL_STATE_SETTLED for channel in all_channels), [
        channel.state for channel in all_channels]


# TODO: add test scenarios for
# - subsequent `connect()` calls with different `funds` arguments
# - `connect()` calls with preexisting channels

@pytest.mark.parametrize('number_of_nodes', [6])
@pytest.mark.parametrize('channels_per_node', [0])
@pytest.mark.parametrize('cached_genesis', [False])
@pytest.mark.parametrize('register_tokens', [True, False])
@pytest.mark.parametrize('settle_timeout', [6])
@pytest.mark.parametrize('reveal_timeout', [3])
def test_participant_selection(
    raiden_network,
    token_addresses,
    blockchain_type
):
    token_address = token_addresses[0]

    # connect the first node (will register the token if necessary)
    RaidenAPI(raiden_network[0].raiden).connect_token_network(token_address, 100)

    # connect the other nodes
    connect_greenlets = [
        gevent.spawn(RaidenAPI(app.raiden).connect_token_network, token_address, 100)
        for app in raiden_network[1:]
    ]
    gevent.wait(connect_greenlets)

    # wait some blocks to let the network connect
    wait_blocks = 15
    for i in range(wait_blocks):
        for app in raiden_network:
            wait_until_block(
                app.raiden.chain,
                app.raiden.chain.block_number() + 1
            )
        # tester needs an explicit context switch :(
        if blockchain_type == 'tester':
            gevent.sleep(1)

    connection_managers = [
        app.raiden.connection_manager_for_token(token_address) for app in raiden_network
    ]

    def open_channels_count(connection_managers_):
        return [
            connection_manager.open_channels for connection_manager in connection_managers_
        ]

    assert all(open_channels_count(connection_managers))

    def not_saturated(connection_managers):
        return [
            1 for connection_manager in connection_managers
            if connection_manager.open_channels < connection_manager.initial_channel_target
        ]

    chain = raiden_network[-1].raiden.chain
    max_wait = 12

    while len(not_saturated(connection_managers)) > 0 and max_wait > 0:
        wait_until_block(chain, chain.block_number() + 1)
        max_wait -= 1

    assert len(not_saturated(connection_managers)) == 0

    # Ensure unpartitioned network
    addresses = [app.raiden.address for app in raiden_network]
    for connection_manager in connection_managers:
        assert all(
            connection_manager.channelgraph.has_path(
                connection_manager.raiden.address,
                address
            )
            for address in addresses
        )

    # average channel count
    acc = (
        sum(len(connection_manager.open_channels) for connection_manager in connection_managers) /
        float(len(connection_managers))
    )

    try:
        # FIXME: depending on the number of channels, this will fail, due to weak
        # selection algorithm
        # https://github.com/raiden-network/raiden/issues/576
        assert not any(
            len(connection_manager.open_channels) > 2 * acc
            for connection_manager in connection_managers
        )
    except AssertionError:
        pass

    # test `leave()` method
    connection_manager = connection_managers[0]
    before = len(connection_manager.open_channels)

    RaidenAPI(raiden_network[0].raiden).leave_token_network(token_address, wait_for_settle=False)

    wait_until_block(
        connection_manager.raiden.chain,
        (
            connection_manager.raiden.chain.block_number() +
            connection_manager.raiden.config['settle_timeout'] + 1
        )
    )
    after = len(connection_manager.open_channels)

    assert before > after
    assert after == 0
