# -*- coding: utf-8 -*-
import pytest
import gevent
from gevent.pool import Pool
from ethereum import slogging

from raiden.tests.utils.blockchain import wait_until_block

log = slogging.getLogger(__name__)


@pytest.mark.parametrize('number_of_nodes', [6])
@pytest.mark.parametrize('channels_per_node', [0])
@pytest.mark.parametrize('cached_genesis', [False])
@pytest.mark.parametrize('register_tokens', [True, False])
def test_participant_selection(
    raiden_network,
    tokens_addresses,
    settle_timeout,
    reveal_timeout,
    blockchain_type
):
    token_address = tokens_addresses[0]

    # adjust timeouts
    for app in raiden_network:
        app.raiden.config['reveal_timeout'] = reveal_timeout
        app.raiden.config['settle_timeout'] = settle_timeout

    # connect the first node (will register the token if necessary)
    raiden_network[0].raiden.api.connect_token_network(token_address, 100)

    # connect the other nodes
    pool = Pool()
    calls = []
    for app in raiden_network[1:]:
        api = app.raiden.api
        calls.append((api.connect_token_network, token_address, 100))

    pool.imap(lambda x: x[0](*x[1:]), calls).join()

    # wait some blocks to let the network connect
    wait_blocks = 15
    if blockchain_type == 'geth':
        wait_until_block(
            raiden_network[-1].raiden.chain,
            raiden_network[-1].raiden.chain.block_number() + wait_blocks
        )
    else:
        for i in range(wait_blocks):
            for app in raiden_network:
                wait_until_block(
                    app.raiden.chain,
                    app.raiden.chain.block_number() + 1
                )
            # tester needs an explicit context switch :(
            gevent.sleep(1)

    connection_managers = [
        app.raiden.connection_manager_for_token(token_address) for app in raiden_network
    ]

    def open_channels_count(connection_managers_):
        return [
            connection_manager.open_channels for connection_manager in connection_managers_
        ]

    assert any(open_channels_count(connection_managers))
    assert all(open_channels_count(connection_managers))

    def not_saturated(connection_managers):
        return [
            1 for connection_manager in connection_managers
            if connection_manager.open_channels < connection_manager.initial_channel_target
        ]

    chain = raiden_network[-1].raiden.chain
    max_wait = 12

    while len(not_saturated(connection_managers)) > 0:
        wait_until_block(chain, chain.block_number() + 1)
        max_wait -= 1
        if max_wait <= 0:
            break

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
    before_block = connection_manager.raiden.chain.block_number()

    raiden_network[0].raiden.api.leave_token_network(token_address, wait_for_settle=False)

    wait_until_block(
        connection_manager.raiden.chain,
        before_block + connection_manager.raiden.config['settle_timeout'] + 1
    )
    after = len(connection_manager.open_channels)

    assert before > after
    assert after == 0
