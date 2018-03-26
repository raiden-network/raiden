# -*- coding: utf-8 -*-
import itertools

import pytest
import gevent
from ethereum import slogging

from raiden.transfer.state import CHANNEL_STATE_SETTLED

log = slogging.getLogger(__name__)


@pytest.mark.parametrize('number_of_nodes', [2])
@pytest.mark.parametrize('number_of_tokens', [1])
@pytest.mark.parametrize('channels_per_node', [1])
@pytest.mark.parametrize('settle_timeout', [6])
@pytest.mark.parametrize('reveal_timeout', [3])
def test_leaving(raiden_network, token_addresses):
    token_address = token_addresses[0]
    connection_managers = [
        app.raiden.connection_manager_for_token(token_address) for app in raiden_network
    ]

    all_channels = list(
        itertools.chain.from_iterable(
            connection_manager.receiving_channels for connection_manager in connection_managers
        )
    )

    leaving_async = [
        app.raiden.leave_all_token_networks_async() for app in raiden_network[1:]
    ]

    gevent.wait(leaving_async, timeout=50)

    assert not connection_managers[0].receiving_channels
    assert all(
        channel.state == CHANNEL_STATE_SETTLED
        for channel in all_channels
    )
