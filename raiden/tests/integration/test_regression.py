# -*- coding: utf-8 -*-
import pytest

from raiden.tests.utils.network import setup_channels


@pytest.mark.parametrize('number_of_nodes', [5])
@pytest.mark.parametrize('channels_per_node', [0])
@pytest.mark.parametrize('blockchain_type', ['tester'])
def test_regression_unfiltered_routes(raiden_network, token_addresses, settle_timeout, deposit):
    app0, app1, app2, app3, app4 = raiden_network
    token = token_addresses[0]

    # Topology:
    #
    #  0 -> 1 -> 2 -> 4
    #       |         ^
    #       +--> 3 ---+
    app_channels = [
        (app0, app1),
        (app1, app2),
        (app1, app3),
        (app3, app4),
        (app2, app4),
    ]

    setup_channels(
        token,
        app_channels,
        deposit,
        settle_timeout,
    )

    # poll the channel manager events
    for app in raiden_network:
        app.raiden.poll_blockchain_events()

    transfer = app0.raiden.mediated_transfer_async(
        token,
        1,
        app4.raiden.address,
        1,
    )
    assert transfer.wait()
