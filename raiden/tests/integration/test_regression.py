# -*- coding: utf-8 -*-
import pytest

from raiden.messages import RevealSecret
from raiden.tests.fixtures.raiden_network import (
    CHAIN,
    wait_for_partners,
)
from raiden.tests.utils.network import setup_channels
from raiden.transfer.mediated_transfer.events import SendRevealSecret2

# pylint: disable=too-many-locals


@pytest.mark.parametrize('number_of_nodes', [5])
@pytest.mark.parametrize('channels_per_node', [0])
@pytest.mark.parametrize('settle_timeout', [32])  # default settlement is too low for 3 hops
def test_regression_unfiltered_routes(raiden_network, token_addresses, settle_timeout, deposit):
    """ The transfer should proceed without triggering an assert.

    Transfers failed in networks where two or more paths to the destination are
    possible but they share same node as a first hop.
    """
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
    wait_for_partners(raiden_network)

    transfer = app0.raiden.mediated_transfer_async(
        token_address=token,
        amount=1,
        target=app4.raiden.address,
        identifier=1,
    )
    assert transfer.wait()


@pytest.mark.parametrize('number_of_nodes', [3])
@pytest.mark.parametrize('channels_per_node', [CHAIN])
def test_regression_revealsecret_after_secret(raiden_network, token_addresses):
    """ A RevealSecret message received after a Secret message must be cleanly
    handled.
    """
    app0, app1, app2 = raiden_network
    token = token_addresses[0]

    identifier = 1
    transfer = app0.raiden.mediated_transfer_async(
        token_address=token,
        amount=1,
        target=app2.raiden.address,
        identifier=identifier,
    )
    assert transfer.wait()

    all_logs = app1.raiden.transaction_log.get_events_in_block_range(
        0,
        app1.raiden.get_block_number(),
    )

    secret = None
    for log in all_logs:
        event = log.event_object
        if isinstance(event, SendRevealSecret2):
            secret = event.secret
            break
    assert secret

    reveal_secret = RevealSecret(secret)
    app2.raiden.sign(reveal_secret)

    reveal_data = reveal_secret.encode()
    app1.raiden.protocol.receive(reveal_data)
