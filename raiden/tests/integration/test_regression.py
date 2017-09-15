# -*- coding: utf-8 -*-
import gevent
import pytest

from raiden.messages import (
    EMPTY_MERKLE_ROOT,
    RevealSecret,
    Secret,
)
from raiden.tests.fixtures.raiden_network import CHAIN
from raiden.tests.utils.network import setup_channels
from raiden.tests.utils.transfer import channel
from raiden.transfer.mediated_transfer.events import (
    SendRevealSecret,
)
from raiden.utils import sha3

# pylint: disable=too-many-locals


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
        token_address=token,
        amount=1,
        target=app4.raiden.address,
        identifier=1,
    )
    assert transfer.wait()


@pytest.mark.parametrize('number_of_nodes', [3])
@pytest.mark.parametrize('channels_per_node', [CHAIN])
@pytest.mark.parametrize('blockchain_type', ['tester'])
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
        if isinstance(event, SendRevealSecret):
            secret = event.secret
            break
    assert secret

    reveal_secret = RevealSecret(secret)
    app2.raiden.sign(reveal_secret)

    reveal_data = reveal_secret.encode()
    app1.raiden.protocol.receive(reveal_data)


@pytest.mark.parametrize('number_of_nodes', [2])
@pytest.mark.parametrize('channels_per_node', [CHAIN])
@pytest.mark.parametrize('blockchain_type', ['tester'])
def test_regression_multiple_revealsecret(raiden_network, token_addresses):
    """ Multiple RevealSecret messages arriving at the same time must be
    handled properly.

    Secret handling followed these steps:

        The Secret message arrives
        The secret is registered
        The channel is updated and the correspoding lock is removed
        * A balance proof for the new channel state is created and sent to the
          payer
        The channel is unregistered for the given hashlock

    The step marked with an asterisk above introduced a context-switch, this
    allowed a second Reveal Secret message to be handled before the channel was
    unregistered, because the channel was already updated an exception was raised
    for an unknown secret.
    """
    app0, app1 = raiden_network
    token = token_addresses[0]

    identifier = 1
    secret = sha3('test_regression_multiple_revealsecret')
    hashlock = sha3(secret)
    expiration = app0.raiden.get_block_number() + 100
    amount = 10

    mediated_transfer = channel(app0, app1, token).create_mediatedtransfer(
        transfer_initiator=app0.raiden.address,
        transfer_target=app1.raiden.address,
        fee=0,
        amount=amount,
        identifier=identifier,
        expiration=expiration,
        hashlock=hashlock,
    )
    app0.raiden.sign(mediated_transfer)

    message_data = mediated_transfer.encode()
    app1.raiden.protocol.receive(message_data)

    reveal_secret = RevealSecret(secret)
    app0.raiden.sign(reveal_secret)
    reveal_secret_data = reveal_secret.encode()

    secret = Secret(
        identifier=identifier,
        nonce=mediated_transfer.nonce + 1,
        channel=channel(app0, app1, token).channel_address,
        transferred_amount=amount,
        locksroot=EMPTY_MERKLE_ROOT,
        secret=secret,
    )
    app0.raiden.sign(secret)
    secret_data = secret.encode()

    messages = [
        secret_data,
        reveal_secret_data,
    ]

    wait = [
        gevent.spawn_later(
            .1,
            app1.raiden.protocol.receive,
            data,
        )
        for data in messages
    ]

    gevent.joinall(wait)
