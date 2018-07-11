import random

import gevent
import pytest

from raiden.constants import UINT64_MAX
from raiden.messages import (
    Lock,
    LockedTransfer,
    RevealSecret,
    Secret,
)
from raiden.tests.integration.fixtures.raiden_network import (
    CHAIN,
    wait_for_channels,
)
from raiden.tests.integration.fixtures.transport import TransportProtocol
from raiden.tests.utils.network import payment_channel_open_and_deposit
from raiden.tests.utils.transfer import get_channelstate
from raiden.tests.utils.factories import UNIT_CHAIN_ID
from raiden.transfer import views
from raiden.transfer.mediated_transfer.events import SendRevealSecret
from raiden.transfer.state import EMPTY_MERKLE_ROOT
from raiden.utils import sha3

# pylint: disable=too-many-locals


@pytest.mark.parametrize('number_of_nodes', [5])
@pytest.mark.parametrize('channels_per_node', [0])
@pytest.mark.parametrize('settle_timeout', [64])  # default settlement is too low for 3 hops
def test_regression_unfiltered_routes(
        raiden_network,
        token_addresses,
        settle_timeout,
        deposit,
):
    """ The transfer should proceed without triggering an assert.

    Transfers failed in networks where two or more paths to the destination are
    possible but they share same node as a first hop.
    """
    app0, app1, app2, app3, app4 = raiden_network
    token = token_addresses[0]
    registry_address = app0.raiden.default_registry.address

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

    greenlets = []
    for first_app, second_app in app_channels:
        greenlets.append(gevent.spawn(
            payment_channel_open_and_deposit,
            first_app,
            second_app,
            token,
            deposit,
            settle_timeout,
        ))
    gevent.wait(greenlets)

    wait_for_channels(
        app_channels,
        registry_address,
        [token],
        deposit,
    )

    payment_network_identifier = app0.raiden.default_registry.address
    token_network_identifier = views.get_token_network_identifier_by_token_address(
        views.state_from_app(app0),
        payment_network_identifier,
        token,
    )
    transfer = app0.raiden.mediated_transfer_async(
        token_network_identifier=token_network_identifier,
        amount=1,
        target=app4.raiden.address,
        identifier=1,
    )
    assert transfer.wait()


@pytest.mark.parametrize('number_of_nodes', [3])
@pytest.mark.parametrize('channels_per_node', [CHAIN])
def test_regression_revealsecret_after_secret(raiden_network, token_addresses, transport_config):
    """ A RevealSecret message received after a Secret message must be cleanly
    handled.
    """
    app0, app1, app2 = raiden_network
    token = token_addresses[0]

    identifier = 1
    payment_network_identifier = app0.raiden.default_registry.address
    token_network_identifier = views.get_token_network_identifier_by_token_address(
        views.state_from_app(app0),
        payment_network_identifier,
        token,
    )
    transfer = app0.raiden.mediated_transfer_async(
        token_network_identifier,
        amount=1,
        target=app2.raiden.address,
        identifier=identifier,
    )
    assert transfer.wait()

    event = None
    for _, event in app1.raiden.wal.storage.get_events_by_block(0, 'latest'):
        if isinstance(event, SendRevealSecret):
            break
    assert event

    message_identifier = random.randint(0, UINT64_MAX)
    reveal_secret = RevealSecret(
        message_identifier,
        event.secret,
    )
    app2.raiden.sign(reveal_secret)

    if transport_config.protocol is TransportProtocol.UDP:
        reveal_data = reveal_secret.encode()
        app1.raiden.transport.receive(reveal_data)
    elif transport_config.protocol is TransportProtocol.MATRIX:
        app1.raiden.transport._receive_message(reveal_secret)
    else:
        raise TypeError('Unknown TransportProtocol')


@pytest.mark.parametrize('number_of_nodes', [2])
@pytest.mark.parametrize('channels_per_node', [CHAIN])
def test_regression_multiple_revealsecret(raiden_network, token_addresses, transport_config):
    """ Multiple RevealSecret messages arriving at the same time must be
    handled properly.

    Secret handling followed these steps:

        The Secret message arrives
        The secret is registered
        The channel is updated and the correspoding lock is removed
        * A balance proof for the new channel state is created and sent to the
          payer
        The channel is unregistered for the given secrethash

    The step marked with an asterisk above introduced a context-switch. This
    allowed a second Reveal Secret message to be handled before the channel was
    unregistered. And because the channel was already updated an exception was raised
    for an unknown secret.
    """
    app0, app1 = raiden_network
    token = token_addresses[0]
    token_network_identifier = views.get_token_network_identifier_by_token_address(
        views.state_from_app(app0),
        app0.raiden.default_registry.address,
        token,
    )
    channelstate_0_1 = get_channelstate(app0, app1, token_network_identifier)

    payment_identifier = 1
    secret = sha3(b'test_regression_multiple_revealsecret')
    secrethash = sha3(secret)
    expiration = app0.raiden.get_block_number() + 100
    lock_amount = 10
    lock = Lock(
        lock_amount,
        expiration,
        secrethash,
    )

    nonce = 1
    transferred_amount = 0
    mediated_transfer = LockedTransfer(
        chain_id=UNIT_CHAIN_ID,
        message_identifier=random.randint(0, UINT64_MAX),
        payment_identifier=payment_identifier,
        nonce=nonce,
        token_network_address=app0.raiden.default_registry.address,
        token=token,
        channel_identifier=channelstate_0_1.identifier,
        transferred_amount=transferred_amount,
        locked_amount=lock_amount,
        recipient=app1.raiden.address,
        locksroot=lock.secrethash,
        lock=lock,
        target=app1.raiden.address,
        initiator=app0.raiden.address,
    )
    app0.raiden.sign(mediated_transfer)

    if transport_config.protocol is TransportProtocol.UDP:
        message_data = mediated_transfer.encode()
        app1.raiden.transport.receive(message_data)
    elif transport_config.protocol is TransportProtocol.MATRIX:
        app1.raiden.transport._receive_message(mediated_transfer)
    else:
        raise TypeError('Unknown TransportProtocol')

    reveal_secret = RevealSecret(
        random.randint(0, UINT64_MAX),
        secret,
    )
    app0.raiden.sign(reveal_secret)

    token_network_identifier = channelstate_0_1.token_network_identifier
    secret = Secret(
        chain_id=UNIT_CHAIN_ID,
        message_identifier=random.randint(0, UINT64_MAX),
        payment_identifier=payment_identifier,
        nonce=mediated_transfer.nonce + 1,
        token_network_address=token_network_identifier,
        channel_identifier=channelstate_0_1.identifier,
        transferred_amount=lock_amount,
        locked_amount=0,
        locksroot=EMPTY_MERKLE_ROOT,
        secret=secret,
    )
    app0.raiden.sign(secret)

    if transport_config.protocol is TransportProtocol.UDP:
        messages = [
            secret.encode(),
            reveal_secret.encode(),
        ]
        receive_method = app1.raiden.transport.receive
    elif transport_config.protocol is TransportProtocol.MATRIX:
        messages = [
            secret,
            reveal_secret,
        ]
        receive_method = app1.raiden.transport._receive_message
    else:
        raise TypeError('Unknown TransportProtocol')

    wait = [
        gevent.spawn_later(
            .1,
            receive_method,
            data,
        )
        for data in messages
    ]

    gevent.joinall(wait)
