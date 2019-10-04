import random
from hashlib import sha256

import gevent
import pytest
from eth_utils import keccak

from raiden.constants import EMPTY_SIGNATURE, LOCKSROOT_OF_NO_LOCKS, UINT64_MAX
from raiden.messages.metadata import Metadata, RouteMetadata
from raiden.messages.transfers import Lock, LockedTransfer, RevealSecret, Unlock
from raiden.tests.fixtures.variables import TransportProtocol
from raiden.tests.integration.fixtures.raiden_network import CHAIN, wait_for_channels
from raiden.tests.utils.detect_failure import raise_on_failure
from raiden.tests.utils.events import (
    raiden_events_search_for_item,
    raiden_state_changes_search_for_item,
    search_for_item,
)
from raiden.tests.utils.factories import UNIT_CHAIN_ID
from raiden.tests.utils.network import payment_channel_open_and_deposit
from raiden.tests.utils.transfer import get_channelstate, transfer, watch_for_unlock_failures
from raiden.transfer import views
from raiden.transfer.mediated_transfer.events import EventRouteFailed, SendSecretReveal
from raiden.transfer.mediated_transfer.state_change import ReceiveTransferCancelRoute
from raiden.utils import PaymentID, sha3

# pylint: disable=too-many-locals


def open_and_wait_for_channels(app_channels, registry_address, token, deposit, settle_timeout):
    greenlets = []
    for first_app, second_app in app_channels:
        greenlets.append(
            gevent.spawn(
                payment_channel_open_and_deposit,
                first_app,
                second_app,
                token,
                deposit,
                settle_timeout,
            )
        )
    gevent.wait(greenlets)

    wait_for_channels(app_channels, registry_address, [token], deposit)


@raise_on_failure
@pytest.mark.parametrize("number_of_nodes", [5])
@pytest.mark.parametrize("channels_per_node", [0])
@pytest.mark.parametrize("settle_timeout", [64])  # default settlement is too low for 3 hops
def test_regression_unfiltered_routes(raiden_network, token_addresses, settle_timeout, deposit):
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
    app_channels = [(app0, app1), (app1, app2), (app1, app3), (app3, app4), (app2, app4)]

    open_and_wait_for_channels(app_channels, registry_address, token, deposit, settle_timeout)
    transfer(initiator_app=app0, target_app=app4, token_address=token, amount=1, identifier=1)


@raise_on_failure
@pytest.mark.parametrize("number_of_nodes", [3])
@pytest.mark.parametrize("channels_per_node", [CHAIN])
def test_regression_revealsecret_after_secret(raiden_network, token_addresses, transport_protocol):
    """ A RevealSecret message received after a Unlock message must be cleanly
    handled.
    """
    app0, app1, app2 = raiden_network
    token = token_addresses[0]

    identifier = 1
    token_network_registry_address = app0.raiden.default_registry.address
    token_network_address = views.get_token_network_address_by_token_address(
        views.state_from_app(app0), token_network_registry_address, token
    )
    payment_status = app0.raiden.mediated_transfer_async(
        token_network_address, amount=1, target=app2.raiden.address, identifier=identifier
    )
    with watch_for_unlock_failures(*raiden_network):
        assert payment_status.payment_done.wait()

    event = search_for_item(app1.raiden.wal.storage.get_events(), SendSecretReveal, {})
    assert event

    message_identifier = random.randint(0, UINT64_MAX)
    reveal_secret = RevealSecret(
        message_identifier=message_identifier, secret=event.secret, signature=EMPTY_SIGNATURE
    )
    app2.raiden.sign(reveal_secret)

    if transport_protocol is TransportProtocol.MATRIX:
        app1.raiden.transport._receive_message(reveal_secret)  # pylint: disable=protected-access
    else:
        raise TypeError("Unknown TransportProtocol")


@raise_on_failure
@pytest.mark.parametrize("number_of_nodes", [2])
@pytest.mark.parametrize("channels_per_node", [CHAIN])
def test_regression_multiple_revealsecret(raiden_network, token_addresses, transport_protocol):
    """ Multiple RevealSecret messages arriving at the same time must be
    handled properly.

    Unlock handling followed these steps:

        The Unlock message arrives
        The secret is registered
        The channel is updated and the correspoding lock is removed
        * A balance proof for the new channel state is created and sent to the
          payer
        The channel is unregistered for the given secrethash

    The step marked with an asterisk above introduced a context-switch. This
    allowed a second Reveal Unlock message to be handled before the channel was
    unregistered. And because the channel was already updated an exception was raised
    for an unknown secret.
    """
    app0, app1 = raiden_network
    token = token_addresses[0]
    token_network_address = views.get_token_network_address_by_token_address(
        views.state_from_app(app0), app0.raiden.default_registry.address, token
    )
    channelstate_0_1 = get_channelstate(app0, app1, token_network_address)

    payment_identifier = 1
    secret = sha3(b"test_regression_multiple_revealsecret")
    secrethash = sha256(secret).digest()
    expiration = app0.raiden.get_block_number() + 100
    lock_amount = 10
    lock = Lock(amount=lock_amount, expiration=expiration, secrethash=secrethash)

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
        fee=0,
        recipient=app1.raiden.address,
        locksroot=keccak(lock.as_bytes),
        lock=lock,
        target=app1.raiden.address,
        initiator=app0.raiden.address,
        signature=EMPTY_SIGNATURE,
        metadata=Metadata(
            routes=[RouteMetadata(route=[app0.raiden.address, app1.raiden.address])]
        ),
    )
    app0.raiden.sign(mediated_transfer)

    if transport_protocol is TransportProtocol.MATRIX:
        app1.raiden.transport._receive_message(mediated_transfer)
    else:
        raise TypeError("Unknown TransportProtocol")

    reveal_secret = RevealSecret(
        message_identifier=random.randint(0, UINT64_MAX), secret=secret, signature=EMPTY_SIGNATURE
    )
    app0.raiden.sign(reveal_secret)

    token_network_address = channelstate_0_1.token_network_address
    unlock = Unlock(
        chain_id=UNIT_CHAIN_ID,
        message_identifier=random.randint(0, UINT64_MAX),
        payment_identifier=payment_identifier,
        nonce=mediated_transfer.nonce + 1,
        token_network_address=token_network_address,
        channel_identifier=channelstate_0_1.identifier,
        transferred_amount=lock_amount,
        locked_amount=0,
        locksroot=LOCKSROOT_OF_NO_LOCKS,
        secret=secret,
        signature=EMPTY_SIGNATURE,
    )
    app0.raiden.sign(unlock)

    if transport_protocol is TransportProtocol.MATRIX:
        messages = [unlock, reveal_secret]
        receive_method = app1.raiden.transport._receive_message
        wait = set(gevent.spawn_later(0.1, receive_method, data) for data in messages)
    else:
        raise TypeError("Unknown TransportProtocol")

    gevent.joinall(wait)


def test_regression_register_secret_once(secret_registry_address, proxy_manager):
    """Register secret transaction must not be sent if the secret is already registered"""
    # pylint: disable=protected-access

    secret_registry = proxy_manager.secret_registry(secret_registry_address)

    secret = sha3(b"test_regression_register_secret_once")
    secret_registry.register_secret(secret=secret)

    previous_nonce = proxy_manager.client._available_nonce
    secret_registry.register_secret(secret=secret)
    assert previous_nonce == proxy_manager.client._available_nonce

    previous_nonce = proxy_manager.client._available_nonce
    secret_registry.register_secret_batch(secrets=[secret])
    assert previous_nonce == proxy_manager.client._available_nonce


@raise_on_failure
@pytest.mark.parametrize("number_of_nodes", [5])
@pytest.mark.parametrize("channels_per_node", [0])
def test_regression_payment_complete_after_refund_to_the_initiator(
    raiden_network, token_addresses, settle_timeout, deposit
):
    """Regression test for issue #3915"""
    app0, app1, app2, app3, app4 = raiden_network
    token = token_addresses[0]
    registry_address = app0.raiden.default_registry.address

    # Topology:
    #
    #  0 -> 1 -> 2
    #  |         ^
    #  v         |
    #  3 ------> 4

    app_channels = [(app0, app1), (app1, app2), (app0, app3), (app3, app4), (app4, app2)]
    open_and_wait_for_channels(app_channels, registry_address, token, deposit, settle_timeout)

    # Use all deposit from app1->app2 to force a refund
    transfer(
        initiator_app=app1,
        target_app=app2,
        token_address=token,
        amount=deposit,
        identifier=PaymentID(1),
    )

    # Send a transfer that will result in a refund app1->app0
    transfer(
        initiator_app=app0,
        target_app=app2,
        token_address=token,
        amount=50,
        identifier=PaymentID(2),
        timeout=20,
    )

    assert raiden_state_changes_search_for_item(
        raiden=app0.raiden, item_type=ReceiveTransferCancelRoute, attributes={}
    )
    assert raiden_events_search_for_item(
        raiden=app0.raiden, item_type=EventRouteFailed, attributes={}
    )
