import gevent
import pytest
from eth_utils import keccak

from raiden.constants import BLOCK_ID_LATEST, EMPTY_SIGNATURE, LOCKSROOT_OF_NO_LOCKS
from raiden.messages.metadata import Metadata, RouteMetadata
from raiden.messages.transfers import Lock, LockedTransfer, RevealSecret, Unlock
from raiden.raiden_service import RaidenService
from raiden.tests.integration.fixtures.raiden_network import CHAIN, wait_for_channels
from raiden.tests.utils.detect_failure import raise_on_failure
from raiden.tests.utils.events import raiden_events_search_for_item
from raiden.tests.utils.factories import (
    UNIT_CHAIN_ID,
    make_message_identifier,
    make_secret_with_hash,
)
from raiden.tests.utils.network import payment_channel_open_and_deposit
from raiden.tests.utils.transfer import (
    create_route_state_for_route,
    get_channelstate,
    transfer,
    watch_for_unlock_failures,
)
from raiden.transfer import views
from raiden.transfer.mediated_transfer.events import SendSecretReveal
from raiden.utils.typing import (
    BlockExpiration,
    InitiatorAddress,
    List,
    LockedAmount,
    Locksroot,
    Nonce,
    PaymentAmount,
    PaymentID,
    PaymentWithFeeAmount,
    TargetAddress,
    TokenAddress,
    TokenAmount,
)

# pylint: disable=too-many-locals


def open_and_wait_for_channels(app_channels, registry_address, token, deposit, settle_timeout):
    greenlets = set()
    for first_app, second_app in app_channels:
        greenlets.add(
            gevent.spawn(
                payment_channel_open_and_deposit,
                first_app,
                second_app,
                token,
                deposit,
                settle_timeout,
            )
        )
    gevent.joinall(greenlets, raise_error=True)

    wait_for_channels(app_channels, registry_address, [token], deposit)


@raise_on_failure
@pytest.mark.parametrize("number_of_nodes", [5])
@pytest.mark.parametrize("channels_per_node", [0])
@pytest.mark.parametrize("settle_timeout", [64])  # default settlement is too low for 3 hops
def test_regression_unfiltered_routes(
    raiden_network: List[RaidenService], token_addresses, settle_timeout, deposit
):
    """The transfer should proceed without triggering an assert.

    Transfers failed in networks where two or more paths to the destination are
    possible but they share same node as a first hop.
    """
    app0, app1, app2, app3, app4 = raiden_network
    token = token_addresses[0]
    registry_address = app0.default_registry.address

    # Topology:
    #
    #  0 -> 1 -> 2 -> 4
    #       |         ^
    #       +--> 3 ---+
    app_channels = [(app0, app1), (app1, app2), (app1, app3), (app3, app4), (app2, app4)]

    open_and_wait_for_channels(app_channels, registry_address, token, deposit, settle_timeout)
    transfer(
        initiator_app=app0,
        target_app=app4,
        token_address=token,
        amount=PaymentAmount(1),
        identifier=PaymentID(1),
        routes=[[app0, app1, app2, app4]],
    )


@raise_on_failure
@pytest.mark.parametrize("number_of_nodes", [3])
@pytest.mark.parametrize("channels_per_node", [CHAIN])
def test_regression_revealsecret_after_secret(
    raiden_network: List[RaidenService], token_addresses: List[TokenAddress]
) -> None:
    """A RevealSecret message received after a Unlock message must be cleanly
    handled.
    """
    app0, app1, app2 = raiden_network
    token = token_addresses[0]
    identifier = PaymentID(1)
    token_network_registry_address = app0.default_registry.address
    token_network = views.get_token_network_by_token_address(
        views.state_from_raiden(app0), token_network_registry_address, token
    )
    assert token_network, "The fixtures must register the token"
    payment_status = app0.mediated_transfer_async(
        token_network.address,
        amount=PaymentAmount(1),
        target=TargetAddress(app2.address),
        identifier=identifier,
        route_states=[create_route_state_for_route([app0, app1, app2], token)],
    )
    with watch_for_unlock_failures(*raiden_network):
        assert payment_status.payment_done.wait()

    assert app1.wal, "The fixtures must start the app."
    event = raiden_events_search_for_item(app1, SendSecretReveal, {})
    assert event

    reveal_secret = RevealSecret(
        message_identifier=make_message_identifier(),
        secret=event.secret,
        signature=EMPTY_SIGNATURE,
    )
    app2.sign(reveal_secret)
    app1.on_messages([reveal_secret])


@raise_on_failure
@pytest.mark.parametrize("number_of_nodes", [2])
@pytest.mark.parametrize("channels_per_node", [CHAIN])
def test_regression_multiple_revealsecret(
    raiden_network: List[RaidenService], token_addresses: List[TokenAddress]
) -> None:
    """Multiple RevealSecret messages arriving at the same time must be
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
        views.state_from_raiden(app0), app0.default_registry.address, token
    )
    assert token_network_address
    channelstate_0_1 = get_channelstate(app0, app1, token_network_address)

    payment_identifier = PaymentID(1)
    secret, secrethash = make_secret_with_hash()
    expiration = BlockExpiration(app0.get_block_number() + 100)
    lock_amount = PaymentWithFeeAmount(10)
    lock = Lock(amount=lock_amount, expiration=expiration, secrethash=secrethash)

    nonce = Nonce(1)
    transferred_amount = TokenAmount(0)
    mediated_transfer = LockedTransfer(
        chain_id=UNIT_CHAIN_ID,
        message_identifier=make_message_identifier(),
        payment_identifier=payment_identifier,
        nonce=nonce,
        token_network_address=token_network_address,
        token=token,
        channel_identifier=channelstate_0_1.identifier,
        transferred_amount=transferred_amount,
        locked_amount=LockedAmount(lock_amount),
        recipient=app1.address,
        locksroot=Locksroot(lock.lockhash),
        lock=lock,
        target=TargetAddress(app1.address),
        initiator=InitiatorAddress(app0.address),
        signature=EMPTY_SIGNATURE,
        metadata=Metadata(
            routes=[RouteMetadata(route=[app0.address, app1.address], address_metadata={})]
        ),
    )
    app0.sign(mediated_transfer)
    app1.on_messages([mediated_transfer])

    reveal_secret = RevealSecret(
        message_identifier=make_message_identifier(), secret=secret, signature=EMPTY_SIGNATURE
    )
    app0.sign(reveal_secret)

    token_network_address = channelstate_0_1.token_network_address
    unlock = Unlock(
        chain_id=UNIT_CHAIN_ID,
        message_identifier=make_message_identifier(),
        payment_identifier=payment_identifier,
        nonce=Nonce(mediated_transfer.nonce + 1),
        token_network_address=token_network_address,
        channel_identifier=channelstate_0_1.identifier,
        transferred_amount=TokenAmount(lock_amount),
        locked_amount=LockedAmount(0),
        locksroot=LOCKSROOT_OF_NO_LOCKS,
        secret=secret,
        signature=EMPTY_SIGNATURE,
    )
    app0.sign(unlock)

    messages = [unlock, reveal_secret]
    receive_method = app1.on_messages
    wait = set(gevent.spawn_later(0.1, receive_method, [data]) for data in messages)

    gevent.joinall(wait, raise_error=True)


def test_regression_register_secret_once(secret_registry_address, proxy_manager):
    """Register secret transaction must not be sent if the secret is already registered"""
    # pylint: disable=protected-access

    secret_registry = proxy_manager.secret_registry(secret_registry_address, BLOCK_ID_LATEST)

    secret = keccak(b"test_regression_register_secret_once")
    secret_registry.register_secret(secret=secret)

    previous_nonce = proxy_manager.client._available_nonce
    secret_registry.register_secret(secret=secret)
    assert previous_nonce == proxy_manager.client._available_nonce

    previous_nonce = proxy_manager.client._available_nonce
    secret_registry.register_secret_batch(secrets=[secret])
    assert previous_nonce == proxy_manager.client._available_nonce
