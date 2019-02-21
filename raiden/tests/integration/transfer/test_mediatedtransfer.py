import gevent
import pytest

from raiden.exceptions import RaidenUnrecoverableError
from raiden.message_handler import MessageHandler
from raiden.messages import LockedTransfer, RevealSecret
from raiden.settings import DEFAULT_NUMBER_OF_BLOCK_CONFIRMATIONS
from raiden.tests.utils.events import search_for_item
from raiden.tests.utils.factories import UNIT_TRANSFER_INITIATOR, make_secret, make_signed_transfer
from raiden.tests.utils.network import CHAIN
from raiden.tests.utils.protocol import WaitForMessage
from raiden.tests.utils.transfer import assert_synced_channel_state, mediated_transfer, wait_assert
from raiden.transfer import views
from raiden.transfer.mediated_transfer.state_change import ActionInitMediator, ActionInitTarget
from raiden.utils import sha3
from raiden.waiting import wait_for_block


@pytest.mark.parametrize('channels_per_node', [CHAIN])
@pytest.mark.parametrize('number_of_nodes', [3])
def test_mediated_transfer(
        raiden_network,
        number_of_nodes,
        deposit,
        token_addresses,
        network_wait,
        public_and_private_rooms,
):
    app0, app1, app2 = raiden_network
    token_address = token_addresses[0]
    chain_state = views.state_from_app(app0)
    payment_network_id = app0.raiden.default_registry.address
    token_network_identifier = views.get_token_network_identifier_by_token_address(
        chain_state,
        payment_network_id,
        token_address,
    )

    amount = 10
    mediated_transfer(
        app0,
        app2,
        token_network_identifier,
        amount,
        timeout=network_wait * number_of_nodes,
    )

    with gevent.Timeout(network_wait):
        wait_assert(
            assert_synced_channel_state,
            token_network_identifier,
            app0, deposit - amount, [],
            app1, deposit + amount, [],
        )
    with gevent.Timeout(network_wait):
        wait_assert(
            assert_synced_channel_state,
            token_network_identifier,
            app1, deposit - amount, [],
            app2, deposit + amount, [],
        )


@pytest.mark.parametrize('channels_per_node', [CHAIN])
@pytest.mark.parametrize('number_of_nodes', [1])
def test_locked_transfer_secret_registered_onchain(
        raiden_network,
        token_addresses,
        secret_registry_address,
        retry_timeout,
):
    app0 = raiden_network[0]
    token_address = token_addresses[0]
    chain_state = views.state_from_app(app0)
    payment_network_id = app0.raiden.default_registry.address
    token_network_identifier = views.get_token_network_identifier_by_token_address(
        chain_state,
        payment_network_id,
        token_address,
    )

    amount = 1
    target = UNIT_TRANSFER_INITIATOR
    identifier = 1
    transfer_secret = sha3(target + b'1')

    secret_registry_proxy = app0.raiden.chain.secret_registry(
        secret_registry_address,
    )
    secret_registry_proxy.register_secret(secret=transfer_secret, given_block_identifier='latest')

    # Wait until our node has processed the block that the secret registration was mined at
    block_number = app0.raiden.get_block_number()
    wait_for_block(
        raiden=app0.raiden,
        block_number=block_number + DEFAULT_NUMBER_OF_BLOCK_CONFIRMATIONS,
        retry_timeout=retry_timeout,
    )

    # Test that sending a transfer with a secret already registered on-chain fails
    with pytest.raises(RaidenUnrecoverableError):
        app0.raiden.start_mediated_transfer_with_secret(
            token_network_identifier,
            amount,
            target,
            identifier,
            transfer_secret,
        )

    # Test that receiving a transfer with a secret already registered on chain fails
    expiration = 9999
    transfer = make_signed_transfer(
        amount,
        UNIT_TRANSFER_INITIATOR,
        app0.raiden.address,
        expiration,
        transfer_secret,
    )

    message_handler = MessageHandler()
    message_handler.handle_message_lockedtransfer(
        app0.raiden,
        transfer,
    )

    state_changes = app0.raiden.wal.storage.get_statechanges_by_identifier(0, 'latest')
    transfer_statechange_dispatched = (
        search_for_item(state_changes, ActionInitMediator, {}) or
        search_for_item(state_changes, ActionInitTarget, {})
    )
    assert not transfer_statechange_dispatched


@pytest.mark.parametrize('channels_per_node', [CHAIN])
@pytest.mark.parametrize('number_of_nodes', [3])
def test_mediated_transfer_with_entire_deposit(
        raiden_network,
        number_of_nodes,
        token_addresses,
        deposit,
        network_wait,
        public_and_private_rooms,
):
    app0, app1, app2 = raiden_network
    token_address = token_addresses[0]
    chain_state = views.state_from_app(app0)
    payment_network_id = app0.raiden.default_registry.address
    token_network_identifier = views.get_token_network_identifier_by_token_address(
        chain_state,
        payment_network_id,
        token_address,
    )
    mediated_transfer(
        app0,
        app2,
        token_network_identifier,
        deposit,
        timeout=network_wait * number_of_nodes,
    )

    mediated_transfer(
        app2,
        app0,
        token_network_identifier,
        deposit * 2,
        timeout=network_wait * number_of_nodes,
    )

    with gevent.Timeout(network_wait):
        wait_assert(
            assert_synced_channel_state,
            token_network_identifier,
            app0, deposit * 2, [],
            app1, 0, [],
        )
    with gevent.Timeout(network_wait):
        wait_assert(
            assert_synced_channel_state,
            token_network_identifier,
            app1, deposit * 2, [],
            app2, 0, [],
        )


@pytest.mark.parametrize('channels_per_node', [CHAIN])
@pytest.mark.parametrize('number_of_nodes', [3])
def test_mediated_transfer_messages_out_of_order(
        raiden_network,
        deposit,
        token_addresses,
        network_wait,
        skip_if_not_matrix,
):
    """Raiden must properly handle repeated locked transfer messages."""
    app0, app1, app2 = raiden_network

    app1_wait_for_message = WaitForMessage()
    app2_wait_for_message = WaitForMessage()

    app1.raiden.message_handler = app1_wait_for_message
    app2.raiden.message_handler = app2_wait_for_message

    secret = make_secret(0)
    secrethash = sha3(secret)

    # Save the messages, these will be processed again
    app1_mediatedtransfer = app1_wait_for_message.wait_for_message(
        LockedTransfer,
        {'lock': {'secrethash': secrethash}},
    )
    app2_mediatedtransfer = app2_wait_for_message.wait_for_message(
        LockedTransfer,
        {'lock': {'secrethash': secrethash}},
    )
    # Wait until the node receives a reveal secret to redispatch the locked
    # transfer message
    app1_revealsecret = app1_wait_for_message.wait_for_message(
        RevealSecret,
        {'secret': secret},
    )
    app2_revealsecret = app2_wait_for_message.wait_for_message(
        RevealSecret,
        {'secret': secret},
    )

    token_address = token_addresses[0]
    chain_state = views.state_from_app(app0)
    payment_network_id = app0.raiden.default_registry.address
    token_network_identifier = views.get_token_network_identifier_by_token_address(
        chain_state,
        payment_network_id,
        token_address,
    )

    amount = 10
    identifier = 1
    transfer_received = app0.raiden.start_mediated_transfer_with_secret(
        token_network_identifier,
        amount,
        app2.raiden.address,
        identifier,
        secret,
    )

    # - Wait until reveal secret is received to replay the message
    # - The secret is revealed backwards, app2 should be first
    # - The locked transfer is sent before the secret reveal, so the mediated
    #   transfers async results must be set and `get_nowait` can be used
    app2_revealsecret.get(timeout=network_wait)
    mediated_transfer_msg = app2_mediatedtransfer.get_nowait()
    app2.raiden.message_handler.handle_message_lockedtransfer(
        app2.raiden,
        mediated_transfer_msg,
    )

    app1_revealsecret.get(timeout=network_wait)
    app1.raiden.message_handler.handle_message_lockedtransfer(
        app1.raiden,
        app1_mediatedtransfer.get_nowait(),
    )

    transfer_received.payment_done.wait()
    with gevent.Timeout(network_wait):
        wait_assert(
            assert_synced_channel_state,
            token_network_identifier,
            app0, deposit - amount, [],
            app1, deposit + amount, [],
        )

    with gevent.Timeout(network_wait):
        wait_assert(
            assert_synced_channel_state,
            token_network_identifier,
            app1, deposit - amount, [],
            app2, deposit + amount, [],
        )
