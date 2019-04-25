from unittest.mock import patch

import gevent
import pytest

from raiden.exceptions import RaidenUnrecoverableError
from raiden.message_handler import MessageHandler
from raiden.messages import LockedTransfer, RevealSecret, SecretRequest
from raiden.settings import DEFAULT_NUMBER_OF_BLOCK_CONFIRMATIONS
from raiden.tests.utils import factories
from raiden.tests.utils.detect_failure import raise_on_failure
from raiden.tests.utils.events import search_for_item
from raiden.tests.utils.network import CHAIN
from raiden.tests.utils.protocol import WaitForMessage
from raiden.tests.utils.transfer import assert_synced_channel_state, transfer, wait_assert
from raiden.transfer import views
from raiden.transfer.mediated_transfer.state_change import ActionInitMediator, ActionInitTarget
from raiden.transfer.state_change import ActionChannelSetFee
from raiden.utils import sha3
from raiden.waiting import wait_for_block


@pytest.mark.parametrize("channels_per_node", [CHAIN])
@pytest.mark.parametrize("number_of_nodes", [3])
def test_mediated_transfer(
    raiden_network, number_of_nodes, deposit, token_addresses, network_wait
):
    raise_on_failure(
        raiden_network,
        run_test_mediated_transfer,
        raiden_network=raiden_network,
        number_of_nodes=number_of_nodes,
        deposit=deposit,
        token_addresses=token_addresses,
        network_wait=network_wait,
    )


def run_test_mediated_transfer(
    raiden_network, number_of_nodes, deposit, token_addresses, network_wait
):
    app0, app1, app2 = raiden_network
    token_address = token_addresses[0]
    chain_state = views.state_from_app(app0)
    payment_network_id = app0.raiden.default_registry.address
    token_network_identifier = views.get_token_network_identifier_by_token_address(
        chain_state, payment_network_id, token_address
    )

    amount = 10
    transfer(
        initiator_app=app0,
        target_app=app2,
        token_address=token_address,
        amount=amount,
        identifier=1,
        timeout=network_wait * number_of_nodes,
    )

    with gevent.Timeout(network_wait):
        wait_assert(
            assert_synced_channel_state,
            token_network_identifier,
            app0,
            deposit - amount,
            [],
            app1,
            deposit + amount,
            [],
        )
    with gevent.Timeout(network_wait):
        wait_assert(
            assert_synced_channel_state,
            token_network_identifier,
            app1,
            deposit - amount,
            [],
            app2,
            deposit + amount,
            [],
        )


@pytest.mark.parametrize("channels_per_node", [CHAIN])
@pytest.mark.parametrize("number_of_nodes", [1])
def test_locked_transfer_secret_registered_onchain(
    raiden_network, token_addresses, secret_registry_address, retry_timeout
):
    raise_on_failure(
        raiden_network,
        run_test_locked_transfer_secret_registered_onchain,
        raiden_network=raiden_network,
        token_addresses=token_addresses,
        secret_registry_address=secret_registry_address,
        retry_timeout=retry_timeout,
    )


def run_test_locked_transfer_secret_registered_onchain(
    raiden_network, token_addresses, secret_registry_address, retry_timeout
):
    app0 = raiden_network[0]
    token_address = token_addresses[0]
    chain_state = views.state_from_app(app0)
    payment_network_id = app0.raiden.default_registry.address
    token_network_identifier = views.get_token_network_identifier_by_token_address(
        chain_state, payment_network_id, token_address
    )

    amount = 1
    target = factories.UNIT_TRANSFER_INITIATOR
    identifier = 1
    transfer_secret = sha3(target + b"1")

    secret_registry_proxy = app0.raiden.chain.secret_registry(secret_registry_address)
    secret_registry_proxy.register_secret(secret=transfer_secret)

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
            token_network_identifier=token_network_identifier,
            amount=amount,
            fee=0,
            target=target,
            identifier=identifier,
            secret=transfer_secret,
        )

    # Test that receiving a transfer with a secret already registered on chain fails
    expiration = 9999
    locked_transfer = factories.create(
        factories.LockedTransferProperties(
            amount=amount,
            target=app0.raiden.address,
            expiration=expiration,
            secret=transfer_secret,
        )
    )

    message_handler = MessageHandler()
    message_handler.handle_message_lockedtransfer(app0.raiden, locked_transfer)

    state_changes = app0.raiden.wal.storage.get_statechanges_by_identifier(0, "latest")
    transfer_statechange_dispatched = search_for_item(
        state_changes, ActionInitMediator, {}
    ) or search_for_item(state_changes, ActionInitTarget, {})
    assert not transfer_statechange_dispatched


@pytest.mark.parametrize("channels_per_node", [CHAIN])
@pytest.mark.parametrize("number_of_nodes", [3])
def test_mediated_transfer_with_entire_deposit(
    raiden_network, number_of_nodes, token_addresses, deposit, network_wait
):
    raise_on_failure(
        raiden_network,
        run_test_mediated_transfer_with_entire_deposit,
        raiden_network=raiden_network,
        number_of_nodes=number_of_nodes,
        token_addresses=token_addresses,
        deposit=deposit,
        network_wait=network_wait,
    )


def run_test_mediated_transfer_with_entire_deposit(
    raiden_network, number_of_nodes, token_addresses, deposit, network_wait
):
    app0, app1, app2 = raiden_network
    token_address = token_addresses[0]
    chain_state = views.state_from_app(app0)
    payment_network_id = app0.raiden.default_registry.address
    token_network_identifier = views.get_token_network_identifier_by_token_address(
        chain_state, payment_network_id, token_address
    )
    transfer(
        initiator_app=app0,
        target_app=app2,
        token_address=token_address,
        amount=deposit,
        identifier=1,
        timeout=network_wait * number_of_nodes,
    )

    transfer(
        initiator_app=app2,
        target_app=app0,
        token_address=token_address,
        amount=deposit * 2,
        identifier=2,
        timeout=network_wait * number_of_nodes,
    )

    with gevent.Timeout(network_wait):
        wait_assert(
            assert_synced_channel_state,
            token_network_identifier,
            app0,
            deposit * 2,
            [],
            app1,
            0,
            [],
        )
    with gevent.Timeout(network_wait):
        wait_assert(
            assert_synced_channel_state,
            token_network_identifier,
            app1,
            deposit * 2,
            [],
            app2,
            0,
            [],
        )


@pytest.mark.parametrize("channels_per_node", [CHAIN])
@pytest.mark.parametrize("number_of_nodes", [3])
def test_mediated_transfer_messages_out_of_order(  # pylint: disable=unused-argument
    raiden_network, deposit, token_addresses, network_wait, skip_if_not_matrix
):
    raise_on_failure(
        raiden_network,
        run_test_mediated_transfer_messages_out_of_order,
        raiden_network=raiden_network,
        deposit=deposit,
        token_addresses=token_addresses,
        network_wait=network_wait,
    )


def run_test_mediated_transfer_messages_out_of_order(
    raiden_network, deposit, token_addresses, network_wait
):
    """Raiden must properly handle repeated locked transfer messages."""
    app0, app1, app2 = raiden_network

    app1_wait_for_message = WaitForMessage()
    app2_wait_for_message = WaitForMessage()

    app1.raiden.message_handler = app1_wait_for_message
    app2.raiden.message_handler = app2_wait_for_message

    secret = factories.make_secret(0)
    secrethash = sha3(secret)

    # Save the messages, these will be processed again
    app1_mediatedtransfer = app1_wait_for_message.wait_for_message(
        LockedTransfer, {"lock": {"secrethash": secrethash}}
    )
    app2_mediatedtransfer = app2_wait_for_message.wait_for_message(
        LockedTransfer, {"lock": {"secrethash": secrethash}}
    )
    # Wait until the node receives a reveal secret to redispatch the locked
    # transfer message
    app1_revealsecret = app1_wait_for_message.wait_for_message(RevealSecret, {"secret": secret})
    app2_revealsecret = app2_wait_for_message.wait_for_message(RevealSecret, {"secret": secret})

    token_address = token_addresses[0]
    chain_state = views.state_from_app(app0)
    payment_network_id = app0.raiden.default_registry.address
    token_network_identifier = views.get_token_network_identifier_by_token_address(
        chain_state, payment_network_id, token_address
    )

    amount = 10
    identifier = 1
    transfer_received = app0.raiden.start_mediated_transfer_with_secret(
        token_network_identifier=token_network_identifier,
        amount=amount,
        fee=0,
        target=app2.raiden.address,
        identifier=identifier,
        secret=secret,
    )

    # - Wait until reveal secret is received to replay the message
    # - The secret is revealed backwards, app2 should be first
    # - The locked transfer is sent before the secret reveal, so the mediated
    #   transfers async results must be set and `get_nowait` can be used
    app2_revealsecret.get(timeout=network_wait)
    mediated_transfer_msg = app2_mediatedtransfer.get_nowait()
    app2.raiden.message_handler.handle_message_lockedtransfer(app2.raiden, mediated_transfer_msg)

    app1_revealsecret.get(timeout=network_wait)
    app1.raiden.message_handler.handle_message_lockedtransfer(
        app1.raiden, app1_mediatedtransfer.get_nowait()
    )

    transfer_received.payment_done.wait()
    with gevent.Timeout(network_wait):
        wait_assert(
            assert_synced_channel_state,
            token_network_identifier,
            app0,
            deposit - amount,
            [],
            app1,
            deposit + amount,
            [],
        )

    with gevent.Timeout(network_wait):
        wait_assert(
            assert_synced_channel_state,
            token_network_identifier,
            app1,
            deposit - amount,
            [],
            app2,
            deposit + amount,
            [],
        )


@pytest.mark.parametrize("number_of_nodes", (1,))
@pytest.mark.parametrize("channels_per_node", (CHAIN,))
def test_mediated_transfer_calls_pfs(raiden_network, token_addresses):
    raise_on_failure(
        raiden_network,
        run_test_mediated_transfer_calls_pfs,
        raiden_network=raiden_network,
        token_addresses=token_addresses,
    )


def run_test_mediated_transfer_calls_pfs(raiden_network, token_addresses):
    app0, = raiden_network
    token_address = token_addresses[0]
    chain_state = views.state_from_app(app0)
    payment_network_id = app0.raiden.default_registry.address
    token_network_id = views.get_token_network_identifier_by_token_address(
        chain_state, payment_network_id, token_address
    )

    with patch("raiden.routing.query_paths", return_value=[]) as patched:

        app0.raiden.start_mediated_transfer_with_secret(
            token_network_identifier=token_network_id,
            amount=10,
            fee=0,
            target=factories.HOP1,
            identifier=1,
            secret=b"1" * 32,
        )
        assert not patched.called

        config_patch = dict(
            pathfinding_service_address="mock-address",
            pathfinding_eth_address=factories.make_checksum_address(),
        )

        with patch.dict(app0.raiden.config["services"], config_patch):
            app0.raiden.start_mediated_transfer_with_secret(
                token_network_identifier=token_network_id,
                amount=11,
                fee=0,
                target=factories.HOP2,
                identifier=2,
                secret=b"2" * 32,
            )
            assert patched.call_count == 1

            locked_transfer = factories.create(
                factories.LockedTransferProperties(
                    amount=5,
                    initiator=factories.HOP1,
                    target=factories.HOP2,
                    sender=factories.HOP1,
                    pkey=factories.HOP1_KEY,
                    token=token_address,
                    canonical_identifier=factories.make_canonical_identifier(
                        token_network_address=token_network_id
                    ),
                )
            )
            app0.raiden.mediate_mediated_transfer(locked_transfer)
            assert patched.call_count == 2


@pytest.mark.parametrize("channels_per_node", [CHAIN])
@pytest.mark.parametrize("number_of_nodes", [4])
def test_mediated_transfer_with_allocated_fee(
    raiden_network, number_of_nodes, deposit, token_addresses, network_wait
):
    """
    Tests the topology of:
    A -> B -> C -> D
    Where C & D are mediators who gain tokens by mediating transfers.
    The test checks that if no mediator sets the channel fee, then the fees
    sent by the initiator will be gained completely by the target as no fees
    will be deducted by the mediators.
    However, if the mediator sets the fee, the channel's fee will be
    deducted from received transfer's fee and the rest goes to
    the mediators in the next hops and maybe eventually to the target.
    """
    raise_on_failure(
        raiden_network,
        run_test_mediated_transfer_with_allocated_fee,
        raiden_network=raiden_network,
        number_of_nodes=number_of_nodes,
        deposit=deposit,
        token_addresses=token_addresses,
        network_wait=network_wait,
    )


def run_test_mediated_transfer_with_allocated_fee(
    raiden_network, number_of_nodes, deposit, token_addresses, network_wait
):
    app0, app1, app2, app3 = raiden_network
    token_address = token_addresses[0]
    chain_state = views.state_from_app(app0)
    payment_network_id = app0.raiden.default_registry.address
    token_network_identifier = views.get_token_network_identifier_by_token_address(
        chain_state, payment_network_id, token_address
    )
    fee = 5
    amount = 10

    transfer(
        initiator_app=app0,
        target_app=app3,
        token_address=token_address,
        amount=amount,
        identifier=1,
        fee=fee,
        timeout=network_wait * number_of_nodes,
    )

    with gevent.Timeout(network_wait):
        wait_assert(
            assert_synced_channel_state,
            token_network_identifier,
            app0,
            deposit - amount - fee,
            [],
            app1,
            deposit + amount + fee,
            [],
        )
    with gevent.Timeout(network_wait):
        wait_assert(
            assert_synced_channel_state,
            token_network_identifier,
            app1,
            deposit - amount - fee,
            [],
            app2,
            deposit + amount + fee,
            [],
        )

    app1_app2_channel_state = views.get_channelstate_by_token_network_and_partner(
        chain_state=views.state_from_raiden(app1.raiden),
        token_network_id=token_network_identifier,
        partner_address=app2.raiden.address,
    )

    # Let app1 consume all of the allocated mediation fee
    action_set_fee = ActionChannelSetFee(
        canonical_identifier=app1_app2_channel_state.canonical_identifier, mediation_fee=fee
    )

    app1.raiden.handle_state_change(state_change=action_set_fee)

    transfer(
        initiator_app=app0,
        target_app=app3,
        token_address=token_address,
        amount=amount,
        identifier=2,
        fee=fee,
        timeout=network_wait * number_of_nodes,
    )

    # The fees have been consumed exclusively by app1
    with gevent.Timeout(network_wait):
        wait_assert(
            assert_synced_channel_state,
            token_network_identifier,
            app0,
            deposit - 2 * (amount + fee),
            [],
            app1,
            deposit + 2 * (amount + fee),
            [],
        )

    # app2's poor soul gets no mediation fees on the second transfer.
    # Only the first transfer had a fee which was paid to app2 though
    # app2 doesn't set its fee but it would still receive the complete
    # locked amount = transfer amount + fee.
    # However app1 received from app0 two transfers
    # which it sent to app2. The first transfer
    # to app2 included the fee as it did not deduct
    # any fee (the channel's fee was 0).
    # The second transfer's fee was deducted by
    # app1 (provided we've set the fee of the channel)
    with gevent.Timeout(network_wait):
        wait_assert(
            assert_synced_channel_state,
            token_network_identifier,
            app1,
            deposit - (amount * 2) - fee,
            [],
            app2,
            deposit + (amount * 2) + fee,
            [],
        )


# pylint: disable=unused-argument
@pytest.mark.parametrize("channels_per_node", [CHAIN])
@pytest.mark.parametrize("number_of_nodes", [3])
def test_mediated_transfer_with_node_consuming_more_than_allocated_fee(
    raiden_network, number_of_nodes, deposit, token_addresses, network_wait
):
    """
    Tests a mediator node consuming more fees than allocated.
    Which means that the initiator will not reveal the secret
    to the target.
    """
    raise_on_failure(
        raiden_network,
        run_test_mediated_transfer_with_node_consuming_more_than_allocated_fee,
        raiden_network=raiden_network,
        number_of_nodes=number_of_nodes,
        deposit=deposit,
        token_addresses=token_addresses,
        network_wait=network_wait,
    )


def run_test_mediated_transfer_with_node_consuming_more_than_allocated_fee(
    raiden_network, number_of_nodes, deposit, token_addresses, network_wait
):
    app0, app1, app2 = raiden_network
    token_address = token_addresses[0]
    chain_state = views.state_from_app(app0)
    payment_network_id = app0.raiden.default_registry.address
    token_network_identifier = views.get_token_network_identifier_by_token_address(
        chain_state, payment_network_id, token_address
    )
    fee = 5
    amount = 10

    app1_app2_channel_state = views.get_channelstate_by_token_network_and_partner(
        chain_state=views.state_from_raiden(app1.raiden),
        token_network_id=token_network_identifier,
        partner_address=app2.raiden.address,
    )

    # Let app1 consume all of the allocated mediation fee
    action_set_fee = ActionChannelSetFee(
        canonical_identifier=app1_app2_channel_state.canonical_identifier, mediation_fee=fee * 2
    )

    app1.raiden.handle_state_change(state_change=action_set_fee)

    secret = factories.make_secret(0)
    secrethash = sha3(secret)

    wait_message_handler = WaitForMessage()
    app0.raiden.message_handler = wait_message_handler
    secret_request_received = wait_message_handler.wait_for_message(
        SecretRequest, {"secrethash": secrethash}
    )

    app0.raiden.start_mediated_transfer_with_secret(
        token_network_identifier=token_network_identifier,
        amount=amount,
        fee=fee,
        target=app2.raiden.address,
        identifier=1,
        secret=secret,
    )

    app0_app1_channel_state = views.get_channelstate_by_token_network_and_partner(
        chain_state=views.state_from_raiden(app0.raiden),
        token_network_id=token_network_identifier,
        partner_address=app1.raiden.address,
    )

    msg = "App0 should have the transfer in secrethashes_to_lockedlocks"
    assert secrethash in app0_app1_channel_state.our_state.secrethashes_to_lockedlocks, msg

    msg = "App0 should have locked the amount + fee"
    lock_amount = app0_app1_channel_state.our_state.secrethashes_to_lockedlocks[secrethash].amount
    assert lock_amount == amount + fee, msg

    secret_request_received.wait()

    app0_chain_state = views.state_from_app(app0)
    initiator_task = app0_chain_state.payment_mapping.secrethashes_to_task[secrethash]

    msg = "App0 should have never revealed the secret"
    assert initiator_task.manager_state.initiator_transfers[secrethash].revealsecret is None
