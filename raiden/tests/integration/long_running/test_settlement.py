import random
from unittest.mock import patch

import gevent
import pytest
from eth_utils import keccak
from gevent import Timeout

from raiden import waiting
from raiden.api.python import RaidenAPI
from raiden.constants import BLOCK_ID_LATEST, EMPTY_SIGNATURE, UINT64_MAX
from raiden.exceptions import InvalidSecret, RaidenUnrecoverableError
from raiden.messages.transfers import LockedTransfer, LockExpired, RevealSecret, Unlock
from raiden.messages.withdraw import WithdrawExpired
from raiden.raiden_service import RaidenService
from raiden.settings import DEFAULT_RETRY_TIMEOUT
from raiden.storage.restore import channel_state_until_state_change
from raiden.storage.sqlite import HIGH_STATECHANGE_ULID, RANGE_ALL_STATE_CHANGES
from raiden.tests.utils import factories
from raiden.tests.utils.client import burn_eth
from raiden.tests.utils.detect_failure import expect_failure, raise_on_failure
from raiden.tests.utils.events import raiden_state_changes_search_for_item, search_for_item
from raiden.tests.utils.network import CHAIN
from raiden.tests.utils.protocol import HoldRaidenEventHandler, WaitForMessage
from raiden.tests.utils.transfer import (
    assert_synced_channel_state,
    block_offset_timeout,
    create_route_state_for_route,
    get_channelstate,
    transfer,
)
from raiden.transfer import channel, views
from raiden.transfer.events import SendWithdrawConfirmation
from raiden.transfer.identifiers import CanonicalIdentifier
from raiden.transfer.state import NettingChannelState
from raiden.transfer.state_change import (
    ContractReceiveChannelBatchUnlock,
    ContractReceiveChannelClosed,
    ContractReceiveChannelSettled,
)
from raiden.utils.formatting import to_checksum_address
from raiden.utils.secrethash import sha256_secrethash
from raiden.utils.typing import (
    Address,
    Balance,
    BlockNumber,
    BlockTimeout as BlockOffset,
    List,
    MessageID,
    PaymentAmount,
    PaymentID,
    Secret,
    SecretRegistryAddress,
    TargetAddress,
    TokenAddress,
    TokenAmount,
    TokenNetworkAddress,
    WithdrawAmount,
)

MSG_BLOCKCHAIN_EVENTS = "Waiting for blockchain events requires a running node and alarm task."


def wait_for_batch_unlock(
    app: RaidenService,
    token_network_address: TokenNetworkAddress,
    receiver: Address,
    sender: Address,
) -> None:
    unlock_event = None
    while not unlock_event:
        gevent.sleep(1)

        assert app.wal, MSG_BLOCKCHAIN_EVENTS
        assert app.alarm, MSG_BLOCKCHAIN_EVENTS

        state_changes = app.wal.storage.get_statechanges_by_range(RANGE_ALL_STATE_CHANGES)

        unlock_event = search_for_item(
            state_changes,
            ContractReceiveChannelBatchUnlock,
            {
                "token_network_address": token_network_address,
                "receiver": receiver,
                "sender": sender,
            },
        )


def is_channel_registered(
    node_app: RaidenService, partner_app: RaidenService, canonical_identifier: CanonicalIdentifier
) -> bool:
    """True if the `node_app` has a channel with `partner_app` in its state."""
    token_network = views.get_token_network_by_address(
        chain_state=views.state_from_raiden(node_app),
        token_network_address=canonical_identifier.token_network_address,
    )
    assert token_network

    is_in_channelid_map = (
        canonical_identifier.channel_identifier in token_network.channelidentifiers_to_channels
    )
    is_in_partner_map = (
        canonical_identifier.channel_identifier
        in token_network.partneraddresses_to_channelidentifiers[partner_app.address]
    )

    return is_in_channelid_map and is_in_partner_map


@raise_on_failure
@pytest.mark.parametrize("number_of_nodes", [2])
def test_settle_is_automatically_called(
    raiden_network: List[RaidenService], token_addresses: List[TokenAddress]
) -> None:
    """Settle is automatically called by one of the nodes."""
    app0, app1 = raiden_network
    registry_address = app0.default_registry.address
    token_address = token_addresses[0]
    token_network_address = views.get_token_network_address_by_token_address(
        views.state_from_raiden(app0), app0.default_registry.address, token_address
    )
    assert token_network_address
    token_network = views.get_token_network_by_address(
        views.state_from_raiden(app0), token_network_address
    )
    assert token_network

    channel_identifier = get_channelstate(app0, app1, token_network_address).identifier

    assert channel_identifier in token_network.partneraddresses_to_channelidentifiers[app1.address]

    # A ChannelClose event will be generated, this will be polled by both apps
    # and each must start a task for calling settle
    RaidenAPI(app1).channel_close(registry_address, token_address, app0.address, coop_settle=False)

    waiting.wait_for_close(
        app0,
        registry_address,
        token_address,
        [channel_identifier],
        app0.alarm.sleep_time,
    )

    channel_state = views.get_channelstate_for(
        views.state_from_raiden(app0), registry_address, token_address, app1.address
    )
    assert channel_state
    assert channel_state.close_transaction
    assert channel_state.close_transaction.finished_block_number

    waiting.wait_for_settle(
        app0,
        registry_address,
        token_address,
        [channel_identifier],
        app0.alarm.sleep_time,
    )

    token_network = views.get_token_network_by_address(
        views.state_from_raiden(app0), token_network_address
    )
    assert token_network

    assert (
        channel_identifier
        not in token_network.partneraddresses_to_channelidentifiers[app1.address]
    )

    assert app0.wal, MSG_BLOCKCHAIN_EVENTS
    assert app0.alarm, MSG_BLOCKCHAIN_EVENTS
    state_changes = app0.wal.storage.get_statechanges_by_range(RANGE_ALL_STATE_CHANGES)

    assert search_for_item(
        state_changes,
        ContractReceiveChannelClosed,
        {
            "token_network_address": token_network_address,
            "channel_identifier": channel_identifier,
            "transaction_from": app1.address,
            "block_number": channel_state.close_transaction.finished_block_number,
        },
    )

    assert search_for_item(
        state_changes,
        ContractReceiveChannelSettled,
        {"token_network_address": token_network_address, "channel_identifier": channel_identifier},
    )


@raise_on_failure
@pytest.mark.parametrize("number_of_nodes", [2])
def test_lock_expiry(
    raiden_network: List[RaidenService], token_addresses: List[TokenAddress], deposit: TokenAmount
) -> None:
    """Test lock expiry and removal."""
    alice_app, bob_app = raiden_network
    token_address = token_addresses[0]
    token_network_address = views.get_token_network_address_by_token_address(
        views.state_from_raiden(alice_app),
        alice_app.default_registry.address,
        token_address,
    )
    assert token_network_address

    hold_event_handler = bob_app.raiden_event_handler
    wait_message_handler = bob_app.message_handler

    msg = "hold event handler necessary to control messages"
    assert isinstance(hold_event_handler, HoldRaidenEventHandler), msg
    assert isinstance(wait_message_handler, WaitForMessage), msg

    token_network = views.get_token_network_by_address(
        views.state_from_raiden(alice_app), token_network_address
    )
    assert token_network

    channel_state = get_channelstate(alice_app, bob_app, token_network_address)
    channel_identifier = channel_state.identifier

    assert (
        channel_identifier in token_network.partneraddresses_to_channelidentifiers[bob_app.address]
    )

    alice_to_bob_amount = PaymentAmount(10)
    identifier = factories.make_payment_id()
    target = TargetAddress(bob_app.address)
    transfer_1_secret = factories.make_secret(0)
    transfer_1_secrethash = sha256_secrethash(transfer_1_secret)
    transfer_2_secret = factories.make_secret(1)
    transfer_2_secrethash = sha256_secrethash(transfer_2_secret)

    hold_event_handler.hold_secretrequest_for(secrethash=transfer_1_secrethash)
    transfer1_received = wait_message_handler.wait_for_message(
        LockedTransfer, {"lock": {"secrethash": transfer_1_secrethash}}
    )
    transfer2_received = wait_message_handler.wait_for_message(
        LockedTransfer, {"lock": {"secrethash": transfer_2_secrethash}}
    )
    remove_expired_lock_received = wait_message_handler.wait_for_message(
        LockExpired, {"secrethash": transfer_1_secrethash}
    )

    with patch("raiden.message_handler.decrypt_secret", side_effect=InvalidSecret):
        alice_app.mediated_transfer_async(
            token_network_address=token_network_address,
            amount=alice_to_bob_amount,
            target=target,
            identifier=identifier,
            secret=transfer_1_secret,
            route_states=[create_route_state_for_route([alice_app, bob_app], token_address)],
        )
        transfer1_received.wait()

    alice_bob_channel_state = get_channelstate(alice_app, bob_app, token_network_address)
    lock = channel.get_lock(alice_bob_channel_state.our_state, transfer_1_secrethash)
    assert lock

    # This is the current state of the protocol:
    #
    #    A -> B LockedTransfer
    #    B -> A SecretRequest
    #    - protocol didn't continue
    assert_synced_channel_state(
        token_network_address, alice_app, Balance(deposit), [lock], bob_app, Balance(deposit), []
    )

    # Verify lock is registered in both channel states
    alice_channel_state = get_channelstate(alice_app, bob_app, token_network_address)
    assert transfer_1_secrethash in alice_channel_state.our_state.secrethashes_to_lockedlocks

    bob_channel_state = get_channelstate(bob_app, alice_app, token_network_address)
    assert transfer_1_secrethash in bob_channel_state.partner_state.secrethashes_to_lockedlocks

    alice_chain_state = views.state_from_raiden(alice_app)
    assert transfer_1_secrethash in alice_chain_state.payment_mapping.secrethashes_to_task

    remove_expired_lock_received.wait()

    alice_channel_state = get_channelstate(alice_app, bob_app, token_network_address)
    assert transfer_1_secrethash not in alice_channel_state.our_state.secrethashes_to_lockedlocks

    # Verify Bob received the message and processed the LockExpired message
    bob_channel_state = get_channelstate(bob_app, alice_app, token_network_address)
    assert transfer_1_secrethash not in bob_channel_state.partner_state.secrethashes_to_lockedlocks

    alice_chain_state = views.state_from_raiden(alice_app)
    assert transfer_1_secrethash not in alice_chain_state.payment_mapping.secrethashes_to_task

    # Make another transfer
    alice_to_bob_amount = PaymentAmount(10)
    identifier = factories.make_payment_id()

    hold_event_handler.hold_secretrequest_for(secrethash=transfer_2_secrethash)

    with patch("raiden.message_handler.decrypt_secret", side_effect=InvalidSecret):
        alice_app.mediated_transfer_async(
            token_network_address=token_network_address,
            amount=alice_to_bob_amount,
            target=target,
            identifier=identifier,
            secret=transfer_2_secret,
            route_states=[create_route_state_for_route([alice_app, bob_app], token_address)],
        )
        transfer2_received.wait()

    # Make sure the other transfer still exists
    alice_chain_state = views.state_from_raiden(alice_app)
    assert transfer_2_secrethash in alice_chain_state.payment_mapping.secrethashes_to_task

    bob_channel_state = get_channelstate(bob_app, alice_app, token_network_address)
    assert transfer_2_secrethash in bob_channel_state.partner_state.secrethashes_to_lockedlocks


@raise_on_failure
@pytest.mark.parametrize("number_of_nodes", [2])
def test_batch_unlock(
    raiden_network: List[RaidenService],
    token_addresses: List[TokenAddress],
    secret_registry_address: SecretRegistryAddress,
    deposit: TokenAmount,
) -> None:
    """Tests that batch unlock is properly called.

    This test will start a single incomplete transfer, the secret will be
    revealed *on-chain*. The node that receives the tokens has to call unlock,
    the node that doesn't gain anything does nothing.
    """
    alice_app, bob_app = raiden_network
    alice_address = alice_app.address
    bob_address = bob_app.address

    token_network_registry_address = alice_app.default_registry.address
    token_address = token_addresses[0]
    token_network_address = views.get_token_network_address_by_token_address(
        views.state_from_raiden(alice_app), token_network_registry_address, token_address
    )
    assert token_network_address

    hold_event_handler = bob_app.raiden_event_handler
    assert isinstance(hold_event_handler, HoldRaidenEventHandler)

    canonical_identifier = get_channelstate(
        alice_app, bob_app, token_network_address
    ).canonical_identifier

    assert is_channel_registered(alice_app, bob_app, canonical_identifier)
    assert is_channel_registered(bob_app, alice_app, canonical_identifier)

    token_proxy = alice_app.proxy_manager.token(token_address, BLOCK_ID_LATEST)
    alice_initial_balance = token_proxy.balance_of(alice_app.address)
    bob_initial_balance = token_proxy.balance_of(bob_app.address)

    alice_to_bob_amount = 10
    identifier = 1
    secret = Secret(keccak(bob_address))
    secrethash = sha256_secrethash(secret)

    secret_request_event = hold_event_handler.hold_secretrequest_for(secrethash=secrethash)

    with patch("raiden.message_handler.decrypt_secret", side_effect=InvalidSecret):
        alice_app.mediated_transfer_async(
            token_network_address=token_network_address,
            amount=PaymentAmount(alice_to_bob_amount),
            target=TargetAddress(bob_address),
            identifier=PaymentID(identifier),
            secret=secret,
            route_states=[create_route_state_for_route([alice_app, bob_app], token_address)],
        )

        secret_request_event.get()  # wait for the messages to be exchanged

    alice_bob_channel_state = get_channelstate(alice_app, bob_app, token_network_address)
    lock = channel.get_lock(alice_bob_channel_state.our_state, secrethash)
    assert lock

    # This is the current state of the protocol:
    #
    #    A -> B LockedTransfer
    #    B -> A SecretRequest
    #    - protocol didn't continue
    assert_synced_channel_state(
        token_network_address, alice_app, Balance(deposit), [lock], bob_app, Balance(deposit), []
    )

    # Test WAL restore to return the latest channel state
    assert alice_app.wal, "WAL must be set."
    alice_app.wal.snapshot(alice_app.state_change_qty)
    our_balance_proof = alice_bob_channel_state.our_state.balance_proof
    restored_channel_state = channel_state_until_state_change(
        raiden=alice_app,
        canonical_identifier=alice_bob_channel_state.canonical_identifier,
        state_change_identifier=HIGH_STATECHANGE_ULID,
    )
    assert restored_channel_state
    our_restored_balance_proof = restored_channel_state.our_state.balance_proof
    assert our_balance_proof == our_restored_balance_proof

    # Close the channel before revealing the secret off-chain. This will leave
    # a pending lock in the channel which has to be unlocked on-chain.
    #
    # The token network will emit a ChannelClose event, this will be polled by
    # both apps and each must start a task for calling settle.
    RaidenAPI(bob_app).channel_close(
        token_network_registry_address, token_address, alice_app.address, coop_settle=False
    )

    # The secret has to be registered manually because Bob never learned the
    # secret. The test is holding the SecretRequest to ensure the off-chain
    # unlock will not happen and the channel is closed with a pending lock.
    #
    # Alternatives would be to hold the unlock messages, or to stop and restart
    # the apps after the channel is closed.
    secret_registry_proxy = alice_app.proxy_manager.secret_registry(
        secret_registry_address, block_identifier=BLOCK_ID_LATEST
    )
    secret_registry_proxy.register_secret(secret=secret)

    msg = (
        "The lock must still be part of the node state for the test to proceed, "
        "otherwise there is not unlock to be done."
    )
    assert lock, msg

    msg = (
        "The secret must be registered before the lock expires, in order for "
        "the unlock to happen on-chain. Otherwise the test will fail on the "
        "expected balances."
    )
    assert lock.expiration > alice_app.get_block_number(), msg
    assert lock.secrethash == sha256_secrethash(secret)

    waiting.wait_for_settle(
        alice_app,
        token_network_registry_address,
        token_address,
        [alice_bob_channel_state.identifier],
        alice_app.alarm.sleep_time,
    )

    msg = "The channel_state must not have been cleared, one of the ends has pending locks to do."
    assert is_channel_registered(alice_app, bob_app, canonical_identifier), msg
    assert is_channel_registered(bob_app, alice_app, canonical_identifier), msg

    msg = (
        "Timeout while waiting for the unlock to be mined. This may happen if "
        "transaction is rejected, not mined, or the node's alarm task is "
        "not running."
    )
    with gevent.Timeout(seconds=30, exception=AssertionError(msg)):
        # Wait for both nodes (Bob and Alice) to see the on-chain unlock
        wait_for_batch_unlock(
            app=alice_app,
            token_network_address=token_network_address,
            receiver=bob_address,
            sender=alice_address,
        )
        wait_for_batch_unlock(
            app=bob_app,
            token_network_address=token_network_address,
            receiver=bob_address,
            sender=alice_address,
        )

    msg = (
        "The nodes have done the unlock, and both ends have seen it, now the "
        "channel must be cleared"
    )
    assert not is_channel_registered(alice_app, bob_app, canonical_identifier), msg
    assert not is_channel_registered(bob_app, alice_app, canonical_identifier), msg

    alice_new_balance = alice_initial_balance + deposit - alice_to_bob_amount
    bob_new_balance = bob_initial_balance + deposit + alice_to_bob_amount

    msg = "Unexpected end balance after channel settlement with batch unlock."
    assert token_proxy.balance_of(alice_app.address) == alice_new_balance, msg
    assert token_proxy.balance_of(bob_app.address) == bob_new_balance, msg


@raise_on_failure
@pytest.mark.parametrize("number_of_nodes", [2])
def test_channel_withdraw(
    raiden_network: List[RaidenService],
    token_addresses: List[TokenAddress],
    deposit: TokenAmount,
    retry_timeout: float,
    pfs_mock,
) -> None:
    """Withdraw funds after a mediated transfer."""
    alice_app, bob_app = raiden_network

    pfs_mock.add_apps(raiden_network)

    token_address = token_addresses[0]
    token_network_address = views.get_token_network_address_by_token_address(
        views.state_from_raiden(alice_app),
        alice_app.default_registry.address,
        token_address,
    )
    assert token_network_address

    token_proxy = bob_app.proxy_manager.token(token_address, BLOCK_ID_LATEST)
    bob_initial_balance = token_proxy.balance_of(bob_app.address)

    message_handler = WaitForMessage()
    bob_app.message_handler = message_handler

    alice_to_bob_amount = PaymentAmount(10)
    identifier = PaymentID(1)
    target = TargetAddress(bob_app.address)
    secret = factories.make_secret()

    payment_status = alice_app.mediated_transfer_async(
        token_network_address=token_network_address,
        amount=alice_to_bob_amount,
        target=target,
        identifier=identifier,
        secret=secret,
        route_states=[create_route_state_for_route([alice_app, bob_app], token_address)],
    )
    wait_for_unlock = bob_app.message_handler.wait_for_message(
        Unlock, {"payment_identifier": identifier}
    )
    with block_offset_timeout(alice_app):
        wait_for_unlock.get()
        msg = (
            f"transfer from {to_checksum_address(alice_app.address)} "
            f"to {to_checksum_address(bob_app.address)} failed."
        )
        assert payment_status.payment_done.get(), msg

    total_withdraw = WithdrawAmount(deposit + alice_to_bob_amount)

    bob_alice_channel_state = get_channelstate(bob_app, alice_app, token_network_address)

    alice_metadata = pfs_mock.query_address_metadata(bob_app.config.pfs_config, alice_app.address)
    bob_app.withdraw(
        canonical_identifier=bob_alice_channel_state.canonical_identifier,
        total_withdraw=total_withdraw,
        recipient_metadata=alice_metadata,
    )

    waiting.wait_for_withdraw_complete(
        raiden=bob_app,
        canonical_identifier=bob_alice_channel_state.canonical_identifier,
        total_withdraw=total_withdraw,
        retry_timeout=retry_timeout,
    )

    bob_balance_after_withdraw = token_proxy.balance_of(bob_app.address)
    assert bob_initial_balance + total_withdraw == bob_balance_after_withdraw


@raise_on_failure
@pytest.mark.parametrize("number_of_nodes", [2])
def test_channel_withdraw_expired(
    raiden_network: List[RaidenService],
    network_wait: float,
    number_of_nodes: int,
    token_addresses: List[TokenAddress],
    deposit: TokenAmount,
    retry_timeout: float,
    pfs_mock,
) -> None:
    """Tests withdraw expiration."""
    alice_app, bob_app = raiden_network
    pfs_mock.add_apps(raiden_network)

    token_address = token_addresses[0]
    token_network_address = views.get_token_network_address_by_token_address(
        views.state_from_raiden(alice_app),
        alice_app.default_registry.address,
        token_address,
    )
    assert token_network_address

    msg = "hold event handler necessary to control messages"
    assert isinstance(alice_app.raiden_event_handler, HoldRaidenEventHandler), msg
    assert isinstance(alice_app.message_handler, WaitForMessage), msg

    msg = "hold event handler necessary to control messages"
    assert isinstance(bob_app.raiden_event_handler, HoldRaidenEventHandler), msg
    assert isinstance(bob_app.message_handler, WaitForMessage), msg

    # Prevent withdraw confirmation from being sent
    send_withdraw_confirmation_event = alice_app.raiden_event_handler.hold(
        SendWithdrawConfirmation, {}
    )

    alice_to_bob_amount = PaymentAmount(10)
    total_withdraw = WithdrawAmount(deposit + alice_to_bob_amount)
    wait_for_withdraw_expired_message = alice_app.message_handler.wait_for_message(
        WithdrawExpired, {"total_withdraw": total_withdraw}
    )

    identifier = PaymentID(1)
    target = TargetAddress(bob_app.address)
    secret = factories.make_secret()

    payment_status = alice_app.mediated_transfer_async(
        token_network_address=token_network_address,
        amount=alice_to_bob_amount,
        target=target,
        identifier=identifier,
        secret=secret,
        route_states=[create_route_state_for_route([alice_app, bob_app], token_address)],
    )
    wait_for_unlock = bob_app.message_handler.wait_for_message(
        Unlock, {"payment_identifier": identifier}
    )
    with block_offset_timeout(alice_app):
        wait_for_unlock.get()
        msg = (
            f"transfer from {to_checksum_address(alice_app.address)} "
            f"to {to_checksum_address(bob_app.address)} failed."
        )
        assert payment_status.payment_done.get(), msg

    bob_alice_channel_state = get_channelstate(bob_app, alice_app, token_network_address)

    alice_metadata = pfs_mock.query_address_metadata(bob_app.config.pfs_config, alice_app.address)
    bob_app.withdraw(
        canonical_identifier=bob_alice_channel_state.canonical_identifier,
        total_withdraw=total_withdraw,
        recipient_metadata=alice_metadata,
    )

    with block_offset_timeout(bob_app):
        send_withdraw_confirmation_event.wait()

    # Make sure proper withdraw state is set in both channel states
    bob_alice_channel_state = get_channelstate(bob_app, alice_app, token_network_address)
    assert bob_alice_channel_state.our_total_withdraw == total_withdraw
    assert bob_alice_channel_state.our_state.withdraws_pending.get(total_withdraw) is not None

    alice_bob_channel_state = get_channelstate(alice_app, bob_app, token_network_address)
    assert alice_bob_channel_state.partner_total_withdraw == total_withdraw
    assert alice_bob_channel_state.partner_state.withdraws_pending.get(total_withdraw) is not None

    withdraw_expiration = bob_alice_channel_state.our_state.withdraws_pending[
        total_withdraw
    ].expiration
    expiration_threshold = channel.get_sender_expiration_threshold(withdraw_expiration)

    waiting.wait_for_block(
        raiden=bob_app,
        block_number=BlockNumber(expiration_threshold + 1),
        retry_timeout=retry_timeout,
    )

    bob_alice_channel_state = get_channelstate(bob_app, alice_app, token_network_address)
    assert bob_alice_channel_state.our_total_withdraw == 0
    assert bob_alice_channel_state.our_state.withdraws_pending.get(total_withdraw) is None

    with gevent.Timeout(network_wait * number_of_nodes):
        wait_for_withdraw_expired_message.wait()

        alice_bob_channel_state = get_channelstate(alice_app, bob_app, token_network_address)
        assert alice_bob_channel_state.partner_total_withdraw == 0
        assert alice_bob_channel_state.partner_state.withdraws_pending.get(total_withdraw) is None


@raise_on_failure
@pytest.mark.parametrize("number_of_nodes", [2])
@pytest.mark.parametrize("channels_per_node", [CHAIN])
def test_settled_lock(
    token_addresses: List[TokenAddress],
    raiden_network: List[RaidenService],
    deposit: TokenAmount,
    retry_timeout,
) -> None:
    """Any transfer following a secret reveal must update the locksroot, so
    that an attacker cannot reuse a secret to double claim a lock.
    """
    app0, app1 = raiden_network
    registry_address = app0.default_registry.address
    token_address = token_addresses[0]
    amount = PaymentAmount(30)
    token_network_address = views.get_token_network_address_by_token_address(
        views.state_from_raiden(app0), app0.default_registry.address, token_address
    )
    assert token_network_address

    hold_event_handler = app1.raiden_event_handler

    msg = "hold event handler necessary to control messages"
    assert isinstance(hold_event_handler, HoldRaidenEventHandler), msg

    address0 = app0.address
    address1 = app1.address

    deposit0 = deposit
    deposit1 = deposit

    token_proxy = app0.proxy_manager.token(token_address, BLOCK_ID_LATEST)
    initial_balance0 = token_proxy.balance_of(address0)
    initial_balance1 = token_proxy.balance_of(address1)
    identifier = factories.make_payment_id()
    target = TargetAddress(app1.address)
    secret = factories.make_secret()
    secrethash = sha256_secrethash(secret)

    secret_available = hold_event_handler.hold_secretrequest_for(secrethash=secrethash)

    with patch("raiden.message_handler.decrypt_secret", side_effect=InvalidSecret):
        app0.mediated_transfer_async(
            token_network_address=token_network_address,
            amount=amount,
            target=target,
            identifier=identifier,
            secret=secret,
            route_states=[create_route_state_for_route([app0, app1], token_address)],
        )

        secret_available.wait()  # wait for the messages to be exchanged

    # Save the pending locks from the pending transfer, used to test the unlock
    channelstate_0_1 = get_channelstate(app0, app1, token_network_address)
    pending_locks = channelstate_0_1.our_state.pending_locks

    hold_event_handler.release_secretrequest_for(app1, secrethash)

    with patch("raiden.message_handler.decrypt_secret", side_effect=InvalidSecret):
        transfer(
            initiator_app=app0,
            target_app=app1,
            token_address=token_address,
            amount=amount,
            identifier=PaymentID(2),
            routes=[[app0, app1]],
        )

    # The channel state has to be recovered before the settlement, otherwise
    # the object is cleared from the node's state.
    channelstate_1_0 = get_channelstate(app1, app0, token_network_address)

    RaidenAPI(app1).channel_close(registry_address, token_address, app0.address, coop_settle=False)

    waiting.wait_for_settle(
        app1,
        app1.default_registry.address,
        token_address,
        [channelstate_0_1.identifier],
        app1.alarm.sleep_time,
    )
    current_block = app1.rpc_client.block_number()

    netting_channel = app1.proxy_manager.payment_channel(
        channel_state=channelstate_1_0, block_identifier=BLOCK_ID_LATEST
    )

    # The transfer locksroot must not contain the unlocked lock, the
    # unlock must fail.
    with pytest.raises(RaidenUnrecoverableError):
        netting_channel.token_network.unlock(
            channel_identifier=netting_channel.channel_identifier,
            sender=channelstate_0_1.our_state.address,
            receiver=channelstate_0_1.partner_state.address,
            pending_locks=pending_locks,
            given_block_identifier=current_block,
        )

    expected_balance0 = initial_balance0 + deposit0 - amount * 2
    expected_balance1 = initial_balance1 + deposit1 + amount * 2
    waiting.wait_for_block(app0, current_block, retry_timeout)

    # The asserts can fail if we do not wait a bit because app1
    # needs to unlock its tokens after settle. The wait() above helps
    # to wait for the block in which the settle happened.
    # Token_proxy queries against state of app0 which can be off by a block or two
    with Timeout(10):
        assert token_proxy.balance_of(address0) == expected_balance0
        assert token_proxy.balance_of(address1) == expected_balance1


@raise_on_failure
@pytest.mark.parametrize("number_of_nodes", [2])
@pytest.mark.parametrize("channels_per_node", [1])
def test_automatic_secret_registration(
    raiden_chain: List[RaidenService], token_addresses: List[TokenAddress]
) -> None:
    app0, app1 = raiden_chain
    token_address = token_addresses[0]
    token_network_address = views.get_token_network_address_by_token_address(
        views.state_from_raiden(app0), app0.default_registry.address, token_address
    )
    assert token_network_address

    hold_event_handler = app1.raiden_event_handler
    message_handler = app1.message_handler

    msg = "hold event handler necessary to control messages"
    assert isinstance(hold_event_handler, HoldRaidenEventHandler), msg
    assert isinstance(message_handler, WaitForMessage), msg

    amount = PaymentAmount(100)
    identifier = factories.make_payment_id()

    target = TargetAddress(app1.address)
    (secret, secrethash) = factories.make_secret_with_hash()

    hold_event_handler.hold_secretrequest_for(secrethash=secrethash)
    locked_transfer_received = message_handler.wait_for_message(LockedTransfer, {})

    app0.mediated_transfer_async(
        token_network_address=token_network_address,
        amount=amount,
        target=target,
        identifier=identifier,
        secret=secret,
        route_states=[create_route_state_for_route([app0, app1], token_address)],
    )

    # Wait for app1 to receive the locked transfer.
    locked_transfer_received.wait()

    # Stop app0 to avoid sending the unlock, this must be done after the locked
    # transfer is sent.
    app0.transport.stop()

    reveal_secret = RevealSecret(
        message_identifier=MessageID(random.randint(0, UINT64_MAX)),
        secret=secret,
        signature=EMPTY_SIGNATURE,
    )
    app0.sign(reveal_secret)
    message_handler.on_messages(app1, [reveal_secret])

    chain_state = views.state_from_raiden(app1)

    secrethash = sha256_secrethash(secret)
    target_task = chain_state.payment_mapping.secrethashes_to_task[secrethash]
    lock_expiration = target_task.target_state.transfer.lock.expiration  # type: ignore
    app1.proxy_manager.client.wait_until_block(target_block_number=lock_expiration)

    assert app1.default_secret_registry.is_secret_registered(
        secrethash=secrethash, block_identifier=BLOCK_ID_LATEST
    )


@raise_on_failure
@pytest.mark.xfail(reason="test incomplete")
@pytest.mark.parametrize("number_of_nodes", [3])
def test_start_end_attack(
    token_addresses: List[TokenAddress],
    raiden_chain: List[RaidenService],
    deposit: List[RaidenService],
) -> None:
    """An attacker can try to steal tokens from a hub or the last node in a
    path.

    The attacker needs to use two addresses (A1 and A2) and connect both to the
    hub H. Once connected a mediated transfer is initialized from A1 to A2
    through H. Once the node A2 receives the mediated transfer the attacker
    uses the known secret and reveal to close and settle the channel H-A2,
    without revealing the secret to H's raiden node.

    The intention is to make the hub transfer the token but for him to be
    unable to require the token A1."""

    token_address = token_addresses[0]
    app0, app1, app2 = raiden_chain  # pylint: disable=unbalanced-tuple-unpacking
    token_network_address = views.get_token_network_address_by_token_address(
        views.state_from_raiden(app0), app0.default_registry.address, token_address
    )
    assert token_network_address

    hold_event_handler = app2.raiden_event_handler
    msg = "hold event handler necessary to control messages"
    assert isinstance(hold_event_handler, HoldRaidenEventHandler), msg

    # the attacker owns app0 and app2 and creates a transfer through app1
    amount = PaymentAmount(30)
    identifier = PaymentID(1)
    target = TargetAddress(app2.address)
    secret, secrethash = factories.make_secret_with_hash()

    hold_event_handler.hold_secretrequest_for(secrethash=secrethash)

    app0.mediated_transfer_async(
        token_network_address=token_network_address,
        amount=amount,
        target=target,
        identifier=identifier,
        secret=secret,
        route_states=[create_route_state_for_route([app0, app1], token_address)],
    )

    attack_channel = get_channelstate(app2, app1, token_network_address)
    attack_transfer = None  # TODO
    attack_contract = attack_channel.external_state.netting_channel.address  # type: ignore
    hub_contract = get_channelstate(  # type: ignore
        app1, app0, token_network_address
    ).external_state.netting_channel.address

    # start the settle counter
    attack_balance_proof = attack_transfer.to_balanceproof()  # type: ignore
    attack_channel.netting_channel.channel_close(attack_balance_proof)  # type: ignore

    # wait until the last block to reveal the secret, hopefully we are not
    # missing a block during the test
    assert attack_transfer
    app2.rpc_client.wait_until_block(target_block_number=attack_transfer.lock.expiration - 1)

    # since the attacker knows the secret he can net the lock
    # <the commented code below is left for documentation purposes>
    # attack_channel.netting_channel.unlock(
    #     UnlockProofState(unlock_proof, attack_transfer.lock, secret)
    # )
    # XXX: verify that the secret was publicized

    # at this point the hub might not know the secret yet, and won't be able to
    # claim the token from the channel A1 - H

    # the attacker settles the contract
    app2.rpc_client.wait_until_block(target_block_number=app2.rpc_client.block_number() + 1)

    attack_channel.netting_channel.settle(token_address, attack_contract)

    # at this point the attacker has the "stolen" funds
    attack_contract = app2.proxy_manager.token_hashchannel[token_address][attack_contract]
    assert attack_contract.participants[app2.address]["netted"] == deposit + amount
    assert attack_contract.participants[app1.address]["netted"] == deposit - amount

    # and the hub's channel A1-H doesn't
    hub_contract = app1.proxy_manager.token_hashchannel[token_address][hub_contract]
    assert hub_contract.participants[app0.address]["netted"] == deposit
    assert hub_contract.participants[app1.address]["netted"] == deposit

    # to mitigate the attack the Hub _needs_ to use a lower expiration for the
    # locked transfer between H-A2 than A1-H. For A2 to acquire the token
    # it needs to make the secret public in the blockchain so it publishes the
    # secret through an event and the Hub is able to require its funds
    app1.rpc_client.wait_until_block(target_block_number=app1.rpc_client.block_number() + 1)

    # XXX: verify that the Hub has found the secret, close and settle the channel

    # the hub has acquired its token
    hub_contract = app1.proxy_manager.token_hashchannel[token_address][hub_contract]
    assert hub_contract.participants[app0.address]["netted"] == deposit + amount
    assert hub_contract.participants[app1.address]["netted"] == deposit - amount


@raise_on_failure
@pytest.mark.parametrize("number_of_nodes", [2])
def test_automatic_dispute(
    raiden_network: List[RaidenService], deposit: TokenAmount, token_addresses: List[TokenAddress]
) -> None:
    app0, app1 = raiden_network
    registry_address = app0.default_registry.address
    token_address = token_addresses[0]
    token_network_address = views.get_token_network_address_by_token_address(
        views.state_from_raiden(app0), app0.default_registry.address, token_address
    )
    assert token_network_address

    channel0 = get_channelstate(app0, app1, token_network_address)
    token_proxy = app0.proxy_manager.token(channel0.token_address, BLOCK_ID_LATEST)
    initial_balance0 = token_proxy.balance_of(app0.address)
    initial_balance1 = token_proxy.balance_of(app1.address)

    amount0_1 = PaymentAmount(10)
    transfer(
        initiator_app=app0,
        target_app=app1,
        token_address=token_address,
        amount=amount0_1,
        identifier=PaymentID(1),
        routes=[[app0, app1]],
    )

    amount1_1 = PaymentAmount(50)
    transfer(
        initiator_app=app1,
        target_app=app0,
        token_address=token_address,
        amount=amount1_1,
        identifier=PaymentID(2),
        routes=[[app1, app0]],
    )

    amount0_2 = PaymentAmount(60)
    transfer(
        initiator_app=app0,
        target_app=app1,
        token_address=token_address,
        amount=amount0_2,
        identifier=PaymentID(3),
        routes=[[app0, app1]],
    )

    # Alice can only provide one of Bob's transfer, so she is incentivized to
    # use the one with the largest transferred_amount.
    RaidenAPI(app0).channel_close(registry_address, token_address, app1.address, coop_settle=False)

    # Bob needs to provide a transfer otherwise its netted balance will be
    # wrong, so he is incentivised to use Alice's transfer with the largest
    # transferred_amount.
    #
    # This is done automatically
    # channel1.external_state.update_transfer(
    #     alice_second_transfer,
    # )

    waiting.wait_for_settle(
        app0,
        registry_address,
        token_address,
        [channel0.identifier],
        app0.alarm.sleep_time,
    )

    # check that the channel is properly settled and that Bob's client
    # automatically called updateTransfer() to reflect the actual transactions
    assert token_proxy.balance_of(Address(token_network_address)) == 0
    total0 = amount0_1 + amount0_2
    total1 = amount1_1
    expected_balance0 = initial_balance0 + deposit - total0 + total1
    expected_balance1 = initial_balance1 + deposit + total0 - total1
    assert token_proxy.balance_of(app0.address) == expected_balance0
    assert token_proxy.balance_of(app1.address) == expected_balance1


@raise_on_failure
@pytest.mark.parametrize("number_of_nodes", [2])
def test_batch_unlock_after_restart(
    raiden_network: List[RaidenService], restart_node, token_addresses, deposit
):
    """Simulate the case where:
    - A sends B a transfer
    - B sends A a transfer
    - Secrets were never revealed
    - B closes channel
    - A crashes
    - Wait for settle
    - Wait for unlock from B
    - Restart A
    At this point, the current unlock logic will try to unlock
    iff the node gains from unlocking. Which means that the node will try to unlock
    either side. In the above scenario, each node will unlock its side.
    This test makes sure that we do NOT invalidate A's unlock transaction based
    on the ContractReceiveChannelBatchUnlock caused by B's unlock.
    """
    alice_app, bob_app = raiden_network
    registry_address = alice_app.default_registry.address
    token_address = token_addresses[0]
    token_network_address = views.get_token_network_address_by_token_address(
        chain_state=views.state_from_raiden(alice_app),
        token_network_registry_address=alice_app.default_registry.address,
        token_address=token_address,
    )
    assert token_network_address
    timeout = 10

    token_network = views.get_token_network_by_address(
        chain_state=views.state_from_raiden(alice_app), token_network_address=token_network_address
    )
    assert token_network

    channel_identifier = get_channelstate(alice_app, bob_app, token_network_address).identifier

    assert (
        channel_identifier in token_network.partneraddresses_to_channelidentifiers[bob_app.address]
    )

    alice_to_bob_amount = PaymentAmount(10)
    identifier = PaymentID(1)

    alice_transfer_secret = Secret(keccak(alice_app.address))
    alice_transfer_secrethash = sha256_secrethash(alice_transfer_secret)

    bob_transfer_secret = Secret(keccak(bob_app.address))
    bob_transfer_secrethash = sha256_secrethash(bob_transfer_secret)

    msg = "test app must use HoldRaidenEventHandler."
    assert isinstance(alice_app.raiden_event_handler, HoldRaidenEventHandler), msg
    assert isinstance(bob_app.raiden_event_handler, HoldRaidenEventHandler), msg

    alice_transfer_hold = bob_app.raiden_event_handler.hold_secretrequest_for(
        secrethash=alice_transfer_secrethash
    )
    bob_transfer_hold = alice_app.raiden_event_handler.hold_secretrequest_for(
        secrethash=bob_transfer_secrethash
    )

    with patch("raiden.message_handler.decrypt_secret", side_effect=InvalidSecret):
        alice_app.mediated_transfer_async(
            token_network_address=token_network_address,
            amount=alice_to_bob_amount,
            target=TargetAddress(bob_app.address),
            identifier=identifier,
            secret=alice_transfer_secret,
            route_states=[create_route_state_for_route([alice_app, bob_app], token_address)],
        )

        bob_app.mediated_transfer_async(
            token_network_address=token_network_address,
            amount=alice_to_bob_amount,
            target=TargetAddress(alice_app.address),
            identifier=PaymentID(identifier + 1),
            secret=bob_transfer_secret,
            route_states=[create_route_state_for_route([bob_app, alice_app], token_address)],
        )

        alice_transfer_hold.wait(timeout=timeout)
        bob_transfer_hold.wait(timeout=timeout)

    alice_bob_channel_state = get_channelstate(alice_app, bob_app, token_network_address)
    alice_lock = channel.get_lock(alice_bob_channel_state.our_state, alice_transfer_secrethash)
    bob_lock = channel.get_lock(alice_bob_channel_state.partner_state, bob_transfer_secrethash)
    assert alice_lock
    assert bob_lock

    # This is the current state of protocol:
    #
    #    A -> B LockedTransfer
    #    - protocol didn't continue
    assert_synced_channel_state(
        token_network_address=token_network_address,
        app0=alice_app,
        balance0=deposit,
        pending_locks0=[alice_lock],
        app1=bob_app,
        balance1=deposit,
        pending_locks1=[bob_lock],
    )

    # A ChannelClose event will be generated, this will be polled by both apps
    # and each must start a task for calling settle
    RaidenAPI(bob_app).channel_close(
        registry_address=registry_address,
        token_address=token_address,
        partner_address=alice_app.address,
        coop_settle=False,
    )

    # wait for the close transaction to be mined, this is necessary to compute
    # the timeout for the settle
    with block_offset_timeout(alice_app):
        waiting.wait_for_close(
            raiden=alice_app,
            token_network_registry_address=registry_address,
            token_address=token_address,
            channel_ids=[alice_bob_channel_state.identifier],
            retry_timeout=alice_app.alarm.sleep_time,
        )

    channel_closed = raiden_state_changes_search_for_item(
        bob_app,
        ContractReceiveChannelClosed,
        {
            "canonical_identifier": {
                "token_network_address": token_network_address,
                "channel_identifier": alice_bob_channel_state.identifier,
            }
        },
    )
    assert isinstance(channel_closed, ContractReceiveChannelClosed)

    offset = BlockOffset(alice_bob_channel_state.settle_timeout * 2)
    with block_offset_timeout(bob_app, "Settle did not happen", offset):
        waiting.wait_for_settle(
            raiden=alice_app,
            token_network_registry_address=registry_address,
            token_address=token_address,
            channel_ids=[alice_bob_channel_state.identifier],
            retry_timeout=alice_app.alarm.sleep_time,
        )

    with gevent.Timeout(timeout):
        wait_for_batch_unlock(
            app=bob_app,
            token_network_address=token_network_address,
            receiver=alice_bob_channel_state.partner_state.address,
            sender=alice_bob_channel_state.our_state.address,
        )

    alice_app.stop()
    restart_node(alice_app)

    with gevent.Timeout(timeout):
        wait_for_batch_unlock(
            app=alice_app,
            token_network_address=token_network_address,
            receiver=alice_bob_channel_state.partner_state.address,
            sender=alice_bob_channel_state.our_state.address,
        )


@expect_failure
@pytest.mark.parametrize("number_of_nodes", (2,))
@pytest.mark.parametrize("channels_per_node", (1,))
def test_handle_insufficient_eth(
    raiden_network: List[RaidenService], restart_node, token_addresses, caplog
):
    app0, app1 = raiden_network
    token = token_addresses[0]
    registry_address = app0.default_registry.address

    channel_state = views.get_channelstate_for(
        chain_state=views.state_from_raiden(app0),
        token_network_registry_address=registry_address,
        token_address=token,
        partner_address=app1.address,
    )
    assert isinstance(channel_state, NettingChannelState)
    channel_identifier = channel_state.identifier

    with block_offset_timeout(app0):
        transfer(
            initiator_app=app0,
            target_app=app1,
            token_address=token,
            amount=PaymentAmount(1),
            identifier=PaymentID(1),
            routes=[[app0, app1]],
        )

    app1.stop()
    burn_eth(app1.rpc_client)
    restart_node(app1)

    block_offset = BlockOffset(channel_state.settle_timeout * 2)
    with block_offset_timeout(app0, "Settle did not happen", block_offset):
        RaidenAPI(app0).channel_close(
            registry_address=registry_address,
            token_address=token,
            partner_address=app1.address,
            coop_settle=False,
        )
        waiting.wait_for_settle(
            raiden=app0,
            token_network_registry_address=registry_address,
            token_address=token,
            channel_ids=[channel_identifier],
            retry_timeout=DEFAULT_RETRY_TIMEOUT,
        )

    assert any(
        "subtask died" in message and "insufficient ETH" in message for message in caplog.messages
    )
