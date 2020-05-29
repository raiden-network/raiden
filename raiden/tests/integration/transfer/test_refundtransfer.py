import gevent
import pytest

from raiden.api.python import RaidenAPI
from raiden.app import App
from raiden.constants import BLOCK_ID_LATEST
from raiden.storage.sqlite import RANGE_ALL_STATE_CHANGES
from raiden.tests.utils.detect_failure import raise_on_failure
from raiden.tests.utils.events import (
    raiden_events_search_for_item,
    search_for_item,
    wait_for_raiden_event,
    wait_for_state_change,
)
from raiden.tests.utils.network import CHAIN
from raiden.tests.utils.protocol import (
    dont_handle_lock_expired_mock,
    dont_handle_node_change_network_state,
)
from raiden.tests.utils.transfer import (
    assert_succeeding_transfer_invariants,
    assert_synced_channel_state,
    block_offset_timeout,
    calculate_fee_for_amount,
    get_channelstate,
    transfer,
    wait_assert,
)
from raiden.transfer import channel, views
from raiden.transfer.events import ContractSendChannelUpdateTransfer, EventPaymentSentFailed
from raiden.transfer.mediated_transfer.events import (
    SendLockedTransfer,
    SendLockExpired,
    SendRefundTransfer,
)
from raiden.transfer.mediated_transfer.initiator import calculate_fee_margin
from raiden.transfer.mediated_transfer.state_change import ReceiveLockExpired
from raiden.transfer.state_change import ContractReceiveChannelBatchUnlock, ReceiveProcessed
from raiden.transfer.views import state_from_raiden
from raiden.utils.typing import BlockNumber, List, PaymentAmount, PaymentID, TargetAddress
from raiden.waiting import wait_for_block, wait_for_settle


@raise_on_failure
@pytest.mark.parametrize("channels_per_node", [CHAIN])
@pytest.mark.parametrize("number_of_nodes", [3])
@pytest.mark.parametrize("settle_timeout", [50])
def test_refund_messages(raiden_chain, token_addresses, deposit):
    # The network has the following topology:
    #
    #   App0 <---> App1 <---> App2
    app0, app1, app2 = raiden_chain  # pylint: disable=unbalanced-tuple-unpacking
    token_address = token_addresses[0]
    token_network_registry_address = app0.raiden.default_registry.address
    token_network_address = views.get_token_network_address_by_token_address(
        views.state_from_app(app0), token_network_registry_address, token_address
    )

    # Exhaust the channel App1 <-> App2 (to force the refund transfer)
    # Here we make a single-hop transfer, no fees are charged so we should
    # send the whole deposit amount to drain the channel.
    transfer(
        initiator_app=app1,
        target_app=app2,
        token_address=token_address,
        amount=deposit,
        identifier=PaymentID(1),
    )

    refund_amount = deposit // 2
    refund_fees = calculate_fee_for_amount(refund_amount)
    fee_margin = calculate_fee_margin(refund_amount, refund_fees)
    refund_amount_with_fees = refund_amount + refund_fees + fee_margin
    identifier = 1
    payment_status = app0.raiden.mediated_transfer_async(
        token_network_address, refund_amount, app2.raiden.address, identifier
    )
    msg = "Must fail, there are no routes available"
    assert isinstance(payment_status.payment_done.wait(), EventPaymentSentFailed), msg

    # The transfer from app0 to app2 failed, so the balances did change.
    # Since the refund is not unlocked both channels have the corresponding
    # amount locked (issue #1091)
    send_lockedtransfer = raiden_events_search_for_item(
        app0.raiden,
        SendLockedTransfer,
        {"transfer": {"lock": {"amount": refund_amount_with_fees}}},
    )
    assert send_lockedtransfer

    send_refundtransfer = raiden_events_search_for_item(app1.raiden, SendRefundTransfer, {})
    assert send_refundtransfer

    with block_offset_timeout(app1.raiden):
        wait_assert(
            func=assert_synced_channel_state,
            token_network_address=token_network_address,
            app0=app0,
            balance0=deposit,
            pending_locks0=[send_lockedtransfer.transfer.lock],
            app1=app1,
            balance1=deposit,
            pending_locks1=[send_refundtransfer.transfer.lock],
        )
        # This channel was exhausted to force the refund transfer except for the fees
        wait_assert(
            func=assert_succeeding_transfer_invariants,
            token_network_address=token_network_address,
            app0=app1,
            balance0=0,
            pending_locks0=[],
            app1=app2,
            balance1=deposit * 2,
            pending_locks1=[],
        )


@raise_on_failure
@pytest.mark.parametrize("privatekey_seed", ["test_refund_transfer:{}"])
@pytest.mark.parametrize("number_of_nodes", [3])
@pytest.mark.parametrize("channels_per_node", [CHAIN])
def test_refund_transfer(raiden_chain, token_addresses, deposit, retry_timeout):
    """A failed transfer must send a refund back.

    TODO:
        - Unlock the token on refund #1091
        - Clear the pending locks and update the locked amount #193
        - Remove the refund message type #490"""
    # Topology:
    #
    #  0 -> 1 -> 2
    #
    app0, app1, app2 = raiden_chain
    token_address = token_addresses[0]
    token_network_registry_address = app0.raiden.default_registry.address
    token_network_address = views.get_token_network_address_by_token_address(
        views.state_from_app(app0), token_network_registry_address, token_address
    )

    # make a transfer to test the path app0 -> app1 -> app2
    identifier_path = PaymentID(1)
    amount_path = PaymentAmount(1)
    with block_offset_timeout(app0.raiden):
        transfer(
            initiator_app=app0,
            target_app=app2,
            token_address=token_address,
            amount=amount_path,
            identifier=identifier_path,
        )

    # drain the channel app1 -> app2
    identifier_drain = PaymentID(2)
    amount_drain = PaymentAmount(deposit * 8 // 10)

    transfer_timeout = block_offset_timeout(app1.raiden)
    with transfer_timeout:
        transfer(
            initiator_app=app1,
            target_app=app2,
            token_address=token_address,
            amount=amount_drain,
            identifier=identifier_drain,
        )
        wait_assert(
            assert_synced_channel_state,
            token_network_address,
            app0,
            deposit - amount_path,
            [],
            app1,
            deposit + amount_path,
            [],
        )
        wait_assert(
            assert_synced_channel_state,
            token_network_address,
            app1,
            deposit - amount_path - amount_drain,
            [],
            app2,
            deposit + amount_path + amount_drain,
            [],
        )

    # app0 -> app1 -> app2 is the only available path, but the channel app1 ->
    # app2 doesn't have capacity, so a refund will be sent on app1 -> app0
    identifier_refund = PaymentID(3)
    amount_refund = PaymentAmount(50)
    fee = calculate_fee_for_amount(amount_refund)
    fee_margin = calculate_fee_margin(amount_refund, fee)
    amount_refund_with_fees = amount_refund + fee + fee_margin
    payment_status = app0.raiden.mediated_transfer_async(
        token_network_address, amount_refund, app2.raiden.address, identifier_refund
    )
    msg = "there is no path with capacity, the transfer must fail"
    assert isinstance(payment_status.payment_done.wait(), EventPaymentSentFailed), msg

    # A lock structure with the correct amount

    send_locked = raiden_events_search_for_item(
        app0.raiden,
        SendLockedTransfer,
        {"transfer": {"lock": {"amount": amount_refund_with_fees}}},
    )
    assert send_locked
    secrethash = send_locked.transfer.lock.secrethash

    send_refund = raiden_events_search_for_item(app1.raiden, SendRefundTransfer, {})
    assert send_refund

    lock = send_locked.transfer.lock
    refund_lock = send_refund.transfer.lock
    assert lock.amount == refund_lock.amount
    assert lock.secrethash
    assert lock.expiration
    assert lock.secrethash == refund_lock.secrethash

    # Both channels have the amount locked because of the refund message
    with transfer_timeout:
        wait_assert(
            assert_synced_channel_state,
            token_network_address,
            app0,
            deposit - amount_path,
            [lock],
            app1,
            deposit + amount_path,
            [refund_lock],
        )
        wait_assert(
            assert_synced_channel_state,
            token_network_address,
            app1,
            deposit - amount_path - amount_drain,
            [],
            app2,
            deposit + amount_path + amount_drain,
            [],
        )

    # Additional checks for LockExpired causing nonce mismatch after refund transfer:
    # https://github.com/raiden-network/raiden/issues/3146#issuecomment-447378046
    # At this point make sure that the initiator has not deleted the payment task
    assert secrethash in state_from_raiden(app0.raiden).payment_mapping.secrethashes_to_task

    # Wait for lock lock expiration but make sure app0 never processes LockExpired
    with dont_handle_lock_expired_mock(app0):
        wait_for_block(
            raiden=app0.raiden,
            block_number=BlockNumber(channel.get_sender_expiration_threshold(lock.expiration) + 1),
            retry_timeout=retry_timeout,
        )
        # make sure that app0 still has the payment task for the secrethash
        # https://github.com/raiden-network/raiden/issues/3183
        assert secrethash in state_from_raiden(app0.raiden).payment_mapping.secrethashes_to_task

        # make sure that app1 sent a lock expired message for the secrethash
        send_lock_expired = raiden_events_search_for_item(
            app1.raiden, SendLockExpired, {"secrethash": secrethash}
        )
        assert send_lock_expired
        # make sure that app0 never got it
        state_changes = app0.raiden.wal.storage.get_statechanges_by_range(RANGE_ALL_STATE_CHANGES)
        assert not search_for_item(state_changes, ReceiveLockExpired, {"secrethash": secrethash})

    # Out of the handicapped app0 transport.
    # Now wait till app0 receives and processes LockExpired
    receive_lock_expired = wait_for_state_change(
        app0.raiden, ReceiveLockExpired, {"secrethash": secrethash}, retry_timeout
    )
    # And also till app1 received the processed
    wait_for_state_change(
        app1.raiden,
        ReceiveProcessed,
        {"message_identifier": receive_lock_expired.message_identifier},
        retry_timeout,
    )

    # make sure app1 queue has cleared the SendLockExpired
    chain_state1 = views.state_from_app(app1)
    queues1 = views.get_all_messagequeues(chain_state=chain_state1)
    result = [
        (queue_id, queue)
        for queue_id, queue in queues1.items()
        if queue_id.recipient == app0.raiden.address and queue
    ]
    assert not result

    # and now wait for 1 more block so that the payment task can be deleted
    wait_for_block(
        raiden=app0.raiden,
        block_number=app0.raiden.get_block_number() + 1,
        retry_timeout=retry_timeout,
    )

    # and since the lock expired message has been sent and processed then the
    # payment task should have been deleted from both nodes
    # https://github.com/raiden-network/raiden/issues/3183
    assert secrethash not in state_from_raiden(app0.raiden).payment_mapping.secrethashes_to_task
    assert secrethash not in state_from_raiden(app1.raiden).payment_mapping.secrethashes_to_task


@raise_on_failure
@pytest.mark.parametrize("privatekey_seed", ["test_different_view_of_last_bp_during_unlock:{}"])
@pytest.mark.parametrize("number_of_nodes", [3])
@pytest.mark.parametrize("channels_per_node", [CHAIN])
def test_different_view_of_last_bp_during_unlock(
    raiden_chain: List[App], restart_node, token_addresses, deposit, retry_timeout, blockchain_type
):
    """Test for https://github.com/raiden-network/raiden/issues/3196#issuecomment-449163888"""
    # Topology:
    #
    #  0 -> 1 -> 2
    #
    app0, app1, app2 = raiden_chain
    token_address = token_addresses[0]
    token_network_registry_address = app0.raiden.default_registry.address
    token_network_address = views.get_token_network_address_by_token_address(
        views.state_from_app(app0), token_network_registry_address, token_address
    )
    assert token_network_address
    token_proxy = app0.raiden.proxy_manager.token(token_address, BLOCK_ID_LATEST)
    initial_balance0 = token_proxy.balance_of(app0.raiden.address)
    initial_balance1 = token_proxy.balance_of(app1.raiden.address)

    # make a transfer to test the path app0 -> app1 -> app2
    identifier_path = PaymentID(1)
    amount_path = PaymentAmount(1)
    with block_offset_timeout(app0.raiden):
        transfer(
            initiator_app=app0,
            target_app=app2,
            token_address=token_address,
            amount=amount_path,
            identifier=identifier_path,
        )

    # drain the channel app1 -> app2
    identifier_drain = PaymentID(2)
    amount_drain = PaymentAmount(deposit * 8 // 10)
    with block_offset_timeout(app1.raiden):
        transfer(
            initiator_app=app1,
            target_app=app2,
            token_address=token_address,
            amount=amount_drain,
            identifier=identifier_drain,
        )
        wait_assert(
            assert_synced_channel_state,
            token_network_address,
            app0,
            deposit - amount_path,
            [],
            app1,
            deposit + amount_path,
            [],
        )
        wait_assert(
            assert_synced_channel_state,
            token_network_address,
            app1,
            deposit - amount_path - amount_drain,
            [],
            app2,
            deposit + amount_path + amount_drain,
            [],
        )

    # app0 -> app1 -> app2 is the only available path, but the channel app1 ->
    # app2 doesn't have capacity, so a refund will be sent on app1 -> app0
    identifier_refund = PaymentID(3)
    amount_refund = PaymentAmount(50)
    fee = calculate_fee_for_amount(amount_refund)
    fee_margin = calculate_fee_margin(amount_refund, fee)
    amount_refund_with_fees = amount_refund + fee + fee_margin
    payment_status = app0.raiden.mediated_transfer_async(
        token_network_address, amount_refund, TargetAddress(app2.raiden.address), identifier_refund
    )
    msg = "there is no path with capacity, the transfer must fail"
    assert isinstance(payment_status.payment_done.wait(), EventPaymentSentFailed), msg

    # A lock structure with the correct amount

    send_locked = raiden_events_search_for_item(
        app0.raiden,
        SendLockedTransfer,
        {"transfer": {"lock": {"amount": amount_refund_with_fees}}},
    )
    assert send_locked
    secrethash = send_locked.transfer.lock.secrethash

    send_refund = raiden_events_search_for_item(app1.raiden, SendRefundTransfer, {})
    assert send_refund

    lock = send_locked.transfer.lock
    refund_lock = send_refund.transfer.lock
    assert lock.amount == refund_lock.amount
    assert lock.secrethash
    assert lock.expiration
    assert lock.secrethash == refund_lock.secrethash

    # Both channels have the amount locked because of the refund message
    with block_offset_timeout(app0.raiden):
        wait_assert(
            assert_synced_channel_state,
            token_network_address,
            app0,
            deposit - amount_path,
            [lock],
            app1,
            deposit + amount_path,
            [refund_lock],
        )
        wait_assert(
            assert_synced_channel_state,
            token_network_address,
            app1,
            deposit - amount_path - amount_drain,
            [],
            app2,
            deposit + amount_path + amount_drain,
            [],
        )

    # Additional checks for LockExpired causing nonce mismatch after refund transfer:
    # https://github.com/raiden-network/raiden/issues/3146#issuecomment-447378046
    # At this point make sure that the initiator has not deleted the payment task
    assert secrethash in state_from_raiden(app0.raiden).payment_mapping.secrethashes_to_task

    with dont_handle_node_change_network_state():
        # now app1 goes offline
        app1.raiden.stop()
        app1.raiden.greenlet.get()
        assert not app1.raiden

        # Wait for lock expiration so that app0 sends a LockExpired
        wait_for_block(
            raiden=app0.raiden,
            block_number=BlockNumber(channel.get_sender_expiration_threshold(lock.expiration) + 1),
            retry_timeout=retry_timeout,
        )

        # make sure that app0 sent a lock expired message for the secrethash
        wait_for_raiden_event(
            app0.raiden, SendLockExpired, {"secrethash": secrethash}, retry_timeout
        )

        # now app0 closes the channel
        RaidenAPI(app0.raiden).channel_close(
            registry_address=token_network_registry_address,
            token_address=token_address,
            partner_address=app1.raiden.address,
        )

    count = 0
    on_raiden_events_original = app1.raiden.raiden_event_handler.on_raiden_events

    def patched_on_raiden_events(raiden, chain_state, events):
        nonlocal count

        count += sum(1 for event in events if type(event) == ContractSendChannelUpdateTransfer)

        on_raiden_events_original(raiden, chain_state, events)

    setattr(app1.raiden.raiden_event_handler, "on_raiden_events", patched_on_raiden_events)  # NOQA

    # and now app1 comes back online
    restart_node(app1)
    # test for https://github.com/raiden-network/raiden/issues/3216
    assert count == 1, "Update transfer should have only been called once during restart"
    channel_identifier = get_channelstate(app0, app1, token_network_address).identifier

    # and we wait for settlement
    wait_for_settle(
        raiden=app0.raiden,
        token_network_registry_address=token_network_registry_address,
        token_address=token_address,
        channel_ids=[channel_identifier],
        retry_timeout=app0.raiden.alarm.sleep_time,
    )

    timeout = 30 if blockchain_type == "parity" else 10
    with gevent.Timeout(timeout):
        unlock_app0 = wait_for_state_change(
            app0.raiden,
            ContractReceiveChannelBatchUnlock,
            {"receiver": app0.raiden.address},
            retry_timeout,
        )
    assert unlock_app0
    assert unlock_app0.returned_tokens == amount_refund_with_fees
    with gevent.Timeout(timeout):
        unlock_app1 = wait_for_state_change(
            app1.raiden,
            ContractReceiveChannelBatchUnlock,
            {"receiver": app1.raiden.address},
            retry_timeout,
        )
    assert unlock_app1
    assert unlock_app1.returned_tokens == amount_refund_with_fees
    final_balance0 = token_proxy.balance_of(app0.raiden.address)
    final_balance1 = token_proxy.balance_of(app1.raiden.address)

    assert final_balance0 - deposit - initial_balance0 == -1
    assert final_balance1 - deposit - initial_balance1 == 1


@raise_on_failure
@pytest.mark.parametrize("privatekey_seed", ["test_refund_transfer:{}"])
@pytest.mark.parametrize("number_of_nodes", [4])
@pytest.mark.parametrize("number_of_tokens", [1])
@pytest.mark.parametrize("channels_per_node", [CHAIN])
def test_refund_transfer_after_2nd_hop(
    raiden_chain, number_of_nodes, token_addresses, deposit, network_wait
):
    """Test the refund transfer sent due to failure after 2nd hop"""
    # Topology:
    #
    #  0 -> 1 -> 2 -> 3
    #
    app0, app1, app2, app3 = raiden_chain
    token_address = token_addresses[0]
    token_network_registry_address = app0.raiden.default_registry.address
    token_network_address = views.get_token_network_address_by_token_address(
        views.state_from_app(app0), token_network_registry_address, token_address
    )

    # make a transfer to test the path app0 -> app1 -> app2 -> app3
    identifier_path = PaymentID(1)
    amount_path = PaymentAmount(1)
    with block_offset_timeout(app0.raiden):
        transfer(
            initiator_app=app0,
            target_app=app3,
            token_address=token_address,
            amount=amount_path,
            identifier=identifier_path,
            timeout=network_wait * number_of_nodes,
        )

    # drain the channel app2 -> app3
    identifier_drain = PaymentID(2)
    amount_drain = PaymentAmount(deposit * 8 // 10)
    with block_offset_timeout(app2.raiden):
        transfer(
            initiator_app=app2,
            target_app=app3,
            token_address=token_address,
            amount=amount_drain,
            identifier=identifier_drain,
            timeout=network_wait,
        )
        wait_assert(
            assert_synced_channel_state,
            token_network_address,
            app0,
            deposit - amount_path,
            [],
            app1,
            deposit + amount_path,
            [],
        )
        wait_assert(
            assert_synced_channel_state,
            token_network_address,
            app1,
            deposit - amount_path,
            [],
            app2,
            deposit + amount_path,
            [],
        )
        wait_assert(
            assert_synced_channel_state,
            token_network_address,
            app2,
            deposit - amount_path - amount_drain,
            [],
            app3,
            deposit + amount_path + amount_drain,
            [],
        )

    # app0 -> app1 -> app2 > app3 is the only available path, but the channel
    # app2 -> app3 doesn't have capacity, so a refund will be sent on
    # app2 -> app1 -> app0
    identifier_refund = PaymentID(3)
    amount_refund = PaymentAmount(50)
    fee = calculate_fee_for_amount(amount_refund)
    fee_margin = calculate_fee_margin(amount_refund, fee)
    amount_refund_with_fees = amount_refund + fee + fee_margin
    payment_status = app0.raiden.mediated_transfer_async(
        token_network_address, amount_refund, app3.raiden.address, identifier_refund
    )
    msg = "there is no path with capacity, the transfer must fail"
    assert isinstance(payment_status.payment_done.wait(), EventPaymentSentFailed), msg

    # Lock structures with the correct amount

    send_locked1 = raiden_events_search_for_item(
        app0.raiden,
        SendLockedTransfer,
        {"transfer": {"lock": {"amount": amount_refund_with_fees}}},
    )
    assert send_locked1

    send_refund1 = raiden_events_search_for_item(app1.raiden, SendRefundTransfer, {})
    assert send_refund1

    lock1 = send_locked1.transfer.lock
    refund_lock1 = send_refund1.transfer.lock
    assert lock1.amount == refund_lock1.amount
    assert lock1.secrethash == refund_lock1.secrethash

    send_locked2 = raiden_events_search_for_item(
        app1.raiden,
        SendLockedTransfer,
        {"transfer": {"lock": {"amount": amount_refund_with_fees}}},
    )
    assert send_locked2

    send_refund2 = raiden_events_search_for_item(app2.raiden, SendRefundTransfer, {})
    assert send_refund2

    lock2 = send_locked2.transfer.lock
    refund_lock2 = send_refund2.transfer.lock
    assert lock2.amount == refund_lock2.amount
    assert lock2.secrethash
    assert lock2.expiration

    # channels have the amount locked because of the refund message

    with block_offset_timeout(app0.raiden):
        wait_assert(
            assert_synced_channel_state,
            token_network_address,
            app0,
            deposit - amount_path,
            [lock1],
            app1,
            deposit + amount_path,
            [refund_lock1],
        )
        wait_assert(
            assert_synced_channel_state,
            token_network_address,
            app1,
            deposit - amount_path,
            [lock2],
            app2,
            deposit + amount_path,
            [refund_lock2],
        )
        wait_assert(
            assert_synced_channel_state,
            token_network_address,
            app2,
            deposit - amount_path - amount_drain,
            [],
            app3,
            deposit + amount_path + amount_drain,
            [],
        )
