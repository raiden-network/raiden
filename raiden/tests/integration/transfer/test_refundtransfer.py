import gevent
import pytest

from raiden.transfer import views
from raiden.tests.utils.network import CHAIN
from raiden.tests.utils.events import raiden_events_must_contain_entry
from raiden.tests.utils.transfer import (
    assert_synched_channel_state,
    direct_transfer,
    mediated_transfer,
)
from raiden.transfer.mediated_transfer.events import (
    SendLockedTransfer,
    SendRefundTransfer,
)
from raiden.transfer.state import lockstate_from_lock


@pytest.mark.parametrize('channels_per_node', [CHAIN])
@pytest.mark.parametrize('number_of_nodes', [3])
@pytest.mark.parametrize('settle_timeout', [50])
def test_refund_messages(raiden_chain, token_addresses, deposit):
    # The network has the following topology:
    #
    #   App0 <---> App1 <---> App2
    app0, app1, app2 = raiden_chain  # pylint: disable=unbalanced-tuple-unpacking
    token_address = token_addresses[0]
    payment_network_identifier = app0.raiden.default_registry.address
    token_network_identifier = views.get_token_network_identifier_by_token_address(
        views.state_from_app(app0),
        payment_network_identifier,
        token_address,
    )

    # Exhaust the channel App1 <-> App2 (to force the refund transfer)
    exhaust_amount = deposit
    direct_transfer(app1, app2, token_network_identifier, exhaust_amount, identifier=1)

    refund_amount = deposit // 2
    identifier = 1
    async_result = app0.raiden.mediated_transfer_async(
        token_network_identifier,
        refund_amount,
        app2.raiden.address,
        identifier,
    )
    assert async_result.wait() is False, 'Must fail, there are no routes available'

    # The transfer from app0 to app2 failed, so the balances did change.
    # Since the refund is not unlocked both channels have the corresponding
    # amount locked (issue #1091)
    send_lockedtransfer = raiden_events_must_contain_entry(
        app0.raiden,
        SendLockedTransfer,
        {'transfer': {'lock': {'amount': refund_amount}}},
    )
    assert send_lockedtransfer

    send_refundtransfer = raiden_events_must_contain_entry(app1.raiden, SendRefundTransfer, {})
    assert send_refundtransfer

    assert_synched_channel_state(
        token_network_identifier,
        app0, deposit, [send_lockedtransfer.transfer.lock],
        app1, deposit, [send_refundtransfer.lock],
    )

    # This channel was exhausted to force the refund transfer
    assert_synched_channel_state(
        token_network_identifier,
        app1, 0, [],
        app2, deposit * 2, [],
    )


@pytest.mark.parametrize('privatekey_seed', ['test_refund_transfer:{}'])
@pytest.mark.parametrize('number_of_nodes', [3])
@pytest.mark.parametrize('channels_per_node', [CHAIN])
def test_refund_transfer(raiden_chain, number_of_nodes, token_addresses, deposit, network_wait):
    """A failed transfer must send a refund back.

    TODO:
        - Unlock the token on refund #1091
        - Clear the merkletree and update the locked amount #193
        - Remove the refund message type #490"""
    # Topology:
    #
    #  0 -> 1 -> 2
    #
    app0, app1, app2 = raiden_chain
    token_address = token_addresses[0]
    payment_network_identifier = app0.raiden.default_registry.address
    token_network_identifier = views.get_token_network_identifier_by_token_address(
        views.state_from_app(app0),
        payment_network_identifier,
        token_address,
    )

    # make a transfer to test the path app0 -> app1 -> app2
    identifier_path = 1
    amount_path = 1
    mediated_transfer(
        app0,
        app2,
        token_network_identifier,
        amount_path,
        identifier_path,
        timeout=network_wait * number_of_nodes,
    )

    # drain the channel app1 -> app2
    identifier_drain = 2
    amount_drain = deposit * 8 // 10
    direct_transfer(
        app1,
        app2,
        token_network_identifier,
        amount_drain,
        identifier_drain,
        timeout=network_wait,
    )

    # wait for the nodes to sync
    gevent.sleep(0.2)

    assert_synched_channel_state(
        token_network_identifier,
        app0, deposit - amount_path, [],
        app1, deposit + amount_path, [],
    )
    assert_synched_channel_state(
        token_network_identifier,
        app1, deposit - amount_path - amount_drain, [],
        app2, deposit + amount_path + amount_drain, [],
    )

    # app0 -> app1 -> app2 is the only available path, but the channel app1 ->
    # app2 doesn't have capacity, so a refund will be sent on app1 -> app0
    identifier_refund = 3
    amount_refund = 50
    async_result = app0.raiden.mediated_transfer_async(
        token_network_identifier,
        amount_refund,
        app2.raiden.address,
        identifier_refund,
    )
    assert async_result.wait() is False, 'there is no path with capacity, the transfer must fail'

    gevent.sleep(0.2)

    # A lock structure with the correct amount

    send_locked = raiden_events_must_contain_entry(
        app0.raiden,
        SendLockedTransfer,
        {'transfer': {'lock': {'amount': amount_refund}}},
    )
    assert send_locked

    send_refund = raiden_events_must_contain_entry(app1.raiden, SendRefundTransfer, {})
    assert send_refund

    lock = send_locked.transfer.lock
    refund_lock = send_refund.lock
    assert lock.amount == refund_lock.amount
    assert lock.secrethash
    assert lock.expiration

    # Both channels have the amount locked because of the refund message
    assert_synched_channel_state(
        token_network_identifier,
        app0, deposit - amount_path, [lockstate_from_lock(lock)],
        app1, deposit + amount_path, [lockstate_from_lock(refund_lock)],
    )
    assert_synched_channel_state(
        token_network_identifier,
        app1, deposit - amount_path - amount_drain, [],
        app2, deposit + amount_path + amount_drain, [],
    )


@pytest.mark.parametrize('privatekey_seed', ['test_refund_transfer:{}'])
@pytest.mark.parametrize('number_of_nodes', [4])
@pytest.mark.parametrize('number_of_tokens', [1])
@pytest.mark.parametrize('channels_per_node', [CHAIN])
def test_refund_transfer_after_2nd_hop(
        raiden_chain,
        number_of_nodes,
        token_addresses,
        deposit,
        network_wait,
):
    """Test the refund transfer sent due to failure after 2nd hop"""
    # Topology:
    #
    #  0 -> 1 -> 2 -> 3
    #
    app0, app1, app2, app3 = raiden_chain
    token_address = token_addresses[0]
    payment_network_identifier = app0.raiden.default_registry.address
    token_network_identifier = views.get_token_network_identifier_by_token_address(
        views.state_from_app(app0),
        payment_network_identifier,
        token_address,
    )

    # make a transfer to test the path app0 -> app1 -> app2 -> app3
    identifier_path = 1
    amount_path = 1
    mediated_transfer(
        app0,
        app3,
        token_network_identifier,
        amount_path,
        identifier_path,
        timeout=network_wait * number_of_nodes,
    )

    # drain the channel app2 -> app3
    identifier_drain = 2
    amount_drain = deposit * 8 // 10
    direct_transfer(
        app2,
        app3,
        token_network_identifier,
        amount_drain,
        identifier_drain,
        timeout=network_wait,
    )

    # wait for the nodes to sync
    gevent.sleep(0.2)

    assert_synched_channel_state(
        token_network_identifier,
        app0, deposit - amount_path, [],
        app1, deposit + amount_path, [],
    )
    assert_synched_channel_state(
        token_network_identifier,
        app1, deposit - amount_path, [],
        app2, deposit + amount_path, [],
    )
    assert_synched_channel_state(
        token_network_identifier,
        app2, deposit - amount_path - amount_drain, [],
        app3, deposit + amount_path + amount_drain, [],
    )

    # app0 -> app1 -> app2 > app3 is the only available path, but the channel
    # app2 -> app3 doesn't have capacity, so a refund will be sent on
    # app2 -> app1 -> app0
    identifier_refund = 3
    amount_refund = 50
    async_result = app0.raiden.mediated_transfer_async(
        token_network_identifier,
        amount_refund,
        app3.raiden.address,
        identifier_refund,
    )
    assert async_result.wait() is False, 'there is no path with capacity, the transfer must fail'

    gevent.sleep(0.2)

    # Lock structures with the correct amount

    send_locked1 = raiden_events_must_contain_entry(
        app0.raiden,
        SendLockedTransfer,
        {'transfer': {'lock': {'amount': amount_refund}}},
    )
    assert send_locked1

    send_refund1 = raiden_events_must_contain_entry(app1.raiden, SendRefundTransfer, {})
    assert send_refund1

    lock1 = send_locked1.transfer.lock
    refund_lock1 = send_refund1.lock
    assert lock1.amount == refund_lock1.amount
    assert lock1.secrethash == refund_lock1.secrethash

    send_locked2 = raiden_events_must_contain_entry(
        app1.raiden,
        SendLockedTransfer,
        {'transfer': {'lock': {'amount': amount_refund}}},
    )
    assert send_locked2

    send_refund2 = raiden_events_must_contain_entry(app2.raiden, SendRefundTransfer, {})
    assert send_refund2

    lock2 = send_locked2.transfer.lock
    refund_lock2 = send_refund2.lock
    assert lock2.amount == refund_lock2.amount
    assert lock2.secrethash
    assert lock2.expiration

    # channels have the amount locked because of the refund message
    assert_synched_channel_state(
        token_network_identifier,
        app0, deposit - amount_path, [lockstate_from_lock(lock1)],
        app1, deposit + amount_path, [lockstate_from_lock(refund_lock1)],
    )
    assert_synched_channel_state(
        token_network_identifier,
        app1, deposit - amount_path, [lockstate_from_lock(lock2)],
        app2, deposit + amount_path, [lockstate_from_lock(refund_lock2)],
    )
    assert_synched_channel_state(
        token_network_identifier,
        app2, deposit - amount_path - amount_drain, [],
        app3, deposit + amount_path + amount_drain, [],
    )
