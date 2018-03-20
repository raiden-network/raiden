# -*- coding: utf-8 -*-
# pylint: disable=invalid-name,too-many-locals,too-many-arguments,too-many-lines
import pytest

from raiden.utils import publickey_to_address
from raiden.transfer import channel
from raiden.transfer.events import ContractSendChannelClose
from raiden.transfer.mediated_transfer import mediator
from raiden.transfer.mediated_transfer.state import (
    MediationPairState2,
    MediatorTransferState,
)
from raiden.transfer.mediated_transfer.state_change import ActionInitMediator2
from raiden.transfer.mediated_transfer.events import (
    EventUnlockSuccess,
    SendBalanceProof2,
    SendMediatedTransfer2,
    SendRefundTransfer2,
    SendRevealSecret2,
)
from raiden.transfer.state import (
    CHANNEL_STATE_CLOSED,
    CHANNEL_STATE_SETTLED,
    TransactionExecutionStatus,
)
from raiden.tests.utils import factories
from raiden.tests.utils.factories import (
    ADDR,
    HOP1,
    HOP1_KEY,
    HOP1_TIMEOUT,
    HOP2,
    HOP2_KEY,
    HOP3,
    HOP3_KEY,
    HOP4,
    HOP4_KEY,
    HOP5_KEY,
    UNIT_HASHLOCK,
    UNIT_REVEAL_TIMEOUT,
    UNIT_SECRET,
    UNIT_TOKEN_ADDRESS,
    UNIT_TRANSFER_AMOUNT,
    UNIT_TRANSFER_IDENTIFIER,
    UNIT_TRANSFER_INITIATOR,
    UNIT_TRANSFER_SENDER,
    UNIT_TRANSFER_TARGET,
)


def make_transfer_pair(
        payee,
        initiator,
        target,
        amount,
        expiration,
        secret,
        reveal_timeout=UNIT_REVEAL_TIMEOUT):

    payer_expiration = expiration
    payee_expiration = expiration - reveal_timeout

    return MediationPairState2(
        factories.make_signed_transfer(amount, initiator, target, payer_expiration, secret=secret),
        payee,
        factories.make_transfer2(amount, initiator, target, payee_expiration, secret=secret),
    )


def make_transfers_pair(privatekeys, amount):
    transfers_pair = list()
    channelmap = dict()
    initial_expiration = (2 * len(privatekeys) + 1) * UNIT_REVEAL_TIMEOUT
    next_expiration = initial_expiration

    addresses = list()
    for pkey in privatekeys:
        pubkey = pkey.public_key.format(compressed=False)
        address = publickey_to_address(pubkey)
        addresses.append(address)

    key_address = list(zip(privatekeys, addresses))

    for (payer_key, payer_address), payee_address in zip(key_address[:-1], addresses[1:]):
        assert next_expiration > 0

        receive_channel = factories.make_channel(
            our_address=factories.HOP1,
            our_balance=amount,
            partner_balance=amount,
            partner_address=payer_address,
            token_address=UNIT_TOKEN_ADDRESS,
        )
        pay_channel = factories.make_channel(
            our_address=factories.HOP1,
            our_balance=amount,
            partner_balance=amount,
            partner_address=payee_address,
            token_address=UNIT_TOKEN_ADDRESS,
        )

        received_transfer = factories.make_signed_transfer(
            amount,
            UNIT_TRANSFER_INITIATOR,
            UNIT_TRANSFER_TARGET,
            next_expiration,
            UNIT_SECRET,
            channel_identifier=receive_channel.identifier,
            pkey=payer_key,
            sender=payer_address,
        )

        is_valid, msg = channel.handle_receive_mediatedtransfer(
            receive_channel,
            received_transfer,
        )
        assert is_valid, msg

        mediatedtransfer_event = channel.send_mediatedtransfer(
            pay_channel,
            UNIT_TRANSFER_INITIATOR,
            UNIT_TRANSFER_TARGET,
            amount,
            UNIT_TRANSFER_IDENTIFIER,
            received_transfer.lock.expiration - UNIT_REVEAL_TIMEOUT,
            UNIT_HASHLOCK,
        )
        assert mediatedtransfer_event
        sent_transfer = mediatedtransfer_event.transfer

        pair = MediationPairState2(
            received_transfer,
            mediatedtransfer_event.recipient,
            sent_transfer,
        )
        transfers_pair.append(pair)

        channelmap[receive_channel.identifier] = receive_channel
        channelmap[pay_channel.identifier] = pay_channel

        # assumes that the node sending the refund will follow the protocol and
        # decrement the expiration for its lock
        next_expiration = next_expiration - UNIT_REVEAL_TIMEOUT

    return channelmap, transfers_pair


def test_is_lock_valid():
    """ A hash time lock is valid up to the expiration block. """
    expiration = 10
    assert mediator.is_lock_valid(expiration, 5) is True
    assert mediator.is_lock_valid(expiration, 10) is True, 'lock is expired at the next block'
    assert mediator.is_lock_valid(expiration, 11) is False


def test_is_safe_to_wait():
    """ It's safe to wait for a secret while there are more than reveal timeout
    blocks until the lock expiration.
    """
    expiration = 40

    # expiration is in 30 blocks, 19 blocks safe for waiting
    block_number = 10
    reveal_timeout = 10
    assert mediator.is_safe_to_wait2(expiration, reveal_timeout, block_number) is True

    # expiration is in 20 blocks, 10 blocks safe for waiting
    block_number = 20
    reveal_timeout = 10
    assert mediator.is_safe_to_wait2(expiration, reveal_timeout, block_number) is True

    # expiration is in 11 blocks, 1 block safe for waiting
    block_number = 29
    reveal_timeout = 10
    assert mediator.is_safe_to_wait2(expiration, reveal_timeout, block_number) is True

    # at the block 30 it's not safe to wait anymore
    block_number = 30
    reveal_timeout = 10
    assert mediator.is_safe_to_wait2(expiration, reveal_timeout, block_number) is False

    block_number = 40
    reveal_timeout = 10
    assert mediator.is_safe_to_wait2(expiration, reveal_timeout, block_number) is False

    block_number = 50
    reveal_timeout = 10
    assert mediator.is_safe_to_wait2(expiration, reveal_timeout, block_number) is False


def test_is_channel_close_needed_unpaid():
    """ Don't close the channel if the payee transfer is not paid. """
    amount = 10
    expiration = 10
    reveal_timeout = 5
    safe_block = expiration - reveal_timeout - 1
    unsafe_block = expiration - reveal_timeout
    channel_state = factories.make_channel(reveal_timeout=reveal_timeout)

    # even if the secret is known by the payee, the transfer is paid only if a
    # withdraw on-chain happened or if the mediator has sent a balance proof
    for unpaid_state in ('payee_pending', 'payee_secret_revealed', 'payee_refund_withdraw'):
        unpaid_pair = make_transfer_pair(
            payee=HOP2,
            initiator=HOP3,
            target=HOP4,
            amount=amount,
            expiration=expiration,
            reveal_timeout=reveal_timeout,
            secret=UNIT_SECRET,
        )

        unpaid_pair.payer_state = unpaid_state
        assert mediator.is_channel_close_needed2(channel_state, unpaid_pair, safe_block) is False
        assert mediator.is_channel_close_needed2(channel_state, unpaid_pair, unsafe_block) is False


def test_is_channel_close_needed_paid():
    """ Close the channel if the payee transfer is paid but the payer has not paid. """
    amount = 10
    expiration = 10
    reveal_timeout = 5
    safe_block = expiration - reveal_timeout - 1
    unsafe_block = expiration - reveal_timeout
    channel_state = factories.make_channel(reveal_timeout=reveal_timeout)

    for paid_state in ('payee_contract_withdraw', 'payee_balance_proof'):
        paid_pair = make_transfer_pair(
            payee=HOP2,
            initiator=HOP3,
            target=HOP4,
            amount=amount,
            expiration=expiration,
            reveal_timeout=reveal_timeout,
            secret=UNIT_SECRET,
        )

        paid_pair.payee_state = paid_state
        assert mediator.is_channel_close_needed2(channel_state, paid_pair, safe_block) is False
        assert mediator.is_channel_close_needed2(channel_state, paid_pair, unsafe_block) is True


def test_is_channel_close_needed_channel_closing():
    """ If the channel is already closing the answer is always no. """
    amount = 10
    expiration = 10
    reveal_timeout = 5
    safe_block = expiration - reveal_timeout - 1
    unsafe_block = expiration - reveal_timeout

    channel_state = factories.make_channel(reveal_timeout=reveal_timeout)
    channel_state.close_transaction = TransactionExecutionStatus(5, None, None)

    for state in MediationPairState2.valid_payee_states:
        pair = make_transfer_pair(
            payee=HOP2,
            initiator=HOP3,
            target=HOP4,
            amount=amount,
            expiration=expiration,
            reveal_timeout=reveal_timeout,
            secret=UNIT_SECRET,
        )

        pair.payee_state = state
        assert mediator.is_channel_close_needed2(channel_state, pair, safe_block) is False
        assert mediator.is_channel_close_needed2(channel_state, pair, unsafe_block) is False


def test_is_channel_close_needed_channel_closed():
    """ If the channel is already closed the answer is always no. """
    amount = 10
    expiration = 10
    reveal_timeout = 5
    safe_block = expiration - reveal_timeout - 1
    unsafe_block = expiration - reveal_timeout
    channel_state = factories.make_channel(reveal_timeout=reveal_timeout)
    channel_state.close_transaction = TransactionExecutionStatus(
        None,
        5,
        TransactionExecutionStatus.SUCCESS,
    )

    for state in MediationPairState2.valid_payee_states:
        pair = make_transfer_pair(
            payee=HOP2,
            initiator=HOP3,
            target=HOP4,
            amount=amount,
            expiration=expiration,
            reveal_timeout=reveal_timeout,
            secret=UNIT_SECRET,
        )

        pair.payee_state = state
        assert mediator.is_channel_close_needed2(channel_state, pair, safe_block) is False
        assert mediator.is_channel_close_needed2(channel_state, pair, unsafe_block) is False


def test_is_channel_close_needed_closed():
    amount = 10
    expiration = 10
    reveal_timeout = 5
    safe_block = expiration - reveal_timeout - 1
    unsafe_block = expiration - reveal_timeout
    channel_state = factories.make_channel(reveal_timeout=reveal_timeout)

    paid_pair = make_transfer_pair(
        payee=HOP2,
        initiator=HOP3,
        target=HOP4,
        amount=amount,
        expiration=expiration,
        reveal_timeout=reveal_timeout,
        secret=UNIT_SECRET,
    )
    paid_pair.payee_state = 'payee_balance_proof'

    assert mediator.is_channel_close_needed2(channel_state, paid_pair, safe_block) is False
    assert mediator.is_channel_close_needed2(channel_state, paid_pair, unsafe_block) is True


def test_is_valid_refund():
    amount = 30
    expiration = 50

    transfer = factories.make_transfer2(
        amount,
        UNIT_TRANSFER_INITIATOR,
        UNIT_TRANSFER_TARGET,
        expiration,
        UNIT_SECRET,
    )

    refund_lower_expiration = factories.make_signed_transfer(
        amount,
        UNIT_TRANSFER_INITIATOR,
        UNIT_TRANSFER_TARGET,
        expiration - 1,
        UNIT_SECRET,
    )

    assert mediator.is_valid_refund2(transfer, refund_lower_expiration) is True

    refund_same_expiration = factories.make_signed_transfer(
        amount,
        UNIT_TRANSFER_INITIATOR,
        UNIT_TRANSFER_TARGET,
        expiration,
        UNIT_SECRET,
    )
    assert mediator.is_valid_refund2(transfer, refund_same_expiration) is False


def test_refund_from_target_is_invalid():
    amount = 30
    expiration = 50
    target = UNIT_TRANSFER_SENDER
    transfer = factories.make_transfer2(
        amount,
        UNIT_TRANSFER_INITIATOR,
        target,
        expiration,
        UNIT_SECRET,
    )

    refund_from_target = factories.make_signed_transfer(
        amount,
        UNIT_TRANSFER_INITIATOR,
        UNIT_TRANSFER_TARGET,
        expiration - 1,
        UNIT_SECRET,
    )

    # target cannot refund
    assert not mediator.is_valid_refund2(transfer, refund_from_target)


def test_get_timeout_blocks():
    settle_timeout = 30
    block_number = 5
    not_closed = None

    early_expire = 10
    early_block = mediator.get_timeout_blocks2(
        settle_timeout,
        not_closed,
        early_expire,
        block_number,
    )
    assert early_block == 5 - mediator.TRANSIT_BLOCKS, 'must use the lock expiration'

    equal_expire = 30
    equal_block = mediator.get_timeout_blocks2(
        settle_timeout,
        not_closed,
        equal_expire,
        block_number,
    )
    assert equal_block == 25 - mediator.TRANSIT_BLOCKS

    # This is the fix for test_lock_timeout_lower_than_previous_channel_settlement_period
    large_expire = 70
    large_block = mediator.get_timeout_blocks2(
        settle_timeout,
        not_closed,
        large_expire,
        block_number,
    )
    assert large_block == 30 - mediator.TRANSIT_BLOCKS, 'must use the settle timeout'

    closed_block_number = 2
    large_block = mediator.get_timeout_blocks2(
        settle_timeout,
        closed_block_number,
        large_expire,
        block_number,
    )
    assert large_block == 27 - mediator.TRANSIT_BLOCKS, 'must use the close block'

    # the computed timeout may be negative, in which case the calling code must /not/ use it
    negative_block_number = large_expire
    negative_block = mediator.get_timeout_blocks2(
        settle_timeout,
        not_closed,
        large_expire,
        negative_block_number,
    )
    assert negative_block == -mediator.TRANSIT_BLOCKS


def test_next_route_amount():
    """ Routes that dont have enough available_balance must be ignored. """
    amount = 10
    reveal_timeout = 30
    timeout_blocks = reveal_timeout + 10
    amount = UNIT_TRANSFER_AMOUNT
    channel1 = factories.make_channel(our_balance=amount)
    channel2 = factories.make_channel(our_balance=0)
    channel3 = factories.make_channel(our_balance=amount)

    channelmap = {
        channel1.identifier: channel1,
        channel2.identifier: channel2,
        channel3.identifier: channel3,
    }

    # the first available route should be used
    available_routes = [factories.route_from_channel(channel1)]
    chosen_channel = mediator.next_channel_from_routes(
        available_routes,
        channelmap,
        amount,
        timeout_blocks,
    )
    assert chosen_channel.identifier == channel1.identifier

    # additional routes do not change the order
    available_routes = [
        factories.route_from_channel(channel1),
        factories.route_from_channel(channel2),
    ]
    chosen_channel = mediator.next_channel_from_routes(
        available_routes,
        channelmap,
        amount,
        timeout_blocks,
    )
    assert chosen_channel.identifier == channel1.identifier

    available_routes = [
        factories.route_from_channel(channel3),
        factories.route_from_channel(channel1),
    ]
    chosen_channel = mediator.next_channel_from_routes(
        available_routes,
        channelmap,
        amount,
        timeout_blocks,
    )
    assert chosen_channel.identifier == channel3.identifier

    # a channel without capacity must be skipped
    available_routes = [
        factories.route_from_channel(channel2),
        factories.route_from_channel(channel1),
    ]
    chosen_channel = mediator.next_channel_from_routes(
        available_routes,
        channelmap,
        amount,
        timeout_blocks,
    )
    assert chosen_channel.identifier == channel1.identifier


def test_next_route_reveal_timeout():
    """ Routes with a larger reveal timeout than timeout_blocks must be ignored. """
    amount = 10
    balance = 20
    timeout_blocks = 10

    channel1 = factories.make_channel(our_balance=balance, reveal_timeout=timeout_blocks * 2)
    channel2 = factories.make_channel(our_balance=balance, reveal_timeout=timeout_blocks + 1)
    channel3 = factories.make_channel(our_balance=balance, reveal_timeout=timeout_blocks // 2)
    channel4 = factories.make_channel(our_balance=balance, reveal_timeout=timeout_blocks)

    channelmap = {
        channel1.identifier: channel1,
        channel2.identifier: channel2,
        channel3.identifier: channel3,
        channel4.identifier: channel4,
    }

    available_routes = [
        factories.route_from_channel(channel1),
        factories.route_from_channel(channel2),
        factories.route_from_channel(channel3),
        factories.route_from_channel(channel4),
    ]
    chosen_channel = mediator.next_channel_from_routes(
        available_routes,
        channelmap,
        amount,
        timeout_blocks,
    )
    assert chosen_channel.identifier == channel3.identifier


def test_next_transfer_pair():
    timeout_blocks = 47
    block_number = 3
    balance = 10
    initiator = HOP1
    target = ADDR
    expiration = 50
    secret = UNIT_SECRET

    payer_transfer = factories.make_signed_transfer(
        balance,
        initiator,
        target,
        expiration,
        secret,
    )

    channel1 = factories.make_channel(our_balance=balance, token_address=UNIT_TOKEN_ADDRESS)
    channelmap = {channel1.identifier: channel1}
    available_routes = [factories.route_from_channel(channel1)]

    pair, events = mediator.next_transfer_pair2(
        payer_transfer,
        available_routes,
        channelmap,
        timeout_blocks,
        block_number,
    )

    assert pair.payer_transfer == payer_transfer
    assert pair.payee_address == channel1.partner_state.address
    assert pair.payee_transfer.lock.expiration < pair.payer_transfer.lock.expiration

    assert isinstance(events[0], SendMediatedTransfer2)
    send_transfer = events[0]
    assert send_transfer.recipient == pair.payee_address

    transfer = send_transfer.transfer
    assert transfer.identifier == payer_transfer.identifier
    assert transfer.token == payer_transfer.token
    assert transfer.initiator == payer_transfer.initiator
    assert transfer.target == payer_transfer.target
    assert transfer.lock.amount == payer_transfer.lock.amount
    assert transfer.lock.hashlock == payer_transfer.lock.hashlock
    assert transfer.lock.expiration < payer_transfer.lock.expiration


def test_set_payee():
    amount = 10
    _, transfers_pair = make_transfers_pair(
        [
            HOP2_KEY,
            HOP3_KEY,
            HOP4_KEY,
        ],
        amount,
    )

    # assert pre conditions
    assert transfers_pair[0].payer_state == 'payer_pending'
    assert transfers_pair[0].payee_state == 'payee_pending'

    assert transfers_pair[1].payer_state == 'payer_pending'
    assert transfers_pair[1].payee_state == 'payee_pending'

    mediator.set_payee_state_and_check_reveal_order2(
        transfers_pair,
        HOP2,
        'payee_secret_revealed',
    )

    # payer address was used, no payee state should change
    assert transfers_pair[0].payer_state == 'payer_pending'
    assert transfers_pair[0].payee_state == 'payee_pending'

    assert transfers_pair[1].payer_state == 'payer_pending'
    assert transfers_pair[1].payee_state == 'payee_pending'

    mediator.set_payee_state_and_check_reveal_order2(
        transfers_pair,
        HOP3,
        'payee_secret_revealed',
    )

    # only the transfer where the address is a payee should change
    assert transfers_pair[0].payer_state == 'payer_pending'
    assert transfers_pair[0].payee_state == 'payee_secret_revealed'

    assert transfers_pair[1].payer_state == 'payer_pending'
    assert transfers_pair[1].payee_state == 'payee_pending'


def test_set_expired_pairs():
    """ The transfer pair must switch to expired at the right block. """
    amount = 10
    _, transfers_pair = make_transfers_pair(
        [HOP2_KEY, HOP3_KEY],
        amount,
    )

    pair = transfers_pair[0]

    # do not generate events if the secret is not known
    first_unsafe_block = pair.payer_transfer.lock.expiration - UNIT_REVEAL_TIMEOUT
    mediator.set_expired_pairs2(
        transfers_pair,
        first_unsafe_block,
    )
    assert pair.payee_state == 'payee_pending'
    assert pair.payer_state == 'payer_pending'

    # edge case for the payee lock expiration
    payee_expiration_block = pair.payee_transfer.lock.expiration
    mediator.set_expired_pairs2(
        transfers_pair,
        payee_expiration_block,
    )
    assert pair.payee_state == 'payee_pending'
    assert pair.payer_state == 'payer_pending'

    # payee lock expired
    mediator.set_expired_pairs2(
        transfers_pair,
        payee_expiration_block + 1,
    )
    assert pair.payee_state == 'payee_expired'
    assert pair.payer_state == 'payer_pending'

    # edge case for the payer lock expiration
    payer_expiration_block = pair.payer_transfer.lock.expiration
    mediator.set_expired_pairs2(
        transfers_pair,
        payer_expiration_block,
    )
    assert pair.payee_state == 'payee_expired'
    assert pair.payer_state == 'payer_pending'

    # payer lock has expired
    mediator.set_expired_pairs2(
        transfers_pair,
        payer_expiration_block + 1,
    )
    assert pair.payee_state == 'payee_expired'
    assert pair.payer_state == 'payer_expired'


def test_events_for_refund():
    amount = 10
    expiration = 30
    timeout_blocks = expiration
    block_number = 1

    refund_channel = factories.make_channel(
        our_balance=amount,
        partner_balance=amount,
        partner_address=UNIT_TRANSFER_SENDER,
    )

    received_transfer = factories.make_signed_transfer(
        amount,
        UNIT_TRANSFER_INITIATOR,
        UNIT_TRANSFER_TARGET,
        expiration,
        UNIT_SECRET,
        channel_identifier=refund_channel.identifier,
    )

    is_valid, msg = channel.handle_receive_mediatedtransfer(
        refund_channel,
        received_transfer,
    )
    assert is_valid, msg

    refund_transfer = factories.make_transfer2(
        amount,
        UNIT_TRANSFER_INITIATOR,
        UNIT_TRANSFER_TARGET,
        expiration,
        UNIT_SECRET,
    )

    small_timeout_blocks = refund_channel.reveal_timeout
    small_refund_events = mediator.events_for_refund_transfer2(
        refund_channel,
        refund_transfer,
        small_timeout_blocks,
        block_number,
    )
    assert not small_refund_events

    events = mediator.events_for_refund_transfer2(
        refund_channel,
        refund_transfer,
        timeout_blocks,
        block_number,
    )
    assert events
    assert events[0].lock.expiration < block_number + timeout_blocks
    assert events[0].lock.amount == amount
    assert events[0].lock.hashlock == refund_transfer.lock.hashlock
    assert events[0].recipient == refund_channel.partner_state.address


def test_events_for_revealsecret():
    """ The secret is revealed backwards to the payer once the payee sent the
    SecretReveal.
    """
    our_address = ADDR
    amount = 10

    _, transfers_pair = make_transfers_pair(
        [HOP2_KEY, HOP3_KEY, HOP4_KEY],
        amount,
    )

    events = mediator.events_for_revealsecret2(
        transfers_pair,
        our_address,
    )

    # the secret is known by this node, but no other payee is at a secret known
    # state, do nothing
    assert not events

    first_pair = transfers_pair[0]
    last_pair = transfers_pair[1]

    last_pair.payee_state = 'payee_secret_revealed'
    events = mediator.events_for_revealsecret2(
        transfers_pair,
        UNIT_SECRET,
    )

    # the last known hop sent a secret reveal message. This node learned the
    # secret and now must reveal it to the payer node from the transfer pair
    assert len(events) == 1
    assert events[0].secret == UNIT_SECRET
    assert events[0].receiver == last_pair.payer_transfer.balance_proof.sender
    assert last_pair.payer_state == 'payer_secret_revealed'

    events = mediator.events_for_revealsecret2(
        transfers_pair,
        our_address,
    )

    # the payeee from the first_pair did not send a secret reveal message, do
    # nothing
    assert not events

    first_pair.payee_state = 'payee_secret_revealed'
    events = mediator.events_for_revealsecret2(
        transfers_pair,
        UNIT_SECRET,
    )

    assert len(events) == 1
    assert events[0].secret == UNIT_SECRET
    assert events[0].receiver == first_pair.payer_transfer.balance_proof.sender
    assert first_pair.payer_state == 'payer_secret_revealed'


def test_events_for_revealsecret_secret_unknown():
    """ When the secret is not known there is nothing to do. """
    amount = 10
    _, transfers_pair = make_transfers_pair(
        [HOP2_KEY, HOP3_KEY, HOP4_KEY],
        amount,
    )

    events = mediator.events_for_revealsecret2(
        transfers_pair,
        ADDR,
    )

    assert not events


def test_events_for_revealsecret_all_states():
    """ The secret must be revealed backwards to the payer if the payee knows
    the secret.
    """
    payee_secret_known = (
        'payee_secret_revealed',
        'payee_refund_withdraw',
        'payee_contract_withdraw',
        'payee_balance_proof',
    )

    amount = 10
    for state in payee_secret_known:
        _, transfers_pair = make_transfers_pair(
            [HOP2_KEY, HOP3_KEY],
            amount,
        )

        pair = transfers_pair[0]
        pair.payee_state = state

        events = mediator.events_for_revealsecret2(
            transfers_pair,
            UNIT_SECRET,
        )

        assert events[0].secret == UNIT_SECRET
        assert events[0].receiver == HOP2


def test_events_for_balanceproof():
    """ Test the simple case where the last hop has learned the secret and sent
    it to the mediator node.
    """
    amount = 10

    channelmap, transfers_pair = make_transfers_pair(
        [HOP1_KEY, HOP2_KEY],
        amount,
    )
    last_pair = transfers_pair[-1]
    last_pair.payee_state = 'payee_secret_revealed'

    # the lock has not expired yet
    block_number = last_pair.payee_transfer.lock.expiration

    events = mediator.events_for_balanceproof2(
        channelmap,
        transfers_pair,
        block_number,
        UNIT_SECRET,
        UNIT_HASHLOCK,
    )
    assert len(events) == 2

    balance_proof = next(e for e in events if isinstance(e, SendBalanceProof2))
    unlock = next(e for e in events if isinstance(e, EventUnlockSuccess))
    assert unlock
    assert balance_proof
    assert balance_proof.receiver == last_pair.payee_address
    assert last_pair.payee_state == 'payee_balance_proof'


def test_events_for_balanceproof_channel_closed():
    """ Balance proofs are useless if the channel is closed/settled. The payee
    needs to go on-chain and use the latest known balance proof which includes
    this lock in the locksroot.
    """

    amount = 10
    block_number = 5
    for invalid_state in (CHANNEL_STATE_CLOSED, CHANNEL_STATE_SETTLED):
        channelmap, transfers_pair = make_transfers_pair(
            [HOP2_KEY, HOP3_KEY],
            amount,
        )

        last_pair = transfers_pair[-1]
        channel_identifier = last_pair.payee_transfer.balance_proof.channel_address
        last_channel = channelmap[channel_identifier]

        if invalid_state == CHANNEL_STATE_CLOSED:
            channel.set_closed(last_channel, block_number)
        else:
            channel.set_settled(last_channel, block_number)

        last_pair.payee_state = 'payee_secret_revealed'
        events = mediator.events_for_balanceproof2(
            channelmap,
            transfers_pair,
            block_number,
            UNIT_SECRET,
            UNIT_HASHLOCK,
        )

        assert not events


def test_events_for_balanceproof_middle_secret():
    """ Even though the secret should only propagate from the end of the chain
    to the front, if there is a payee node in the middle that knows the secret
    the Balance Proof is nevertheless sent.

    This can be done safely because the secret is known to the mediator and
    there is `reveal_timeout` blocks to withdraw the lock on-chain with the payer.
    """
    amount = 10
    channelmap, transfers_pair = make_transfers_pair(
        [HOP2_KEY, HOP3_KEY, HOP4_KEY, HOP5_KEY],
        amount,
    )

    block_number = 1
    middle_pair = transfers_pair[1]
    middle_pair.payee_state = 'payee_secret_revealed'

    events = mediator.events_for_balanceproof2(
        channelmap,
        transfers_pair,
        block_number,
        UNIT_SECRET,
        UNIT_HASHLOCK,
    )

    balance_proof = next(e for e in events if isinstance(e, SendBalanceProof2))

    assert len(events) == 2
    assert any(isinstance(e, EventUnlockSuccess) for e in events)
    assert balance_proof.receiver == middle_pair.payee_address
    assert middle_pair.payee_state == 'payee_balance_proof'


def test_events_for_balanceproof_secret_unknown():
    """ Nothing to do if the secret is not known. """
    block_number = 1
    amount = 10
    channelmap, transfers_pair = make_transfers_pair(
        [HOP2_KEY, HOP3_KEY, HOP4_KEY],
        amount,
    )

    # the secret is not known, so no event should be used
    events = mediator.events_for_balanceproof2(
        channelmap,
        transfers_pair,
        block_number,
        UNIT_SECRET,
        UNIT_HASHLOCK,
    )
    assert not events


def test_events_for_balanceproof_lock_expired():
    """ The balance proof should not be sent if the lock has expired. """
    amount = 10
    channelmap, transfers_pair = make_transfers_pair(
        [HOP2_KEY, HOP3_KEY, HOP4_KEY, HOP5_KEY],
        amount,
    )

    last_pair = transfers_pair[-1]
    last_pair.payee_state = 'payee_secret_revealed'
    block_number = last_pair.payee_transfer.lock.expiration + 1

    # the lock has expired, do not send a balance proof
    events = mediator.events_for_balanceproof2(
        channelmap,
        transfers_pair,
        block_number,
        UNIT_SECRET,
        UNIT_HASHLOCK,
    )
    assert not events

    middle_pair = transfers_pair[-2]
    middle_pair.payee_state = 'payee_secret_revealed'

    # Even though the last node did not receive the payment we should send the
    # balance proof to the middle node to avoid unnecessarily closing the
    # middle channel. This state should not be reached under normal operation.
    # The last hop needs to choose a proper reveal_timeout and must go on-chain
    # to withdraw the token before the lock expires.
    events = mediator.events_for_balanceproof2(
        channelmap,
        transfers_pair,
        block_number,
        UNIT_SECRET,
        UNIT_HASHLOCK,
    )

    balance_proof = next(e for e in events if isinstance(e, SendBalanceProof2))

    assert len(events) == 2
    assert any(isinstance(e, EventUnlockSuccess) for e in events)
    assert balance_proof.receiver == middle_pair.payee_address
    assert middle_pair.payee_state == 'payee_balance_proof'


def test_events_for_close():
    """ The node must close to unlock on-chain if the payee was paid. """
    amount = 10

    for payee_state in ('payee_balance_proof', 'payee_contract_withdraw'):
        channelmap, transfers_pair = make_transfers_pair(
            [HOP2_KEY, HOP3_KEY],
            amount,
        )

        pair = transfers_pair[0]
        pair.payee_state = payee_state
        channel_identifier = pair.payer_transfer.balance_proof.channel_address
        channel_state = channelmap[channel_identifier]

        block_number = (
            pair.payer_transfer.lock.expiration - channel_state.reveal_timeout
        )

        events = mediator.events_for_close2(
            channelmap,
            transfers_pair,
            block_number,
        )

        assert isinstance(events[0], ContractSendChannelClose)
        assert events[0].channel_identifier == pair.payer_transfer.balance_proof.channel_address
        assert pair.payer_state == 'payer_waiting_close'


def test_events_for_close_hold_for_unpaid_payee():
    """ If the secret is known but the payee transfer has not been paid the
    node must not settle on-chain, otherwise the payee can burn tokens to
    force the mediator to close a channel.
    """

    amount = 10
    channelmap, transfers_pair = make_transfers_pair(
        [HOP2_KEY, HOP3_KEY],
        amount,
    )
    pair = transfers_pair[0]

    for channel_state in channelmap.values():
        channel.register_secret(channel_state, UNIT_SECRET, UNIT_HASHLOCK)

    # preconditions
    assert pair.payee_state not in mediator.STATE_TRANSFER_PAID

    # do not generate events if the secret is known AND the payee is not paid
    channel_identifier = pair.payer_transfer.balance_proof.channel_address
    channel_state = channelmap[channel_identifier]
    first_unsafe_block = pair.payer_transfer.lock.expiration - channel_state.reveal_timeout
    events = mediator.events_for_close2(
        channelmap,
        transfers_pair,
        first_unsafe_block,
    )

    assert not events
    assert pair.payee_state not in mediator.STATE_TRANSFER_PAID
    assert pair.payer_state not in mediator.STATE_TRANSFER_PAID

    payer_expiration_block = pair.payer_transfer.lock.expiration
    events = mediator.events_for_close2(
        channelmap,
        transfers_pair,
        payer_expiration_block,
    )
    assert not events
    assert pair.payee_state not in mediator.STATE_TRANSFER_PAID
    assert pair.payer_state not in mediator.STATE_TRANSFER_PAID

    payer_expiration_block = pair.payer_transfer.lock.expiration
    events = mediator.events_for_close2(
        channelmap,
        transfers_pair,
        payer_expiration_block + 1,
    )
    assert not events
    assert pair.payee_state not in mediator.STATE_TRANSFER_PAID
    assert pair.payer_state not in mediator.STATE_TRANSFER_PAID


def test_secret_learned():
    amount = UNIT_TRANSFER_AMOUNT
    target = HOP2
    from_expiration = HOP1_TIMEOUT

    from_channel = factories.make_channel(
        partner_balance=amount,
        partner_address=UNIT_TRANSFER_SENDER,
        token_address=UNIT_TOKEN_ADDRESS,
    )
    from_route = factories.route_from_channel(from_channel)

    from_transfer = factories.make_signed_transfer_for(
        from_channel,
        amount,
        HOP1,
        target,
        from_expiration,
        UNIT_SECRET,
    )

    channel1 = factories.make_channel(
        our_balance=amount,
        token_address=UNIT_TOKEN_ADDRESS,
    )
    available_routes = [factories.route_from_channel(channel1)]
    channelmap = {
        from_channel.identifier: from_channel,
        channel1.identifier: channel1,
    }

    block_number = 1
    payment_network_identifier = factories.make_address()
    init_state_change = ActionInitMediator2(
        payment_network_identifier,
        available_routes,
        from_route,
        from_transfer,
    )

    initial_state = None
    iteration = mediator.state_transition2(
        initial_state,
        init_state_change,
        channelmap,
        block_number,
    )

    iteration = mediator.secret_learned2(
        iteration.new_state,
        channelmap,
        block_number,
        UNIT_SECRET,
        UNIT_HASHLOCK,
        channel1.partner_state.address,
        'payee_secret_revealed',
    )
    transfer_pair = iteration.new_state.transfers_pair[0]

    assert from_transfer.lock.expiration > transfer_pair.payee_transfer.lock.expiration
    assert mediator.is_send_transfer_almost_equal(transfer_pair.payee_transfer, from_transfer)
    assert transfer_pair.payee_address == available_routes[0].node_address

    assert transfer_pair.payer_transfer.balance_proof.sender == from_route.node_address
    assert transfer_pair.payer_transfer == from_transfer

    assert iteration.new_state.secret == UNIT_SECRET

    assert transfer_pair.payee_state == 'payee_balance_proof'
    assert transfer_pair.payer_state == 'payer_secret_revealed'

    reveal_events = [e for e in iteration.events if isinstance(e, SendRevealSecret2)]
    assert len(reveal_events) == 1

    balance_events = [e for e in iteration.events if isinstance(e, SendBalanceProof2)]
    assert len(balance_events) == 1


def test_mediate_transfer():
    amount = 10
    block_number = 5
    target = HOP2
    expiration = 30

    payer_channel = factories.make_channel(
        partner_balance=amount,
        partner_address=UNIT_TRANSFER_SENDER,
        token_address=UNIT_TOKEN_ADDRESS,
    )

    payer_transfer = factories.make_signed_transfer_for(
        payer_channel,
        amount,
        HOP1,
        target,
        expiration,
        UNIT_SECRET,
    )

    channel1 = factories.make_channel(
        our_balance=amount,
        token_address=UNIT_TOKEN_ADDRESS,
    )
    channelmap = {
        channel1.identifier: channel1,
        payer_channel.identifier: payer_channel,
    }
    possible_routes = [factories.route_from_channel(channel1)]

    mediator_state = MediatorTransferState(UNIT_HASHLOCK)
    iteration = mediator.mediate_transfer2(
        mediator_state,
        possible_routes,
        payer_channel,
        channelmap,
        payer_transfer,
        block_number,
    )
    assert len(iteration.events) == 1

    send_transfer = iteration.events[0]
    assert isinstance(send_transfer, SendMediatedTransfer2)

    transfer = send_transfer.transfer
    assert transfer.identifier == payer_transfer.identifier
    assert transfer.token == payer_transfer.token
    assert transfer.lock.amount == payer_transfer.lock.amount
    assert transfer.lock.hashlock == payer_transfer.lock.hashlock
    assert transfer.target == payer_transfer.target
    assert payer_transfer.lock.expiration > transfer.lock.expiration
    assert send_transfer.recipient == channel1.partner_state.address


def test_init_mediator():
    amount = UNIT_TRANSFER_AMOUNT
    target = HOP2
    from_expiration = HOP1_TIMEOUT

    from_channel = factories.make_channel(
        partner_balance=amount,
        partner_address=UNIT_TRANSFER_SENDER,
        token_address=UNIT_TOKEN_ADDRESS,
    )
    from_route = factories.route_from_channel(from_channel)

    from_transfer = factories.make_signed_transfer_for(
        from_channel,
        amount,
        HOP1,
        target,
        from_expiration,
        UNIT_SECRET,
    )

    channel1 = factories.make_channel(
        our_balance=amount,
        partner_address=HOP2,
        token_address=UNIT_TOKEN_ADDRESS,
    )
    available_routes = [factories.route_from_channel(channel1)]
    channelmap = {
        from_channel.identifier: from_channel,
        channel1.identifier: channel1,
    }

    block_number = 1
    payment_network_identifier = factories.make_address()
    init_state_change = ActionInitMediator2(
        payment_network_identifier,
        available_routes,
        from_route,
        from_transfer,
    )

    mediator_state = None
    iteration = mediator.state_transition2(
        mediator_state,
        init_state_change,
        channelmap,
        block_number,
    )

    assert isinstance(iteration.new_state, MediatorTransferState)
    assert iteration.new_state.transfers_pair[0].payer_transfer == from_transfer

    msg = 'we have a valid route, the mediated transfer event must be emitted'
    assert iteration.events, msg

    mediated_transfers = [e for e in iteration.events if isinstance(e, SendMediatedTransfer2)]
    assert len(mediated_transfers) == 1, 'mediated_transfer should /not/ split the transfer'
    send_transfer = mediated_transfers[0]
    mediated_transfer = send_transfer.transfer

    assert mediated_transfer.token == from_transfer.token, 'transfer token address mismatch'
    assert mediated_transfer.lock.amount == from_transfer.lock.amount, 'transfer amount mismatch'
    msg = 'transfer expiration mismatch'
    assert mediated_transfer.lock.expiration < from_transfer.lock.expiration, msg
    assert mediated_transfer.lock.hashlock == from_transfer.lock.hashlock, 'wrong hashlock'


def test_no_valid_routes():
    amount = UNIT_TRANSFER_AMOUNT
    target = HOP2
    from_expiration = HOP1_TIMEOUT

    from_channel = factories.make_channel(
        our_balance=amount,
        partner_balance=amount,
        partner_address=UNIT_TRANSFER_SENDER,
        token_address=UNIT_TOKEN_ADDRESS,
    )
    from_route = factories.route_from_channel(from_channel)

    from_transfer = factories.make_signed_transfer_for(
        from_channel,
        amount,
        HOP1,
        target,
        from_expiration,
        UNIT_SECRET,
    )

    channel1 = factories.make_channel(
        our_balance=amount - 1,
        token_address=UNIT_TOKEN_ADDRESS,
    )
    channel2 = factories.make_channel(
        our_balance=0,
        token_address=UNIT_TOKEN_ADDRESS,
    )
    available_routes = [
        factories.route_from_channel(channel1),
        factories.route_from_channel(channel2),
    ]
    channelmap = {
        from_channel.identifier: from_channel,
        channel1.identifier: channel1,
        channel2.identifier: channel2,
    }

    block_number = 1
    payment_network_identifier = factories.make_address()
    init_state_change = ActionInitMediator2(
        payment_network_identifier,
        available_routes,
        from_route,
        from_transfer,
    )

    mediator_state = None
    iteration = mediator.state_transition2(
        mediator_state,
        init_state_change,
        channelmap,
        block_number,
    )
    assert iteration.new_state is None

    assert len(iteration.events) == 1
    assert isinstance(iteration.events[0], SendRefundTransfer2)


def test_lock_timeout_lower_than_previous_channel_settlement_period():
    # For a path A-B-C, B cannot forward a mediated transfer to C with
    # a lock timeout larger than the settlement timeout of the A-B
    # channel.
    #
    # Consider that an attacker controls both nodes A and C:
    #
    # Channels A <-> B and B <-> C have a settlement=10 and B has a
    # reveal_timeout=5
    #
    # (block=1) A -> B [T1 expires=20]
    # (block=1) B -> C [T2 expires=20-5]
    # (block=1) A close channel A-B
    # (block=5) C close channel B-C (waited until lock_expiration=settle_timeout)
    # (block=11) A call settle on channel A-B (settle_timeout is over)
    # (block=12) C call unlock on channel B-C (lock is still valid)
    #
    # If B used min(lock.expiration, previous_channel.settlement)
    #
    # (block=1) A -> B [T1 expires=20]
    # (block=1) B -> C [T2 expires=min(20,10)-5]
    # (block=1) A close channel A-B
    # (block=4) C close channel B-C (waited all possible blocks)
    # (block=5) C call unlock on channel B-C (C is forced to unlock)
    # (block=6) B learns the secret
    # (block=7) B call unlock on channel A-B (settle_timeout is over)
    amount = UNIT_TRANSFER_AMOUNT
    target = HOP2
    high_from_expiration = 20
    low_reveal_timeout = 5
    low_settlement_expiration = 10

    from_channel = factories.make_channel(
        our_balance=amount,
        partner_balance=amount,
        partner_address=UNIT_TRANSFER_SENDER,
        token_address=UNIT_TOKEN_ADDRESS,
        reveal_timeout=low_reveal_timeout,
        settle_timeout=low_settlement_expiration,
    )
    from_route = factories.route_from_channel(from_channel)

    from_transfer = factories.make_signed_transfer_for(
        from_channel,
        amount,
        HOP1,
        target,
        high_from_expiration,
        UNIT_SECRET,
    )

    # Assert the precondition for the test. The message is still valid, and the
    # receiver cannot control the received lock expiration
    assert from_transfer.lock.expiration >= from_channel.settle_timeout

    channel1 = factories.make_channel(
        our_balance=amount,
        token_address=UNIT_TOKEN_ADDRESS,
        reveal_timeout=low_reveal_timeout,
        settle_timeout=low_settlement_expiration,
    )

    available_routes = [
        factories.route_from_channel(channel1),
    ]
    channelmap = {
        from_channel.identifier: from_channel,
        channel1.identifier: channel1,
    }

    block_number = 1
    payment_network_identifier = factories.make_address()
    init_state_change = ActionInitMediator2(
        payment_network_identifier,
        available_routes,
        from_route,
        from_transfer,
    )

    mediator_state = None
    iteration = mediator.state_transition2(
        mediator_state,
        init_state_change,
        channelmap,
        block_number,
    )

    assert isinstance(iteration.new_state, MediatorTransferState)
    assert iteration.events

    mediated_transfers = [e for e in iteration.events if isinstance(e, SendMediatedTransfer2)]
    assert len(mediated_transfers) == 1, 'mediated_transfer should /not/ split the transfer'
    send_transfer = mediated_transfers[0]
    mediated_transfer = send_transfer.transfer

    msg = 'transfer expiration must be lower than the funding channel settlement window'
    assert mediated_transfer.lock.expiration < low_settlement_expiration, msg


@pytest.mark.xfail(reason='Not implemented. Issue: #382')
def test_do_not_withdraw_an_almost_expiring_lock_if_a_payment_didnt_occur():
    # For a path A1-B-C-A2, an attacker controlling A1 and A2 should not be
    # able to force B-C to close the channel by burning token.
    #
    # The attack would be as follows:
    #
    # - Attacker uses two nodes to open two really cheap channels A1 <-> B and
    #   node A2 <-> C
    # - Attacker sends a mediated message with the lowest possible token
    #   amount from A1 through B and C to A2
    # - Since the attacker controls A1 and A2 it knows the secret, she can choose
    #   when the secret is revealed
    # - The secret is held back until the hash time lock B->C is almost expiring,
    #   then it's revealed (meaning that the attacker is losing token, that's why
    #   it's using the lowest possible amount)
    # - C wants the token from B. It will reveal the secret and close the channel
    #   (because it must assume the balance proof won't make in time and it needs
    #   to unlock on-chain)
    #
    # Mitigation:
    #
    # - C should only close the channel B-C if he has paid A2, since this may
    #   only happen if the lock for the transfer C-A2 has not yet expired then C
    #   has enough time to follow the protocol without closing the channel B-C.
    raise NotImplementedError()


@pytest.mark.xfail(reason='Not implemented. Issue: #382')
def mediate_transfer_payee_timeout_must_be_lower_than_settlement_and_payer_timeout():
    # Test:
    # - the current payer route/transfer is the reference, not the from_route / from_transfer
    # - the lowest value from blocks_until_settlement and lock expiration must be used
    raise NotImplementedError()


@pytest.mark.xfail(reason='Not implemented. Issue: #382')
def payee_timeout_must_be_lower_than_payer_timeout_minus_reveal_timeout():
    # The payee could reveal the secret on its lock expiration block, the
    # mediator node will respond with a balance-proof to the payee since the
    # lock is valid and the mediator can safely get the token from the payer.
    # The secret is known and if there are no additional blocks the mediator
    # will be at risk of not being able to withdraw on-chain, so the channel
    # will be closed to safely withdraw.
    #
    # T2.expiration cannot be equal to T1.expiration - reveal_timeout:
    #
    # T1 |---|
    # T2     |---|
    #        ^- reveal the secret
    #        T1.expiration - reveal_timeout == current_block -> withdraw on chain
    #
    # If T2.expiration cannot be equal to T1.expiration - reveal_timeout minus ONE:
    #
    # T1 |---|
    # T2      |---|
    #         ^- reveal the secret
    #
    # Race:
    #  1> Secret is learned
    #  2> balance-proof is sent to payee (payee transfer is paid)
    #  3! New block is mined and Raiden learns about it
    #  4> Now the secret is known, the payee is paid, and the current block is
    #     equal to the payer.expiration - reveal-timeout -> withdraw on chain
    #
    # The race is depending on the handling of 3 before 4.
    #
    raise NotImplementedError()
