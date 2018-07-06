# pylint: disable=invalid-name,too-many-locals,too-many-arguments,too-many-lines
import random

import pytest

from raiden.utils import publickey_to_address
from raiden.transfer import channel
from raiden.transfer.events import ContractSendChannelClose
from raiden.transfer.mediated_transfer import mediator
from raiden.transfer.mediated_transfer.state import (
    MediationPairState,
    MediatorTransferState,
)
from raiden.transfer.mediated_transfer.state_change import (
    ActionInitMediator,
    ReceiveSecretReveal,
)
from raiden.transfer.mediated_transfer.events import (
    EventUnlockFailed,
    EventUnlockSuccess,
    SendBalanceProof,
    SendLockedTransfer,
    SendRefundTransfer,
    SendRevealSecret,
)
from raiden.transfer.mediated_transfer.mediator import set_secret
from raiden.transfer.state import (
    CHANNEL_STATE_CLOSED,
    CHANNEL_STATE_SETTLED,
    message_identifier_from_prng,
    TransactionExecutionStatus,
)
from raiden.transfer.state_change import Block
from raiden.transfer.events import ContractSendSecretReveal
from raiden.tests.utils import factories
from raiden.tests.utils.events import must_contain_entry
from raiden.tests.utils.factories import (
    ADDR,
    HOP1,
    HOP1_KEY,
    UNIT_SETTLE_TIMEOUT,
    HOP2,
    HOP2_KEY,
    HOP3,
    HOP3_KEY,
    HOP4,
    HOP4_KEY,
    HOP5,
    HOP5_KEY,
    UNIT_SECRETHASH,
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

    return MediationPairState(
        factories.make_signed_transfer(amount, initiator, target, payer_expiration, secret=secret),
        payee,
        factories.make_transfer(amount, initiator, target, payee_expiration, secret=secret),
    )


def make_transfers_pair(privatekeys, amount):
    transfers_pair = list()
    channelmap = dict()
    initial_expiration = (2 * len(privatekeys) + 1) * UNIT_REVEAL_TIMEOUT
    next_expiration = initial_expiration
    pseudo_random_generator = random.Random()

    addresses = list()
    for pkey in privatekeys:
        pubkey = pkey.public_key.format(compressed=False)
        address = publickey_to_address(pubkey)
        addresses.append(address)

    key_address = list(zip(privatekeys, addresses))

    payment_identifier = UNIT_TRANSFER_IDENTIFIER

    channels_state = {
        address: factories.make_channel(
            our_address=factories.HOP1,
            our_balance=amount,
            partner_balance=amount,
            partner_address=address,
            token_address=UNIT_TOKEN_ADDRESS,
        )
        for address in addresses
    }

    for (payer_key, payer_address), payee_address in zip(key_address[:-1], addresses[1:]):
        assert next_expiration > 0

        pay_channel = channels_state[payee_address]
        receive_channel = channels_state[payer_address]

        received_transfer = factories.make_signed_transfer(
            amount,
            UNIT_TRANSFER_INITIATOR,
            UNIT_TRANSFER_TARGET,
            next_expiration,
            UNIT_SECRET,
            payment_identifier=payment_identifier,
            channel_identifier=receive_channel.identifier,
            pkey=payer_key,
            sender=payer_address,
        )

        is_valid, _, msg = channel.handle_receive_lockedtransfer(
            receive_channel,
            received_transfer,
        )
        assert is_valid, msg

        message_identifier = message_identifier_from_prng(pseudo_random_generator)
        lockedtransfer_event = channel.send_lockedtransfer(
            pay_channel,
            UNIT_TRANSFER_INITIATOR,
            UNIT_TRANSFER_TARGET,
            amount,
            message_identifier,
            payment_identifier,
            received_transfer.lock.expiration - UNIT_REVEAL_TIMEOUT,
            UNIT_SECRETHASH,
        )
        assert lockedtransfer_event
        sent_transfer = lockedtransfer_event.transfer

        pair = MediationPairState(
            received_transfer,
            lockedtransfer_event.recipient,
            sent_transfer,
        )
        transfers_pair.append(pair)

        channelmap[receive_channel.identifier] = receive_channel
        channelmap[pay_channel.identifier] = pay_channel

        # assumes that the node sending the refund will follow the protocol and
        # decrement the expiration for its lock
        next_expiration = next_expiration - (UNIT_REVEAL_TIMEOUT * 2)

        assert channel.is_lock_locked(receive_channel.partner_state, UNIT_SECRETHASH)
        assert channel.is_lock_locked(pay_channel.our_state, UNIT_SECRETHASH)

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
    assert mediator.is_safe_to_wait(expiration, reveal_timeout, block_number) is True

    # expiration is in 20 blocks, 10 blocks safe for waiting
    block_number = 20
    reveal_timeout = 10
    assert mediator.is_safe_to_wait(expiration, reveal_timeout, block_number) is True

    # expiration is in 11 blocks, 1 block safe for waiting
    block_number = 29
    reveal_timeout = 10
    assert mediator.is_safe_to_wait(expiration, reveal_timeout, block_number) is True

    # at the block 30 it's not safe to wait anymore
    block_number = 30
    reveal_timeout = 10
    assert mediator.is_safe_to_wait(expiration, reveal_timeout, block_number) is False

    block_number = 40
    reveal_timeout = 10
    assert mediator.is_safe_to_wait(expiration, reveal_timeout, block_number) is False

    block_number = 50
    reveal_timeout = 10
    assert mediator.is_safe_to_wait(expiration, reveal_timeout, block_number) is False


def test_is_channel_close_needed_unpaid():
    """ Don't close the channel if the payee transfer is not paid. """
    amount = 10
    expiration = 10
    reveal_timeout = 5
    safe_block = expiration - reveal_timeout - 1
    unsafe_block = expiration - reveal_timeout
    channel_state = factories.make_channel(reveal_timeout=reveal_timeout)

    # even if the secret is known by the payee, the transfer is paid only if a
    # unlock on-chain happened or if the mediator has sent a balance proof
    for unpaid_state in ('payee_pending', 'payee_secret_revealed'):
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
        assert mediator.is_channel_close_needed(channel_state, unpaid_pair, safe_block) is False
        assert mediator.is_channel_close_needed(channel_state, unpaid_pair, unsafe_block) is False


def test_is_channel_close_needed_paid():
    """ Close the channel if the payee transfer is paid but the payer has not paid. """
    amount = 10
    expiration = 10
    reveal_timeout = 5
    safe_block = expiration - reveal_timeout - 1
    unsafe_block = expiration - reveal_timeout
    channel_state = factories.make_channel(reveal_timeout=reveal_timeout)

    for paid_state in ('payee_contract_unlock', 'payee_balance_proof'):
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
        assert mediator.is_channel_close_needed(channel_state, paid_pair, safe_block) is False
        assert mediator.is_channel_close_needed(channel_state, paid_pair, unsafe_block) is True


def test_is_channel_close_needed_channel_closing():
    """ If the channel is already closing the answer is always no. """
    amount = 10
    expiration = 10
    reveal_timeout = 5
    safe_block = expiration - reveal_timeout - 1
    unsafe_block = expiration - reveal_timeout

    channel_state = factories.make_channel(reveal_timeout=reveal_timeout)
    channel_state.close_transaction = TransactionExecutionStatus(5, None, None)

    for state in MediationPairState.valid_payee_states:
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
        assert mediator.is_channel_close_needed(channel_state, pair, safe_block) is False
        assert mediator.is_channel_close_needed(channel_state, pair, unsafe_block) is False


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

    for state in MediationPairState.valid_payee_states:
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
        assert mediator.is_channel_close_needed(channel_state, pair, safe_block) is False
        assert mediator.is_channel_close_needed(channel_state, pair, unsafe_block) is False


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

    assert mediator.is_channel_close_needed(channel_state, paid_pair, safe_block) is False
    assert mediator.is_channel_close_needed(channel_state, paid_pair, unsafe_block) is True


def test_get_timeout_blocks():
    settle_timeout = 30
    block_number = 5
    not_closed = None

    early_expire = 10
    early_block = mediator.get_timeout_blocks(
        settle_timeout,
        not_closed,
        early_expire,
        block_number,
    )
    assert early_block == 5 - mediator.TRANSIT_BLOCKS, 'must use the lock expiration'

    equal_expire = 30
    equal_block = mediator.get_timeout_blocks(
        settle_timeout,
        not_closed,
        equal_expire,
        block_number,
    )
    assert equal_block == 25 - mediator.TRANSIT_BLOCKS

    # This is the fix for test_lock_timeout_lower_than_previous_channel_settlement_period
    large_expire = 70
    large_block = mediator.get_timeout_blocks(
        settle_timeout,
        not_closed,
        large_expire,
        block_number,
    )
    assert large_block == 30 - mediator.TRANSIT_BLOCKS, 'must use the settle timeout'

    closed_block_number = 2
    large_block = mediator.get_timeout_blocks(
        settle_timeout,
        closed_block_number,
        large_expire,
        block_number,
    )
    assert large_block == 27 - mediator.TRANSIT_BLOCKS, 'must use the close block'

    # the computed timeout may be negative, in which case the calling code must /not/ use it
    negative_block_number = large_expire
    negative_block = mediator.get_timeout_blocks(
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
    pseudo_random_generator = random.Random()

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

    pair, events = mediator.next_transfer_pair(
        payer_transfer,
        available_routes,
        channelmap,
        pseudo_random_generator,
        timeout_blocks,
        block_number,
    )

    assert pair.payer_transfer == payer_transfer
    assert pair.payee_address == channel1.partner_state.address
    assert pair.payee_transfer.lock.expiration < pair.payer_transfer.lock.expiration

    assert isinstance(events[0], SendLockedTransfer)
    send_transfer = events[0]
    assert send_transfer.recipient == pair.payee_address

    transfer = send_transfer.transfer
    assert transfer.payment_identifier == payer_transfer.payment_identifier
    assert transfer.token == payer_transfer.token
    assert transfer.initiator == payer_transfer.initiator
    assert transfer.target == payer_transfer.target
    assert transfer.lock.amount == payer_transfer.lock.amount
    assert transfer.lock.secrethash == payer_transfer.lock.secrethash
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

    mediator.set_payee_state_and_check_reveal_order(
        transfers_pair,
        HOP2,
        'payee_secret_revealed',
    )

    # payer address was used, no payee state should change
    assert transfers_pair[0].payer_state == 'payer_pending'
    assert transfers_pair[0].payee_state == 'payee_pending'

    assert transfers_pair[1].payer_state == 'payer_pending'
    assert transfers_pair[1].payee_state == 'payee_pending'

    mediator.set_payee_state_and_check_reveal_order(
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
    mediator.set_expired_pairs(
        transfers_pair,
        first_unsafe_block,
    )
    assert pair.payee_state == 'payee_pending'
    assert pair.payer_state == 'payer_pending'

    # edge case for the payee lock expiration
    payee_expiration_block = pair.payee_transfer.lock.expiration
    mediator.set_expired_pairs(
        transfers_pair,
        payee_expiration_block,
    )
    assert pair.payee_state == 'payee_pending'
    assert pair.payer_state == 'payer_pending'

    # payee lock expired
    mediator.set_expired_pairs(
        transfers_pair,
        payee_expiration_block + 1,
    )
    assert pair.payee_state == 'payee_expired'
    assert pair.payer_state == 'payer_pending'

    # edge case for the payer lock expiration
    payer_expiration_block = pair.payer_transfer.lock.expiration
    mediator.set_expired_pairs(
        transfers_pair,
        payer_expiration_block,
    )
    assert pair.payee_state == 'payee_expired'
    assert pair.payer_state == 'payer_pending'

    # payer lock has expired
    mediator.set_expired_pairs(
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
    pseudo_random_generator = random.Random()

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

    is_valid, _, msg = channel.handle_receive_lockedtransfer(
        refund_channel,
        received_transfer,
    )
    assert is_valid, msg

    refund_transfer = factories.make_transfer(
        amount,
        UNIT_TRANSFER_INITIATOR,
        UNIT_TRANSFER_TARGET,
        expiration,
        UNIT_SECRET,
    )

    small_timeout_blocks = refund_channel.reveal_timeout
    small_refund_events = mediator.events_for_refund_transfer(
        refund_channel,
        refund_transfer,
        pseudo_random_generator,
        small_timeout_blocks,
        block_number,
    )
    assert not small_refund_events

    events = mediator.events_for_refund_transfer(
        refund_channel,
        refund_transfer,
        pseudo_random_generator,
        timeout_blocks,
        block_number,
    )
    assert events
    assert events[0].lock.expiration < block_number + timeout_blocks
    assert events[0].lock.amount == amount
    assert events[0].lock.secrethash == refund_transfer.lock.secrethash
    assert events[0].recipient == refund_channel.partner_state.address


def test_events_for_revealsecret():
    """ The secret is revealed backwards to the payer once the payee sent the
    SecretReveal.
    """
    our_address = ADDR
    amount = 10
    pseudo_random_generator = random.Random()

    _, transfers_pair = make_transfers_pair(
        [HOP2_KEY, HOP3_KEY, HOP4_KEY],
        amount,
    )

    events = mediator.events_for_revealsecret(
        transfers_pair,
        our_address,
        pseudo_random_generator,
    )

    # the secret is known by this node, but no other payee is at a secret known
    # state, do nothing
    assert not events

    first_pair = transfers_pair[0]
    last_pair = transfers_pair[1]

    last_pair.payee_state = 'payee_secret_revealed'
    events = mediator.events_for_revealsecret(
        transfers_pair,
        UNIT_SECRET,
        pseudo_random_generator,
    )

    # the last known hop sent a secret reveal message. This node learned the
    # secret and now must reveal it to the payer node from the transfer pair
    assert len(events) == 1
    assert events[0].secret == UNIT_SECRET
    assert events[0].recipient == last_pair.payer_transfer.balance_proof.sender
    assert last_pair.payer_state == 'payer_secret_revealed'

    events = mediator.events_for_revealsecret(
        transfers_pair,
        our_address,
        pseudo_random_generator,
    )

    # the payeee from the first_pair did not send a secret reveal message, do
    # nothing
    assert not events

    first_pair.payee_state = 'payee_secret_revealed'
    events = mediator.events_for_revealsecret(
        transfers_pair,
        UNIT_SECRET,
        pseudo_random_generator,
    )

    assert len(events) == 1
    assert events[0].secret == UNIT_SECRET
    assert events[0].recipient == first_pair.payer_transfer.balance_proof.sender
    assert first_pair.payer_state == 'payer_secret_revealed'


def test_events_for_revealsecret_secret_unknown():
    """ When the secret is not known there is nothing to do. """
    amount = 10
    pseudo_random_generator = random.Random()

    _, transfers_pair = make_transfers_pair(
        [HOP2_KEY, HOP3_KEY, HOP4_KEY],
        amount,
    )

    events = mediator.events_for_revealsecret(
        transfers_pair,
        ADDR,
        pseudo_random_generator,
    )

    assert not events


def test_events_for_revealsecret_all_states():
    """ The secret must be revealed backwards to the payer if the payee knows
    the secret.
    """
    payee_secret_known = (
        'payee_secret_revealed',
        'payee_contract_unlock',
        'payee_balance_proof',
    )
    pseudo_random_generator = random.Random()

    amount = 10
    for state in payee_secret_known:
        _, transfers_pair = make_transfers_pair(
            [HOP2_KEY, HOP3_KEY],
            amount,
        )

        pair = transfers_pair[0]
        pair.payee_state = state

        events = mediator.events_for_revealsecret(
            transfers_pair,
            UNIT_SECRET,
            pseudo_random_generator,
        )

        assert events[0].secret == UNIT_SECRET
        assert events[0].recipient == HOP2


def test_events_for_balanceproof():
    """ Test the simple case where the last hop has learned the secret and sent
    it to the mediator node.
    """
    amount = 10
    pseudo_random_generator = random.Random()

    channelmap, transfers_pair = make_transfers_pair(
        [HOP1_KEY, HOP2_KEY],
        amount,
    )
    last_pair = transfers_pair[-1]
    last_pair.payee_state = 'payee_secret_revealed'

    # the lock has not expired yet
    block_number = last_pair.payee_transfer.lock.expiration

    events = mediator.events_for_balanceproof(
        channelmap,
        transfers_pair,
        pseudo_random_generator,
        block_number,
        UNIT_SECRET,
        UNIT_SECRETHASH,
    )
    assert len(events) == 2

    balance_proof = next(e for e in events if isinstance(e, SendBalanceProof))
    unlock = next(e for e in events if isinstance(e, EventUnlockSuccess))
    assert unlock
    assert balance_proof
    assert balance_proof.recipient == last_pair.payee_address
    assert last_pair.payee_state == 'payee_balance_proof'


def test_events_for_balanceproof_channel_closed():
    """ Balance proofs are useless if the channel is closed/settled. The payee
    needs to go on-chain and use the latest known balance proof which includes
    this lock in the locksroot.
    """
    amount = 10
    block_number = 5
    pseudo_random_generator = random.Random()

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
        events = mediator.events_for_balanceproof(
            channelmap,
            transfers_pair,
            pseudo_random_generator,
            block_number,
            UNIT_SECRET,
            UNIT_SECRETHASH,
        )

        assert not events


def test_events_for_balanceproof_middle_secret():
    """ Even though the secret should only propagate from the end of the chain
    to the front, if there is a payee node in the middle that knows the secret
    the Balance Proof is nevertheless sent.

    This can be done safely because the secret is known to the mediator and
    there is `reveal_timeout` blocks to unlock the lock on-chain with the payer.
    """
    amount = 10
    pseudo_random_generator = random.Random()

    channelmap, transfers_pair = make_transfers_pair(
        [HOP2_KEY, HOP3_KEY, HOP4_KEY, HOP5_KEY],
        amount,
    )

    block_number = 1
    middle_pair = transfers_pair[1]
    middle_pair.payee_state = 'payee_secret_revealed'

    events = mediator.events_for_balanceproof(
        channelmap,
        transfers_pair,
        pseudo_random_generator,
        block_number,
        UNIT_SECRET,
        UNIT_SECRETHASH,
    )

    balance_proof = next(e for e in events if isinstance(e, SendBalanceProof))

    assert len(events) == 2
    assert any(isinstance(e, EventUnlockSuccess) for e in events)
    assert balance_proof.recipient == middle_pair.payee_address
    assert middle_pair.payee_state == 'payee_balance_proof'


def test_events_for_balanceproof_secret_unknown():
    """ Nothing to do if the secret is not known. """
    block_number = 1
    amount = 10
    pseudo_random_generator = random.Random()

    channelmap, transfers_pair = make_transfers_pair(
        [HOP2_KEY, HOP3_KEY, HOP4_KEY],
        amount,
    )

    # the secret is not known, so no event should be used
    events = mediator.events_for_balanceproof(
        channelmap,
        transfers_pair,
        pseudo_random_generator,
        block_number,
        UNIT_SECRET,
        UNIT_SECRETHASH,
    )
    assert not events


def test_events_for_balanceproof_lock_expired():
    """ The balance proof should not be sent if the lock has expired. """
    amount = 10
    pseudo_random_generator = random.Random()

    channelmap, transfers_pair = make_transfers_pair(
        [HOP2_KEY, HOP3_KEY, HOP4_KEY, HOP5_KEY],
        amount,
    )

    last_pair = transfers_pair[-1]
    last_pair.payee_state = 'payee_secret_revealed'
    block_number = last_pair.payee_transfer.lock.expiration + 1

    # the lock has expired, do not send a balance proof
    events = mediator.events_for_balanceproof(
        channelmap,
        transfers_pair,
        pseudo_random_generator,
        block_number,
        UNIT_SECRET,
        UNIT_SECRETHASH,
    )
    assert not events

    middle_pair = transfers_pair[-2]
    middle_pair.payee_state = 'payee_secret_revealed'

    # Even though the last node did not receive the payment we should send the
    # balance proof to the middle node to avoid unnecessarily closing the
    # middle channel. This state should not be reached under normal operation.
    # The last hop needs to choose a proper reveal_timeout and must go on-chain
    # to unlock the token before the lock expires.
    events = mediator.events_for_balanceproof(
        channelmap,
        transfers_pair,
        pseudo_random_generator,
        block_number,
        UNIT_SECRET,
        UNIT_SECRETHASH,
    )

    balance_proof = next(e for e in events if isinstance(e, SendBalanceProof))

    assert len(events) == 2
    assert any(isinstance(e, EventUnlockSuccess) for e in events)
    assert balance_proof.recipient == middle_pair.payee_address
    assert middle_pair.payee_state == 'payee_balance_proof'


def test_events_for_close():
    """ The node must close to unlock on-chain if the payee was paid. """
    amount = 10

    for payee_state in ('payee_balance_proof', 'payee_contract_unlock'):
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

        events = mediator.events_for_close(
            channelmap,
            transfers_pair,
            block_number,
        )

        assert isinstance(events[0], ContractSendChannelClose)
        assert events[0].channel_identifier == pair.payer_transfer.balance_proof.channel_address
        assert pair.payer_state == 'payer_waiting_close'


def test_events_for_onchain_secretreveal():
    """ Secret must be registered on-chain when the unsafe region is reached and
    the secret is known.
    """
    amount = 10
    channelmap, transfers_pair = make_transfers_pair(
        [HOP2_KEY, HOP3_KEY],
        amount,
    )

    pair = transfers_pair[0]
    channel_identifier = pair.payer_transfer.balance_proof.channel_address
    channel_state = channelmap[channel_identifier]

    # Reveal the secret off-chain
    for channel_state in channelmap.values():
        channel.register_secret(channel_state, UNIT_SECRET, UNIT_SECRETHASH)

    block_number = (
        pair.payer_transfer.lock.expiration - channel_state.reveal_timeout
    )

    # If we are not in the unsafe region, we must NOT emit ContractSendSecretReveal
    events = mediator.events_for_onchain_secretreveal(
        channelmap,
        transfers_pair,
        block_number - 1,
    )
    assert not events

    # If we are in the unsafe region, we must emit ContractSendSecretReveal
    events = mediator.events_for_onchain_secretreveal(
        channelmap,
        transfers_pair,
        block_number,
    )

    assert must_contain_entry(events, ContractSendSecretReveal, {
        'secret': UNIT_SECRET,
    })


@pytest.mark.skip(reason='issue #1736')
def test_onchain_secretreveal_must_be_emitted_only_once():
    amount = 10
    channelmap, transfers_pair = make_transfers_pair(
        [HOP2_KEY, HOP3_KEY],
        amount,
    )

    pair = transfers_pair[0]
    channel_identifier = pair.payer_transfer.balance_proof.channel_address
    channel_state = channelmap[channel_identifier]

    # Reveal the secret off-chain
    for channel_state in channelmap.values():
        channel.register_secret(channel_state, UNIT_SECRET, UNIT_SECRETHASH)

    block_number = (
        pair.payer_transfer.lock.expiration - channel_state.reveal_timeout
    )

    events = mediator.events_for_onchain_secretreveal(
        channelmap,
        transfers_pair,
        block_number,
    )

    assert must_contain_entry(events, ContractSendSecretReveal, {
        'secret': UNIT_SECRET,
    })

    events = mediator.events_for_onchain_secretreveal(
        channelmap,
        transfers_pair,
        block_number,
    )
    assert not events


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
        channel.register_secret(channel_state, UNIT_SECRET, UNIT_SECRETHASH)

    # preconditions
    assert pair.payee_state not in mediator.STATE_TRANSFER_PAID

    # do not generate events if the secret is known AND the payee is not paid
    channel_identifier = pair.payer_transfer.balance_proof.channel_address
    channel_state = channelmap[channel_identifier]
    first_unsafe_block = pair.payer_transfer.lock.expiration - channel_state.reveal_timeout
    events = mediator.events_for_close(
        channelmap,
        transfers_pair,
        first_unsafe_block,
    )

    assert not events
    assert pair.payee_state not in mediator.STATE_TRANSFER_PAID
    assert pair.payer_state not in mediator.STATE_TRANSFER_PAID

    payer_expiration_block = pair.payer_transfer.lock.expiration
    events = mediator.events_for_close(
        channelmap,
        transfers_pair,
        payer_expiration_block,
    )
    assert not events
    assert pair.payee_state not in mediator.STATE_TRANSFER_PAID
    assert pair.payer_state not in mediator.STATE_TRANSFER_PAID

    payer_expiration_block = pair.payer_transfer.lock.expiration
    events = mediator.events_for_close(
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
    from_expiration = UNIT_SETTLE_TIMEOUT
    pseudo_random_generator = random.Random()

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
    init_state_change = ActionInitMediator(
        available_routes,
        from_route,
        from_transfer,
    )

    initial_state = None
    iteration = mediator.state_transition(
        initial_state,
        init_state_change,
        channelmap,
        pseudo_random_generator,
        block_number,
    )

    iteration = mediator.secret_learned(
        iteration.new_state,
        channelmap,
        pseudo_random_generator,
        block_number,
        UNIT_SECRET,
        UNIT_SECRETHASH,
        channel1.partner_state.address,
        'payee_secret_revealed',
        False,
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

    reveal_events = [e for e in iteration.events if isinstance(e, SendRevealSecret)]
    assert len(reveal_events) == 1

    balance_events = [e for e in iteration.events if isinstance(e, SendBalanceProof)]
    assert len(balance_events) == 1


def test_secret_learned_with_refund():
    """ Test  """
    amount = 10
    privatekeys = [HOP2_KEY, HOP3_KEY, HOP4_KEY]
    addresses = [HOP2, HOP3, HOP4]

    #                                             /-> HOP3
    # Emulate HOP2(Initiator) -> HOP1 (This node)
    #                                             \-> HOP4 -> HOP5
    channelmap, transfers_pair = make_transfers_pair(
        privatekeys,
        amount,
    )

    # Map HOP1 channel partner addresses to their channel states
    partner_to_channel = {
        channel_state.partner_state.address: channel_state
        for channel_state in channelmap.values()
    }

    # Make sure that our state is updated once transfers are sent.
    for address in addresses[1:]:
        channel_state = partner_to_channel[address]
        assert channel.is_lock_locked(channel_state.our_state, UNIT_SECRETHASH)

    mediator_state = MediatorTransferState(UNIT_SECRETHASH)
    mediator_state.transfers_pair = transfers_pair

    # Emulate a ReceiveSecretReveal state transition_result
    # Which means that HOP5 sent a SecretReveal -> HOP4 -> HOP1 (Us)
    transition_result = mediator.state_transition(
        mediator_state,
        ReceiveSecretReveal(UNIT_SECRET, HOP5),
        channelmap,
        random.Random(),
        5,
    )

    assert not transition_result.events

    assert mediator_state.secret == UNIT_SECRET

    for address in addresses[:-1]:
        channel_state = partner_to_channel[address]
        assert channel.is_secret_known(channel_state.partner_state, UNIT_SECRETHASH)

    for address in addresses[1:]:
        channel_state = partner_to_channel[address]
        assert channel.is_secret_known(channel_state.our_state, UNIT_SECRETHASH)


def test_mediate_transfer():
    amount = 10
    block_number = 5
    target = HOP2
    expiration = 30
    pseudo_random_generator = random.Random()

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

    mediator_state = MediatorTransferState(UNIT_SECRETHASH)
    iteration = mediator.mediate_transfer(
        mediator_state,
        possible_routes,
        payer_channel,
        channelmap,
        pseudo_random_generator,
        payer_transfer,
        block_number,
    )
    assert len(iteration.events) == 1

    send_transfer = iteration.events[0]
    assert isinstance(send_transfer, SendLockedTransfer)

    transfer = send_transfer.transfer
    assert transfer.payment_identifier == payer_transfer.payment_identifier
    assert transfer.token == payer_transfer.token
    assert transfer.lock.amount == payer_transfer.lock.amount
    assert transfer.lock.secrethash == payer_transfer.lock.secrethash
    assert transfer.target == payer_transfer.target
    assert payer_transfer.lock.expiration > transfer.lock.expiration
    assert send_transfer.recipient == channel1.partner_state.address


def test_init_mediator():
    amount = UNIT_TRANSFER_AMOUNT
    target = HOP2
    from_expiration = UNIT_SETTLE_TIMEOUT
    pseudo_random_generator = random.Random()

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
    init_state_change = ActionInitMediator(
        available_routes,
        from_route,
        from_transfer,
    )

    mediator_state = None
    iteration = mediator.state_transition(
        mediator_state,
        init_state_change,
        channelmap,
        pseudo_random_generator,
        block_number,
    )

    assert isinstance(iteration.new_state, MediatorTransferState)
    assert iteration.new_state.transfers_pair[0].payer_transfer == from_transfer

    msg = 'we have a valid route, the mediated transfer event must be emitted'
    assert iteration.events, msg

    mediated_transfers = [e for e in iteration.events if isinstance(e, SendLockedTransfer)]
    assert len(mediated_transfers) == 1, 'mediated_transfer should /not/ split the transfer'
    send_transfer = mediated_transfers[0]
    mediated_transfer = send_transfer.transfer

    assert mediated_transfer.token == from_transfer.token, 'transfer token address mismatch'
    assert mediated_transfer.lock.amount == from_transfer.lock.amount, 'transfer amount mismatch'
    msg = 'transfer expiration mismatch'
    assert mediated_transfer.lock.expiration < from_transfer.lock.expiration, msg
    assert mediated_transfer.lock.secrethash == from_transfer.lock.secrethash, 'wrong secrethash'


def test_no_valid_routes():
    amount = UNIT_TRANSFER_AMOUNT
    target = HOP2
    from_expiration = UNIT_SETTLE_TIMEOUT
    pseudo_random_generator = random.Random()

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
    init_state_change = ActionInitMediator(
        available_routes,
        from_route,
        from_transfer,
    )

    mediator_state = None
    iteration = mediator.state_transition(
        mediator_state,
        init_state_change,
        channelmap,
        pseudo_random_generator,
        block_number,
    )
    assert iteration.new_state is None

    send_refund = next(e for e in iteration.events if isinstance(e, SendRefundTransfer))
    assert send_refund


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
    pseudo_random_generator = random.Random()

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
    # recipient cannot control the received lock expiration
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
    init_state_change = ActionInitMediator(
        available_routes,
        from_route,
        from_transfer,
    )

    mediator_state = None
    iteration = mediator.state_transition(
        mediator_state,
        init_state_change,
        channelmap,
        pseudo_random_generator,
        block_number,
    )

    assert isinstance(iteration.new_state, MediatorTransferState)
    assert iteration.events

    send_mediated = next(e for e in iteration.events if isinstance(e, SendLockedTransfer))
    assert send_mediated

    msg = 'transfer expiration must be lower than the funding channel settlement window'
    assert send_mediated.transfer.lock.expiration < low_settlement_expiration, msg


def test_do_not_claim_an_almost_expiring_lock_if_a_payment_didnt_occur():
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
    # - The secret is held back until the hash time lock B->C has *expired*,
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
    amount = UNIT_TRANSFER_AMOUNT
    block_number = 1
    from_expiration = UNIT_SETTLE_TIMEOUT
    pseudo_random_generator = random.Random()

    # C's channel with the Attacker node A2
    attacked_channel = factories.make_channel(
        our_balance=amount,
        token_address=UNIT_TOKEN_ADDRESS,
    )
    target_attacker2 = attacked_channel.partner_state.address

    bc_channel = factories.make_channel(
        our_balance=amount,
        partner_balance=amount,
        partner_address=UNIT_TRANSFER_SENDER,
        token_address=UNIT_TOKEN_ADDRESS,
    )
    from_route = factories.route_from_channel(bc_channel)

    from_transfer = factories.make_signed_transfer_for(
        bc_channel,
        amount,
        HOP1,
        target_attacker2,
        from_expiration,
        UNIT_SECRET,
    )

    available_routes = [
        factories.route_from_channel(attacked_channel),
    ]
    channelmap = {
        bc_channel.identifier: bc_channel,
        attacked_channel.identifier: attacked_channel,
    }

    init_state_change = ActionInitMediator(
        available_routes,
        from_route,
        from_transfer,
    )

    mediator_state = None
    iteration = mediator.state_transition(
        mediator_state,
        init_state_change,
        channelmap,
        pseudo_random_generator,
        block_number,
    )

    attack_block_number = from_transfer.lock.expiration - attacked_channel.reveal_timeout
    assert not mediator.is_safe_to_wait(
        from_transfer.lock.expiration,
        attacked_channel.reveal_timeout,
        attack_block_number,
    )

    # Wait until it's not safe to wait for the off-chain unlock for B-C (and expire C-A2)
    new_iteration = iteration
    for new_block_number in range(block_number, attack_block_number + 1):
        new_iteration = mediator.state_transition(
            new_iteration.new_state,
            Block(new_block_number),
            channelmap,
            pseudo_random_generator,
            new_block_number,
        )

        assert not any(
            event
            for event in new_iteration.events
            if not isinstance(event, EventUnlockFailed)
        )

    # and reveal the secret
    receive_secret = ReceiveSecretReveal(
        UNIT_SECRET,
        target_attacker2,
    )
    attack_iteration = mediator.state_transition(
        new_iteration.new_state,
        receive_secret,
        channelmap,
        pseudo_random_generator,
        attack_block_number,
    )
    assert not any(
        isinstance(event, ContractSendChannelClose)
        for event in attack_iteration.events
    )

    # don't go on-chain since the balance proof was not received
    for new_block_number in range(block_number, from_transfer.lock.expiration + 1):
        new_iteration = mediator.state_transition(
            new_iteration.new_state,
            Block(new_block_number),
            channelmap,
            pseudo_random_generator,
            new_block_number,
        )
        assert not any(
            event
            for event in new_iteration.events
            if not isinstance(event, (EventUnlockFailed, ContractSendSecretReveal))
        )


@pytest.mark.xfail(reason='Not implemented. Issue: #382')
def mediate_transfer_payee_timeout_must_be_lower_than_settlement_and_payer_timeout():
    # Test:
    # - the current payer route/transfer is the reference, not the from_route / from_transfer
    # - the lowest value from blocks_until_settlement and lock expiration must be used
    raise NotImplementedError()


def test_payee_timeout_must_be_lower_than_payer_timeout_minus_reveal_timeout():
    # The payee could reveal the secret on its lock expiration block, the
    # mediator node will respond with a balance-proof to the payee since the
    # lock is valid and the mediator can safely get the token from the payer.
    # The secret is known and if there are no additional blocks the mediator
    # will be at risk of not being able to unlock and claim on-chain, so the channel
    # will be closed to safely unlock.
    #
    # T2.expiration cannot be equal to T1.expiration - reveal_timeout:
    #
    #           v- T1.expiration - reveal_timeout
    # T1 |------****|
    # T2 |--****|   ^- T1.expiration
    #           ^- T2.expiration
    #
    # Race:
    #  1> Secret is learned
    #  2> balance-proof is sent to payee (payee transfer is paid)
    #  3! New block is mined and Raiden learns about it
    #  4> Now the secret is known, the payee is paid, and the current block is
    #     equal to the payer.expiration - reveal-timeout -> unlock on chain
    #
    # The race is depending on the handling of 3 before 4.
    #
    block_number = 5
    expiration = 30
    pseudo_random_generator = random.Random()

    payer_channel = factories.make_channel(
        partner_balance=UNIT_TRANSFER_AMOUNT,
        partner_address=UNIT_TRANSFER_SENDER,
        token_address=UNIT_TOKEN_ADDRESS,
    )

    payer_transfer = factories.make_signed_transfer_for(
        payer_channel,
        UNIT_TRANSFER_AMOUNT,
        HOP1,
        UNIT_TRANSFER_TARGET,
        expiration,
        UNIT_SECRET,
    )

    channel1 = factories.make_channel(
        our_balance=UNIT_TRANSFER_AMOUNT,
        token_address=UNIT_TOKEN_ADDRESS,
    )
    channelmap = {
        channel1.identifier: channel1,
        payer_channel.identifier: payer_channel,
    }
    possible_routes = [factories.route_from_channel(channel1)]

    mediator_state = MediatorTransferState(UNIT_SECRETHASH)
    iteration = mediator.mediate_transfer(
        mediator_state,
        possible_routes,
        payer_channel,
        channelmap,
        pseudo_random_generator,
        payer_transfer,
        block_number,
    )

    send_mediated = next(e for e in iteration.events if isinstance(e, SendLockedTransfer))
    assert isinstance(send_mediated, SendLockedTransfer)

    race_block = payer_transfer.lock.expiration - channel1.reveal_timeout - mediator.TRANSIT_BLOCKS
    assert mediator.TRANSIT_BLOCKS > 0
    assert send_mediated.transfer.lock.expiration == race_block


def test_set_secret():
    mediator_state = MediatorTransferState(UNIT_SECRETHASH)

    assert mediator_state.transfers_pair == list()
    assert mediator_state.secret is None
    assert mediator_state.secrethash == UNIT_SECRETHASH

    amount = 10
    channelmap, transfers_pair = make_transfers_pair(
        [
            HOP2_KEY,
            HOP3_KEY,
        ],
        amount,
    )
    mediator_state.transfers_pair = transfers_pair

    payer_channelid = transfers_pair[0].payer_transfer.balance_proof.channel_address
    payee_channelid = transfers_pair[0].payee_transfer.balance_proof.channel_address

    payer_channel_our_state = channelmap[payer_channelid].our_state
    payer_channel_partner_state = channelmap[payer_channelid].partner_state
    payee_channel_our_state = channelmap[payee_channelid].our_state
    payee_channel_partner_state = channelmap[payee_channelid].partner_state

    assert payer_channel_our_state.secrethashes_to_lockedlocks == dict()
    assert payer_channel_our_state.secrethashes_to_unlockedlocks == dict()

    assert UNIT_SECRETHASH in payer_channel_partner_state.secrethashes_to_lockedlocks.keys()
    assert payer_channel_partner_state.secrethashes_to_unlockedlocks == dict()

    assert UNIT_SECRETHASH in payee_channel_our_state.secrethashes_to_lockedlocks.keys()
    assert payee_channel_our_state.secrethashes_to_unlockedlocks == dict()

    assert payee_channel_partner_state.secrethashes_to_lockedlocks == dict()
    assert payee_channel_partner_state.secrethashes_to_unlockedlocks == dict()

    set_secret(mediator_state, channelmap, UNIT_SECRET, UNIT_SECRETHASH)

    assert mediator_state.secret == UNIT_SECRET

    assert payer_channel_our_state.secrethashes_to_lockedlocks == dict()
    assert payer_channel_our_state.secrethashes_to_unlockedlocks == dict()

    assert payer_channel_partner_state.secrethashes_to_lockedlocks == dict()
    assert UNIT_SECRETHASH in payer_channel_partner_state.secrethashes_to_unlockedlocks.keys()

    assert payee_channel_our_state.secrethashes_to_lockedlocks == dict()
    assert UNIT_SECRETHASH in payee_channel_our_state.secrethashes_to_unlockedlocks.keys()

    assert payee_channel_partner_state.secrethashes_to_lockedlocks == dict()
    assert payee_channel_partner_state.secrethashes_to_unlockedlocks == dict()
