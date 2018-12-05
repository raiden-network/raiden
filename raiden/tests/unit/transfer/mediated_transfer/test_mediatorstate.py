# pylint: disable=invalid-name,too-many-locals,too-many-arguments,too-many-lines
import random
from copy import deepcopy

import pytest

from raiden.constants import EMPTY_HASH, EMPTY_HASH_KECCAK, MAXIMUM_PENDING_TRANSFERS
from raiden.settings import DEFAULT_NUMBER_OF_BLOCK_CONFIRMATIONS
from raiden.tests.utils import factories
from raiden.tests.utils.events import must_contain_entry
from raiden.tests.utils.factories import (
    ADDR,
    HOP1,
    HOP1_KEY,
    HOP2,
    HOP2_KEY,
    HOP3,
    HOP3_KEY,
    HOP4,
    HOP4_KEY,
    HOP5,
    HOP5_KEY,
    UNIT_CHAIN_ID,
    UNIT_REVEAL_TIMEOUT,
    UNIT_SECRET,
    UNIT_SECRETHASH,
    UNIT_SETTLE_TIMEOUT,
    UNIT_TOKEN_ADDRESS,
    UNIT_TOKEN_NETWORK_ADDRESS,
    UNIT_TRANSFER_AMOUNT,
    UNIT_TRANSFER_IDENTIFIER,
    UNIT_TRANSFER_INITIATOR,
    UNIT_TRANSFER_PKEY,
    UNIT_TRANSFER_SENDER,
    UNIT_TRANSFER_TARGET,
    mediator_make_channel_pair,
    mediator_make_init_action,
)
from raiden.transfer import channel
from raiden.transfer.events import (
    ContractSendChannelClose,
    ContractSendSecretReveal,
    EventInvalidReceivedLockedTransfer,
    SendProcessed,
)
from raiden.transfer.mediated_transfer import mediator
from raiden.transfer.mediated_transfer.events import (
    EventUnlockFailed,
    EventUnlockSuccess,
    SendBalanceProof,
    SendLockedTransfer,
    SendLockExpired,
    SendRefundTransfer,
    SendSecretReveal,
)
from raiden.transfer.mediated_transfer.mediator import set_offchain_secret
from raiden.transfer.mediated_transfer.state import MediatorTransferState, RouteState
from raiden.transfer.mediated_transfer.state_change import (
    ActionInitMediator,
    ReceiveLockExpired,
    ReceiveSecretReveal,
)
from raiden.transfer.state import (
    CHANNEL_STATE_CLOSED,
    CHANNEL_STATE_SETTLED,
    EMPTY_MERKLE_ROOT,
    message_identifier_from_prng,
)
from raiden.transfer.state_change import Block, ContractReceiveSecretReveal
from raiden.utils import random_secret


def make_route_from_channelstate(channel_state):
    return RouteState(
        channel_state.partner_state.address,
        channel_state.channel_identifier,
    )


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
    is_safe, msg = mediator.is_safe_to_wait(expiration, reveal_timeout, block_number)
    assert is_safe, msg

    # expiration is in 20 blocks, 10 blocks safe for waiting
    block_number = 20
    reveal_timeout = 10
    is_safe, msg = mediator.is_safe_to_wait(expiration, reveal_timeout, block_number)
    assert is_safe, msg

    # expiration is in 11 blocks, 1 block safe for waiting
    block_number = 29
    reveal_timeout = 10
    is_safe, msg = mediator.is_safe_to_wait(expiration, reveal_timeout, block_number)
    assert is_safe, msg

    # at the block 30 it's not safe to wait anymore
    block_number = 30
    reveal_timeout = 10
    is_safe, _ = mediator.is_safe_to_wait(expiration, reveal_timeout, block_number)
    assert not is_safe, 'this is expiration must not be safe'

    block_number = 40
    reveal_timeout = 10
    is_safe, _ = mediator.is_safe_to_wait(expiration, reveal_timeout, block_number)
    assert not is_safe, 'this is expiration must not be safe'

    block_number = 50
    reveal_timeout = 10
    is_safe, _ = mediator.is_safe_to_wait(expiration, reveal_timeout, block_number)
    assert not is_safe, 'this is expiration must not be safe'


def test_next_route_amount():
    """ Routes that dont have enough available_balance must be ignored. """
    reveal_timeout = 30
    timeout_blocks = reveal_timeout + 10
    amount = UNIT_TRANSFER_AMOUNT

    channels = factories.make_channel_set([
        {'our_state': {'balance': amount}},
        {'our_state': {'balance': 0}},
        {'our_state': {'balance': amount}},
    ])

    # the first available route should be used
    chosen_channel = mediator.next_channel_from_routes(
        channels.get_routes(0),
        channels.channel_map,
        amount,
        timeout_blocks,
    )
    assert chosen_channel.identifier == channels[0].identifier

    # additional routes do not change the order
    chosen_channel = mediator.next_channel_from_routes(
        channels.get_routes(0, 1),
        channels.channel_map,
        amount,
        timeout_blocks,
    )
    assert chosen_channel.identifier == channels[0].identifier

    chosen_channel = mediator.next_channel_from_routes(
        channels.get_routes(2, 0),
        channels.channel_map,
        amount,
        timeout_blocks,
    )
    assert chosen_channel.identifier == channels[2].identifier

    # a channel without capacity must be skipped
    chosen_channel = mediator.next_channel_from_routes(
        channels.get_routes(1, 0),
        channels.channel_map,
        amount,
        timeout_blocks,
    )
    assert chosen_channel.identifier == channels[0].identifier


def test_next_route_reveal_timeout():
    """ Routes with a larger reveal timeout than timeout_blocks must be ignored. """
    timeout_blocks = 10

    channels = factories.make_channel_set([
        {'reveal_timeout': timeout_blocks * 2},
        {'reveal_timeout': timeout_blocks + 1},
        {'reveal_timeout': timeout_blocks // 2},
        {'reveal_timeout': timeout_blocks},
    ])

    chosen_channel = mediator.next_channel_from_routes(
        channels.get_routes(0, 1, 2, 3),
        channels.channel_map,
        UNIT_TRANSFER_AMOUNT,
        timeout_blocks,
    )
    assert chosen_channel.identifier == channels[2].identifier


def test_next_transfer_pair():
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

    channels = factories.make_channel_set([{'our_state': {'balance': balance}}])

    pair, events = mediator.forward_transfer_pair(
        payer_transfer,
        channels.get_routes(0),
        channels.channel_map,
        pseudo_random_generator,
        block_number,
    )

    assert pair.payer_transfer == payer_transfer
    assert pair.payee_address == channels[0].partner_state.address
    assert pair.payee_transfer.lock.expiration == pair.payer_transfer.lock.expiration

    assert must_contain_entry(events, SendLockedTransfer, {
        'recipient': pair.payee_address,
        'transfer': {
            'payment_identifier': payer_transfer.payment_identifier,
            'token': payer_transfer.token,
            'initiator': payer_transfer.initiator,
            'target': payer_transfer.target,
            'lock': {
                'amount': payer_transfer.lock.amount,
                'secrethash': payer_transfer.lock.secrethash,
                'expiration': payer_transfer.lock.expiration,
            },
        },
    })


def test_set_payee():
    amount = 10
    block_number = 1
    _, transfers_pair = factories.make_transfers_pair(
        [
            HOP2_KEY,
            HOP3_KEY,
            HOP4_KEY,
        ],
        amount,
        block_number,
    )

    # assert pre conditions
    assert transfers_pair[0].payer_state == 'payer_pending'
    assert transfers_pair[0].payee_state == 'payee_pending'

    assert transfers_pair[1].payer_state == 'payer_pending'
    assert transfers_pair[1].payee_state == 'payee_pending'

    mediator.set_offchain_reveal_state(transfers_pair, HOP2)

    # payer address was used, no payee state should change
    assert transfers_pair[0].payer_state == 'payer_pending'
    assert transfers_pair[0].payee_state == 'payee_pending'

    assert transfers_pair[1].payer_state == 'payer_pending'
    assert transfers_pair[1].payee_state == 'payee_pending'

    mediator.set_offchain_reveal_state(transfers_pair, HOP3)

    # only the transfer where the address is a payee should change
    assert transfers_pair[0].payer_state == 'payer_pending'
    assert transfers_pair[0].payee_state == 'payee_secret_revealed'

    assert transfers_pair[1].payer_state == 'payer_pending'
    assert transfers_pair[1].payee_state == 'payee_pending'


def test_events_for_expired_pairs():
    """ The transfer pair must switch to expired at the right block. """
    amount = 10
    block_number = 1
    channelmap, transfers_pair = factories.make_transfers_pair(
        [HOP2_KEY, HOP3_KEY],
        amount,
        block_number,
    )

    pair = transfers_pair[0]

    first_unsafe_block = pair.payer_transfer.lock.expiration - UNIT_REVEAL_TIMEOUT

    mediator.events_for_expired_pairs(
        channelmap,
        transfers_pair,
        None,
        first_unsafe_block,
    )
    assert pair.payer_state == 'payer_pending'

    # edge case for the lock expiration
    payee_expiration_block = pair.payee_transfer.lock.expiration
    mediator.events_for_expired_pairs(
        channelmap,
        transfers_pair,
        None,
        payee_expiration_block,
    )
    assert pair.payer_state == 'payer_pending'

    # lock expired
    payer_lock_expiration_threshold = (
        pair.payer_transfer.lock.expiration +
        DEFAULT_NUMBER_OF_BLOCK_CONFIRMATIONS * 2
    )
    mediator.events_for_expired_pairs(
        channelmap,
        transfers_pair,
        None,
        payer_lock_expiration_threshold,
    )
    assert pair.payer_state == 'payer_expired'


def test_events_for_refund():
    amount = 10
    expiration = 30
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
        token_network_address=refund_channel.token_network_identifier,
    )

    is_valid, _, msg = channel.handle_receive_lockedtransfer(
        refund_channel,
        received_transfer,
    )
    assert is_valid, msg

    transfer_pair, refund_events = mediator.backward_transfer_pair(
        refund_channel,
        received_transfer,
        pseudo_random_generator,
        block_number,
    )

    assert must_contain_entry(refund_events, SendRefundTransfer, {
        'transfer': {
            'lock': {
                'expiration': received_transfer.lock.expiration,
                'amount': amount,
                'secrethash': received_transfer.lock.secrethash,
            },
        },
        'recipient': refund_channel.partner_state.address,
    })
    assert transfer_pair.payer_transfer == received_transfer


def test_events_for_secretreveal():
    """ The secret is revealed backwards to the payer once the payee sent the
    SecretReveal.
    """
    our_address = ADDR
    amount = 10
    pseudo_random_generator = random.Random()
    block_number = 1

    _, transfers_pair = factories.make_transfers_pair(
        [HOP2_KEY, HOP3_KEY, HOP4_KEY],
        amount,
        block_number,
    )

    events = mediator.events_for_secretreveal(
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
    events = mediator.events_for_secretreveal(
        transfers_pair,
        UNIT_SECRET,
        pseudo_random_generator,
    )

    # the last known hop sent a secret reveal message. This node learned the
    # secret and now must reveal it to the payer node from the transfer pair
    assert must_contain_entry(events, SendSecretReveal, {
        'secret': UNIT_SECRET,
        'recipient': last_pair.payer_transfer.balance_proof.sender,
    })
    assert last_pair.payer_state == 'payer_secret_revealed'

    events = mediator.events_for_secretreveal(
        transfers_pair,
        our_address,
        pseudo_random_generator,
    )

    # the payeee from the first_pair did not send a secret reveal message, do
    # nothing
    assert not events

    first_pair.payee_state = 'payee_secret_revealed'
    events = mediator.events_for_secretreveal(
        transfers_pair,
        UNIT_SECRET,
        pseudo_random_generator,
    )

    assert must_contain_entry(events, SendSecretReveal, {
        'secret': UNIT_SECRET,
        'recipient': first_pair.payer_transfer.balance_proof.sender,
    })
    assert first_pair.payer_state == 'payer_secret_revealed'


def test_events_for_secretreveal_secret_unknown():
    """ When the secret is not known there is nothing to do. """
    amount = 10
    pseudo_random_generator = random.Random()
    block_number = 1

    _, transfers_pair = factories.make_transfers_pair(
        [HOP2_KEY, HOP3_KEY, HOP4_KEY],
        amount,
        block_number,
    )

    events = mediator.events_for_secretreveal(
        transfers_pair,
        ADDR,
        pseudo_random_generator,
    )

    assert not events


def test_events_for_secretreveal_all_states():
    """ The secret must be revealed backwards to the payer if the payee knows
    the secret.
    """
    payee_secret_known = (
        'payee_secret_revealed',
        'payee_contract_unlock',
        'payee_balance_proof',
    )
    pseudo_random_generator = random.Random()
    block_number = 1

    amount = 10
    for state in payee_secret_known:
        _, transfers_pair = factories.make_transfers_pair(
            [HOP2_KEY, HOP3_KEY],
            amount,
            block_number,
        )

        pair = transfers_pair[0]
        pair.payee_state = state

        events = mediator.events_for_secretreveal(
            transfers_pair,
            UNIT_SECRET,
            pseudo_random_generator,
        )

        assert must_contain_entry(events, SendSecretReveal, {
            'secret': UNIT_SECRET,
            'recipient': HOP2,
        })


def test_events_for_balanceproof():
    """ Test the simple case where the last hop has learned the secret and sent
    it to the mediator node.
    """
    amount = 10
    pseudo_random_generator = random.Random()
    block_number = 1

    channel_map, transfers_pair = factories.make_transfers_pair(
        [HOP1_KEY, HOP2_KEY],
        amount,
        block_number,
    )
    last_pair = transfers_pair[-1]
    last_pair.payee_state = 'payee_secret_revealed'

    # the lock is not in the danger zone yet
    payer_channel = mediator.get_payer_channel(channel_map, last_pair)
    payee_channel = mediator.get_payee_channel(channel_map, last_pair)
    block_number = last_pair.payee_transfer.lock.expiration - payer_channel.reveal_timeout - 1

    prng_copy = deepcopy(pseudo_random_generator)
    msg_identifier = message_identifier_from_prng(prng_copy)

    events = mediator.events_for_balanceproof(
        channel_map,
        transfers_pair,
        pseudo_random_generator,
        block_number,
        UNIT_SECRET,
        UNIT_SECRETHASH,
    )

    assert must_contain_entry(events, EventUnlockSuccess, {
        'identifier': UNIT_TRANSFER_IDENTIFIER,
        'secrethash': UNIT_SECRETHASH,
    })
    assert must_contain_entry(
        events,
        SendBalanceProof,
        {
            'recipient': last_pair.payee_address,
            'message_identifier': msg_identifier,
            'payment_identifier': UNIT_TRANSFER_IDENTIFIER,
            'queue_identifier': {
                'recipient': last_pair.payee_address,
                'channel_identifier': payee_channel.identifier,
            },
            'secret': UNIT_SECRET,
            'balance_proof': {
                'nonce': 2,
                'transferred_amount': UNIT_TRANSFER_AMOUNT,
                'locked_amount': 0,
                # 'locksroot':  ignored here
                'token_network_identifier': UNIT_TOKEN_NETWORK_ADDRESS,
                'channel_identifier': payee_channel.identifier,
                'chain_id': UNIT_CHAIN_ID,
            },
        },
    )
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
        channel_map, transfers_pair = factories.make_transfers_pair(
            [HOP2_KEY, HOP3_KEY],
            amount,
            block_number,
        )

        last_pair = transfers_pair[-1]
        channel_identifier = last_pair.payee_transfer.balance_proof.channel_identifier
        last_channel = channel_map[channel_identifier]

        if invalid_state == CHANNEL_STATE_CLOSED:
            channel.set_closed(last_channel, block_number)
        else:
            channel.set_settled(last_channel, block_number)

        last_pair.payee_state = 'payee_secret_revealed'
        events = mediator.events_for_balanceproof(
            channel_map,
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
    block_number = 1

    channel_map, transfers_pair = factories.make_transfers_pair(
        [HOP2_KEY, HOP3_KEY, HOP4_KEY, HOP5_KEY],
        amount,
        block_number,
    )

    middle_pair = transfers_pair[1]
    middle_pair.payee_state = 'payee_secret_revealed'

    events = mediator.events_for_balanceproof(
        channel_map,
        transfers_pair,
        pseudo_random_generator,
        block_number,
        UNIT_SECRET,
        UNIT_SECRETHASH,
    )

    assert must_contain_entry(events, SendBalanceProof, {
        'recipient': middle_pair.payee_address,
    })
    assert must_contain_entry(events, EventUnlockSuccess, {})
    assert middle_pair.payee_state == 'payee_balance_proof'


def test_events_for_balanceproof_secret_unknown():
    """ Nothing to do if the secret is not known. """
    block_number = 1
    amount = 10
    pseudo_random_generator = random.Random()

    channel_map, transfers_pair = factories.make_transfers_pair(
        [HOP2_KEY, HOP3_KEY, HOP4_KEY],
        amount,
        block_number,
    )

    # the secret is not known, so no event should be used
    events = mediator.events_for_balanceproof(
        channel_map,
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
    block_number = 1

    channel_map, transfers_pair = factories.make_transfers_pair(
        [HOP2_KEY, HOP3_KEY, HOP4_KEY, HOP5_KEY],
        amount,
        block_number,
    )

    last_pair = transfers_pair[-1]
    last_pair.payee_state = 'payee_secret_revealed'
    block_number = last_pair.payee_transfer.lock.expiration + 1

    # the lock has expired, do not send a balance proof
    events = mediator.events_for_balanceproof(
        channel_map,
        transfers_pair,
        pseudo_random_generator,
        block_number,
        UNIT_SECRET,
        UNIT_SECRETHASH,
    )
    assert not events

    middle_pair = transfers_pair[-2]
    middle_pair.payee_state = 'payee_secret_revealed'

    # The channel doesn't need to be closed to do a on-chain unlock, therefor
    # it's not required to send a balance proof to the payee if the lock is
    # near expiration
    events = mediator.events_for_balanceproof(
        channel_map,
        transfers_pair,
        pseudo_random_generator,
        block_number,
        UNIT_SECRET,
        UNIT_SECRETHASH,
    )
    assert not events


def test_events_for_onchain_secretreveal():
    """ Secret must be registered on-chain when the unsafe region is reached and
    the secret is known.
    """
    amount = 10
    block_number = 1
    channel_map, transfers_pair = factories.make_transfers_pair(
        [HOP2_KEY, HOP3_KEY],
        amount,
        block_number,
    )

    pair = transfers_pair[0]
    channel_identifier = pair.payer_transfer.balance_proof.channel_identifier
    channel_state = channel_map[channel_identifier]

    # Reveal the secret off-chain
    for channel_state in channel_map.values():
        channel.register_offchain_secret(channel_state, UNIT_SECRET, UNIT_SECRETHASH)

    block_number = (
        pair.payer_transfer.lock.expiration - channel_state.reveal_timeout
    )

    # If we are not in the unsafe region, we must NOT emit ContractSendSecretReveal
    events = mediator.events_for_onchain_secretreveal_if_dangerzone(
        channel_map,
        UNIT_SECRETHASH,
        transfers_pair,
        block_number - 1,
    )
    assert not events

    # If we are in the unsafe region, we must emit ContractSendSecretReveal
    events = mediator.events_for_onchain_secretreveal_if_dangerzone(
        channel_map,
        UNIT_SECRETHASH,
        transfers_pair,
        block_number,
    )

    assert must_contain_entry(events, ContractSendSecretReveal, {
        'secret': UNIT_SECRET,
    })


def test_events_for_onchain_secretreveal_once():
    """ Secret must be registered on-chain only once. """
    amount = 10
    block_number = 1
    channel_map, transfers_pair = factories.make_transfers_pair(
        [HOP2_KEY, HOP3_KEY, HOP4_KEY, HOP5_KEY],
        amount,
        block_number,
    )

    pair = transfers_pair[0]
    channel_identifier = pair.payer_transfer.balance_proof.channel_identifier
    channel_state = channel_map[channel_identifier]

    for channel_state in channel_map.values():
        channel.register_offchain_secret(channel_state, UNIT_SECRET, UNIT_SECRETHASH)

    start_danger_zone_block_number = (
        pair.payer_transfer.lock.expiration - channel_state.reveal_timeout
    )

    events = mediator.events_for_onchain_secretreveal_if_dangerzone(
        channel_map,
        UNIT_SECRETHASH,
        transfers_pair,
        start_danger_zone_block_number,
    )
    assert len(events) == 1

    for pair in transfers_pair:
        assert pair.payer_state == 'payer_waiting_secret_reveal'

    end_danger_zone_block_number = (
        pair.payer_transfer.lock.expiration - 1
    )

    events = mediator.events_for_onchain_secretreveal_if_dangerzone(
        channel_map,
        UNIT_SECRETHASH,
        transfers_pair,
        end_danger_zone_block_number,
    )
    assert not events

    for pair in transfers_pair:
        assert pair.payer_state == 'payer_waiting_secret_reveal'

    events = mediator.events_for_onchain_secretreveal_if_dangerzone(
        channel_map,
        UNIT_SECRETHASH,
        transfers_pair,
        pair.payer_transfer.lock.expiration,
    )
    assert not events

    for pair in transfers_pair:
        assert pair.payer_state == 'payer_waiting_secret_reveal'


def test_secret_learned():
    pseudo_random_generator = random.Random()

    channels = mediator_make_channel_pair()

    from_transfer = factories.make_default_signed_transfer_for(channels[0])

    iteration = mediator.state_transition(
        mediator_state=None,
        state_change=mediator_make_init_action(channels, from_transfer),
        channelidentifiers_to_channels=channels.channel_map,
        pseudo_random_generator=pseudo_random_generator,
        block_number=1,
    )

    iteration = mediator.secret_learned(
        state=iteration.new_state,
        channelidentifiers_to_channels=channels.channel_map,
        pseudo_random_generator=pseudo_random_generator,
        block_number=1,
        secret=UNIT_SECRET,
        secrethash=UNIT_SECRETHASH,
        payee_address=channels[1].partner_state.address,
    )
    transfer_pair = iteration.new_state.transfers_pair[0]

    assert from_transfer.lock.expiration == transfer_pair.payee_transfer.lock.expiration
    assert mediator.is_send_transfer_almost_equal(transfer_pair.payee_transfer, from_transfer)
    assert transfer_pair.payee_address == channels.get_route(1).node_address

    assert transfer_pair.payer_transfer.balance_proof.sender == channels.get_route(0).node_address
    assert transfer_pair.payer_transfer == from_transfer

    assert iteration.new_state.secret == UNIT_SECRET

    assert transfer_pair.payee_state == 'payee_balance_proof'
    assert transfer_pair.payer_state == 'payer_secret_revealed'

    assert must_contain_entry(iteration.events, SendSecretReveal, {})
    assert must_contain_entry(iteration.events, SendBalanceProof, {})


def test_secret_learned_with_refund():
    amount = 10
    privatekeys = [HOP2_KEY, HOP3_KEY, HOP4_KEY]
    addresses = [HOP2, HOP3, HOP4]
    block_number = 1

    #                                             /-> HOP3
    # Emulate HOP2(Initiator) -> HOP1 (This node)
    #                                             \-> HOP4 -> HOP5
    channel_map, transfers_pair = factories.make_transfers_pair(
        privatekeys,
        amount,
        block_number,
    )

    # Map HOP1 channel partner addresses to their channel states
    partner_to_channel = {
        channel_state.partner_state.address: channel_state
        for channel_state in channel_map.values()
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
        mediator_state=mediator_state,
        state_change=ReceiveSecretReveal(UNIT_SECRET, HOP5),
        channelidentifiers_to_channels=channel_map,
        pseudo_random_generator=random.Random(),
        block_number=5,
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
    block_number = 5
    pseudo_random_generator = random.Random()

    channels = mediator_make_channel_pair()
    payer_transfer = factories.make_default_signed_transfer_for(channels[0], expiration=30)

    mediator_state = MediatorTransferState(UNIT_SECRETHASH)
    iteration = mediator.mediate_transfer(
        mediator_state,
        channels.get_routes(1),
        channels[0],
        channels.channel_map,
        pseudo_random_generator,
        payer_transfer,
        block_number,
    )

    assert must_contain_entry(iteration.events, SendLockedTransfer, {
        'recipient': channels[1].partner_state.address,
        'transfer': {
            'payment_identifier': payer_transfer.payment_identifier,
            'token': payer_transfer.token,
            'lock': {
                'amount': payer_transfer.lock.amount,
                'secrethash': payer_transfer.lock.secrethash,
                'expiration': payer_transfer.lock.expiration,
            },
            'target': payer_transfer.target,
        },
    })


def test_init_mediator():
    channels = mediator_make_channel_pair()
    from_transfer = factories.make_default_signed_transfer_for(channels[0])

    iteration = mediator.state_transition(
        mediator_state=None,
        state_change=mediator_make_init_action(channels, from_transfer),
        channelidentifiers_to_channels=channels.channel_map,
        pseudo_random_generator=random.Random(),
        block_number=1,
    )

    assert isinstance(iteration.new_state, MediatorTransferState)
    assert iteration.new_state.transfers_pair[0].payer_transfer == from_transfer
    assert must_contain_entry(iteration.events, SendLockedTransfer, {
        'transfer': {
            'token': from_transfer.token,
            'lock': {
                'amount': from_transfer.lock.amount,
                'expiration': from_transfer.lock.expiration,
                'secrethash': from_transfer.lock.secrethash,
            },
        },
    }), 'mediated_transfer should /not/ split the transfer'


def test_mediator_reject_keccak_empty_hash():
    channels = mediator_make_channel_pair()
    from_transfer = factories.make_default_signed_transfer_for(
        channel_state=channels[0],
        initiator=HOP1,
        secret=EMPTY_HASH,
        allow_invalid=True,
    )

    iteration = mediator.state_transition(
        mediator_state=None,
        state_change=mediator_make_init_action(channels, from_transfer),
        channelidentifiers_to_channels=channels.channel_map,
        pseudo_random_generator=random.Random(),
        block_number=1,
    )

    assert not iteration.new_state


def test_mediator_secret_reveal_empty_hash():
    pseudo_random_generator = random.Random()

    channels = mediator_make_channel_pair()
    from_transfer = factories.make_default_signed_transfer_for(channels[0], initiator=HOP1)

    block_number = 1
    iteration = mediator.state_transition(
        mediator_state=None,
        state_change=mediator_make_init_action(channels, from_transfer),
        channelidentifiers_to_channels=channels.channel_map,
        pseudo_random_generator=pseudo_random_generator,
        block_number=1,
    )
    assert isinstance(iteration.new_state, MediatorTransferState)
    assert iteration.new_state.transfers_pair[0].payer_transfer == from_transfer
    current_state = iteration.new_state

    # an empty hash offchain secret reveal should be rejected
    receive_secret = ReceiveSecretReveal(EMPTY_HASH, UNIT_TRANSFER_TARGET)
    iteration = mediator.state_transition(
        mediator_state=current_state,
        state_change=receive_secret,
        channelidentifiers_to_channels=channels.channel_map,
        pseudo_random_generator=pseudo_random_generator,
        block_number=2,
    )
    assert len(iteration.events) == 0

    # an empty hash onchain secret reveal should be rejected
    secrethash = EMPTY_HASH_KECCAK
    onchain_reveal = ContractReceiveSecretReveal(
        transaction_hash=factories.make_address(),
        secret_registry_address=factories.make_address(),
        secrethash=secrethash,
        secret=EMPTY_HASH,
        block_number=block_number,
    )
    iteration = mediator.state_transition(
        mediator_state=current_state,
        state_change=onchain_reveal,
        channelidentifiers_to_channels=channels.channel_map,
        pseudo_random_generator=pseudo_random_generator,
        block_number=2,
    )
    assert secrethash not in channels[0].partner_state.secrethashes_to_onchain_unlockedlocks


def test_no_valid_routes():
    channels = factories.make_channel_set([
        {
            'partner_state': {
                'balance': UNIT_TRANSFER_AMOUNT,
                'address': UNIT_TRANSFER_SENDER,
            },
            'our_state': {'balance': UNIT_TRANSFER_AMOUNT},
        },
        {'our_state': {'balance': UNIT_TRANSFER_AMOUNT - 1}},
        {'our_state': {'balance': 0}},
    ])
    from_transfer = factories.make_default_signed_transfer_for(channels[0], initiator=HOP1)

    iteration = mediator.state_transition(
        mediator_state=None,
        state_change=mediator_make_init_action(channels, from_transfer),
        channelidentifiers_to_channels=channels.channel_map,
        pseudo_random_generator=random.Random(),
        block_number=1,
    )
    msg = (
        'The task must be kept alive, '
        'either to handle future available routes, or lock expired messages'
    )
    assert iteration.new_state is not None, msg
    assert must_contain_entry(iteration.events, SendRefundTransfer, {})


def test_lock_timeout_larger_than_settlement_period_must_be_ignored():
    """ The lock expiration must be constant through out the path, if a
    transfer with an expiration larger than the channel's settle_timeout is
    received it must be ignored.

    Alternative: The node can wait until the lock timeout is lower then the
    settle timeout before forwarding the transfer.
    """
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
    high_expiration = 20
    base = {
        'reveal_timeout': 5,
        'settle_timeout': 10,
    }

    channels = mediator_make_channel_pair(base=base)
    from_transfer = factories.make_default_signed_transfer_for(
        channels[0],
        initiator=HOP1,
        expiration=high_expiration,
        allow_invalid=True,
    )

    # Assert the precondition for the test. The message is still valid, and the
    # recipient cannot control the received lock expiration
    assert from_transfer.lock.expiration >= channels[0].settle_timeout

    iteration = mediator.state_transition(
        mediator_state=None,
        state_change=mediator_make_init_action(channels, from_transfer),
        channelidentifiers_to_channels=channels.channel_map,
        pseudo_random_generator=random.Random(),
        block_number=1,
    )

    msg = (
        'The transfer must not be forwarded because the lock timeout is '
        'larger then the settlement timeout'
    )
    assert not must_contain_entry(iteration.events, SendLockedTransfer, {}), msg


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

    from_transfer = factories.make_default_signed_transfer_for(
        bc_channel,
        initiator=HOP1,
        target=target_attacker2,
    )

    available_routes = [
        factories.route_from_channel(attacked_channel),
    ]
    channel_map = {
        bc_channel.identifier: bc_channel,
        attacked_channel.identifier: attacked_channel,
    }

    init_state_change = ActionInitMediator(
        available_routes,
        from_route,
        from_transfer,
    )

    iteration = mediator.state_transition(
        mediator_state=None,
        state_change=init_state_change,
        channelidentifiers_to_channels=channel_map,
        pseudo_random_generator=pseudo_random_generator,
        block_number=block_number,
    )

    attack_block_number = from_transfer.lock.expiration - attacked_channel.reveal_timeout
    is_safe, _ = mediator.is_safe_to_wait(
        from_transfer.lock.expiration,
        attacked_channel.reveal_timeout,
        attack_block_number,
    )
    assert not is_safe

    # Wait until it's not safe to wait for the off-chain unlock for B-C (and expire C-A2)
    new_iteration = iteration
    for new_block_number in range(block_number, attack_block_number + 1):
        block = Block(
            block_number=new_block_number,
            gas_limit=1,
            block_hash=factories.make_transaction_hash(),
        )

        new_iteration = mediator.state_transition(
            mediator_state=new_iteration.new_state,
            state_change=block,
            channelidentifiers_to_channels=channel_map,
            pseudo_random_generator=pseudo_random_generator,
            block_number=new_block_number,
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
        mediator_state=new_iteration.new_state,
        state_change=receive_secret,
        channelidentifiers_to_channels=channel_map,
        pseudo_random_generator=pseudo_random_generator,
        block_number=attack_block_number,
    )
    assert not any(
        isinstance(event, ContractSendChannelClose)
        for event in attack_iteration.events
    )

    # don't go on-chain since the balance proof was not received
    for new_block_number in range(block_number, from_transfer.lock.expiration + 1):
        block = Block(
            block_number=new_block_number,
            gas_limit=1,
            block_hash=factories.make_transaction_hash(),
        )
        new_iteration = mediator.state_transition(
            mediator_state=new_iteration.new_state,
            state_change=block,
            channelidentifiers_to_channels=channel_map,
            pseudo_random_generator=pseudo_random_generator,
            block_number=new_block_number,
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


def test_payee_timeout_must_be_equal_to_payer_timeout():
    # The description below /was/ true without a secret registry. With the
    # secret registry expirations are constant and the race below is not
    # possible anymore.
    #
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
    pseudo_random_generator = random.Random()

    channels = mediator_make_channel_pair()
    payer_transfer = factories.make_default_signed_transfer_for(channels[0], expiration=30)

    mediator_state = MediatorTransferState(UNIT_SECRETHASH)
    iteration = mediator.mediate_transfer(
        mediator_state,
        channels.get_routes(1),
        channels[0],
        channels.channel_map,
        pseudo_random_generator,
        payer_transfer,
        block_number,
    )

    assert must_contain_entry(iteration.events, SendLockedTransfer, {
        'transfer': {
            'lock': {
                'expiration': payer_transfer.lock.expiration,
            },
        },
    })


def test_set_offchain_secret():
    mediator_state = MediatorTransferState(UNIT_SECRETHASH)

    assert mediator_state.transfers_pair == list()
    assert mediator_state.secret is None
    assert mediator_state.secrethash == UNIT_SECRETHASH

    amount = 10
    block_number = 1
    channel_map, transfers_pair = factories.make_transfers_pair(
        [
            HOP2_KEY,
            HOP3_KEY,
        ],
        amount,
        block_number,
    )
    mediator_state.transfers_pair = transfers_pair

    payer_channelid = transfers_pair[0].payer_transfer.balance_proof.channel_identifier
    payee_channelid = transfers_pair[0].payee_transfer.balance_proof.channel_identifier

    payer_channel_our_state = channel_map[payer_channelid].our_state
    payer_channel_partner_state = channel_map[payer_channelid].partner_state
    payee_channel_our_state = channel_map[payee_channelid].our_state
    payee_channel_partner_state = channel_map[payee_channelid].partner_state

    assert payer_channel_our_state.secrethashes_to_lockedlocks == dict()
    assert payer_channel_our_state.secrethashes_to_unlockedlocks == dict()

    assert UNIT_SECRETHASH in payer_channel_partner_state.secrethashes_to_lockedlocks.keys()
    assert payer_channel_partner_state.secrethashes_to_unlockedlocks == dict()

    assert UNIT_SECRETHASH in payee_channel_our_state.secrethashes_to_lockedlocks.keys()
    assert payee_channel_our_state.secrethashes_to_unlockedlocks == dict()

    assert payee_channel_partner_state.secrethashes_to_lockedlocks == dict()
    assert payee_channel_partner_state.secrethashes_to_unlockedlocks == dict()

    set_offchain_secret(mediator_state, channel_map, UNIT_SECRET, UNIT_SECRETHASH)

    assert mediator_state.secret == UNIT_SECRET

    assert payer_channel_our_state.secrethashes_to_lockedlocks == dict()
    assert payer_channel_our_state.secrethashes_to_unlockedlocks == dict()

    assert payer_channel_partner_state.secrethashes_to_lockedlocks == dict()
    assert UNIT_SECRETHASH in payer_channel_partner_state.secrethashes_to_unlockedlocks.keys()

    assert payee_channel_our_state.secrethashes_to_lockedlocks == dict()
    assert UNIT_SECRETHASH in payee_channel_our_state.secrethashes_to_unlockedlocks.keys()

    assert payee_channel_partner_state.secrethashes_to_lockedlocks == dict()
    assert payee_channel_partner_state.secrethashes_to_unlockedlocks == dict()


def test_mediate_transfer_with_maximum_pending_transfers_exceeded():
    pseudo_random_generator = random.Random()

    balance = 2 * MAXIMUM_PENDING_TRANSFERS * UNIT_TRANSFER_AMOUNT
    channels = factories.make_channel_set([
        {'partner_state': {'balance': balance, 'address': UNIT_TRANSFER_SENDER}},
        {'our_state': {'balance': balance}},
    ])

    iterations = []
    for index in range(1, MAXIMUM_PENDING_TRANSFERS + 2):
        from_transfer = factories.make_default_signed_transfer_for(
            channels[0],
            initiator=HOP1,
            expiration=UNIT_SETTLE_TIMEOUT,
            secret=random_secret(),
            identifier=index,
            nonce=index,
            locked_amount=index * UNIT_TRANSFER_AMOUNT,
            compute_locksroot=True,
            allow_invalid=True,
        )

        iterations.append(mediator.state_transition(
            mediator_state=None,
            state_change=mediator_make_init_action(channels, from_transfer),
            channelidentifiers_to_channels=channels.channel_map,
            pseudo_random_generator=pseudo_random_generator,
            block_number=1,
        ))

    # last iteration should have failed due to exceeded pending transfer limit
    failed_iteration = iterations.pop()
    assert failed_iteration.new_state is None
    assert must_contain_entry(failed_iteration.events, EventInvalidReceivedLockedTransfer, {
        'payment_identifier': MAXIMUM_PENDING_TRANSFERS + 1,
        'reason': (
            'Invalid LockedTransfer message. Adding the transfer would '
            'exceed the allowed limit of 160 pending transfers per channel.'
        ),
    })

    assert all(isinstance(iteration.new_state, MediatorTransferState) for iteration in iterations)


def test_mediator_lock_expired_with_new_block():
    block_number = 5
    pseudo_random_generator = random.Random()

    channels = mediator_make_channel_pair()

    payer_transfer = factories.make_default_signed_transfer_for(
        channels[0],
        initiator=HOP1,
        expiration=30,
    )

    mediator_state = MediatorTransferState(UNIT_SECRETHASH)
    iteration = mediator.mediate_transfer(
        state=mediator_state,
        possible_routes=channels.get_routes(1),
        payer_channel=channels[0],
        channelidentifiers_to_channels=channels.channel_map,
        pseudo_random_generator=pseudo_random_generator,
        payer_transfer=payer_transfer,
        block_number=block_number,
    )
    assert len(iteration.events) == 1

    send_transfer = must_contain_entry(iteration.events, SendLockedTransfer, {})
    assert send_transfer

    transfer = send_transfer.transfer

    block_expiration_number = transfer.lock.expiration + DEFAULT_NUMBER_OF_BLOCK_CONFIRMATIONS * 2
    block = Block(
        block_number=block_expiration_number,
        gas_limit=1,
        block_hash=factories.make_transaction_hash(),
    )
    iteration = mediator.state_transition(
        mediator_state=mediator_state,
        state_change=block,
        channelidentifiers_to_channels=channels.channel_map,
        pseudo_random_generator=pseudo_random_generator,
        block_number=block_expiration_number,
    )

    assert iteration.events
    assert must_contain_entry(iteration.events, SendLockExpired, {
        'secrethash': transfer.lock.secrethash,
    })
    assert must_contain_entry(iteration.events, EventUnlockFailed, {
        'secrethash': transfer.lock.secrethash,
    })
    assert transfer.lock.secrethash not in channels[1].our_state.secrethashes_to_lockedlocks


def test_mediator_lock_expired_with_receive_lock_expired():
    expiration = 30
    pseudo_random_generator = random.Random()

    channels = mediator_make_channel_pair()
    transfer = factories.make_default_signed_transfer_for(channels[0], expiration=expiration)

    iteration = mediator.state_transition(
        mediator_state=None,
        state_change=mediator_make_init_action(channels, transfer),
        channelidentifiers_to_channels=channels.channel_map,
        pseudo_random_generator=pseudo_random_generator,
        block_number=5,
    )

    assert must_contain_entry(iteration.events, SendLockedTransfer, {
        'recipient': UNIT_TRANSFER_TARGET,
        'transfer': {
            'lock': {
                'amount': 10,
                'expiration': expiration,
                'secrethash': transfer.lock.secrethash,
            },
            'balance_proof': {
                'nonce': 1,
                'transferred_amount': 0,
                'locked_amount': 10,
                'locksroot': transfer.balance_proof.locksroot,
            },
        },
    })

    balance_proof = factories.make_signed_balance_proof(
        nonce=2,
        transferred_amount=transfer.balance_proof.transferred_amount,
        locked_amount=0,
        token_network_address=transfer.balance_proof.token_network_identifier,
        channel_identifier=channels[0].identifier,
        locksroot=EMPTY_MERKLE_ROOT,
        extra_hash=transfer.lock.secrethash,
        sender_address=UNIT_TRANSFER_SENDER,
        private_key=UNIT_TRANSFER_PKEY,
    )

    lock_expired_state_change = ReceiveLockExpired(
        balance_proof=balance_proof,
        secrethash=transfer.lock.secrethash,
        message_identifier=1,
    )

    block_before_confirmed_expiration = expiration + DEFAULT_NUMBER_OF_BLOCK_CONFIRMATIONS - 1
    iteration = mediator.state_transition(
        mediator_state=iteration.new_state,
        state_change=lock_expired_state_change,
        channelidentifiers_to_channels=channels.channel_map,
        pseudo_random_generator=pseudo_random_generator,
        block_number=block_before_confirmed_expiration,
    )
    assert not must_contain_entry(iteration.events, SendProcessed, {})

    block_lock_expired = block_before_confirmed_expiration + 1
    iteration = mediator.state_transition(
        mediator_state=iteration.new_state,
        state_change=lock_expired_state_change,
        channelidentifiers_to_channels=channels.channel_map,
        pseudo_random_generator=pseudo_random_generator,
        block_number=block_lock_expired,
    )
    assert must_contain_entry(iteration.events, SendProcessed, {})

    assert iteration.new_state
    assert iteration.new_state.transfers_pair[0].payer_state == 'payer_expired'
    assert iteration.new_state.transfers_pair[0].payee_state == 'payee_pending'


def test_mediator_receive_lock_expired_after_secret_reveal():
    """
    Test the following scenario:
    I -> M -> T

    - Mediator forwards a transfer from I to T.
    - T receives secret from I and never registers into on-chain.
    - T sends SecretReveal to M, lockedlock becomes an unlockedlock
    - I expires the lock and sends LockExpired to M.
    - M should remove the lock from both secrethashes_to_lockedlocks
      and secrethashes_to_unlocklocks.
    """
    expiration = 30
    pseudo_random_generator = random.Random()

    channels = mediator_make_channel_pair()
    transfer = factories.make_default_signed_transfer_for(channels[0], expiration=expiration)

    iteration = mediator.state_transition(
        mediator_state=None,
        state_change=mediator_make_init_action(channels, transfer),
        channelidentifiers_to_channels=channels.channel_map,
        pseudo_random_generator=pseudo_random_generator,
        block_number=5,
    )

    secrethash = transfer.lock.secrethash

    block_lock_expired = expiration + DEFAULT_NUMBER_OF_BLOCK_CONFIRMATIONS

    assert secrethash in channels[0].partner_state.secrethashes_to_lockedlocks

    # Reveal secret just before the lock expires
    secret_reveal = ReceiveSecretReveal(UNIT_SECRET, UNIT_TRANSFER_TARGET)

    iteration = mediator.state_transition(
        mediator_state=iteration.new_state,
        state_change=secret_reveal,
        channelidentifiers_to_channels=channels.channel_map,
        pseudo_random_generator=pseudo_random_generator,
        block_number=block_lock_expired,
    )

    # Make sure the lock was moved
    assert secrethash not in channels[0].partner_state.secrethashes_to_lockedlocks
    assert secrethash in channels[0].partner_state.secrethashes_to_unlockedlocks

    balance_proof = factories.make_signed_balance_proof(
        nonce=2,
        transferred_amount=transfer.balance_proof.transferred_amount,
        locked_amount=0,
        token_network_address=transfer.balance_proof.token_network_identifier,
        channel_identifier=channels[0].identifier,
        locksroot=EMPTY_MERKLE_ROOT,
        extra_hash=transfer.lock.secrethash,
        sender_address=UNIT_TRANSFER_SENDER,
        private_key=UNIT_TRANSFER_PKEY,
    )

    lock_expired_state_change = ReceiveLockExpired(
        balance_proof=balance_proof,
        secrethash=transfer.lock.secrethash,
        message_identifier=1,
    )

    iteration = mediator.state_transition(
        mediator_state=iteration.new_state,
        state_change=lock_expired_state_change,
        channelidentifiers_to_channels=channels.channel_map,
        pseudo_random_generator=pseudo_random_generator,
        block_number=block_lock_expired + 1,
    )

    # LockExpired should remove the lock from both lockedlocks and unlockedlocks
    assert secrethash not in channels[0].partner_state.secrethashes_to_lockedlocks
    assert secrethash not in channels[0].partner_state.secrethashes_to_unlockedlocks


def test_mediator_lock_expired_after_receive_secret_reveal():
    """
    Test the following scenario:
    I -> M -> T

    - Mediator forwards a transfer from I to T.
    - T receives secret from I and never registers into on-chain.
    - T sends SecretReveal to M, lockedlock becomes an unlockedlock
    - M expires the lock.
    - M should remove the lock from both secrethashes_to_lockedlocks
      and secrethashes_to_unlocklocks.
    """
    expiration = 30
    pseudo_random_generator = random.Random()

    channels = mediator_make_channel_pair()
    transfer = factories.make_default_signed_transfer_for(channels[0], expiration=30)

    iteration = mediator.state_transition(
        mediator_state=None,
        state_change=mediator_make_init_action(channels, transfer),
        channelidentifiers_to_channels=channels.channel_map,
        pseudo_random_generator=pseudo_random_generator,
        block_number=5,
    )

    secrethash = transfer.lock.secrethash

    block_lock_expired = expiration + DEFAULT_NUMBER_OF_BLOCK_CONFIRMATIONS

    assert secrethash in channels[0].partner_state.secrethashes_to_lockedlocks

    # Reveal secret just before the lock expires
    secret_reveal = ReceiveSecretReveal(UNIT_SECRET, UNIT_TRANSFER_TARGET)

    iteration = mediator.state_transition(
        mediator_state=iteration.new_state,
        state_change=secret_reveal,
        channelidentifiers_to_channels=channels.channel_map,
        pseudo_random_generator=pseudo_random_generator,
        block_number=block_lock_expired,
    )

    # Mediator should NOT send balance proof
    assert must_contain_entry(iteration.events, SendBalanceProof, {}) is None

    # Make sure the lock was moved
    payer_channel, payee_channel = channels[0], channels[1]
    assert secrethash not in payer_channel.partner_state.secrethashes_to_lockedlocks
    assert secrethash in payer_channel.partner_state.secrethashes_to_unlockedlocks

    assert secrethash not in payee_channel.our_state.secrethashes_to_lockedlocks
    assert secrethash in payee_channel.our_state.secrethashes_to_unlockedlocks

    block_expiration_number = transfer.lock.expiration + DEFAULT_NUMBER_OF_BLOCK_CONFIRMATIONS * 2
    block = Block(
        block_number=block_expiration_number,
        gas_limit=1,
        block_hash=factories.make_transaction_hash(),
    )

    iteration = mediator.state_transition(
        mediator_state=iteration.new_state,
        state_change=block,
        channelidentifiers_to_channels=channels.channel_map,
        pseudo_random_generator=pseudo_random_generator,
        block_number=block_expiration_number,
    )

    assert secrethash not in channels[0].our_state.secrethashes_to_unlockedlocks
    assert must_contain_entry(iteration.events, SendLockExpired, {})
