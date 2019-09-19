# pylint: disable=invalid-name,too-many-locals,too-many-arguments,too-many-lines
import random
from copy import deepcopy
from dataclasses import replace
from typing import List, Optional, Tuple

import pytest

from raiden.constants import (
    EMPTY_HASH,
    EMPTY_SECRET,
    EMPTY_SECRET_SHA256,
    MAXIMUM_PENDING_TRANSFERS,
)
from raiden.settings import DEFAULT_NUMBER_OF_BLOCK_CONFIRMATIONS
from raiden.tests.utils import factories
from raiden.tests.utils.events import search_for_item
from raiden.tests.utils.factories import (
    ADDR,
    HOP1,
    HOP2,
    UNIT_CHAIN_ID,
    UNIT_REVEAL_TIMEOUT,
    UNIT_SECRET,
    UNIT_SECRETHASH,
    UNIT_SETTLE_TIMEOUT,
    UNIT_TOKEN_NETWORK_ADDRESS,
    UNIT_TRANSFER_AMOUNT,
    UNIT_TRANSFER_IDENTIFIER,
    UNIT_TRANSFER_SENDER,
    UNIT_TRANSFER_TARGET,
    BalanceProofSignedStateProperties,
    FeeScheduleStateProperties,
    LockedTransferSignedStateProperties,
    NettingChannelEndStateProperties,
    NettingChannelStateProperties,
    create,
    create_properties,
    make_canonical_identifier,
    make_channel_set,
    mediator_make_channel_pair,
    mediator_make_init_action,
)
from raiden.tests.utils.transfer import assert_dropped
from raiden.transfer import channel, routes
from raiden.transfer.architecture import Event
from raiden.transfer.events import (
    ContractSendChannelClose,
    ContractSendSecretReveal,
    EventInvalidReceivedLockedTransfer,
    EventInvalidReceivedUnlock,
    SendProcessed,
)
from raiden.transfer.mediated_transfer import mediator
from raiden.transfer.mediated_transfer.events import (
    EventUnlockClaimSuccess,
    EventUnlockFailed,
    EventUnlockSuccess,
    SendBalanceProof,
    SendLockedTransfer,
    SendLockExpired,
    SendRefundTransfer,
    SendSecretReveal,
)
from raiden.transfer.mediated_transfer.mediation_fee import (
    FeeScheduleState,
    calculate_imbalance_fees,
)
from raiden.transfer.mediated_transfer.mediator import get_payee_channel, set_offchain_secret
from raiden.transfer.mediated_transfer.state import (
    MediationPairState,
    MediatorTransferState,
    WaitingTransferState,
)
from raiden.transfer.mediated_transfer.state_change import (
    ActionInitMediator,
    ReceiveLockExpired,
    ReceiveSecretReveal,
)
from raiden.transfer.state import (
    ChannelState,
    HashTimeLockState,
    HopState,
    NettingChannelState,
    NetworkState,
    RouteState,
    message_identifier_from_prng,
)
from raiden.transfer.state_change import (
    ActionChangeNodeNetworkState,
    Block,
    ContractReceiveChannelClosed,
    ContractReceiveSecretReveal,
    ReceiveUnlock,
)
from raiden.utils import random_secret
from raiden.utils.typing import BlockExpiration, BlockNumber, FeeAmount, TokenAmount


def make_route_from_channelstate(channel_state):
    return HopState(channel_state.partner_state.address, channel_state.channel_identifier)


def test_is_lock_valid():
    """ A hash time lock is valid up to the expiration block. """
    expiration = 10
    assert mediator.is_lock_valid(expiration, 5) is True
    assert mediator.is_lock_valid(expiration, 10) is True, "lock is expired at the next block"
    assert mediator.is_lock_valid(expiration, 11) is False


def test_is_safe_to_wait():
    """ It's safe to wait for a secret while there are more than reveal timeout
    blocks until the lock expiration.
    """
    expiration = 40

    # expiration is in 30 blocks, 19 blocks safe for waiting
    block_number = 10
    reveal_timeout = 10
    assert mediator.is_safe_to_wait(expiration, reveal_timeout, block_number).ok

    # expiration is in 20 blocks, 10 blocks safe for waiting
    block_number = 20
    reveal_timeout = 10
    assert mediator.is_safe_to_wait(expiration, reveal_timeout, block_number).ok

    # expiration is in 11 blocks, 1 block safe for waiting
    block_number = 29
    reveal_timeout = 10
    assert mediator.is_safe_to_wait(expiration, reveal_timeout, block_number).ok

    # at the block 30 it's not safe to wait anymore
    block_number = 30
    reveal_timeout = 10
    assert mediator.is_safe_to_wait(
        expiration, reveal_timeout, block_number
    ).fail, "this is expiration must not be safe"

    block_number = 40
    reveal_timeout = 10
    assert mediator.is_safe_to_wait(
        expiration, reveal_timeout, block_number
    ).fail, "this is expiration must not be safe"

    block_number = 50
    reveal_timeout = 10
    assert mediator.is_safe_to_wait(
        expiration, reveal_timeout, block_number
    ).fail, "this is expiration must not be safe"


def test_is_channel_usable_for_mediation():
    """ Check rules that determine if a channel can be used for transfers """
    reveal_timeout = 30
    timeout_blocks = reveal_timeout + 10
    amount = UNIT_TRANSFER_AMOUNT

    channels = factories.make_channel_set(
        [
            NettingChannelStateProperties(
                our_state=NettingChannelEndStateProperties(balance=amount)
            ),
            NettingChannelStateProperties(our_state=NettingChannelEndStateProperties(balance=0)),
            NettingChannelStateProperties(
                our_state=NettingChannelEndStateProperties(balance=amount),
                reveal_timeout=timeout_blocks,
                settle_timeout=timeout_blocks * 2,
            ),
        ]
    )

    # the first channel is usable
    assert channel.is_channel_usable_for_mediation(
        channel_state=channels[0], transfer_amount=amount, lock_timeout=timeout_blocks
    )

    # a channel without capacity must be skipped
    assert not channel.is_channel_usable_for_mediation(
        channel_state=channels[1], transfer_amount=amount, lock_timeout=timeout_blocks
    )

    # channel should be usable, due to lock_timeout larger than channel.reveal_timeout
    assert channel.is_channel_usable_for_mediation(
        channel_state=channels[2], transfer_amount=amount, lock_timeout=timeout_blocks + 1
    )

    # channel should not be usable, when lock_timeout equal or greater than channel.reveal_timeout
    assert not channel.is_channel_usable_for_mediation(
        channel_state=channels[2], transfer_amount=amount, lock_timeout=timeout_blocks
    )


def test_next_transfer_pair():
    block_number = 3
    balance = 10
    pseudo_random_generator = random.Random()

    payer_transfer = create(
        LockedTransferSignedStateProperties(
            amount=balance, initiator=HOP1, target=ADDR, expiration=50
        )
    )

    channels = make_channel_set(
        [
            NettingChannelStateProperties(
                our_state=NettingChannelEndStateProperties(balance=balance)
            ),
            NettingChannelStateProperties(
                our_state=NettingChannelEndStateProperties(balance=balance)
            ),
        ]
    )

    route_state_table = channels.get_routes(1)
    pair, events = mediator.forward_transfer_pair(
        payer_transfer=payer_transfer,
        payer_channel=channels[0],
        route_state=route_state_table[0],
        route_state_table=route_state_table,
        channelidentifiers_to_channels=channels.channel_map,
        pseudo_random_generator=pseudo_random_generator,
        block_number=block_number,
    )

    assert pair.payer_transfer == payer_transfer
    assert pair.payee_address == channels[1].partner_state.address
    assert pair.payee_transfer.lock.expiration == pair.payer_transfer.lock.expiration

    assert search_for_item(
        events,
        SendLockedTransfer,
        {
            "recipient": pair.payee_address,
            "transfer": {
                "payment_identifier": payer_transfer.payment_identifier,
                "token": payer_transfer.token,
                "initiator": payer_transfer.initiator,
                "target": payer_transfer.target,
                "lock": {
                    "amount": payer_transfer.lock.amount,
                    "secrethash": payer_transfer.lock.secrethash,
                    "expiration": payer_transfer.lock.expiration,
                },
            },
        },
    )


def test_set_payee():
    setup = factories.make_transfers_pair(3)
    transfers_pair = setup.transfers_pair

    # assert pre conditions
    assert transfers_pair[0].payer_state == "payer_pending"
    assert transfers_pair[0].payee_state == "payee_pending"

    assert transfers_pair[1].payer_state == "payer_pending"
    assert transfers_pair[1].payee_state == "payee_pending"

    mediator.set_offchain_reveal_state(transfers_pair, setup.channels.partner_address(0))

    # payer address was used, no payee state should change
    assert transfers_pair[0].payer_state == "payer_pending"
    assert transfers_pair[0].payee_state == "payee_pending"

    assert transfers_pair[1].payer_state == "payer_pending"
    assert transfers_pair[1].payee_state == "payee_pending"

    mediator.set_offchain_reveal_state(transfers_pair, setup.channels.partner_address(1))

    # only the transfer where the address is a payee should change
    assert transfers_pair[0].payer_state == "payer_pending"
    assert transfers_pair[0].payee_state == "payee_secret_revealed"

    assert transfers_pair[1].payer_state == "payer_pending"
    assert transfers_pair[1].payee_state == "payee_pending"


def test_events_for_expired_pairs():
    """ The transfer pair must switch to expired at the right block. """
    setup = factories.make_transfers_pair(2)
    pair = setup.transfers_pair[0]

    first_unsafe_block = pair.payer_transfer.lock.expiration - UNIT_REVEAL_TIMEOUT

    mediator.events_for_expired_pairs(
        setup.channel_map, setup.transfers_pair, None, first_unsafe_block
    )
    assert pair.payer_state == "payer_pending"

    # edge case for the lock expiration
    payee_expiration_block = pair.payee_transfer.lock.expiration
    mediator.events_for_expired_pairs(
        setup.channel_map, setup.transfers_pair, None, payee_expiration_block
    )
    assert pair.payer_state == "payer_pending"

    # lock expired
    payer_lock_expiration_threshold = channel.get_sender_expiration_threshold(
        pair.payer_transfer.lock.expiration
    )
    mediator.events_for_expired_pairs(
        setup.channel_map, setup.transfers_pair, None, payer_lock_expiration_threshold
    )
    assert pair.payer_state == "payer_expired"


def test_events_for_refund():
    amount = 10
    block_number = 1
    pseudo_random_generator = random.Random()

    our_state = factories.NettingChannelEndStateProperties(balance=amount)
    partner_state = replace(our_state, address=UNIT_TRANSFER_SENDER)
    refund_channel = factories.create(
        factories.NettingChannelStateProperties(our_state=our_state, partner_state=partner_state)
    )

    transfer_data = LockedTransferSignedStateProperties(
        amount=amount, expiration=30, canonical_identifier=refund_channel.canonical_identifier
    )
    received_transfer = create(transfer_data)

    is_valid, _, msg = channel.handle_receive_lockedtransfer(refund_channel, received_transfer)
    assert is_valid, msg

    transfer_pair, refund_events = mediator.backward_transfer_pair(
        refund_channel, received_transfer, pseudo_random_generator, block_number
    )

    assert search_for_item(
        refund_events,
        SendRefundTransfer,
        {
            "transfer": {
                "lock": {
                    "expiration": received_transfer.lock.expiration,
                    "amount": amount,
                    "secrethash": received_transfer.lock.secrethash,
                }
            },
            # pylint: disable=E1101
            "recipient": refund_channel.partner_state.address,
        },
    )
    assert transfer_pair.payer_transfer == received_transfer


def test_events_for_secretreveal():
    """ The secret is revealed backwards to the payer once the payee sent the
    SecretReveal.
    """
    our_address = ADDR
    pseudo_random_generator = random.Random()
    setup = factories.make_transfers_pair(3)

    events = mediator.events_for_secretreveal(
        setup.transfers_pair, our_address, pseudo_random_generator
    )

    # the secret is known by this node, but no other payee is at a secret known
    # state, do nothing
    assert not events

    first_pair = setup.transfers_pair[0]
    last_pair = setup.transfers_pair[1]

    last_pair.payee_state = "payee_secret_revealed"
    events = mediator.events_for_secretreveal(
        setup.transfers_pair, UNIT_SECRET, pseudo_random_generator
    )

    # the last known hop sent a secret reveal message. This node learned the
    # secret and now must reveal it to the payer node from the transfer pair
    assert search_for_item(
        events,
        SendSecretReveal,
        {"secret": UNIT_SECRET, "recipient": last_pair.payer_transfer.balance_proof.sender},
    )
    assert last_pair.payer_state == "payer_secret_revealed"

    events = mediator.events_for_secretreveal(
        setup.transfers_pair, our_address, pseudo_random_generator
    )

    # the payee from the first_pair did not send a secret reveal message, do
    # nothing
    assert not events

    first_pair.payee_state = "payee_secret_revealed"
    events = mediator.events_for_secretreveal(
        setup.transfers_pair, UNIT_SECRET, pseudo_random_generator
    )

    assert search_for_item(
        events,
        SendSecretReveal,
        {"secret": UNIT_SECRET, "recipient": first_pair.payer_transfer.balance_proof.sender},
    )
    assert first_pair.payer_state == "payer_secret_revealed"


def test_events_for_secretreveal_secret_unknown():
    """ When the secret is not known there is nothing to do. """
    pseudo_random_generator = random.Random()

    setup = factories.make_transfers_pair(3)

    events = mediator.events_for_secretreveal(setup.transfers_pair, ADDR, pseudo_random_generator)

    assert not events


def test_events_for_secretreveal_all_states():
    """ The secret must be revealed backwards to the payer if the payee knows
    the secret.
    """
    payee_secret_known = ("payee_secret_revealed", "payee_contract_unlock", "payee_balance_proof")
    pseudo_random_generator = random.Random()

    for state in payee_secret_known:
        setup = factories.make_transfers_pair(2)

        pair = setup.transfers_pair[0]
        pair.payee_state = state

        events = mediator.events_for_secretreveal(
            setup.transfers_pair, UNIT_SECRET, pseudo_random_generator
        )

        assert search_for_item(
            events,
            SendSecretReveal,
            {"secret": UNIT_SECRET, "recipient": setup.channels.partner_address(0)},
        )


def test_events_for_balanceproof():
    """ Test the simple case where the last hop has learned the secret and sent
    it to the mediator node.
    """
    pseudo_random_generator = random.Random()

    setup = factories.make_transfers_pair(2, amount=UNIT_TRANSFER_AMOUNT, block_number=1)
    last_pair = setup.transfers_pair[-1]
    last_pair.payee_state = "payee_secret_revealed"

    # the lock is not in the danger zone yet
    payer_channel = mediator.get_payer_channel(setup.channel_map, last_pair)
    payee_channel = mediator.get_payee_channel(setup.channel_map, last_pair)
    safe_block = last_pair.payee_transfer.lock.expiration - payer_channel.reveal_timeout - 1

    prng_copy = deepcopy(pseudo_random_generator)
    msg_identifier = message_identifier_from_prng(prng_copy)

    events = mediator.events_for_balanceproof(
        setup.channel_map,
        setup.transfers_pair,
        pseudo_random_generator,
        safe_block,
        UNIT_SECRET,
        UNIT_SECRETHASH,
    )

    assert search_for_item(
        events,
        EventUnlockSuccess,
        {"identifier": UNIT_TRANSFER_IDENTIFIER, "secrethash": UNIT_SECRETHASH},
    )
    assert search_for_item(
        events,
        SendBalanceProof,
        {
            "recipient": last_pair.payee_address,
            "message_identifier": msg_identifier,
            "payment_identifier": UNIT_TRANSFER_IDENTIFIER,
            "queue_identifier": {
                "recipient": last_pair.payee_address,
                "canonical_identifier": {
                    "chain_identifier": UNIT_CHAIN_ID,
                    "token_network_address": UNIT_TOKEN_NETWORK_ADDRESS,
                    "channel_identifier": payee_channel.identifier,
                },
            },
            "secret": UNIT_SECRET,
            "balance_proof": {
                "nonce": 2,
                "transferred_amount": UNIT_TRANSFER_AMOUNT,
                "locked_amount": 0,
                # 'locksroot':  ignored here
                "token_network_address": UNIT_TOKEN_NETWORK_ADDRESS,
                "channel_identifier": payee_channel.identifier,
                "chain_id": UNIT_CHAIN_ID,
            },
        },
    )
    assert last_pair.payee_state == "payee_balance_proof"


def test_events_for_balanceproof_channel_closed():
    """ Balance proofs are useless if the channel is closed/settled. The payee
    needs to go on-chain and use the latest known balance proof which includes
    this lock in the locksroot.
    """
    pseudo_random_generator = random.Random()

    for invalid_state in (ChannelState.STATE_CLOSED, ChannelState.STATE_SETTLED):
        setup = factories.make_transfers_pair(2)
        last_pair = setup.transfers_pair[-1]
        last_channel = mediator.get_payee_channel(setup.channel_map, last_pair)

        if invalid_state == ChannelState.STATE_CLOSED:
            channel.set_closed(last_channel, setup.block_number)
        else:
            channel.set_settled(last_channel, setup.block_number)

        last_pair.payee_state = "payee_secret_revealed"
        events = mediator.events_for_balanceproof(
            setup.channel_map,
            setup.transfers_pair,
            pseudo_random_generator,
            setup.block_number,
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
    pseudo_random_generator = random.Random()

    setup = factories.make_transfers_pair(4, block_number=1)
    middle_pair = setup.transfers_pair[1]
    middle_pair.payee_state = "payee_secret_revealed"

    events = mediator.events_for_balanceproof(
        setup.channel_map,
        setup.transfers_pair,
        pseudo_random_generator,
        setup.block_number,
        UNIT_SECRET,
        UNIT_SECRETHASH,
    )

    assert search_for_item(events, SendBalanceProof, {"recipient": middle_pair.payee_address})
    assert search_for_item(events, EventUnlockSuccess, {})
    assert middle_pair.payee_state == "payee_balance_proof"


def test_events_for_balanceproof_secret_unknown():
    """ Nothing to do if the secret is not known. """
    pseudo_random_generator = random.Random()
    setup = factories.make_transfers_pair(3, block_number=1)

    # the secret is not known, so no event should be used
    events = mediator.events_for_balanceproof(
        setup.channel_map,
        setup.transfers_pair,
        pseudo_random_generator,
        setup.block_number,
        UNIT_SECRET,
        UNIT_SECRETHASH,
    )
    assert not events


def test_events_for_balanceproof_lock_expired():
    """ The balance proof should not be sent if the lock has expired. """
    pseudo_random_generator = random.Random()
    setup = factories.make_transfers_pair(4, block_number=1)
    last_pair = setup.transfers_pair[-1]
    last_pair.payee_state = "payee_secret_revealed"

    block_number = last_pair.payee_transfer.lock.expiration + 1

    # the lock has expired, do not send a balance proof
    events = mediator.events_for_balanceproof(
        setup.channel_map,
        setup.transfers_pair,
        pseudo_random_generator,
        block_number,
        UNIT_SECRET,
        UNIT_SECRETHASH,
    )
    assert not events

    middle_pair = setup.transfers_pair[-2]
    middle_pair.payee_state = "payee_secret_revealed"

    # The channel doesn't need to be closed to do a on-chain unlock, therefor
    # it's not required to send a balance proof to the payee if the lock is
    # near expiration
    events = mediator.events_for_balanceproof(
        setup.channel_map,
        setup.transfers_pair,
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
    setup = factories.make_transfers_pair(2, block_number=1)
    pair = setup.transfers_pair[0]

    channel_state = mediator.get_payer_channel(setup.channel_map, pair)
    # Reveal the secret off-chain
    for channel_state in setup.channel_map.values():
        channel.register_offchain_secret(channel_state, UNIT_SECRET, UNIT_SECRETHASH)

    block_number = pair.payer_transfer.lock.expiration - channel_state.reveal_timeout

    # If we are not in the unsafe region, we must NOT emit ContractSendSecretReveal
    events = mediator.events_for_onchain_secretreveal_if_dangerzone(
        channelmap=setup.channel_map,
        secrethash=UNIT_SECRETHASH,
        transfers_pair=setup.transfers_pair,
        block_number=block_number - 1,
        block_hash=factories.make_block_hash(),
    )
    assert not events

    # If we are in the unsafe region, we must emit ContractSendSecretReveal
    events = mediator.events_for_onchain_secretreveal_if_dangerzone(
        channelmap=setup.channel_map,
        secrethash=UNIT_SECRETHASH,
        transfers_pair=setup.transfers_pair,
        block_number=block_number,
        block_hash=factories.make_block_hash(),
    )

    assert search_for_item(events, ContractSendSecretReveal, {"secret": UNIT_SECRET})


def test_events_for_onchain_secretreveal_once():
    """ Secret must be registered on-chain only once. """
    setup = factories.make_transfers_pair(4, block_number=1)
    pair = setup.transfers_pair[0]
    channel_state = mediator.get_payer_channel(setup.channel_map, pair)

    for channel_state in setup.channel_map.values():
        channel.register_offchain_secret(channel_state, UNIT_SECRET, UNIT_SECRETHASH)

    start_danger_zone_block_number = (
        pair.payer_transfer.lock.expiration - channel_state.reveal_timeout
    )

    events = mediator.events_for_onchain_secretreveal_if_dangerzone(
        channelmap=setup.channel_map,
        secrethash=UNIT_SECRETHASH,
        transfers_pair=setup.transfers_pair,
        block_number=start_danger_zone_block_number,
        block_hash=factories.make_block_hash(),
    )
    assert len(events) == 1

    for pair in setup.transfers_pair:
        assert pair.payer_state == "payer_waiting_secret_reveal"

    end_danger_zone_block_number = pair.payer_transfer.lock.expiration - 1

    events = mediator.events_for_onchain_secretreveal_if_dangerzone(
        channelmap=setup.channel_map,
        secrethash=UNIT_SECRETHASH,
        transfers_pair=setup.transfers_pair,
        block_number=end_danger_zone_block_number,
        block_hash=factories.make_block_hash(),
    )
    assert not events

    for pair in setup.transfers_pair:
        assert pair.payer_state == "payer_waiting_secret_reveal"

    events = mediator.events_for_onchain_secretreveal_if_dangerzone(
        channelmap=setup.channel_map,
        secrethash=UNIT_SECRETHASH,
        transfers_pair=setup.transfers_pair,
        block_number=pair.payer_transfer.lock.expiration,
        block_hash=factories.make_block_hash(),
    )
    assert not events

    for pair in setup.transfers_pair:
        assert pair.payer_state == "payer_waiting_secret_reveal"


def secret_learned_setup():
    pseudo_random_generator = random.Random()
    channels = mediator_make_channel_pair()
    from_transfer = factories.make_signed_transfer_for(channels[0])

    nodeaddresses_to_networkstates = factories.make_node_availability_map([UNIT_TRANSFER_TARGET])
    iteration = mediator.state_transition(
        mediator_state=None,
        state_change=mediator_make_init_action(channels, from_transfer),
        channelidentifiers_to_channels=channels.channel_map,
        nodeaddresses_to_networkstates=nodeaddresses_to_networkstates,
        pseudo_random_generator=pseudo_random_generator,
        block_number=1,
        block_hash=factories.make_block_hash(),
    )

    return pseudo_random_generator, channels, from_transfer, iteration


def test_secret_learned():
    pseudo_random_generator, channels, from_transfer, iteration = secret_learned_setup()

    iteration = mediator.secret_learned(
        state=iteration.new_state,
        channelidentifiers_to_channels=channels.channel_map,
        pseudo_random_generator=pseudo_random_generator,
        block_number=1,
        block_hash=factories.make_block_hash(),
        secret=UNIT_SECRET,
        secrethash=UNIT_SECRETHASH,
        payee_address=channels[1].partner_state.address,
    )
    transfer_pair = iteration.new_state.transfers_pair[0]

    assert from_transfer.lock.expiration == transfer_pair.payee_transfer.lock.expiration
    assert mediator.is_send_transfer_almost_equal(
        get_payee_channel(channels.channel_map, transfer_pair),
        transfer_pair.payee_transfer,
        from_transfer,
    )
    assert transfer_pair.payee_address == channels.get_hop(1).node_address

    assert transfer_pair.payer_transfer.balance_proof.sender == channels.get_hop(0).node_address
    assert transfer_pair.payer_transfer == from_transfer

    assert iteration.new_state.secret == UNIT_SECRET

    assert transfer_pair.payee_state == "payee_balance_proof"
    assert transfer_pair.payer_state == "payer_secret_revealed"

    assert search_for_item(iteration.events, SendSecretReveal, {})
    assert search_for_item(iteration.events, SendBalanceProof, {})


def test_secret_learned_with_refund():
    hop5 = factories.make_address()
    #                                             /-> hop3
    # Emulate HOP2(Initiator) -> HOP1 (This node)
    #                                             \-> hop4 -> hop5
    setup = factories.make_transfers_pair(3, block_number=1)
    channel_map, transfers_pair = setup.channel_map, setup.transfers_pair

    # Make sure that our state is updated once transfers are sent.
    assert channel.is_lock_locked(setup.channels[1].our_state, UNIT_SECRETHASH)
    assert channel.is_lock_locked(setup.channels[2].our_state, UNIT_SECRETHASH)

    mediator_state = MediatorTransferState(secrethash=UNIT_SECRETHASH, routes=[])
    mediator_state.transfers_pair = transfers_pair

    nodeaddresses_to_networkstates = factories.make_node_availability_map(
        [setup.channels.ADDRESSES]
    )

    # Emulate a ReceiveSecretReveal state transition_result
    # Which means that hop5 sent a SecretReveal -> hop4 -> HOP1 (Us)
    transition_result = mediator.state_transition(
        mediator_state=mediator_state,
        state_change=ReceiveSecretReveal(secret=UNIT_SECRET, sender=hop5),
        channelidentifiers_to_channels=channel_map,
        nodeaddresses_to_networkstates=nodeaddresses_to_networkstates,
        pseudo_random_generator=random.Random(),
        block_number=5,
        block_hash=factories.make_block_hash(),
    )

    assert not transition_result.events
    assert mediator_state.secret == UNIT_SECRET

    assert channel.is_secret_known(setup.channels[0].partner_state, UNIT_SECRETHASH)
    assert channel.is_secret_known(setup.channels[1].partner_state, UNIT_SECRETHASH)
    assert channel.is_secret_known(setup.channels[1].our_state, UNIT_SECRETHASH)
    assert channel.is_secret_known(setup.channels[2].our_state, UNIT_SECRETHASH)


def test_secret_learned_for_closed_channel():
    pseudo_random_generator, channels, _, iteration = secret_learned_setup()
    close_transaction = factories.create(factories.TransactionExecutionStatusProperties())
    channels[0].close_transaction = close_transaction

    iteration = mediator.secret_learned(
        state=iteration.new_state,
        channelidentifiers_to_channels=channels.channel_map,
        pseudo_random_generator=pseudo_random_generator,
        block_number=1,
        block_hash=factories.make_block_hash(),
        secret=UNIT_SECRET,
        secrethash=UNIT_SECRETHASH,
        payee_address=channels[1].partner_state.address,
    )
    assert search_for_item(iteration.events, ContractSendSecretReveal, {"secret": UNIT_SECRET})


def test_mediate_transfer():
    block_number = 5
    pseudo_random_generator = random.Random()

    channels = mediator_make_channel_pair()
    payer_transfer = factories.make_signed_transfer_for(
        channels[0], LockedTransferSignedStateProperties(expiration=30)
    )

    route_states = channels.get_routes(1)
    mediator_state = MediatorTransferState(secrethash=UNIT_SECRETHASH, routes=route_states)

    iteration = mediator.mediate_transfer(
        state=mediator_state,
        candidate_route_states=route_states,
        payer_channel=channels[0],
        channelidentifiers_to_channels=channels.channel_map,
        nodeaddresses_to_networkstates=channels.nodeaddresses_to_networkstates,
        pseudo_random_generator=pseudo_random_generator,
        payer_transfer=payer_transfer,
        block_number=block_number,
    )

    item = search_for_item(
        iteration.events,
        SendLockedTransfer,
        {
            "recipient": channels[1].partner_state.address,
            "transfer": {
                "payment_identifier": payer_transfer.payment_identifier,
                "token": payer_transfer.token,
                "lock": {
                    "amount": payer_transfer.lock.amount,
                    "secrethash": payer_transfer.lock.secrethash,
                    "expiration": payer_transfer.lock.expiration,
                },
                "target": payer_transfer.target,
            },
        },
    )

    assert item is not None


def test_init_mediator():
    channels = mediator_make_channel_pair()
    from_transfer = factories.make_signed_transfer_for(channels[0])

    iteration = mediator.state_transition(
        mediator_state=None,
        state_change=mediator_make_init_action(channels, from_transfer),
        channelidentifiers_to_channels=channels.channel_map,
        nodeaddresses_to_networkstates=channels.nodeaddresses_to_networkstates,
        pseudo_random_generator=random.Random(),
        block_number=1,
        block_hash=factories.make_block_hash(),
    )

    assert isinstance(iteration.new_state, MediatorTransferState)
    assert iteration.new_state.transfers_pair[0].payer_transfer == from_transfer
    assert search_for_item(
        iteration.events,
        SendLockedTransfer,
        {
            "transfer": {
                "token": from_transfer.token,
                "lock": {
                    "amount": from_transfer.lock.amount,
                    "expiration": from_transfer.lock.expiration,
                    "secrethash": from_transfer.lock.secrethash,
                },
            }
        },
    ), "mediated_transfer should /not/ split the transfer"


def test_mediator_accept_sha256_empty_hash():
    channels = mediator_make_channel_pair()
    from_transfer = factories.make_signed_transfer_for(
        channels[0],
        LockedTransferSignedStateProperties(initiator=HOP1, secret=EMPTY_HASH),
        allow_invalid=True,
    )

    iteration = mediator.state_transition(
        mediator_state=None,
        state_change=mediator_make_init_action(channels, from_transfer),
        channelidentifiers_to_channels=channels.channel_map,
        nodeaddresses_to_networkstates=channels.nodeaddresses_to_networkstates,
        pseudo_random_generator=random.Random(),
        block_number=1,
        block_hash=factories.make_block_hash(),
    )

    assert iteration.new_state


def test_mediator_secret_reveal_empty_hash():
    pseudo_random_generator = random.Random()

    channels = mediator_make_channel_pair()
    from_transfer = factories.make_signed_transfer_for(
        channels[0], LockedTransferSignedStateProperties(initiator=HOP1)
    )

    block_number = 1
    iteration = mediator.state_transition(
        mediator_state=None,
        state_change=mediator_make_init_action(channels, from_transfer),
        channelidentifiers_to_channels=channels.channel_map,
        nodeaddresses_to_networkstates=channels.nodeaddresses_to_networkstates,
        pseudo_random_generator=pseudo_random_generator,
        block_number=1,
        block_hash=factories.make_block_hash(),
    )
    assert isinstance(iteration.new_state, MediatorTransferState)
    assert iteration.new_state.transfers_pair[0].payer_transfer == from_transfer
    current_state = iteration.new_state

    # an empty hash should be rejected because it's not the transfer's secret
    receive_secret = ReceiveSecretReveal(EMPTY_HASH, UNIT_TRANSFER_TARGET)
    iteration = mediator.state_transition(
        mediator_state=current_state,
        state_change=receive_secret,
        channelidentifiers_to_channels=channels.channel_map,
        nodeaddresses_to_networkstates=channels.nodeaddresses_to_networkstates,
        pseudo_random_generator=pseudo_random_generator,
        block_number=2,
        block_hash=factories.make_block_hash(),
    )
    assert len(iteration.events) == 0

    # an empty hash onchain secret reveal should be rejected because it's not the transfer's secret
    secrethash = EMPTY_SECRET_SHA256
    onchain_reveal = ContractReceiveSecretReveal(
        transaction_hash=factories.make_address(),
        secret_registry_address=factories.make_address(),
        secrethash=secrethash,
        secret=EMPTY_SECRET,
        block_number=block_number,
        block_hash=factories.make_block_hash(),
    )
    iteration = mediator.state_transition(
        mediator_state=current_state,
        state_change=onchain_reveal,
        channelidentifiers_to_channels=channels.channel_map,
        nodeaddresses_to_networkstates=channels.nodeaddresses_to_networkstates,
        pseudo_random_generator=pseudo_random_generator,
        block_number=2,
        block_hash=factories.make_block_hash(),
    )
    assert secrethash not in channels[0].partner_state.secrethashes_to_onchain_unlockedlocks


def test_no_valid_routes():
    channels = make_channel_set(
        [
            NettingChannelStateProperties(
                canonical_identifier=make_canonical_identifier(channel_identifier=1),
                partner_state=NettingChannelEndStateProperties(
                    balance=UNIT_TRANSFER_AMOUNT, address=UNIT_TRANSFER_SENDER
                ),
            ),
            NettingChannelStateProperties(
                make_canonical_identifier(channel_identifier=2),
                our_state=NettingChannelEndStateProperties(balance=UNIT_TRANSFER_AMOUNT - 1),
            ),
            NettingChannelStateProperties(
                make_canonical_identifier(channel_identifier=3),
                our_state=NettingChannelEndStateProperties(balance=0),
            ),
        ]
    )
    from_transfer = factories.make_signed_transfer_for(
        channels[0], LockedTransferSignedStateProperties(initiator=HOP1)
    )

    state_change = mediator_make_init_action(channels, from_transfer)

    iteration = mediator.state_transition(
        mediator_state=None,
        state_change=state_change,
        channelidentifiers_to_channels=channels.channel_map,
        nodeaddresses_to_networkstates=channels.nodeaddresses_to_networkstates,
        pseudo_random_generator=random.Random(),
        block_number=1,
        block_hash=factories.make_block_hash(),
    )
    msg = (
        "The task must be kept alive, "
        "either to handle future available routes, or lock expired messages"
    )
    assert iteration.new_state is not None, msg
    assert search_for_item(iteration.events, SendRefundTransfer, {})


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
    channel_defaults = create_properties(
        NettingChannelStateProperties(reveal_timeout=5, settle_timeout=10)
    )

    channels = mediator_make_channel_pair(defaults=channel_defaults)
    from_transfer = factories.make_signed_transfer_for(
        channels[0],
        LockedTransferSignedStateProperties(initiator=HOP1, expiration=high_expiration),
        allow_invalid=True,
    )

    # Assert the precondition for the test. The message is still valid, and the
    # recipient cannot control the received lock expiration
    assert from_transfer.lock.expiration >= channels[0].settle_timeout

    iteration = mediator.state_transition(
        mediator_state=None,
        state_change=mediator_make_init_action(channels, from_transfer),
        channelidentifiers_to_channels=channels.channel_map,
        nodeaddresses_to_networkstates=channels.nodeaddresses_to_networkstates,
        pseudo_random_generator=random.Random(),
        block_number=1,
        block_hash=factories.make_block_hash(),
    )

    msg = (
        "The transfer must not be forwarded because the lock timeout is "
        "larger then the settlement timeout"
    )
    assert not search_for_item(iteration.events, SendLockedTransfer, {}), msg


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
    our_state = factories.NettingChannelEndStateProperties(balance=amount)
    partner_state = replace(our_state, address=UNIT_TRANSFER_SENDER)

    attacked_channel = factories.create(
        factories.NettingChannelStateProperties(our_state=our_state)
    )
    # pylint: disable=E1101
    target_attacker2 = attacked_channel.partner_state.address

    bc_channel = factories.create(
        factories.NettingChannelStateProperties(our_state=our_state, partner_state=partner_state)
    )
    from_hop = factories.make_hop_from_channel(bc_channel)

    from_transfer = factories.make_signed_transfer_for(
        bc_channel,
        LockedTransferSignedStateProperties(
            initiator=HOP1,
            target=target_attacker2,
            canonical_identifier=factories.make_canonical_identifier(
                token_network_address=bc_channel.token_network_address
            ),
        ),
    )

    channel_map = {
        bc_channel.identifier: bc_channel,
        attacked_channel.identifier: attacked_channel,
    }

    init_state_change = ActionInitMediator(
        route_states=[
            RouteState(
                route=[our_state.address, attacked_channel.partner_state.address],
                forward_channel_id=attacked_channel.canonical_identifier.channel_identifier,
            )
        ],
        from_hop=from_hop,
        from_transfer=from_transfer,
        balance_proof=from_transfer.balance_proof,
        sender=from_transfer.balance_proof.sender,
    )

    nodeaddresses_to_networkstates = {UNIT_TRANSFER_TARGET: NetworkState.REACHABLE}

    iteration = mediator.state_transition(
        mediator_state=None,
        state_change=init_state_change,
        channelidentifiers_to_channels=channel_map,
        nodeaddresses_to_networkstates=nodeaddresses_to_networkstates,
        pseudo_random_generator=pseudo_random_generator,
        block_number=block_number,
        block_hash=factories.make_block_hash(),
    )

    attack_block_number = from_transfer.lock.expiration - attacked_channel.reveal_timeout
    is_safe = mediator.is_safe_to_wait(
        from_transfer.lock.expiration, attacked_channel.reveal_timeout, attack_block_number
    )
    assert is_safe.fail

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
            nodeaddresses_to_networkstates=nodeaddresses_to_networkstates,
            pseudo_random_generator=pseudo_random_generator,
            block_number=new_block_number,
            block_hash=factories.make_block_hash(),
        )

        assert not any(
            event for event in new_iteration.events if not isinstance(event, EventUnlockFailed)
        )

    # and reveal the secret
    receive_secret = ReceiveSecretReveal(UNIT_SECRET, target_attacker2)
    attack_iteration = mediator.state_transition(
        mediator_state=new_iteration.new_state,
        state_change=receive_secret,
        channelidentifiers_to_channels=channel_map,
        nodeaddresses_to_networkstates=nodeaddresses_to_networkstates,
        pseudo_random_generator=pseudo_random_generator,
        block_number=attack_block_number,
        block_hash=factories.make_block_hash(),
    )
    assert not any(
        isinstance(event, ContractSendChannelClose) for event in attack_iteration.events
    )

    # don't go on-chain since the balance proof was not received
    for new_block_number in range(block_number, from_transfer.lock.expiration + 1):
        new_block_hash = factories.make_block_hash()
        block = Block(block_number=new_block_number, gas_limit=1, block_hash=new_block_hash)
        new_iteration = mediator.state_transition(
            mediator_state=new_iteration.new_state,
            state_change=block,
            channelidentifiers_to_channels=channel_map,
            nodeaddresses_to_networkstates=nodeaddresses_to_networkstates,
            pseudo_random_generator=pseudo_random_generator,
            block_number=new_block_number,
            block_hash=new_block_hash,
        )
        assert not any(
            event
            for event in new_iteration.events
            if not isinstance(event, (EventUnlockFailed, ContractSendSecretReveal))
        )


@pytest.mark.xfail(reason="Not implemented. Issue: #382")
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
    payer_transfer = factories.make_signed_transfer_for(
        channels[0], LockedTransferSignedStateProperties(expiration=30)
    )

    mediator_state = MediatorTransferState(UNIT_SECRETHASH, channels.get_routes())
    iteration = mediator.mediate_transfer(
        mediator_state,
        channels.get_routes(1),
        channels[0],
        channels.channel_map,
        channels.nodeaddresses_to_networkstates,
        pseudo_random_generator,
        payer_transfer,
        block_number,
    )

    assert search_for_item(
        iteration.events,
        SendLockedTransfer,
        {"transfer": {"lock": {"expiration": payer_transfer.lock.expiration}}},
    )


def test_set_offchain_secret():
    mediator_state = MediatorTransferState(UNIT_SECRETHASH, [])

    assert mediator_state.transfers_pair == list()
    assert mediator_state.secret is None
    assert mediator_state.secrethash == UNIT_SECRETHASH

    setup = factories.make_transfers_pair(2, block_number=1)
    channel_map = setup.channel_map
    transfers_pair = setup.transfers_pair
    mediator_state.transfers_pair = transfers_pair

    payee_channel = mediator.get_payee_channel(channel_map, transfers_pair[0])
    payer_channel = mediator.get_payer_channel(channel_map, transfers_pair[0])

    assert payer_channel.our_state.secrethashes_to_lockedlocks == dict()
    assert payer_channel.our_state.secrethashes_to_unlockedlocks == dict()

    assert UNIT_SECRETHASH in payer_channel.partner_state.secrethashes_to_lockedlocks.keys()
    assert payer_channel.partner_state.secrethashes_to_unlockedlocks == dict()

    assert UNIT_SECRETHASH in payee_channel.our_state.secrethashes_to_lockedlocks.keys()
    assert payee_channel.our_state.secrethashes_to_unlockedlocks == dict()

    assert payee_channel.partner_state.secrethashes_to_lockedlocks == dict()
    assert payee_channel.partner_state.secrethashes_to_unlockedlocks == dict()

    set_offchain_secret(mediator_state, channel_map, UNIT_SECRET, UNIT_SECRETHASH)

    assert mediator_state.secret == UNIT_SECRET

    assert payer_channel.our_state.secrethashes_to_lockedlocks == dict()
    assert payer_channel.our_state.secrethashes_to_unlockedlocks == dict()

    assert payer_channel.partner_state.secrethashes_to_lockedlocks == dict()
    assert UNIT_SECRETHASH in payer_channel.partner_state.secrethashes_to_unlockedlocks.keys()

    assert payee_channel.our_state.secrethashes_to_lockedlocks == dict()
    assert UNIT_SECRETHASH in payee_channel.our_state.secrethashes_to_unlockedlocks.keys()

    assert payee_channel.partner_state.secrethashes_to_lockedlocks == dict()
    assert payee_channel.partner_state.secrethashes_to_unlockedlocks == dict()


def test_mediate_transfer_with_maximum_pending_transfers_exceeded():
    pseudo_random_generator = random.Random()

    balance = 2 * MAXIMUM_PENDING_TRANSFERS * UNIT_TRANSFER_AMOUNT
    channels = make_channel_set(
        [
            NettingChannelStateProperties(
                make_canonical_identifier(channel_identifier=1),
                our_state=NettingChannelEndStateProperties.OUR_STATE,
                partner_state=NettingChannelEndStateProperties(
                    balance=balance, address=UNIT_TRANSFER_SENDER
                ),
            ),
            NettingChannelStateProperties(
                make_canonical_identifier(channel_identifier=2),
                our_state=replace(NettingChannelEndStateProperties.OUR_STATE, balance=balance),
            ),
        ]
    )

    iterations = []
    for index in range(1, MAXIMUM_PENDING_TRANSFERS + 2):
        from_transfer = factories.make_signed_transfer_for(
            channels[0],
            LockedTransferSignedStateProperties(
                initiator=HOP1,
                expiration=UNIT_SETTLE_TIMEOUT,
                secret=random_secret(),
                payment_identifier=index,
                nonce=index,
                locked_amount=index * UNIT_TRANSFER_AMOUNT,
                canonical_identifier=factories.make_canonical_identifier(channel_identifier=2),
                transferred_amount=0,
                message_identifier=index,
                routes=[[factories.UNIT_OUR_ADDRESS, channels.channels[1].partner_state.address]],
            ),
            calculate_locksroot=True,
            allow_invalid=True,
            only_transfer=False,
        )

        iterations.append(
            mediator.state_transition(
                mediator_state=None,
                state_change=mediator_make_init_action(channels, from_transfer),
                channelidentifiers_to_channels=channels.channel_map,
                nodeaddresses_to_networkstates=channels.nodeaddresses_to_networkstates,
                pseudo_random_generator=pseudo_random_generator,
                block_number=1,
                block_hash=factories.make_block_hash(),
            )
        )

    # last iteration should have failed due to exceeded pending transfer limit
    failed_iteration = iterations.pop()
    assert failed_iteration.new_state is None
    assert search_for_item(
        failed_iteration.events,
        EventInvalidReceivedLockedTransfer,
        {
            "payment_identifier": MAXIMUM_PENDING_TRANSFERS + 1,
            "reason": (
                "Invalid LockedTransfer message. Adding the transfer would "
                "exceed the allowed limit of 160 pending transfers per channel."
            ),
        },
    )

    assert all(isinstance(iteration.new_state, MediatorTransferState) for iteration in iterations)


def test_mediator_lock_expired_with_new_block():
    block_number = 5
    pseudo_random_generator = random.Random()

    channels = mediator_make_channel_pair()

    payer_transfer = factories.make_signed_transfer_for(
        channels[0], LockedTransferSignedStateProperties(initiator=HOP1, expiration=30)
    )

    mediator_state = MediatorTransferState(UNIT_SECRETHASH, channels.get_routes())
    iteration = mediator.mediate_transfer(
        state=mediator_state,
        candidate_route_states=channels.get_routes(0),
        payer_channel=channels[0],
        channelidentifiers_to_channels=channels.channel_map,
        nodeaddresses_to_networkstates=channels.nodeaddresses_to_networkstates,
        pseudo_random_generator=pseudo_random_generator,
        payer_transfer=payer_transfer,
        block_number=block_number,
    )
    assert len(iteration.events) == 1

    send_transfer = search_for_item(iteration.events, SendLockedTransfer, {})
    assert send_transfer

    transfer = send_transfer.transfer

    block_expiration_number = channel.get_sender_expiration_threshold(transfer.lock.expiration)
    block_expiration_hash = factories.make_block_hash()
    block = Block(
        block_number=block_expiration_number, gas_limit=1, block_hash=block_expiration_hash
    )
    iteration = mediator.state_transition(
        mediator_state=mediator_state,
        state_change=block,
        channelidentifiers_to_channels=channels.channel_map,
        nodeaddresses_to_networkstates=channels.nodeaddresses_to_networkstates,
        pseudo_random_generator=pseudo_random_generator,
        block_number=block_expiration_number,
        block_hash=block_expiration_hash,
    )

    assert iteration.events
    assert search_for_item(
        iteration.events, SendLockExpired, {"secrethash": transfer.lock.secrethash}
    )
    assert search_for_item(
        iteration.events, EventUnlockFailed, {"secrethash": transfer.lock.secrethash}
    )
    assert transfer.lock.secrethash not in channels[1].our_state.secrethashes_to_lockedlocks


def test_mediator_must_not_send_lock_expired_when_channel_is_closed():
    block_number = 5
    block_hash = factories.make_block_hash()
    pseudo_random_generator = random.Random()

    channels = mediator_make_channel_pair()
    payer_channel_state = channels[0]
    payee_channel_state = channels[1]

    payer_transfer = factories.make_signed_transfer_for(
        payer_channel_state, LockedTransferSignedStateProperties(initiator=HOP1, expiration=30)
    )

    mediator_state = MediatorTransferState(UNIT_SECRETHASH, channels.get_routes())
    iteration = mediator.mediate_transfer(
        state=mediator_state,
        candidate_route_states=channels.get_routes(1),
        payer_channel=channels[0],
        channelidentifiers_to_channels=channels.channel_map,
        nodeaddresses_to_networkstates=channels.nodeaddresses_to_networkstates,
        pseudo_random_generator=pseudo_random_generator,
        payer_transfer=payer_transfer,
        block_number=block_number,
    )

    send_transfer = search_for_item(iteration.events, SendLockedTransfer, {})
    transfer = send_transfer.transfer

    channel_closed = ContractReceiveChannelClosed(
        transaction_hash=factories.make_transaction_hash(),
        transaction_from=factories.make_address(),
        canonical_identifier=payee_channel_state.canonical_identifier,
        block_number=block_number,
        block_hash=block_hash,
    )
    channel_close_transition = channel.state_transition(
        channel_state=payee_channel_state,
        state_change=channel_closed,
        block_number=block_number,
        block_hash=block_hash,
        pseudo_random_generator=pseudo_random_generator,
    )
    payee_channel_state = channel_close_transition.new_state

    block_expiration_number = channel.get_sender_expiration_threshold(transfer.lock.expiration)
    block_expiration_hash = factories.make_transaction_hash()
    block = Block(
        block_number=block_expiration_number, gas_limit=1, block_hash=block_expiration_hash
    )

    iteration = mediator.state_transition(
        mediator_state=mediator_state,
        state_change=block,
        channelidentifiers_to_channels=channels.channel_map,
        nodeaddresses_to_networkstates=channels.nodeaddresses_to_networkstates,
        pseudo_random_generator=pseudo_random_generator,
        block_number=block_expiration_number,
        block_hash=block_expiration_hash,
    )

    assert iteration.events
    assert search_for_item(iteration.events, SendLockExpired, {}) is None


def setup():
    channels = mediator_make_channel_pair()
    expiration = 30
    transfer_properties = LockedTransferSignedStateProperties(expiration=expiration)
    transfer = factories.make_signed_transfer_for(channels[0], transfer_properties)

    balance_proof = create(
        BalanceProofSignedStateProperties(
            nonce=2,
            # pylint: disable=no-member
            transferred_amount=transfer.balance_proof.transferred_amount,
            canonical_identifier=channels[0].canonical_identifier,
            message_hash=transfer.lock.secrethash,
        )
    )

    return channels, transfer, balance_proof, expiration


def test_mediator_lock_expired_with_receive_lock_expired():
    pseudo_random_generator = random.Random()

    channels, transfer, balance_proof, expiration = setup()

    iteration = mediator.state_transition(
        mediator_state=None,
        state_change=mediator_make_init_action(channels, transfer),
        channelidentifiers_to_channels=channels.channel_map,
        nodeaddresses_to_networkstates=channels.nodeaddresses_to_networkstates,
        pseudo_random_generator=pseudo_random_generator,
        block_number=5,
        block_hash=factories.make_block_hash(),
    )

    assert search_for_item(
        iteration.events,
        SendLockedTransfer,
        {
            "recipient": UNIT_TRANSFER_TARGET,
            "transfer": {
                "lock": {
                    "amount": UNIT_TRANSFER_AMOUNT,
                    "expiration": expiration,
                    "secrethash": transfer.lock.secrethash,
                },
                "balance_proof": {
                    "nonce": 1,
                    "transferred_amount": 0,
                    "locked_amount": UNIT_TRANSFER_AMOUNT,
                    # pylint: disable=no-member
                    "locksroot": transfer.balance_proof.locksroot,
                },
            },
        },
    )

    lock_expired_state_change = ReceiveLockExpired(
        balance_proof=balance_proof,
        secrethash=transfer.lock.secrethash,
        message_identifier=1,
        sender=balance_proof.sender,
    )

    block_before_confirmed_expiration = expiration + DEFAULT_NUMBER_OF_BLOCK_CONFIRMATIONS - 1
    iteration = mediator.state_transition(
        mediator_state=iteration.new_state,
        state_change=lock_expired_state_change,
        channelidentifiers_to_channels=channels.channel_map,
        nodeaddresses_to_networkstates=channels.nodeaddresses_to_networkstates,
        pseudo_random_generator=pseudo_random_generator,
        block_number=block_before_confirmed_expiration,
        block_hash=factories.make_block_hash(),
    )
    assert not search_for_item(iteration.events, SendProcessed, {})

    block_lock_expired = block_before_confirmed_expiration + 1
    iteration = mediator.state_transition(
        mediator_state=iteration.new_state,
        state_change=lock_expired_state_change,
        channelidentifiers_to_channels=channels.channel_map,
        nodeaddresses_to_networkstates=channels.nodeaddresses_to_networkstates,
        pseudo_random_generator=pseudo_random_generator,
        block_number=block_lock_expired,
        block_hash=factories.make_block_hash(),
    )
    assert search_for_item(iteration.events, SendProcessed, {})

    assert iteration.new_state
    assert iteration.new_state.transfers_pair[0].payer_state == "payer_expired"
    assert iteration.new_state.transfers_pair[0].payee_state == "payee_pending"


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
    pseudo_random_generator = random.Random()
    channels, transfer, balance_proof, expiration = setup()

    iteration = mediator.state_transition(
        mediator_state=None,
        state_change=mediator_make_init_action(channels, transfer),
        channelidentifiers_to_channels=channels.channel_map,
        nodeaddresses_to_networkstates=channels.nodeaddresses_to_networkstates,
        pseudo_random_generator=pseudo_random_generator,
        block_number=5,
        block_hash=factories.make_block_hash(),
    )

    secrethash = transfer.lock.secrethash

    block_lock_expired = expiration + DEFAULT_NUMBER_OF_BLOCK_CONFIRMATIONS

    assert secrethash in channels[0].partner_state.secrethashes_to_lockedlocks

    # Reveal secret just before the lock expires
    secret_reveal = ReceiveSecretReveal(secret=UNIT_SECRET, sender=UNIT_TRANSFER_TARGET)

    iteration = mediator.state_transition(
        mediator_state=iteration.new_state,
        state_change=secret_reveal,
        channelidentifiers_to_channels=channels.channel_map,
        nodeaddresses_to_networkstates=channels.nodeaddresses_to_networkstates,
        pseudo_random_generator=pseudo_random_generator,
        block_number=block_lock_expired,
        block_hash=factories.make_block_hash(),
    )

    # Make sure the lock was moved
    assert secrethash not in channels[0].partner_state.secrethashes_to_lockedlocks
    assert secrethash in channels[0].partner_state.secrethashes_to_unlockedlocks

    lock_expired_state_change = ReceiveLockExpired(
        sender=balance_proof.sender,
        balance_proof=balance_proof,
        secrethash=transfer.lock.secrethash,
        message_identifier=1,
    )

    iteration = mediator.state_transition(
        mediator_state=iteration.new_state,
        state_change=lock_expired_state_change,
        channelidentifiers_to_channels=channels.channel_map,
        nodeaddresses_to_networkstates=channels.nodeaddresses_to_networkstates,
        pseudo_random_generator=pseudo_random_generator,
        block_number=block_lock_expired + 1,
        block_hash=factories.make_block_hash(),
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
    transfer = factories.make_signed_transfer_for(
        channels[0], LockedTransferSignedStateProperties(expiration=30)
    )

    iteration = mediator.state_transition(
        mediator_state=None,
        state_change=mediator_make_init_action(channels, transfer),
        channelidentifiers_to_channels=channels.channel_map,
        nodeaddresses_to_networkstates=channels.nodeaddresses_to_networkstates,
        pseudo_random_generator=pseudo_random_generator,
        block_number=5,
        block_hash=factories.make_block_hash(),
    )

    secrethash = transfer.lock.secrethash

    block_lock_expired = expiration + DEFAULT_NUMBER_OF_BLOCK_CONFIRMATIONS

    assert secrethash in channels[0].partner_state.secrethashes_to_lockedlocks

    # Reveal secret just before the lock expires
    secret_reveal = ReceiveSecretReveal(secret=UNIT_SECRET, sender=UNIT_TRANSFER_TARGET)

    iteration = mediator.state_transition(
        mediator_state=iteration.new_state,
        state_change=secret_reveal,
        channelidentifiers_to_channels=channels.channel_map,
        nodeaddresses_to_networkstates=channels.nodeaddresses_to_networkstates,
        pseudo_random_generator=pseudo_random_generator,
        block_number=block_lock_expired,
        block_hash=factories.make_block_hash(),
    )

    # Mediator should NOT send balance proof
    assert search_for_item(iteration.events, SendBalanceProof, {}) is None

    # Make sure the lock was moved
    payer_channel, payee_channel = channels[0], channels[1]
    assert secrethash not in payer_channel.partner_state.secrethashes_to_lockedlocks
    assert secrethash in payer_channel.partner_state.secrethashes_to_unlockedlocks

    assert secrethash not in payee_channel.our_state.secrethashes_to_lockedlocks
    assert secrethash in payee_channel.our_state.secrethashes_to_unlockedlocks

    block_expiration_number = channel.get_sender_expiration_threshold(transfer.lock.expiration)
    block = Block(
        block_number=block_expiration_number,
        gas_limit=1,
        block_hash=factories.make_transaction_hash(),
    )

    iteration = mediator.state_transition(
        mediator_state=iteration.new_state,
        state_change=block,
        channelidentifiers_to_channels=channels.channel_map,
        nodeaddresses_to_networkstates=channels.nodeaddresses_to_networkstates,
        pseudo_random_generator=pseudo_random_generator,
        block_number=block_expiration_number,
        block_hash=factories.make_block_hash(),
    )

    assert secrethash not in channels[0].our_state.secrethashes_to_unlockedlocks
    assert search_for_item(iteration.events, SendLockExpired, {})


def test_filter_reachable_routes():
    """ Try to mediate a transfer where a node, that is part of the routes_order,
    was unreachable and became reachable before the locked transfer expired.
    Expected result is to route the transfer through this node.
    """
    target = factories.make_address()
    partner1 = factories.NettingChannelEndStateProperties(address=HOP1)
    partner2 = replace(partner1, address=HOP2)
    channel1 = factories.create(factories.NettingChannelStateProperties(partner_state=partner1))
    channel2 = factories.create(factories.NettingChannelStateProperties(partner_state=partner2))

    possible_routes = [
        RouteState(
            # pylint: disable=E1101
            route=[channel1.our_state.address, partner1.address, target],
            forward_channel_id=channel1.canonical_identifier.channel_identifier,
        ),
        RouteState(
            # pylint: disable=E1101
            route=[channel1.our_state.address, partner2.address, target],
            forward_channel_id=channel2.canonical_identifier.channel_identifier,
        ),
    ]

    # Both nodes are online
    nodeaddresses_to_networkstates = factories.make_node_availability_map([HOP1, HOP2])

    filtered_routes = routes.filter_reachable_routes(
        route_states=possible_routes, nodeaddresses_to_networkstates=nodeaddresses_to_networkstates
    )

    assert possible_routes[0] in filtered_routes
    assert possible_routes[1] in filtered_routes

    # Only HOP2 is online
    nodeaddresses_to_networkstates = factories.make_node_availability_map([HOP2])

    filtered_routes = routes.filter_reachable_routes(
        route_states=possible_routes, nodeaddresses_to_networkstates=nodeaddresses_to_networkstates
    )

    assert possible_routes[0] not in filtered_routes
    assert possible_routes[1] in filtered_routes

    # None of the route nodes are available
    nodeaddresses_to_networkstates = factories.make_node_availability_map([])

    filtered_routes = routes.filter_reachable_routes(
        route_states=possible_routes, nodeaddresses_to_networkstates=nodeaddresses_to_networkstates
    )

    assert possible_routes[0] not in filtered_routes
    assert possible_routes[1] not in filtered_routes


def test_node_change_network_state_reachable_node():
    """ Test that a mediator who has a waiting_transfer
    set (the transfer couldn't be sent forward or backward
    due to availability or capacity issues) will retry
    mediating the waiting_transfer as soon as this transfer's
    next hop becomes available.
    """
    setup = factories.make_transfers_pair(2)

    # Also add transfer sender channel
    partner_state = factories.NettingChannelEndStateProperties(address=UNIT_TRANSFER_SENDER)
    payer_channel = factories.create(
        factories.NettingChannelStateProperties(partner_state=partner_state)
    )
    setup.channels.channels.append(payer_channel)

    possible_routes = setup.channels.get_routes()

    lock_expiration = UNIT_REVEAL_TIMEOUT * 2
    received_transfer = factories.create(
        factories.LockedTransferSignedStateProperties(
            amount=1,
            expiration=lock_expiration,
            canonical_identifier=payer_channel.canonical_identifier,
        )
    )

    mediator_state = MediatorTransferState(secrethash=UNIT_SECRETHASH, routes=[])
    mediator_state.waiting_transfer = WaitingTransferState(received_transfer)
    mediator_state.routes = possible_routes

    iteration = mediator.state_transition(
        mediator_state=mediator_state,
        state_change=ActionChangeNodeNetworkState(HOP2, NetworkState.REACHABLE),
        channelidentifiers_to_channels=setup.channel_map,
        nodeaddresses_to_networkstates=setup.channels.nodeaddresses_to_networkstates,
        pseudo_random_generator=random.Random(),
        block_number=1,
        block_hash=factories.make_block_hash(),
    )

    # A LockedTransfer is expected
    assert search_for_item(
        iteration.events,
        SendLockedTransfer,
        {
            "recipient": HOP2,
            "transfer": {
                "lock": {
                    "amount": 1,
                    "expiration": UNIT_REVEAL_TIMEOUT * 2,
                    "secrethash": received_transfer.lock.secrethash,
                },
                "balance_proof": {"nonce": 1, "transferred_amount": 0, "locked_amount": 1},
            },
        },
    )


def test_node_change_network_state_unreachable_node():
    mediator_state = MediatorTransferState(secrethash=UNIT_SECRETHASH, routes=[])
    iteration = mediator.handle_node_change_network_state(
        mediator_state=mediator_state,
        state_change=ActionChangeNodeNetworkState(HOP1, NetworkState.UNREACHABLE),
        channelidentifiers_to_channels={},
        pseudo_random_generator=random.Random(),
        block_number=1,
    )

    # Nothing changed
    assert iteration.new_state == mediator_state
    # No events
    assert iteration.events == []


def _foward_transfer_pair(
    amount: TokenAmount,
    channel_in: NettingChannelStateProperties,
    channel_out: NettingChannelStateProperties,
) -> Tuple[Optional[MediationPairState], List[Event]]:
    payer_transfer = create(
        LockedTransferSignedStateProperties(
            amount=amount, initiator=HOP1, target=ADDR, expiration=BlockExpiration(50)
        )
    )

    channels = make_channel_set([channel_in, channel_out])

    pair, events = mediator.forward_transfer_pair(
        payer_transfer=payer_transfer,
        payer_channel=channels[0],
        route_state=channels.get_route(1),
        route_state_table=channels.get_routes(),
        channelidentifiers_to_channels=channels.channel_map,
        pseudo_random_generator=random.Random(),
        block_number=BlockNumber(2),
    )
    return pair, events


def test_next_transfer_pair_with_fees_deducted():
    balance = 10
    fee_in = 1
    fee_out = 2

    pair, events = _foward_transfer_pair(
        balance,
        NettingChannelStateProperties(
            our_state=NettingChannelEndStateProperties(balance=balance),
            fee_schedule=FeeScheduleState(flat=fee_in),
        ),
        NettingChannelStateProperties(
            our_state=NettingChannelEndStateProperties(balance=balance - fee_in - fee_out),
            fee_schedule=FeeScheduleState(flat=fee_out),
        ),
    )
    assert pair

    event = search_for_item(events, SendLockedTransfer, {"recipient": pair.payee_address})
    assert event.transfer.lock.amount == balance - fee_in - fee_out


def test_imbalance_penalty_at_insufficent_payer_balance():
    """
    Test that having an imbalance penalty fee during a transfer where payer has
    insufficient balance does not throw an UndefinedMediationFee exception from
    the state machine.

    Regression test for https://github.com/raiden-network/raiden/issues/4835
    """
    # imbalance_penalty result is not checked, we only verify that the calculation does not fail.
    imbalance_penalty = calculate_imbalance_fees(channel_capacity=20, proportional_imbalance_fee=1)
    pair, _ = _foward_transfer_pair(
        10,
        NettingChannelStateProperties(
            # the payer's capacity is 20 - 11 = 9
            our_state=NettingChannelEndStateProperties(balance=11),
            fee_schedule=FeeScheduleState(flat=0, imbalance_penalty=imbalance_penalty),
        ),
        NettingChannelStateProperties(
            our_state=NettingChannelEndStateProperties(balance=11),
            fee_schedule=FeeScheduleState(flat=0, imbalance_penalty=imbalance_penalty),
        ),
    )
    assert not pair


def test_imbalance_penalty_at_insufficent_mediator_balance():
    """
    Test that having an imbalance penalty fee during a transfer where mediator has
    insufficient balance does not throw an UndefinedMediationFee exception from
    the state machine.
    """
    # imbalance_penalty result is not checked, we only verify that the calculation does not fail.
    imbalance_penalty = calculate_imbalance_fees(channel_capacity=20, proportional_imbalance_fee=1)
    pair, _ = _foward_transfer_pair(
        10,
        NettingChannelStateProperties(
            our_state=NettingChannelEndStateProperties(balance=11),
            fee_schedule=FeeScheduleState(flat=0, imbalance_penalty=imbalance_penalty),
        ),
        NettingChannelStateProperties(
            our_state=NettingChannelEndStateProperties(balance=9),
            fee_schedule=FeeScheduleState(flat=0, imbalance_penalty=imbalance_penalty),
        ),
    )
    assert not pair


def test_imbalance_penalty_with_barely_sufficient_balance():
    """
    Without keeping the flat fee, the mediator's balance would be insufficient.
    This tests that the imbalance fee calculation does not fail in such a case.
    """
    # imbalance_penalty result is not checked, we only verify that the calculation does not fail.
    imbalance_penalty = calculate_imbalance_fees(channel_capacity=20, proportional_imbalance_fee=1)
    pair, _ = _foward_transfer_pair(
        10,
        NettingChannelStateProperties(
            # the payer's capacity is 20 - 9 = 11
            our_state=NettingChannelEndStateProperties(balance=9),
            fee_schedule=FeeScheduleState(flat=0, imbalance_penalty=imbalance_penalty),
        ),
        NettingChannelStateProperties(
            our_state=NettingChannelEndStateProperties(balance=9),
            fee_schedule=FeeScheduleState(flat=1, imbalance_penalty=imbalance_penalty),
        ),
    )
    assert pair


def test_imbalance_penalty_prevents_transfer():
    """
    In this case the imbalance fee is negative and increases the amount
    transferred from the mediator to the target above the mediators capacity on
    that channel. The mediator has two choices:
    1. Only transfer as much as he has capacity. If this payment succeeds, this
       is to the mediator's advantage, since he gets to keep more tokens.
    2. Refund the transfer, because he can't send the negative imbalance fee he
    promised and the payment is likely to have enough tokens when reaching the
    target.
    This test verifies that we choose option 2.
    """
    # Will reward payment with the enormous amount of 1 token per transferred token!
    imbalance_penalty = [(0, 100), (100, 0)]
    pair, _ = _foward_transfer_pair(
        10,
        NettingChannelStateProperties(
            our_state=NettingChannelEndStateProperties(balance=10),
            fee_schedule=FeeScheduleState(flat=0, imbalance_penalty=imbalance_penalty),
        ),
        NettingChannelStateProperties(
            our_state=NettingChannelEndStateProperties(balance=10),
            fee_schedule=FeeScheduleState(flat=0, imbalance_penalty=imbalance_penalty),
        ),
    )
    assert not pair


def test_outdated_imbalance_penalty_at_transfer():
    """
    Test that having an outdated (for older capacity) imbalance penalty fee
    during a transfer where we have sufficient balance does not throw an
    UndefinedMediationFee exception from the state machine.

    Regression test for https://github.com/raiden-network/raiden/issues/4835
    """
    payer_transfer = create(
        LockedTransferSignedStateProperties(amount=10, initiator=HOP1, target=ADDR, expiration=50)
    )

    imbalance_penalty = calculate_imbalance_fees(
        channel_capacity=5, proportional_imbalance_fee=4000
    )
    channels = make_channel_set(
        [
            NettingChannelStateProperties(
                our_state=NettingChannelEndStateProperties(balance=10),
                fee_schedule=FeeScheduleState(flat=0, imbalance_penalty=imbalance_penalty),
            ),
            NettingChannelStateProperties(
                our_state=NettingChannelEndStateProperties(balance=10),
                fee_schedule=FeeScheduleState(flat=0, imbalance_penalty=imbalance_penalty),
            ),
        ]
    )

    pair, _ = mediator.forward_transfer_pair(
        payer_transfer=payer_transfer,
        payer_channel=channels[0],
        route_state=channels.get_route(1),
        route_state_table=channels.get_routes(),
        channelidentifiers_to_channels=channels.channel_map,
        pseudo_random_generator=random.Random(),
        block_number=2,
    )
    # Up for discussion: Shouldn't this transfer actually succeed? If the imbalance fee
    # is outdated for some reason and we can't calculate it shouldn't we just
    # omit it and mediate without it as a mediator? Or is the current behaviour
    # from this PR, namely to not mediate the transfer, okay?
    assert not pair


def test_backward_transfer_pair_with_fees_deducted():
    amount = 10
    fee = FeeAmount(0)  # Fee handling for refunds is currently undefined, so set it to 0 for now.

    end_state = factories.NettingChannelEndStateProperties(balance=amount + fee)
    partner_state = replace(end_state, address=UNIT_TRANSFER_SENDER)
    refund_channel: NettingChannelState = factories.create(
        factories.NettingChannelStateProperties(our_state=end_state, partner_state=partner_state)
    )

    refund_channel.fee_schedule.flat = fee

    transfer_data = LockedTransferSignedStateProperties(
        amount=amount + fee,
        expiration=10,
        canonical_identifier=refund_channel.canonical_identifier,
        locked_amount=amount + fee,
    )
    received_transfer = create(transfer_data)

    is_valid, _, msg = channel.handle_receive_lockedtransfer(refund_channel, received_transfer)
    assert is_valid, msg

    transfer_pair, refund_events = mediator.backward_transfer_pair(
        backward_channel=refund_channel,
        payer_transfer=received_transfer,
        pseudo_random_generator=random.Random(),
        block_number=1,
    )

    assert search_for_item(
        refund_events,
        SendRefundTransfer,
        {
            "transfer": {
                "lock": {
                    "expiration": received_transfer.lock.expiration,
                    "amount": amount,
                    "secrethash": received_transfer.lock.secrethash,
                }
            },
            # pylint: disable=E1101
            "recipient": refund_channel.partner_state.address,
        },
    )
    assert transfer_pair.payer_transfer == received_transfer


def test_sanity_check_for_refund_transfer_with_fees():
    fee = FeeAmount(0)  # Fee handling for refunds is currently undefined, so set it to 0 for now.
    channels = make_channel_set(
        [
            NettingChannelStateProperties(
                fee_schedule=FeeScheduleStateProperties(flat=fee, proportional=0),
                canonical_identifier=make_canonical_identifier(channel_identifier=1),
                our_state=NettingChannelEndStateProperties.OUR_STATE,
                partner_state=NettingChannelEndStateProperties(
                    balance=UNIT_TRANSFER_AMOUNT + fee, address=UNIT_TRANSFER_SENDER
                ),
            ),
            NettingChannelStateProperties(
                make_canonical_identifier(channel_identifier=2),
                our_state=replace(
                    NettingChannelEndStateProperties.OUR_STATE, balance=UNIT_TRANSFER_AMOUNT - 1
                ),
            ),
            NettingChannelStateProperties(
                make_canonical_identifier(channel_identifier=3),
                our_state=replace(NettingChannelEndStateProperties.OUR_STATE, balance=0),
            ),
        ]
    )

    next_hop_address = channels[1].partner_state.address

    from_transfer_amount = UNIT_TRANSFER_AMOUNT + fee
    from_transfer = factories.make_signed_transfer_for(
        channel_state=channels[0],
        properties=LockedTransferSignedStateProperties(
            initiator=UNIT_TRANSFER_SENDER,
            amount=from_transfer_amount,
            routes=[
                [factories.UNIT_OUR_ADDRESS, next_hop_address, factories.UNIT_TRANSFER_TARGET]
            ],
        ),
    )

    assert from_transfer.routes[0][0] == factories.UNIT_OUR_ADDRESS, "not matching"
    assert from_transfer.routes[0][1] == next_hop_address, "not right next hop"

    iteration = mediator.state_transition(
        mediator_state=None,
        state_change=mediator_make_init_action(channels, from_transfer),
        channelidentifiers_to_channels=channels.channel_map,
        nodeaddresses_to_networkstates=channels.nodeaddresses_to_networkstates,
        pseudo_random_generator=random.Random(),
        block_number=1,
        block_hash=factories.make_block_hash(),
    )
    msg = (
        "The task must be kept alive, "
        "either to handle future available routes, or lock expired messages"
    )
    assert iteration.new_state is not None, msg
    assert (
        search_for_item(
            iteration.events,
            SendRefundTransfer,
            {"transfer": {"lock": {"amount": UNIT_TRANSFER_AMOUNT}}},
        )
        is not None
    )


def test_receive_unlock():
    channels = mediator_make_channel_pair()
    state = MediatorTransferState(secrethash=factories.UNIT_SECRETHASH, routes=[])
    balance_proof = factories.create(
        factories.BalanceProofSignedStateProperties(
            canonical_identifier=channels[0].canonical_identifier, nonce=1
        )
    )

    state_change = ReceiveUnlock(
        message_identifier=1,
        secret=factories.UNIT_SECRET,
        balance_proof=balance_proof,
        sender=balance_proof.sender,
    )
    prng = random.Random()
    block_hash = factories.make_block_hash()

    iteration = mediator.state_transition(
        state, state_change, channels.channel_map, dict(), prng, 1, block_hash
    )
    assert_dropped(iteration, state_change, "no transfer pairs in mediator state")

    payer_transfer = factories.create(
        factories.LockedTransferSignedStateProperties(sender=HOP1, pkey=factories.HOP1_KEY)
    )
    payee_transfer = factories.create(factories.LockedTransferUnsignedStateProperties())
    wrong_pair = MediationPairState(
        payer_transfer=payer_transfer, payee_address=HOP2, payee_transfer=payee_transfer
    )
    state.transfers_pair = [wrong_pair]
    iteration = mediator.state_transition(
        state, state_change, channels.channel_map, dict(), prng, 1, block_hash
    )
    assert_dropped(iteration, state_change, "no matching transfer pair in mediator state")

    payer_transfer = factories.create(factories.LockedTransferSignedStateProperties())
    pair = MediationPairState(
        payer_transfer=payer_transfer,
        payee_address=UNIT_TRANSFER_TARGET,
        payee_transfer=payee_transfer,
    )
    state.transfers_pair = [pair]
    iteration = mediator.state_transition(state, state_change, dict(), dict(), prng, 1, block_hash)
    assert_dropped(iteration, state_change, "channel identifier unknown")

    iteration = mediator.state_transition(
        state, state_change, channels.channel_map, dict(), prng, 1, block_hash
    )
    msg = "Expected rejection due to no corresponding lock"
    assert search_for_item(iteration.events, EventInvalidReceivedUnlock, {}), msg

    sender_state = channels[0].partner_state
    lock = HashTimeLockState(
        amount=UNIT_TRANSFER_AMOUNT, expiration=10, secrethash=UNIT_SECRETHASH
    )
    sender_state.secrethashes_to_lockedlocks[factories.UNIT_SECRETHASH] = lock
    sender_state.pending_locks = factories.make_pending_locks([lock])
    sender_state.balance_proof = factories.create(
        factories.BalanceProofProperties(transferred_amount=0, locked_amount=10)
    )
    state.secret = UNIT_SECRET
    iteration = mediator.state_transition(
        state, state_change, channels.channel_map, dict(), prng, 1, block_hash
    )
    assert search_for_item(iteration.events, EventUnlockClaimSuccess, {})
    assert iteration.new_state is None, "Only transfer has been cleared."
