# pylint: disable=invalid-name,too-many-locals
import random
from typing import NamedTuple

import pytest

from raiden.constants import EMPTY_HASH, EMPTY_HASH_KECCAK, EMPTY_MERKLE_ROOT, UINT64_MAX
from raiden.settings import DEFAULT_NUMBER_OF_BLOCK_CONFIRMATIONS
from raiden.tests.utils import factories
from raiden.tests.utils.events import search_for_item
from raiden.tests.utils.factories import (
    UNIT_SECRET,
    UNIT_SECRETHASH,
    UNIT_TRANSFER_INITIATOR,
    UNIT_TRANSFER_SENDER,
    UNIT_TRANSFER_TARGET,
    BalanceProofProperties,
    BalanceProofSignedStateProperties,
    LockedTransferProperties,
    LockedTransferSignedStateProperties,
    NettingChannelEndStateProperties,
    NettingChannelStateProperties,
    create,
    make_channel_set,
)
from raiden.transfer import channel
from raiden.transfer.events import ContractSendSecretReveal, SendProcessed
from raiden.transfer.mediated_transfer import target
from raiden.transfer.mediated_transfer.events import (
    EventUnlockClaimFailed,
    SendSecretRequest,
    SendSecretReveal,
)
from raiden.transfer.mediated_transfer.state import TargetTransferState
from raiden.transfer.mediated_transfer.state_change import (
    ActionInitTarget,
    ReceiveLockExpired,
    ReceiveSecretReveal,
)
from raiden.transfer.state_change import Block, ContractReceiveSecretReveal, ReceiveUnlock
from raiden.utils import typing


def make_target_transfer(channel, amount=None, expiration=None, initiator=None, block_number=1):
    default_expiration = block_number + channel.settle_timeout - channel.reveal_timeout

    return factories.make_signed_transfer_for(
        channel,
        factories.LockedTransferSignedStateProperties(
            transfer=factories.LockedTransferProperties(
                amount=amount or channel.partner_state.contract_balance,
                expiration=expiration or default_expiration,
                initiator=initiator or UNIT_TRANSFER_INITIATOR,
                target=channel.our_state.address,
            ),
        ),
    )


class TargetStateSetup(NamedTuple):
    channel: typing.ChannelState
    new_state: TargetTransferState
    our_address: typing.Address
    initiator: typing.Address
    amount: typing.TokenAmount
    block_number: typing.BlockNumber
    expiration: typing.BlockExpiration
    pseudo_random_generator: random.Random


def make_target_state(
        our_address=factories.ADDR,
        amount=3,
        block_number=1,
        initiator=UNIT_TRANSFER_INITIATOR,
        expiration=None,
        pseudo_random_generator=None,
):
    pseudo_random_generator = pseudo_random_generator or random.Random()
    channels = make_channel_set([
        NettingChannelStateProperties(
            our_state=NettingChannelEndStateProperties(address=our_address),
            partner_state=NettingChannelEndStateProperties(
                address=UNIT_TRANSFER_SENDER,
                balance=amount,
            ),
        ),
    ])

    expiration = expiration or channels[0].reveal_timeout + block_number + 1
    from_transfer = make_target_transfer(channels[0], amount, expiration, initiator)

    state_change = ActionInitTarget(route=channels.get_route(0), transfer=from_transfer)
    iteration = target.handle_inittarget(
        state_change=state_change,
        channel_state=channels[0],
        pseudo_random_generator=pseudo_random_generator,
        block_number=block_number,
    )

    return TargetStateSetup(
        channel=channels[0],
        new_state=iteration.new_state,
        our_address=our_address,
        initiator=initiator,
        expiration=expiration,
        amount=amount,
        block_number=block_number,
        pseudo_random_generator=pseudo_random_generator,
    )


channel_properties = NettingChannelStateProperties(
    our_state=NettingChannelEndStateProperties(address=UNIT_TRANSFER_TARGET),
    partner_state=NettingChannelEndStateProperties(address=UNIT_TRANSFER_SENDER, balance=3),
)

channel_properties2 = NettingChannelStateProperties(
    our_state=NettingChannelEndStateProperties(address=factories.make_address(), balance=100),
    partner_state=NettingChannelEndStateProperties(address=UNIT_TRANSFER_SENDER, balance=130),
)


def test_events_for_onchain_secretreveal():
    """ Secret must be registered on-chain when the unsafe region is reached and
    the secret is known.
    """
    block_number = 10
    expiration = block_number + 30

    channels = make_channel_set([channel_properties])
    from_transfer = make_target_transfer(channels[0], expiration=expiration)

    channel.handle_receive_lockedtransfer(channels[0], from_transfer)

    channel.register_offchain_secret(channels[0], UNIT_SECRET, UNIT_SECRETHASH)

    safe_to_wait = expiration - channels[0].reveal_timeout - 1
    unsafe_to_wait = expiration - channels[0].reveal_timeout

    state = TargetTransferState(channels.get_route(0), from_transfer)
    events = target.events_for_onchain_secretreveal(
        target_state=state,
        channel_state=channels[0],
        block_number=safe_to_wait,
        block_hash=factories.make_block_hash(),
    )
    assert not events

    events = target.events_for_onchain_secretreveal(
        target_state=state,
        channel_state=channels[0],
        block_number=unsafe_to_wait,
        block_hash=factories.make_block_hash(),
    )

    msg = 'when its not safe to wait, the contract send must be emitted'
    assert search_for_item(events, ContractSendSecretReveal, {'secret': UNIT_SECRET}), msg

    msg = 'second call must not emit ContractSendSecretReveal again'
    assert not target.events_for_onchain_secretreveal(
        target_state=state,
        channel_state=channels[0],
        block_number=unsafe_to_wait,
        block_hash=factories.make_block_hash(),
    ), msg


def test_handle_inittarget():
    """ Init transfer must send a secret request if the expiration is valid. """
    block_number = 1
    pseudo_random_generator = random.Random()

    channels = make_channel_set([channel_properties])

    transfer_properties = LockedTransferSignedStateProperties(
        transfer=LockedTransferProperties(
            amount=channels[0].partner_state.contract_balance,
            expiration=channels[0].reveal_timeout + block_number + 1,
            balance_proof=BalanceProofProperties(
                channel_identifier=channels[0].identifier,
                token_network_identifier=channels[0].token_network_identifier,
                transferred_amount=0,
                locked_amount=channels[0].partner_state.contract_balance,
            ),
        ),
    )
    from_transfer = create(transfer_properties)

    state_change = ActionInitTarget(channels.get_route(0), from_transfer)

    iteration = target.handle_inittarget(
        state_change,
        channels[0],
        pseudo_random_generator,
        block_number,
    )

    assert search_for_item(iteration.events, SendSecretRequest, {
        'payment_identifier': from_transfer.payment_identifier,
        'amount': from_transfer.lock.amount,
        'secrethash': from_transfer.lock.secrethash,
        'recipient': UNIT_TRANSFER_INITIATOR,
    })
    assert search_for_item(iteration.events, SendProcessed, {})


def test_handle_inittarget_bad_expiration():
    """ Init transfer must do nothing if the expiration is bad. """
    block_number = 1
    pseudo_random_generator = random.Random()

    channels = make_channel_set([channel_properties])
    expiration = channels[0].reveal_timeout + block_number + 1
    from_transfer = make_target_transfer(channels[0], expiration=expiration)

    channel.handle_receive_lockedtransfer(channels[0], from_transfer)

    state_change = ActionInitTarget(channels.get_route(0), from_transfer)
    iteration = target.handle_inittarget(
        state_change,
        channels[0],
        pseudo_random_generator,
        block_number,
    )
    assert search_for_item(iteration.events, EventUnlockClaimFailed, {})


def test_handle_offchain_secretreveal():
    """ The target node needs to inform the secret to the previous node to
    receive an updated balance proof.
    """
    setup = make_target_state()
    state_change = ReceiveSecretReveal(UNIT_SECRET, setup.initiator)
    iteration = target.handle_offchain_secretreveal(
        target_state=setup.new_state,
        state_change=state_change,
        channel_state=setup.channel,
        pseudo_random_generator=setup.pseudo_random_generator,
        block_number=setup.block_number,
    )
    assert len(iteration.events) == 1

    reveal = iteration.events[0]
    assert isinstance(reveal, SendSecretReveal)

    assert iteration.new_state.state == 'reveal_secret'
    assert reveal.secret == UNIT_SECRET
    assert reveal.recipient == setup.new_state.route.node_address

    # if we get an empty hash secret make sure it's rejected
    secret = EMPTY_HASH
    state_change = ReceiveSecretReveal(secret, setup.initiator)
    iteration = target.handle_offchain_secretreveal(
        target_state=setup.new_state,
        state_change=state_change,
        channel_state=setup.channel,
        pseudo_random_generator=setup.pseudo_random_generator,
        block_number=setup.block_number,
    )
    assert len(iteration.events) == 0


def test_handle_offchain_secretreveal_after_lock_expired():
    """Test that getting the secret revealed after lock expiration for the
    target does not end up continuously emitting EventUnlockClaimFailed

    Target part for https://github.com/raiden-network/raiden/issues/3086
    """
    setup = make_target_state()

    lock_expiration_block_number = channel.get_sender_expiration_threshold(
        setup.new_state.transfer.lock,
    )
    lock_expiration_block = Block(
        block_number=lock_expiration_block_number,
        gas_limit=1,
        block_hash=factories.make_transaction_hash(),
    )
    iteration = target.state_transition(
        target_state=setup.new_state,
        state_change=lock_expiration_block,
        channel_state=setup.channel,
        pseudo_random_generator=setup.pseudo_random_generator,
        block_number=lock_expiration_block_number,
    )
    state = iteration.new_state

    msg = 'At the expiration block we should get an EventUnlockClaimFailed'
    assert search_for_item(iteration.events, EventUnlockClaimFailed, {}), msg

    iteration = target.state_transition(
        target_state=state,
        state_change=ReceiveSecretReveal(UNIT_SECRET, setup.initiator),
        channel_state=setup.channel,
        pseudo_random_generator=setup.pseudo_random_generator,
        block_number=lock_expiration_block_number + 1,
    )
    state = iteration.new_state

    next_block = Block(
        block_number=lock_expiration_block_number + 1,
        gas_limit=1,
        block_hash=factories.make_transaction_hash(),
    )
    iteration = target.state_transition(
        target_state=state,
        state_change=next_block,
        channel_state=setup.channel,
        pseudo_random_generator=setup.pseudo_random_generator,
        block_number=lock_expiration_block_number + 1,
    )
    msg = 'At the next block we should not get the same event'
    assert not search_for_item(iteration.events, EventUnlockClaimFailed, {}), msg


def test_handle_onchain_secretreveal():
    """ The target node must update the lock state when the secret is
    registered in the blockchain.
    """
    setup = make_target_state(
        block_number=1,
        expiration=1 + factories.UNIT_REVEAL_TIMEOUT,
    )
    assert factories.UNIT_SECRETHASH in setup.channel.partner_state.secrethashes_to_lockedlocks

    offchain_secret_reveal_iteration = target.state_transition(
        target_state=setup.new_state,
        state_change=ReceiveSecretReveal(UNIT_SECRET, setup.initiator),
        channel_state=setup.channel,
        pseudo_random_generator=setup.pseudo_random_generator,
        block_number=setup.block_number,
    )
    assert UNIT_SECRETHASH in setup.channel.partner_state.secrethashes_to_unlockedlocks
    assert UNIT_SECRETHASH not in setup.channel.partner_state.secrethashes_to_lockedlocks

    # Make sure that an emptyhash on chain reveal is rejected.
    block_number_prior_the_expiration = setup.expiration - 2
    onchain_reveal = ContractReceiveSecretReveal(
        transaction_hash=factories.make_address(),
        secret_registry_address=factories.make_address(),
        secrethash=EMPTY_HASH_KECCAK,
        secret=EMPTY_HASH,
        block_number=block_number_prior_the_expiration,
        block_hash=factories.make_block_hash(),
    )
    onchain_secret_reveal_iteration = target.state_transition(
        target_state=offchain_secret_reveal_iteration.new_state,
        state_change=onchain_reveal,
        channel_state=setup.channel,
        pseudo_random_generator=setup.pseudo_random_generator,
        block_number=block_number_prior_the_expiration,
    )
    unlocked_onchain = setup.channel.partner_state.secrethashes_to_onchain_unlockedlocks
    assert EMPTY_HASH_KECCAK not in unlocked_onchain

    # now let's go for the actual secret
    onchain_reveal.secret = UNIT_SECRET
    onchain_reveal.secrethash = UNIT_SECRETHASH
    onchain_secret_reveal_iteration = target.state_transition(
        target_state=offchain_secret_reveal_iteration.new_state,
        state_change=onchain_reveal,
        channel_state=setup.channel,
        pseudo_random_generator=setup.pseudo_random_generator,
        block_number=block_number_prior_the_expiration,
    )
    unlocked_onchain = setup.channel.partner_state.secrethashes_to_onchain_unlockedlocks
    assert UNIT_SECRETHASH in unlocked_onchain

    # Check that after we register a lock on-chain handling the block again will
    # not cause us to attempt an onchain re-register
    extra_block_handle_transition = target.handle_block(
        target_state=onchain_secret_reveal_iteration.new_state,
        channel_state=setup.channel,
        block_number=block_number_prior_the_expiration + 1,
        block_hash=factories.make_block_hash(),
    )
    assert len(extra_block_handle_transition.events) == 0


def test_handle_block():
    """ Increase the block number. """
    setup = make_target_state()

    new_block = Block(
        block_number=setup.block_number + 1,
        gas_limit=1,
        block_hash=factories.make_transaction_hash(),
    )

    iteration = target.state_transition(
        target_state=setup.new_state,
        state_change=new_block,
        channel_state=setup.channel,
        pseudo_random_generator=setup.pseudo_random_generator,
        block_number=new_block.block_number,
    )

    assert iteration.new_state
    assert not iteration.events


def test_handle_block_equal_block_number():
    """ Nothing changes. """
    setup = make_target_state()

    new_block = Block(
        block_number=1,
        gas_limit=1,
        block_hash=factories.make_transaction_hash(),
    )

    iteration = target.state_transition(
        target_state=setup.new_state,
        state_change=new_block,
        channel_state=setup.channel,
        pseudo_random_generator=random.Random(),
        block_number=new_block.block_number,
    )

    assert iteration.new_state
    assert not iteration.events


def test_handle_block_lower_block_number():
    """ Nothing changes. """
    setup = make_target_state(block_number=10)

    new_block = Block(
        block_number=setup.block_number - 1,
        gas_limit=1,
        block_hash=factories.make_transaction_hash(),
    )
    iteration = target.state_transition(
        target_state=setup.new_state,
        state_change=new_block,
        channel_state=setup.channel,
        pseudo_random_generator=setup.pseudo_random_generator,
        block_number=new_block.block_number,
    )
    assert iteration.new_state
    assert not iteration.events


def test_state_transition():
    """ Happy case testing. """
    lock_amount = 7
    block_number = 1
    initiator = factories.HOP6
    pseudo_random_generator = random.Random()

    channels = make_channel_set([channel_properties2])
    from_transfer = make_target_transfer(channels[0], amount=lock_amount, initiator=initiator)

    init = ActionInitTarget(channels.get_route(0), from_transfer)

    init_transition = target.state_transition(
        target_state=None,
        state_change=init,
        channel_state=channels[0],
        pseudo_random_generator=pseudo_random_generator,
        block_number=block_number,
    )
    assert init_transition.new_state is not None
    assert init_transition.new_state.route == channels.get_route(0)
    assert init_transition.new_state.transfer == from_transfer

    first_new_block = Block(
        block_number=block_number + 1,
        gas_limit=1,
        block_hash=factories.make_transaction_hash(),
    )
    first_block_iteration = target.state_transition(
        target_state=init_transition.new_state,
        state_change=first_new_block,
        channel_state=channels[0],
        pseudo_random_generator=pseudo_random_generator,
        block_number=first_new_block.block_number,
    )

    secret_reveal = ReceiveSecretReveal(factories.UNIT_SECRET, initiator)
    reveal_iteration = target.state_transition(
        target_state=first_block_iteration.new_state,
        state_change=secret_reveal,
        channel_state=channels[0],
        pseudo_random_generator=pseudo_random_generator,
        block_number=first_new_block.block_number,
    )
    assert reveal_iteration.events

    second_new_block = Block(
        block_number=block_number + 2,
        gas_limit=1,
        block_hash=factories.make_transaction_hash(),
    )
    iteration = target.state_transition(
        target_state=init_transition.new_state,
        state_change=second_new_block,
        channel_state=channels[0],
        pseudo_random_generator=pseudo_random_generator,
        block_number=second_new_block.block_number,
    )
    assert not iteration.events

    balance_proof = create(BalanceProofSignedStateProperties(
        balance_proof=BalanceProofProperties(
            nonce=from_transfer.balance_proof.nonce + 1,
            transferred_amount=lock_amount,
            locked_amount=0,
            token_network_identifier=channels[0].token_network_identifier,
            channel_identifier=channels.get_route(0).channel_identifier,
            locksroot=EMPTY_MERKLE_ROOT,
        ),
        message_hash=b'\x00' * 32,  # invalid
    ))

    balance_proof_state_change = ReceiveUnlock(
        message_identifier=random.randint(0, UINT64_MAX),
        secret=UNIT_SECRET,
        balance_proof=balance_proof,
    )

    proof_iteration = target.state_transition(
        target_state=init_transition.new_state,
        state_change=balance_proof_state_change,
        channel_state=channels[0],
        pseudo_random_generator=pseudo_random_generator,
        block_number=block_number + 2,
    )
    assert proof_iteration.new_state is None


def test_target_reject_keccak_empty_hash():
    lock_amount = 7
    block_number = 1
    pseudo_random_generator = random.Random()

    channels = make_channel_set([channel_properties2])
    expiration = block_number + channels[0].settle_timeout - channels[0].reveal_timeout

    from_transfer = factories.make_signed_transfer_for(
        channels[0],
        factories.LockedTransferSignedStateProperties(
            transfer=factories.LockedTransferProperties(
                amount=lock_amount,
                target=channels.our_address(0),
                expiration=expiration,
                secret=EMPTY_HASH,
            ),
        ),
        allow_invalid=True,
    )

    init = ActionInitTarget(route=channels.get_route(0), transfer=from_transfer)

    init_transition = target.state_transition(
        target_state=None,
        state_change=init,
        channel_state=channels[0],
        pseudo_random_generator=pseudo_random_generator,
        block_number=block_number,
    )
    assert init_transition.new_state is None


def test_target_receive_lock_expired():
    lock_amount = 7
    block_number = 1
    pseudo_random_generator = random.Random()

    channels = make_channel_set([channel_properties2])
    expiration = block_number + channels[0].settle_timeout - channels[0].reveal_timeout

    from_transfer = make_target_transfer(
        channels[0],
        amount=lock_amount,
        block_number=block_number,
    )

    init = ActionInitTarget(channels.get_route(0), from_transfer)

    init_transition = target.state_transition(
        target_state=None,
        state_change=init,
        channel_state=channels[0],
        pseudo_random_generator=pseudo_random_generator,
        block_number=block_number,
    )
    assert init_transition.new_state is not None
    assert init_transition.new_state.route == channels.get_route(0)
    assert init_transition.new_state.transfer == from_transfer

    balance_proof = create(BalanceProofSignedStateProperties(
        balance_proof=BalanceProofProperties(
            nonce=2,
            transferred_amount=from_transfer.balance_proof.transferred_amount,
            locked_amount=0,
            token_network_identifier=from_transfer.balance_proof.token_network_identifier,
            channel_identifier=channels[0].identifier,
        ),
        message_hash=from_transfer.lock.secrethash,
    ))

    lock_expired_state_change = ReceiveLockExpired(
        balance_proof=balance_proof,
        secrethash=from_transfer.lock.secrethash,
        message_identifier=1,
    )

    block_before_confirmed_expiration = expiration + DEFAULT_NUMBER_OF_BLOCK_CONFIRMATIONS - 1
    iteration = target.state_transition(
        target_state=init_transition.new_state,
        state_change=lock_expired_state_change,
        channel_state=channels[0],
        pseudo_random_generator=pseudo_random_generator,
        block_number=block_before_confirmed_expiration,
    )
    assert not search_for_item(iteration.events, SendProcessed, {})

    block_lock_expired = block_before_confirmed_expiration + 1
    iteration = target.state_transition(
        target_state=init_transition.new_state,
        state_change=lock_expired_state_change,
        channel_state=channels[0],
        pseudo_random_generator=pseudo_random_generator,
        block_number=block_lock_expired,
    )
    assert search_for_item(iteration.events, SendProcessed, {})


def test_target_lock_is_expired_if_secret_is_not_registered_onchain():
    lock_amount = 7
    block_number = 1
    pseudo_random_generator = random.Random()

    channels = make_channel_set([channel_properties2])
    from_transfer = make_target_transfer(channels[0], amount=lock_amount, block_number=1)

    init = ActionInitTarget(channels.get_route(0), from_transfer)

    init_transition = target.state_transition(
        target_state=None,
        state_change=init,
        channel_state=channels[0],
        pseudo_random_generator=pseudo_random_generator,
        block_number=block_number,
    )
    assert init_transition.new_state is not None

    secret_reveal_iteration = target.state_transition(
        target_state=init_transition.new_state,
        state_change=ReceiveSecretReveal(UNIT_SECRET, channels[0].partner_state.address),
        channel_state=channels[0],
        pseudo_random_generator=pseudo_random_generator,
        block_number=block_number,
    )

    expired_block_number = channel.get_receiver_expiration_threshold(from_transfer.lock)
    iteration = target.state_transition(
        target_state=secret_reveal_iteration.new_state,
        state_change=Block(expired_block_number, None, None),
        channel_state=channels[0],
        pseudo_random_generator=pseudo_random_generator,
        block_number=expired_block_number,
    )
    assert search_for_item(iteration.events, EventUnlockClaimFailed, {})


@pytest.mark.xfail(reason='Not implemented #522')
def test_transfer_successful_after_secret_learned():
    # TransferCompleted event must be used only after the secret is learned and
    # there is enough time to unlock the lock on chain.
    #
    # A mediated transfer might be received during the settlement period of the
    # current channel. The secret request is sent to the initiator and at the time
    # the secret is revealed there might not be enough time to safely unlock
    # the token on-chain.
    raise NotImplementedError()
