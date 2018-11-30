# pylint: disable=invalid-name,too-many-locals
import random

import pytest

from raiden.constants import EMPTY_HASH, EMPTY_HASH_KECCAK, UINT64_MAX
from raiden.settings import DEFAULT_NUMBER_OF_BLOCK_CONFIRMATIONS
from raiden.tests.utils import factories
from raiden.tests.utils.events import must_contain_entry
from raiden.tests.utils.factories import (
    HOP1,
    UNIT_SECRET,
    UNIT_SECRETHASH,
    UNIT_TRANSFER_PKEY,
    UNIT_TRANSFER_SENDER,
    UNIT_TRANSFER_TARGET,
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
from raiden.transfer.state import EMPTY_MERKLE_ROOT
from raiden.transfer.state_change import Block, ContractReceiveSecretReveal, ReceiveUnlock


def make_target_state(
        our_address,
        amount,
        block_number,
        initiator,
        expiration=None,
        pseudo_random_generator=None,
):
    pseudo_random_generator = pseudo_random_generator or random.Random()

    from_channel = factories.make_channel(
        our_address=our_address,
        partner_address=UNIT_TRANSFER_SENDER,
        partner_balance=amount,
    )
    from_route = factories.route_from_channel(from_channel)

    if expiration is None:
        expiration = from_channel.reveal_timeout + block_number + 1

    from_transfer = factories.make_signed_transfer_for(
        from_channel,
        amount,
        initiator,
        our_address,
        expiration,
        UNIT_SECRET,
    )

    state_change = ActionInitTarget(from_route, from_transfer)
    iteration = target.handle_inittarget(
        state_change,
        from_channel,
        pseudo_random_generator,
        block_number,
    )
    return from_channel, iteration.new_state


def test_events_for_onchain_secretreveal():
    """ Secret must be registered on-chain when the unsafe region is reached and
    the secret is known.
    """
    amount = 3
    block_number = 10
    expiration = block_number + 30
    initiator = HOP1
    target_address = UNIT_TRANSFER_TARGET

    from_channel = factories.make_channel(
        our_address=target_address,
        partner_address=UNIT_TRANSFER_SENDER,
        partner_balance=amount,
    )
    from_route = factories.route_from_channel(from_channel)

    from_transfer = factories.make_signed_transfer_for(
        from_channel,
        amount,
        initiator,
        target_address,
        expiration,
        UNIT_SECRET,
    )

    channel.handle_receive_lockedtransfer(
        from_channel,
        from_transfer,
    )

    channel.register_offchain_secret(from_channel, UNIT_SECRET, UNIT_SECRETHASH)

    safe_to_wait = expiration - from_channel.reveal_timeout - 1
    unsafe_to_wait = expiration - from_channel.reveal_timeout

    state = TargetTransferState(from_route, from_transfer)
    events = target.events_for_onchain_secretreveal(state, from_channel, safe_to_wait)
    assert not events

    events = target.events_for_onchain_secretreveal(state, from_channel, unsafe_to_wait)
    assert events
    assert isinstance(events[0], ContractSendSecretReveal)
    assert events[0].secret == UNIT_SECRET


def test_handle_inittarget():
    """ Init transfer must send a secret request if the expiration is valid. """
    amount = 3
    block_number = 1
    initiator = factories.HOP1
    target_address = UNIT_TRANSFER_TARGET
    pseudo_random_generator = random.Random()

    from_channel = factories.make_channel(
        our_address=target_address,
        partner_address=UNIT_TRANSFER_SENDER,
        partner_balance=amount,
    )
    from_route = factories.route_from_channel(from_channel)

    expiration = from_channel.reveal_timeout + block_number + 1
    from_transfer = factories.make_signed_transfer(
        amount,
        initiator,
        target_address,
        expiration,
        UNIT_SECRET,
        channel_identifier=from_channel.identifier,
        token_network_address=from_channel.token_network_identifier,
    )

    state_change = ActionInitTarget(
        from_route,
        from_transfer,
    )

    iteration = target.handle_inittarget(
        state_change,
        from_channel,
        pseudo_random_generator,
        block_number,
    )

    assert must_contain_entry(iteration.events, SendSecretRequest, {
        'payment_identifier': from_transfer.payment_identifier,
        'amount': from_transfer.lock.amount,
        'secrethash': from_transfer.lock.secrethash,
        'recipient': initiator,
    })
    assert must_contain_entry(iteration.events, SendProcessed, {})


def test_handle_inittarget_bad_expiration():
    """ Init transfer must do nothing if the expiration is bad. """
    block_number = 1
    amount = 3
    initiator = factories.HOP1
    target_address = UNIT_TRANSFER_TARGET
    pseudo_random_generator = random.Random()

    from_channel = factories.make_channel(
        our_address=target_address,
        partner_address=UNIT_TRANSFER_SENDER,
        partner_balance=amount,
    )
    from_route = factories.route_from_channel(from_channel)

    expiration = from_channel.reveal_timeout + block_number + 1
    from_transfer = factories.make_signed_transfer_for(
        from_channel,
        amount,
        initiator,
        target_address,
        expiration,
        UNIT_SECRET,
    )

    channel.handle_receive_lockedtransfer(
        from_channel,
        from_transfer,
    )

    state_change = ActionInitTarget(from_route, from_transfer)
    iteration = target.handle_inittarget(
        state_change,
        from_channel,
        pseudo_random_generator,
        block_number,
    )
    assert must_contain_entry(iteration.events, EventUnlockClaimFailed, {})


def test_handle_offchain_secretreveal():
    """ The target node needs to inform the secret to the previous node to
    receive an updated balance proof.
    """
    amount = 3
    block_number = 1
    expiration = block_number + factories.UNIT_REVEAL_TIMEOUT
    initiator = factories.HOP1
    our_address = factories.ADDR
    secret = factories.UNIT_SECRET
    pseudo_random_generator = random.Random()

    channel_state, state = make_target_state(
        our_address,
        amount,
        block_number,
        initiator,
        expiration,
    )
    state_change = ReceiveSecretReveal(secret, initiator)
    iteration = target.handle_offchain_secretreveal(
        state,
        state_change,
        channel_state,
        pseudo_random_generator,
    )
    assert len(iteration.events) == 1

    reveal = iteration.events[0]
    assert isinstance(reveal, SendSecretReveal)

    assert iteration.new_state.state == 'reveal_secret'
    assert reveal.secret == secret
    assert reveal.recipient == state.route.node_address

    # if we get an empty hash secret make sure it's rejected
    secret = EMPTY_HASH
    state_change = ReceiveSecretReveal(secret, initiator)
    iteration = target.handle_offchain_secretreveal(
        state,
        state_change,
        channel_state,
        pseudo_random_generator,
    )
    assert len(iteration.events) == 0


def test_handle_onchain_secretreveal():
    """ The target node must update the lock state when the secret is
    registered in the blockchain.
    """
    amount = 3
    block_number = 1
    expiration = block_number + factories.UNIT_REVEAL_TIMEOUT
    initiator = factories.HOP1
    our_address = factories.ADDR
    secret = factories.UNIT_SECRET
    pseudo_random_generator = random.Random()

    channel_state, state = make_target_state(
        our_address,
        amount,
        block_number,
        initiator,
        expiration,
    )
    assert factories.UNIT_SECRETHASH in channel_state.partner_state.secrethashes_to_lockedlocks

    offchain_secret_reveal_iteration = target.state_transition(
        state,
        ReceiveSecretReveal(secret, initiator),
        channel_state,
        pseudo_random_generator,
        block_number,
    )
    assert factories.UNIT_SECRETHASH in channel_state.partner_state.secrethashes_to_unlockedlocks
    assert factories.UNIT_SECRETHASH not in channel_state.partner_state.secrethashes_to_lockedlocks

    # Make sure that an emptyhash on chain reveal is rejected.
    block_number_prior_the_expiration = expiration - 2
    onchain_reveal = ContractReceiveSecretReveal(
        transaction_hash=factories.make_address(),
        secret_registry_address=factories.make_address(),
        secrethash=EMPTY_HASH_KECCAK,
        secret=EMPTY_HASH,
        block_number=block_number_prior_the_expiration,
    )
    onchain_secret_reveal_iteration = target.state_transition(
        offchain_secret_reveal_iteration.new_state,
        onchain_reveal,
        channel_state,
        pseudo_random_generator,
        block_number_prior_the_expiration,
    )
    unlocked_onchain = channel_state.partner_state.secrethashes_to_onchain_unlockedlocks
    assert EMPTY_HASH_KECCAK not in unlocked_onchain

    # now let's go for the actual secret
    onchain_reveal.secret = secret
    onchain_reveal.secrethash = factories.UNIT_SECRETHASH
    onchain_secret_reveal_iteration = target.state_transition(
        offchain_secret_reveal_iteration.new_state,
        onchain_reveal,
        channel_state,
        pseudo_random_generator,
        block_number_prior_the_expiration,
    )
    unlocked_onchain = channel_state.partner_state.secrethashes_to_onchain_unlockedlocks
    assert factories.UNIT_SECRETHASH in unlocked_onchain

    # Check that after we register a lock on-chain handling the block again will
    # not cause us to attempt an onchain re-register
    extra_block_handle_transition = target.handle_block(
        onchain_secret_reveal_iteration.new_state,
        channel_state,
        block_number_prior_the_expiration + 1,
    )
    assert len(extra_block_handle_transition.events) == 0


def test_handle_block():
    """ Increase the block number. """
    initiator = factories.HOP6
    our_address = factories.ADDR
    amount = 3
    block_number = 1
    pseudo_random_generator = random.Random()

    from_channel, state = make_target_state(
        our_address,
        amount,
        block_number,
        initiator,
    )

    new_block = Block(
        block_number=block_number + 1,
        gas_limit=1,
        block_hash=factories.make_transaction_hash(),
    )
    iteration = target.state_transition(
        state,
        new_block,
        from_channel,
        pseudo_random_generator,
        new_block.block_number,
    )
    assert iteration.new_state
    assert not iteration.events


def test_handle_block_equal_block_number():
    """ Nothing changes. """
    initiator = factories.HOP6
    our_address = factories.ADDR
    amount = 3
    block_number = 1
    pseudo_random_generator = random.Random()

    from_channel, state = make_target_state(
        our_address,
        amount,
        block_number,
        initiator,
    )

    new_block = Block(
        block_number=block_number,
        gas_limit=1,
        block_hash=factories.make_transaction_hash(),
    )
    iteration = target.state_transition(
        state,
        new_block,
        from_channel,
        pseudo_random_generator,
        new_block.block_number,
    )
    assert iteration.new_state
    assert not iteration.events


def test_handle_block_lower_block_number():
    """ Nothing changes. """
    initiator = factories.HOP6
    our_address = factories.ADDR
    amount = 3
    block_number = 10
    pseudo_random_generator = random.Random()

    from_channel, state = make_target_state(
        our_address,
        amount,
        block_number,
        initiator,
    )

    new_block = Block(
        block_number=block_number - 1,
        gas_limit=1,
        block_hash=factories.make_transaction_hash(),
    )
    iteration = target.state_transition(
        state,
        new_block,
        from_channel,
        pseudo_random_generator,
        new_block.block_number,
    )
    assert iteration.new_state
    assert not iteration.events


def test_state_transition():
    """ Happy case testing. """
    lock_amount = 7
    block_number = 1
    initiator = factories.HOP6
    pseudo_random_generator = random.Random()

    our_balance = 100
    our_address = factories.make_address()
    partner_balance = 130

    from_channel = factories.make_channel(
        our_address=our_address,
        our_balance=our_balance,
        partner_address=UNIT_TRANSFER_SENDER,
        partner_balance=partner_balance,
    )
    from_route = factories.route_from_channel(from_channel)
    expiration = block_number + from_channel.settle_timeout - from_channel.reveal_timeout

    from_transfer = factories.make_signed_transfer_for(
        from_channel,
        lock_amount,
        initiator,
        our_address,
        expiration,
        UNIT_SECRET,
    )

    init = ActionInitTarget(
        from_route,
        from_transfer,
    )

    init_transition = target.state_transition(
        None,
        init,
        from_channel,
        pseudo_random_generator,
        block_number,
    )
    assert init_transition.new_state is not None
    assert init_transition.new_state.route == from_route
    assert init_transition.new_state.transfer == from_transfer

    first_new_block = Block(
        block_number=block_number + 1,
        gas_limit=1,
        block_hash=factories.make_transaction_hash(),
    )
    first_block_iteration = target.state_transition(
        init_transition.new_state,
        first_new_block,
        from_channel,
        pseudo_random_generator,
        first_new_block.block_number,
    )

    secret_reveal = ReceiveSecretReveal(factories.UNIT_SECRET, initiator)
    reveal_iteration = target.state_transition(
        first_block_iteration.new_state,
        secret_reveal,
        from_channel,
        pseudo_random_generator,
        first_new_block,
    )
    assert reveal_iteration.events

    second_new_block = Block(
        block_number=block_number + 2,
        gas_limit=1,
        block_hash=factories.make_transaction_hash(),
    )
    iteration = target.state_transition(
        init_transition.new_state,
        second_new_block,
        from_channel,
        pseudo_random_generator,
        second_new_block.block_number,
    )
    assert not iteration.events

    nonce = from_transfer.balance_proof.nonce + 1
    transferred_amount = lock_amount
    locksroot = EMPTY_MERKLE_ROOT
    invalid_message_hash = b'\x00' * 32
    locked_amount = 0

    balance_proof = factories.make_signed_balance_proof(
        nonce,
        transferred_amount,
        locked_amount,
        from_channel.token_network_identifier,
        from_route.channel_identifier,
        locksroot,
        invalid_message_hash,
        UNIT_TRANSFER_PKEY,
        UNIT_TRANSFER_SENDER,
    )

    balance_proof_state_change = ReceiveUnlock(
        message_identifier=random.randint(0, UINT64_MAX),
        secret=UNIT_SECRET,
        balance_proof=balance_proof,
    )

    proof_iteration = target.state_transition(
        init_transition.new_state,
        balance_proof_state_change,
        from_channel,
        pseudo_random_generator,
        block_number + 2,
    )
    assert proof_iteration.new_state is None


def test_target_reject_keccak_empty_hash():
    lock_amount = 7
    block_number = 1
    initiator = factories.HOP6
    pseudo_random_generator = random.Random()

    our_balance = 100
    our_address = factories.make_address()
    partner_balance = 130

    from_channel = factories.make_channel(
        our_address=our_address,
        our_balance=our_balance,
        partner_address=UNIT_TRANSFER_SENDER,
        partner_balance=partner_balance,
    )
    from_route = factories.route_from_channel(from_channel)
    expiration = block_number + from_channel.settle_timeout - from_channel.reveal_timeout

    from_transfer = factories.make_signed_transfer_for(
        channel_state=from_channel,
        amount=lock_amount,
        initiator=initiator,
        target=our_address,
        expiration=expiration,
        secret=EMPTY_HASH,
        allow_invalid=True,
    )

    init = ActionInitTarget(
        route=from_route,
        transfer=from_transfer,
    )

    init_transition = target.state_transition(
        None,
        init,
        from_channel,
        pseudo_random_generator,
        block_number,
    )
    assert init_transition.new_state is None


def test_target_receive_lock_expired():
    lock_amount = 7
    block_number = 1
    initiator = factories.HOP6
    pseudo_random_generator = random.Random()

    our_balance = 100
    our_address = factories.make_address()
    partner_balance = 130

    from_channel = factories.make_channel(
        our_address=our_address,
        our_balance=our_balance,
        partner_address=UNIT_TRANSFER_SENDER,
        partner_balance=partner_balance,
    )
    from_route = factories.route_from_channel(from_channel)
    expiration = block_number + from_channel.settle_timeout - from_channel.reveal_timeout

    from_transfer = factories.make_signed_transfer_for(
        channel_state=from_channel,
        amount=lock_amount,
        initiator=initiator,
        target=our_address,
        expiration=expiration,
        secret=UNIT_SECRET,
    )

    init = ActionInitTarget(
        from_route,
        from_transfer,
    )

    init_transition = target.state_transition(
        None,
        init,
        from_channel,
        pseudo_random_generator,
        block_number,
    )
    assert init_transition.new_state is not None
    assert init_transition.new_state.route == from_route
    assert init_transition.new_state.transfer == from_transfer

    balance_proof = factories.make_signed_balance_proof(
        2,
        from_transfer.balance_proof.transferred_amount,
        0,
        from_transfer.balance_proof.token_network_identifier,
        from_channel.identifier,
        EMPTY_MERKLE_ROOT,
        from_transfer.lock.secrethash,
        sender_address=UNIT_TRANSFER_SENDER,
        private_key=UNIT_TRANSFER_PKEY,
    )

    lock_expired_state_change = ReceiveLockExpired(
        balance_proof=balance_proof,
        secrethash=from_transfer.lock.secrethash,
        message_identifier=1,
    )

    block_before_confirmed_expiration = expiration + DEFAULT_NUMBER_OF_BLOCK_CONFIRMATIONS - 1
    iteration = target.state_transition(
        init_transition.new_state,
        lock_expired_state_change,
        from_channel,
        pseudo_random_generator,
        block_before_confirmed_expiration,
    )
    assert not must_contain_entry(iteration.events, SendProcessed, {})

    block_lock_expired = block_before_confirmed_expiration + 1
    iteration = target.state_transition(
        init_transition.new_state,
        lock_expired_state_change,
        from_channel,
        pseudo_random_generator,
        block_lock_expired,
    )
    assert must_contain_entry(iteration.events, SendProcessed, {})


def test_target_lock_is_expired_if_secret_is_not_registered_onchain():
    lock_amount = 7
    block_number = 1
    initiator = factories.HOP6
    pseudo_random_generator = random.Random()

    our_balance = 100
    our_address = factories.make_address()
    partner_balance = 130

    from_channel = factories.make_channel(
        our_address=our_address,
        our_balance=our_balance,
        partner_address=UNIT_TRANSFER_SENDER,
        partner_balance=partner_balance,
    )
    from_route = factories.route_from_channel(from_channel)
    expiration = block_number + from_channel.settle_timeout - from_channel.reveal_timeout

    from_transfer = factories.make_signed_transfer_for(
        from_channel,
        lock_amount,
        initiator,
        our_address,
        expiration,
        UNIT_SECRET,
    )

    init = ActionInitTarget(
        from_route,
        from_transfer,
    )

    init_transition = target.state_transition(
        None,
        init,
        from_channel,
        pseudo_random_generator,
        block_number,
    )
    assert init_transition.new_state is not None

    secret_reveal_iteration = target.state_transition(
        target_state=init_transition.new_state,
        state_change=ReceiveSecretReveal(UNIT_SECRET, from_channel.partner_state.address),
        channel_state=from_channel,
        pseudo_random_generator=pseudo_random_generator,
        block_number=block_number,
    )

    expired_block_number = from_transfer.lock.expiration + DEFAULT_NUMBER_OF_BLOCK_CONFIRMATIONS
    iteration = target.state_transition(
        target_state=secret_reveal_iteration.new_state,
        state_change=Block(expired_block_number, None, None),
        channel_state=from_channel,
        pseudo_random_generator=pseudo_random_generator,
        block_number=expired_block_number,
    )
    assert must_contain_entry(iteration.events, EventUnlockClaimFailed, {})


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
