# pylint: disable=invalid-name,too-many-locals,too-many-arguments,too-many-lines
import random

from raiden.messages.decode import balanceproof_from_envelope
from raiden.messages.encode import message_from_sendevent
from raiden.tests.utils import factories
from raiden.tests.utils.events import search_for_item
from raiden.tests.utils.factories import (
    HOP2,
    HOP2_KEY,
    UNIT_SECRET,
    UNIT_SECRETHASH,
    UNIT_TRANSFER_AMOUNT,
    NettingChannelEndStateProperties,
    NettingChannelStateProperties,
    make_channel_set,
)
from raiden.transfer import channel
from raiden.transfer.mediated_transfer import mediator
from raiden.transfer.mediated_transfer.events import (
    EventUnlockClaimFailed,
    SendLockedTransfer,
    SendLockExpired,
)
from raiden.transfer.mediated_transfer.state import MediatorTransferState
from raiden.transfer.mediated_transfer.state_change import (
    ActionInitMediator,
    ReceiveLockExpired,
    ReceiveSecretReveal,
)
from raiden.transfer.state import message_identifier_from_prng
from raiden.transfer.state_change import Block, ContractReceiveSecretReveal
from raiden.utils.signer import LocalSigner
from raiden.utils.typing import BlockExpiration

LONG_EXPIRATION = factories.create_properties(
    factories.LockedTransferSignedStateProperties(expiration=BlockExpiration(30))
)


def test_payer_enter_danger_zone_with_transfer_payed():
    """A mediator may have paid the next hop (payee), and didn't get paid by
    the previous hop (payer).

    When this happens, an assertion must not be hit, because it means the
    transfer must be unlocked on-chain.

    Issue: https://github.com/raiden-network/raiden/issues/1013
    """
    block_number = 5
    pseudo_random_generator = random.Random()

    channels = factories.mediator_make_channel_pair()
    payer_transfer = factories.make_signed_transfer_for(channels[0], LONG_EXPIRATION)

    initial_iteration = mediator.state_transition(
        mediator_state=None,
        state_change=factories.mediator_make_init_action(channels, payer_transfer),
        channelidentifiers_to_channels=channels.channel_map,
        addresses_to_channel=channels.addresses_to_channel(),
        pseudo_random_generator=pseudo_random_generator,
        block_number=block_number,
        block_hash=factories.make_block_hash(),
    )

    send_transfer = search_for_item(initial_iteration.events, SendLockedTransfer, {})
    assert send_transfer

    lock_expiration = send_transfer.transfer.lock.expiration

    new_state = initial_iteration.new_state
    for block_number in range(block_number, lock_expiration - channels[1].reveal_timeout):
        block_state_change = Block(
            block_number=block_number, gas_limit=1, block_hash=factories.make_transaction_hash()
        )

        block_iteration = mediator.handle_block(
            mediator_state=new_state,
            state_change=block_state_change,
            channelidentifiers_to_channels=channels.channel_map,
            addresses_to_channel=channels.addresses_to_channel(),
            pseudo_random_generator=pseudo_random_generator,
        )
        new_state = block_iteration.new_state

    # send the balance proof, transitioning the payee state to paid
    assert new_state.transfers_pair[0].payee_state == "payee_pending"
    receive_secret = ReceiveSecretReveal(
        secret=UNIT_SECRET, sender=channels[1].partner_state.address
    )
    paid_iteration = mediator.state_transition(
        mediator_state=new_state,
        state_change=receive_secret,
        channelidentifiers_to_channels=channels.channel_map,
        addresses_to_channel=channels.addresses_to_channel(),
        pseudo_random_generator=pseudo_random_generator,
        block_number=block_number,
        block_hash=factories.make_block_hash(),
    )
    paid_state = paid_iteration.new_state
    assert paid_state.transfers_pair[0].payee_state == "payee_balance_proof"

    # move to the block in which the payee lock expires. This must not raise an
    # assertion
    expired_block_number = lock_expiration + 1
    expired_block_state_change = Block(
        block_number=expired_block_number,
        gas_limit=1,
        block_hash=factories.make_transaction_hash(),
    )
    block_iteration = mediator.handle_block(
        mediator_state=paid_state,
        state_change=expired_block_state_change,
        channelidentifiers_to_channels=channels.channel_map,
        addresses_to_channel=channels.addresses_to_channel(),
        pseudo_random_generator=pseudo_random_generator,
    )


def test_regression_mediator_send_lock_expired_with_new_block():
    """The mediator must send the lock expired, but it must **not** clear
    itself if it has not **received** the corresponding message.
    """
    pseudo_random_generator = random.Random()

    channels = factories.mediator_make_channel_pair()
    payer_transfer = factories.make_signed_transfer_for(channels[0], LONG_EXPIRATION)

    init_iteration = mediator.state_transition(
        mediator_state=None,
        state_change=factories.mediator_make_init_action(channels, payer_transfer),
        channelidentifiers_to_channels=channels.channel_map,
        addresses_to_channel=channels.addresses_to_channel(),
        pseudo_random_generator=pseudo_random_generator,
        block_number=5,
        block_hash=factories.make_block_hash(),
    )
    assert init_iteration.new_state is not None
    send_transfer = search_for_item(init_iteration.events, SendLockedTransfer, {})
    assert send_transfer

    transfer = send_transfer.transfer

    block_expiration_number = channel.get_sender_expiration_threshold(transfer.lock.expiration)
    block = Block(
        block_number=block_expiration_number,
        gas_limit=1,
        block_hash=factories.make_transaction_hash(),
    )
    iteration = mediator.state_transition(
        mediator_state=init_iteration.new_state,
        state_change=block,
        channelidentifiers_to_channels=channels.channel_map,
        addresses_to_channel=channels.addresses_to_channel(),
        pseudo_random_generator=pseudo_random_generator,
        block_number=block_expiration_number,
        block_hash=factories.make_block_hash(),
    )

    msg = (
        "The payer's lock has also expired, "
        "but it must not be removed locally (without an Expired lock)"
    )
    assert transfer.lock.secrethash in channels[0].partner_state.secrethashes_to_lockedlocks, msg

    msg = "The payer has not yet sent an expired lock, the task can not be cleared yet"
    assert iteration.new_state is not None, msg

    assert search_for_item(
        iteration.events, SendLockExpired, {"secrethash": transfer.lock.secrethash}
    )
    assert transfer.lock.secrethash not in channels[1].our_state.secrethashes_to_lockedlocks


def test_regression_mediator_task_no_routes():
    """The mediator must only be cleared after the waiting transfer's lock has
    been handled.

    If a node receives a transfer to mediate, but there is no route available
    (because there is no sufficient capacity or the partner nodes are offline),
    and a refund is not possible, the mediator task must not be cleared,
    otherwise followup remove expired lock messages wont be processed and the
    nodes will get out of sync.
    """
    pseudo_random_generator = random.Random()

    channels = make_channel_set(
        [
            NettingChannelStateProperties(
                our_state=NettingChannelEndStateProperties(balance=0),
                partner_state=NettingChannelEndStateProperties(
                    balance=UNIT_TRANSFER_AMOUNT, address=HOP2, privatekey=HOP2_KEY
                ),
            )
        ]
    )

    payer_transfer = factories.make_signed_transfer_for(
        channels[0],
        factories.LockedTransferSignedStateProperties(sender=HOP2, pkey=HOP2_KEY, expiration=30),
    )

    init_state_change = ActionInitMediator(
        from_hop=channels.get_hop(0),
        candidate_route_states=channels.get_routes(),
        from_transfer=payer_transfer,
        balance_proof=payer_transfer.balance_proof,
        sender=payer_transfer.balance_proof.sender,  # pylint: disable=no-member
    )
    init_iteration = mediator.state_transition(
        mediator_state=None,
        state_change=init_state_change,
        channelidentifiers_to_channels=channels.channel_map,
        addresses_to_channel=channels.addresses_to_channel(),
        pseudo_random_generator=pseudo_random_generator,
        block_number=5,
        block_hash=factories.make_block_hash(),
    )

    msg = "The task must not be cleared, even if there is no route to forward the transfer"
    assert init_iteration.new_state is not None, msg
    assert init_iteration.new_state.waiting_transfer.transfer == payer_transfer
    assert search_for_item(init_iteration.events, SendLockedTransfer, {}) is None

    secrethash = UNIT_SECRETHASH
    lock = channels[0].partner_state.secrethashes_to_lockedlocks[secrethash]

    # Creates a transfer as it was from the *partner*
    send_lock_expired, _ = channel.create_sendexpiredlock(
        sender_end_state=channels[0].partner_state,
        locked_lock=lock,
        pseudo_random_generator=pseudo_random_generator,
        chain_id=channels[0].chain_id,
        token_network_address=channels[0].token_network_address,
        channel_identifier=channels[0].identifier,
        recipient=channels[0].our_state.address,
    )
    assert send_lock_expired
    lock_expired_message = message_from_sendevent(send_lock_expired)
    lock_expired_message.sign(LocalSigner(channels.partner_privatekeys[0]))
    balance_proof = balanceproof_from_envelope(lock_expired_message)

    message_identifier = message_identifier_from_prng(pseudo_random_generator)

    # Regression: The mediator must still be able to process the block which
    # expires the lock
    expired_block_number = channel.get_sender_expiration_threshold(lock.expiration)
    block_hash = factories.make_block_hash()
    expire_block_iteration = mediator.state_transition(
        mediator_state=init_iteration.new_state,
        state_change=Block(block_number=expired_block_number, gas_limit=0, block_hash=block_hash),
        channelidentifiers_to_channels=channels.channel_map,
        addresses_to_channel=channels.addresses_to_channel(),
        pseudo_random_generator=pseudo_random_generator,
        block_number=expired_block_number,
        block_hash=block_hash,
    )
    assert expire_block_iteration.new_state is not None

    receive_expired_iteration = mediator.state_transition(
        mediator_state=expire_block_iteration.new_state,
        state_change=ReceiveLockExpired(
            sender=balance_proof.sender,  # pylint: disable=no-member
            balance_proof=balance_proof,
            secrethash=secrethash,
            message_identifier=message_identifier,
        ),
        channelidentifiers_to_channels=channels.channel_map,
        addresses_to_channel=channels.addresses_to_channel(),
        pseudo_random_generator=pseudo_random_generator,
        block_number=expired_block_number,
        block_hash=block_hash,
    )

    msg = "The only used channel had the lock cleared, the task must be cleared"
    assert receive_expired_iteration.new_state is None, msg
    assert secrethash not in channels[0].partner_state.secrethashes_to_lockedlocks


def test_regression_mediator_not_update_payer_state_twice():
    """Regression Test for https://github.com/raiden-network/raiden/issues/3086
    Make sure that after a lock expired the mediator doesn't update the pair
    twice causing EventUnlockClaimFailed to be generated at every block.
    """
    pseudo_random_generator = random.Random()

    pair = factories.mediator_make_channel_pair()
    payer_channel, payee_channel = pair.channels
    payer_route = factories.make_hop_from_channel(payer_channel)
    payer_transfer = factories.make_signed_transfer_for(payer_channel, LONG_EXPIRATION)

    init_state_change = ActionInitMediator(
        from_hop=payer_route,
        candidate_route_states=pair.get_routes(),
        from_transfer=payer_transfer,
        balance_proof=payer_transfer.balance_proof,
        sender=payer_transfer.balance_proof.sender,  # pylint: disable=no-member
    )

    iteration = mediator.state_transition(
        mediator_state=None,
        state_change=init_state_change,
        channelidentifiers_to_channels=pair.channel_map,
        addresses_to_channel=pair.addresses_to_channel(),
        pseudo_random_generator=pseudo_random_generator,
        block_number=5,
        block_hash=factories.make_block_hash(),
    )
    assert iteration.new_state is not None

    current_state = iteration.new_state
    send_transfer = search_for_item(iteration.events, SendLockedTransfer, {})
    assert send_transfer

    transfer = send_transfer.transfer
    block_expiration_number = channel.get_sender_expiration_threshold(transfer.lock.expiration)

    block = Block(
        block_number=block_expiration_number, gas_limit=1, block_hash=factories.make_block_hash()
    )
    iteration = mediator.state_transition(
        mediator_state=current_state,
        state_change=block,
        channelidentifiers_to_channels=pair.channel_map,
        addresses_to_channel=pair.addresses_to_channel(),
        pseudo_random_generator=pseudo_random_generator,
        block_number=block_expiration_number,
        block_hash=factories.make_block_hash(),
    )

    msg = "At the expiration block we should get an EventUnlockClaimFailed"
    assert search_for_item(iteration.events, EventUnlockClaimFailed, {}), msg

    current_state = iteration.new_state
    next_block = Block(
        block_number=block_expiration_number + 1,
        gas_limit=1,
        block_hash=factories.make_transaction_hash(),
    )

    # Initiator receives the secret reveal after the lock expired
    receive_secret = ReceiveSecretReveal(
        secret=UNIT_SECRET, sender=payee_channel.partner_state.address
    )
    iteration = mediator.state_transition(
        mediator_state=current_state,
        state_change=receive_secret,
        channelidentifiers_to_channels=pair.channel_map,
        addresses_to_channel=pair.addresses_to_channel(),
        pseudo_random_generator=pseudo_random_generator,
        block_number=next_block.block_number,
        block_hash=next_block.block_hash,
    )
    current_state = iteration.new_state
    lock = payer_transfer.lock
    secrethash = lock.secrethash
    assert secrethash in payer_channel.partner_state.secrethashes_to_lockedlocks
    assert current_state.transfers_pair[0].payee_state == "payee_expired"
    assert not channel.is_secret_known(payer_channel.partner_state, secrethash)

    assert mediator.is_safe_to_wait(
        lock_expiration=lock.expiration,
        reveal_timeout=payer_channel.reveal_timeout,
        block_number=lock.expiration + 10,
    ).fail

    iteration = mediator.state_transition(
        mediator_state=current_state,
        state_change=next_block,
        channelidentifiers_to_channels=pair.channel_map,
        addresses_to_channel=pair.addresses_to_channel(),
        pseudo_random_generator=pseudo_random_generator,
        block_number=block_expiration_number,
        block_hash=factories.make_block_hash(),
    )
    msg = "At the next block we should not get the same event"
    assert not search_for_item(iteration.events, EventUnlockClaimFailed, {}), msg


def test_regression_onchain_secret_reveal_must_update_channel_state():
    """If a secret is learned off-chain and then on-chain, the state of the
    lock must be updated in the channel.
    """
    pseudo_random_generator = random.Random()

    setup = factories.make_transfers_pair(2, block_number=10)

    mediator_state = MediatorTransferState(
        secrethash=UNIT_SECRETHASH, routes=setup.channels.get_routes()
    )
    mediator_state.transfers_pair = setup.transfers_pair

    secret = UNIT_SECRET
    secrethash = UNIT_SECRETHASH
    payer_channel = mediator.get_payer_channel(setup.channel_map, setup.transfers_pair[0])
    payee_channel = mediator.get_payee_channel(setup.channel_map, setup.transfers_pair[0])
    lock = payer_channel.partner_state.secrethashes_to_lockedlocks[secrethash]

    mediator.state_transition(
        mediator_state=mediator_state,
        state_change=ReceiveSecretReveal(
            secret=secret, sender=payee_channel.partner_state.address
        ),
        channelidentifiers_to_channels=setup.channel_map,
        addresses_to_channel=setup.channels.addresses_to_channel(),
        pseudo_random_generator=pseudo_random_generator,
        block_number=setup.block_number,
        block_hash=setup.block_hash,
    )
    assert secrethash in payer_channel.partner_state.secrethashes_to_unlockedlocks

    secret_registry_address = factories.make_address()
    transaction_hash = factories.make_address()
    mediator.state_transition(
        mediator_state=mediator_state,
        state_change=ContractReceiveSecretReveal(
            transaction_hash=transaction_hash,
            secret_registry_address=secret_registry_address,
            secrethash=secrethash,
            secret=secret,
            block_number=setup.block_number,
            block_hash=setup.block_hash,
        ),
        channelidentifiers_to_channels=setup.channel_map,
        addresses_to_channel=setup.channels.addresses_to_channel(),
        pseudo_random_generator=pseudo_random_generator,
        block_number=setup.block_number,
        block_hash=setup.block_hash,
    )
    assert secrethash in payer_channel.partner_state.secrethashes_to_onchain_unlockedlocks

    # Creates a transfer as it was from the *partner*
    send_lock_expired, _ = channel.create_sendexpiredlock(
        sender_end_state=payer_channel.partner_state,
        locked_lock=lock,
        pseudo_random_generator=pseudo_random_generator,
        chain_id=payer_channel.chain_id,
        token_network_address=payer_channel.token_network_address,
        channel_identifier=payer_channel.identifier,
        recipient=payer_channel.our_state.address,
    )
    assert send_lock_expired
    expired_message = message_from_sendevent(send_lock_expired)
    expired_message.sign(LocalSigner(setup.channels.partner_privatekeys[0]))
    balance_proof = balanceproof_from_envelope(expired_message)

    message_identifier = message_identifier_from_prng(pseudo_random_generator)
    expired_block_number = channel.get_sender_expiration_threshold(lock.expiration)
    mediator.state_transition(
        mediator_state=mediator_state,
        state_change=ReceiveLockExpired(
            sender=balance_proof.sender,  # pylint: disable=no-member
            balance_proof=balance_proof,
            secrethash=secrethash,
            message_identifier=message_identifier,
        ),
        channelidentifiers_to_channels=setup.channel_map,
        addresses_to_channel=setup.channels.addresses_to_channel(),
        pseudo_random_generator=pseudo_random_generator,
        block_number=expired_block_number,
        block_hash=factories.make_block_hash(),
    )
    assert secrethash in payer_channel.partner_state.secrethashes_to_onchain_unlockedlocks
