""" Utilities to make and assert transfers. """
import random

import gevent
import time
from coincurve import PrivateKey

from raiden.constants import UINT64_MAX
from raiden.messages import (
    LockedTransfer,
    Secret,
)
from raiden.message_handler import on_message
from raiden.raiden_service import (
    initiator_init,
    mediator_init,
    target_init,
)

from raiden.tests.utils.events import must_contain_entry
from raiden.transfer import channel, views
from raiden.transfer.mediated_transfer.events import SendLockedTransfer
from raiden.transfer.mediated_transfer.state import lockedtransfersigned_from_message
from raiden.transfer.merkle_tree import compute_layers
from raiden.transfer.state import (
    EMPTY_MERKLE_TREE,
    MerkleTreeState,
    balanceproof_from_envelope,
    NettingChannelState,
)
from raiden.transfer.state_change import ReceiveUnlock
from raiden.utils import sha3


def sign_and_inject(message, key, address, app):
    """Sign the message with key and inject it directly in the app transport layer."""
    message.sign(key)
    on_message(app.raiden, message)


def get_channelstate(app0, app1, token_network_identifier) -> NettingChannelState:
    channel_state = views.get_channelstate_by_token_network_and_partner(
        views.state_from_app(app0),
        token_network_identifier,
        app1.raiden.address,
    )
    return channel_state


def transfer(initiator_app, target_app, token, amount, identifier):
    """ Nice to read shortcut to make a transfer.

    The transfer is either a DirectTransfer or a LockedTransfer, in both
    cases all apps are synched, in the case of a LockedTransfer the secret
    will be revealed.
    """
    payment_network_identifier = initiator_app.raiden.default_registry.address
    token_network_identifier = views.get_token_network_identifier_by_token_address(
        views.state_from_app(initiator_app),
        payment_network_identifier,
        token,
    )
    async_result = initiator_app.raiden.mediated_transfer_async(
        token_network_identifier,
        amount,
        target_app.raiden.address,
        identifier,
    )
    assert async_result.wait()


def direct_transfer(
        initiator_app,
        target_app,
        token_network_identifier,
        amount,
        identifier=None,
        timeout=5,
):
    """ Nice to read shortcut to make a DirectTransfer. """

    channel_state = views.get_channelstate_by_token_network_and_partner(
        views.state_from_app(initiator_app),
        token_network_identifier,
        target_app.raiden.address,
    )
    assert channel_state, 'there is not a direct channel'

    initiator_app.raiden.direct_transfer_async(
        token_network_identifier,
        amount,
        target_app.raiden.address,
        identifier,
    )
    # direct transfers don't have confirmation
    gevent.sleep(timeout)


def mediated_transfer(
        initiator_app,
        target_app,
        token_network_identifier,
        amount,
        identifier=None,
        timeout=5,
):
    """ Nice to read shortcut to make a LockedTransfer.

    The secret will be revealed and the apps will be synchronized."""
    # pylint: disable=too-many-arguments

    async_result = initiator_app.raiden.mediated_transfer_async(
        token_network_identifier,
        amount,
        target_app.raiden.address,
        identifier,
    )
    assert async_result.wait(timeout)
    gevent.sleep(0.3)  # let the other nodes synch


def pending_mediated_transfer(app_chain, token_network_identifier, amount, identifier):
    """ Nice to read shortcut to make a LockedTransfer where the secret is _not_ revealed.

    While the secret is not revealed all apps will be synchronized, meaning
    they are all going to receive the LockedTransfer message.
    Returns:
        The secret used to generate the LockedTransfer
    """
    # pylint: disable=too-many-locals

    if len(app_chain) < 2:
        raise ValueError('Cannot make a LockedTransfer with less than two apps')

    target = app_chain[-1].raiden.address

    # Generate a secret
    initiator_channel = views.get_channelstate_by_token_network_and_partner(
        views.state_from_app(app_chain[0]),
        token_network_identifier,
        app_chain[1].raiden.address,
    )
    address = initiator_channel.identifier
    nonce_int = channel.get_next_nonce(initiator_channel.our_state)
    nonce_bytes = nonce_int.to_bytes(2, 'big')
    secret = sha3(address + nonce_bytes)

    initiator_app = app_chain[0]
    init_initiator_statechange = initiator_init(
        initiator_app.raiden,
        identifier,
        amount,
        secret,
        token_network_identifier,
        target,
    )
    events = initiator_app.raiden.wal.log_and_dispatch(
        init_initiator_statechange,
        initiator_app.raiden.get_block_number(),
    )
    send_transfermessage = must_contain_entry(events, SendLockedTransfer, {})
    transfermessage = LockedTransfer.from_event(send_transfermessage)
    initiator_app.raiden.sign(transfermessage)

    for mediator_app in app_chain[1:-1]:
        mediator_init_statechange = mediator_init(mediator_app.raiden, transfermessage)
        events = mediator_app.raiden.wal.log_and_dispatch(
            mediator_init_statechange,
            mediator_app.raiden.get_block_number(),
        )
        send_transfermessage = must_contain_entry(events, SendLockedTransfer, {})
        transfermessage = LockedTransfer.from_event(send_transfermessage)
        mediator_app.raiden.sign(transfermessage)

    target_app = app_chain[-1]
    mediator_init_statechange = target_init(transfermessage)
    events = target_app.raiden.wal.log_and_dispatch(
        mediator_init_statechange,
        target_app.raiden.get_block_number(),
    )
    return secret


def claim_lock(app_chain, payment_identifier, token_network_identifier, secret):
    """ Unlock a pending transfer. """
    secrethash = sha3(secret)
    for from_, to_ in zip(app_chain[:-1], app_chain[1:]):
        from_channel = get_channelstate(from_, to_, token_network_identifier)
        partner_channel = get_channelstate(to_, from_, token_network_identifier)

        unlock_lock = channel.send_unlock(
            from_channel,
            random.randint(0, UINT64_MAX),
            payment_identifier,
            secret,
            secrethash,
        )

        secret_message = Secret(
            unlock_lock.balance_proof.chain_id,
            unlock_lock.message_identifier,
            unlock_lock.payment_identifier,
            unlock_lock.balance_proof.nonce,
            partner_channel.token_network_identifier,
            unlock_lock.balance_proof.channel_address,
            unlock_lock.balance_proof.transferred_amount,
            unlock_lock.balance_proof.locked_amount,
            unlock_lock.balance_proof.locksroot,
            unlock_lock.secret,
        )
        from_.raiden.sign(secret_message)

        balance_proof = balanceproof_from_envelope(secret_message)
        receive_unlock = ReceiveUnlock(
            message_identifier=random.randint(0, UINT64_MAX),
            secret=unlock_lock.secret,
            balance_proof=balance_proof,
        )

        is_valid, _, msg = channel.handle_unlock(
            partner_channel,
            receive_unlock,
        )
        assert is_valid, msg


def assert_synched_channel_state(
        token_network_identifier,
        app0,
        balance0,
        pending_locks0,
        app1,
        balance1,
        pending_locks1,
):
    """ Assert the values of two synched channels.

    Note:
        This assert does not work for an intermediate state, where one message
        hasn't been delivered yet or has been completely lost."""
    # pylint: disable=too-many-arguments

    channel0 = get_channelstate(app0, app1, token_network_identifier)
    channel1 = get_channelstate(app1, app0, token_network_identifier)

    assert channel0.our_state.contract_balance == channel1.partner_state.contract_balance
    assert channel0.partner_state.contract_balance == channel1.our_state.contract_balance

    total_token = channel0.our_state.contract_balance + channel1.our_state.contract_balance

    our_balance0 = channel.get_balance(channel0.our_state, channel0.partner_state)
    partner_balance0 = channel.get_balance(channel0.partner_state, channel0.our_state)
    assert our_balance0 + partner_balance0 == total_token

    our_balance1 = channel.get_balance(channel1.our_state, channel1.partner_state)
    partner_balance1 = channel.get_balance(channel1.partner_state, channel1.our_state)
    assert our_balance1 + partner_balance1 == total_token

    locked_amount0 = sum(lock.amount for lock in pending_locks0)
    locked_amount1 = sum(lock.amount for lock in pending_locks1)

    assert_balance(channel0, balance0, locked_amount0)
    assert_balance(channel1, balance1, locked_amount1)

    # a participant's outstanding is the other's pending locks.
    assert_locked(channel0, pending_locks0)
    assert_locked(channel1, pending_locks1)

    assert_mirror(channel0, channel1)
    assert_mirror(channel1, channel0)


def wait_assert(*args, func, timeout=5, **kwargs):
    """Like assert_*, but retry and raises the last AssertionError only after timeout"""
    start_time = time.time()
    while True:
        try:
            func(*args, **kwargs)
        except AssertionError:
            if timeout and time.time() > start_time + timeout:
                raise
            gevent.sleep(0.5)
        else:
            return True


def assert_mirror(original, mirror):
    """ Assert that `mirror` has a correct `partner_state` to represent `original`."""
    original_locked_amount = channel.get_amount_locked(original.our_state)
    mirror_locked_amount = channel.get_amount_locked(mirror.partner_state)
    assert original_locked_amount == mirror_locked_amount

    balance0 = channel.get_balance(original.our_state, original.partner_state)
    balance1 = channel.get_balance(mirror.partner_state, mirror.our_state)
    assert balance0 == balance1

    balanceproof0 = channel.get_current_balanceproof(original.our_state)
    balanceproof1 = channel.get_current_balanceproof(mirror.partner_state)
    assert balanceproof0 == balanceproof1

    distributable0 = channel.get_distributable(original.our_state, original.partner_state)
    distributable1 = channel.get_distributable(mirror.partner_state, mirror.our_state)
    assert distributable0 == distributable1


def assert_locked(from_channel, pending_locks):
    """ Assert the locks created from `from_channel`. """
    # a locked transfer is registered in the _partner_ state
    if pending_locks:
        leaves = [sha3(lock.encoded) for lock in pending_locks]
        layers = compute_layers(leaves)
        tree = MerkleTreeState(layers)
    else:
        tree = EMPTY_MERKLE_TREE

    assert from_channel.our_state.merkletree == tree

    for lock in pending_locks:
        pending = lock.secrethash in from_channel.our_state.secrethashes_to_lockedlocks
        unclaimed = lock.secrethash in from_channel.our_state.secrethashes_to_unlockedlocks
        assert pending or unclaimed


def assert_balance(from_channel, balance, locked):
    """ Assert the from_channel overall token values. """
    assert balance >= 0
    assert locked >= 0

    distributable = balance - locked
    channel_distributable = channel.get_distributable(
        from_channel.our_state,
        from_channel.partner_state,
    )

    assert channel.get_balance(from_channel.our_state, from_channel.partner_state) == balance
    assert channel_distributable == distributable
    assert channel.get_amount_locked(from_channel.our_state) == locked

    amount_locked = channel.get_amount_locked(from_channel.our_state)
    assert balance == amount_locked + distributable


def make_mediated_transfer(
        from_channel,
        partner_channel,
        initiator,
        target,
        lock,
        pkey,
        secret=None,
):
    """ Helper to create and register a mediated transfer from `from_channel` to
    `partner_channel`."""
    payment_identifier = channel.get_next_nonce(from_channel.our_state)
    message_identifier = random.randint(0, UINT64_MAX)

    lockedtransfer = channel.send_lockedtransfer(
        from_channel,
        initiator,
        target,
        lock.amount,
        message_identifier,
        payment_identifier,
        lock.expiration,
        lock.secrethash,
    )
    mediated_transfer_msg = LockedTransfer.from_event(lockedtransfer)

    sign_key = PrivateKey(pkey)
    mediated_transfer_msg.sign(sign_key)

    # compute the signature
    balance_proof = balanceproof_from_envelope(mediated_transfer_msg)
    lockedtransfer.balance_proof = balance_proof

    # if this fails it's not the right key for the current `from_channel`
    assert mediated_transfer_msg.sender == from_channel.our_state.address
    receive_lockedtransfer = lockedtransfersigned_from_message(mediated_transfer_msg)

    channel.handle_receive_lockedtransfer(
        partner_channel,
        receive_lockedtransfer,
    )

    if secret is not None:
        secrethash = sha3(secret)

        channel.register_secret(from_channel, secret, secrethash)
        channel.register_secret(partner_channel, secret, secrethash)

    return mediated_transfer_msg
