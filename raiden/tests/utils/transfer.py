""" Utilities to make and assert transfers. """
import random

import gevent

from raiden.constants import UINT64_MAX
from raiden.message_handler import MessageHandler
from raiden.messages import LockedTransfer, LockExpired
from raiden.tests.utils.factories import make_address
from raiden.transfer import channel, views
from raiden.transfer.mediated_transfer.state import (
    LockedTransferSignedState,
    lockedtransfersigned_from_message,
)
from raiden.transfer.mediated_transfer.state_change import ReceiveLockExpired
from raiden.transfer.merkle_tree import MERKLEROOT, compute_layers
from raiden.transfer.state import (
    HashTimeLockState,
    MerkleTreeState,
    NettingChannelState,
    balanceproof_from_envelope,
    make_empty_merkle_tree,
)
from raiden.utils import sha3
from raiden.utils.signer import LocalSigner, Signer


def sign_and_inject(message, signer: Signer, app):
    """Sign the message with key and inject it directly in the app transport layer."""
    message.sign(signer)
    MessageHandler().on_message(app.raiden, message)


def get_channelstate(app0, app1, token_network_identifier) -> NettingChannelState:
    channel_state = views.get_channelstate_by_token_network_and_partner(
        views.state_from_app(app0),
        token_network_identifier,
        app1.raiden.address,
    )
    return channel_state


def transfer(initiator_app, target_app, token, amount, identifier):
    """ Nice to read shortcut to make a transfer.

    The transfer is a LockedTransfer and we make sure,
    all apps are synched. The secret
    will also be revealed.
    """
    payment_network_identifier = initiator_app.raiden.default_registry.address
    token_network_identifier = views.get_token_network_identifier_by_token_address(
        views.state_from_app(initiator_app),
        payment_network_identifier,
        token,
    )
    payment_status = initiator_app.raiden.mediated_transfer_async(
        token_network_identifier,
        amount,
        target_app.raiden.address,
        identifier,
    )
    assert payment_status.payment_done.wait()


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

    payment_status = initiator_app.raiden.mediated_transfer_async(
        token_network_identifier,
        amount,
        target_app.raiden.address,
        identifier,
    )
    assert payment_status.payment_done.wait(timeout), f'timeout for transfer id={identifier}'
    gevent.sleep(0.3)  # let the other nodes synch


def assert_synced_channel_state(
        token_network_identifier,
        app0,
        balance0,
        pending_locks0,
        app1,
        balance1,
        pending_locks1,
):
    """ Assert the values of two synced channels.

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


def wait_assert(func, *args, **kwargs):
    """ Utility to re-run `func` if it raises an assert. Return once `func`
    doesn't hit a failed assert anymore.

    This will loop forever unless a gevent.Timeout is used.
    """
    while True:
        try:
            func(*args, **kwargs)
        except AssertionError as e:
            try:
                gevent.sleep(0.5)
            except gevent.Timeout:
                raise e
        else:
            break


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
        tree = make_empty_merkle_tree()

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

    mediated_transfer_msg.sign(LocalSigner(pkey))

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

        channel.register_offchain_secret(from_channel, secret, secrethash)
        channel.register_offchain_secret(partner_channel, secret, secrethash)

    return mediated_transfer_msg


def make_receive_transfer_mediated(
        channel_state,
        privkey,
        nonce,
        transferred_amount,
        lock,
        merkletree_leaves=None,
        locked_amount=None,
        chain_id=None,
):

    if not isinstance(lock, HashTimeLockState):
        raise ValueError('lock must be of type HashTimeLockState')

    signer = LocalSigner(privkey)
    address = signer.address
    if address not in (channel_state.our_state.address, channel_state.partner_state.address):
        raise ValueError('Private key does not match any of the participants.')

    if merkletree_leaves is None:
        layers = [[lock.lockhash]]
    else:
        assert lock.lockhash in merkletree_leaves
        layers = compute_layers(merkletree_leaves)

    if locked_amount is None:
        locked_amount = lock.amount

    assert locked_amount >= lock.amount

    locksroot = layers[MERKLEROOT][0]

    payment_identifier = nonce
    transfer_target = make_address()
    transfer_initiator = make_address()
    chain_id = chain_id or channel_state.chain_id
    mediated_transfer_msg = LockedTransfer(
        chain_id=chain_id,
        message_identifier=random.randint(0, UINT64_MAX),
        payment_identifier=payment_identifier,
        nonce=nonce,
        token_network_address=channel_state.token_network_identifier,
        token=channel_state.token_address,
        channel_identifier=channel_state.identifier,
        transferred_amount=transferred_amount,
        locked_amount=locked_amount,
        recipient=channel_state.partner_state.address,
        locksroot=locksroot,
        lock=lock,
        target=transfer_target,
        initiator=transfer_initiator,
    )
    mediated_transfer_msg.sign(signer)

    balance_proof = balanceproof_from_envelope(mediated_transfer_msg)

    receive_lockedtransfer = LockedTransferSignedState(
        random.randint(0, UINT64_MAX),
        payment_identifier,
        channel_state.token_address,
        balance_proof,
        lock,
        transfer_initiator,
        transfer_target,
    )

    return receive_lockedtransfer


def make_receive_expired_lock(
        channel_state,
        privkey,
        nonce,
        transferred_amount,
        lock,
        merkletree_leaves=None,
        locked_amount=None,
        chain_id=None,
):

    if not isinstance(lock, HashTimeLockState):
        raise ValueError('lock must be of type HashTimeLockState')

    signer = LocalSigner(privkey)
    address = signer.address
    if address not in (channel_state.our_state.address, channel_state.partner_state.address):
        raise ValueError('Private key does not match any of the participants.')

    if merkletree_leaves is None:
        layers = make_empty_merkle_tree().layers
    else:
        assert lock.lockhash not in merkletree_leaves
        layers = compute_layers(merkletree_leaves)

    locksroot = layers[MERKLEROOT][0]

    chain_id = chain_id or channel_state.chain_id
    lock_expired_msg = LockExpired(
        chain_id=chain_id,
        nonce=nonce,
        message_identifier=random.randint(0, UINT64_MAX),
        transferred_amount=transferred_amount,
        locked_amount=locked_amount,
        locksroot=locksroot,
        channel_identifier=channel_state.identifier,
        token_network_address=channel_state.token_network_identifier,
        recipient=channel_state.partner_state.address,
        secrethash=lock.secrethash,
    )
    lock_expired_msg.sign(signer)

    balance_proof = balanceproof_from_envelope(lock_expired_msg)

    receive_lockedtransfer = ReceiveLockExpired(
        balance_proof=balance_proof,
        secrethash=lock.secrethash,
        message_identifier=random.randint(0, UINT64_MAX),
    )

    return receive_lockedtransfer
