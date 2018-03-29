""" Utilities to make and assert transfers. """
from coincurve import PrivateKey

from raiden.channel.netting_channel import Channel
from raiden.messages import DirectTransfer
from raiden.messages import MediatedTransfer
from raiden.tests.utils.factories import make_address
from raiden.transfer import channel, views
from raiden.transfer.events import SendDirectTransfer
from raiden.transfer.mediated_transfer.state import lockedtransfersigned_from_message
from raiden.transfer.mediated_transfer.state_change import ReceiveSecretReveal
from raiden.transfer.merkle_tree import (
    compute_layers,
    merkleroot,
)
from raiden.transfer.state import (
    EMPTY_MERKLE_ROOT,
    MerkleTreeState,
    balanceproof_from_envelope,
)
from raiden.transfer.state_change import (
    ActionTransferDirect2,
    ReceiveTransferDirect2,
)
from raiden.utils import sha3, privatekey_to_address


def get_sent_transfer(app_channel, transfer_number):
    assert isinstance(app_channel, Channel)
    return app_channel.sent_transfers[transfer_number]


def get_received_transfer(app_channel, transfer_number):
    return app_channel.received_transfers[transfer_number]


def get_channelstate(app0, app1, token_address) -> 'NettingChannelState':
    registry_address = app0.raiden.default_registry.address
    channel_state = views.get_channelstate_for(
        views.state_from_app(app0),
        registry_address,
        token_address,
        app1.raiden.address,
    )
    return channel_state


def transfer(initiator_app, target_app, token, amount, identifier):
    """ Nice to read shortcut to make a transfer.

    The transfer is either a DirectTransfer or a MediatedTransfer, in both
    cases all apps are synched, in the case of a MediatedTransfer the secret
    will be revealed.
    """

    async_result = initiator_app.raiden.mediated_transfer_async(
        token,
        amount,
        target_app.raiden.address,
        identifier
    )
    assert async_result.wait()


def assert_synched_channels(channel0, balance0, outstanding_locks0, channel1,
                            balance1, outstanding_locks1):
    """ Assert the values of two synched channels.

    Note:
        This assert does not work if for a intermediate state, were one message
        hasn't being delivered yet or has been completely lost.
    """
    # pylint: disable=too-many-arguments

    total_token = channel0.contract_balance + channel1.contract_balance
    assert total_token == channel0.balance + channel1.balance

    locked_amount0 = sum(lock.amount for lock in outstanding_locks0)
    locked_amount1 = sum(lock.amount for lock in outstanding_locks1)

    assert_balance(channel0, balance0, locked_amount0, channel0.balance - locked_amount1)
    assert_balance(channel1, balance1, locked_amount1, channel1.balance - locked_amount0)

    # a participant's outstanding is the other's pending locks.
    pending_locks0 = outstanding_locks1
    pending_locks1 = outstanding_locks0

    assert_locked(channel0, pending_locks0)
    assert_locked(channel1, pending_locks1)

    assert_mirror(channel0, channel1)


def assert_mirror(channel0, channel1):
    """ Assert that `channel0` has a correct `partner_state` to represent
    `channel1` and vice-versa.
    """
    unclaimed0 = merkleroot(channel0.our_state.merkletree)
    unclaimed1 = merkleroot(channel1.partner_state.merkletree)
    assert unclaimed0 == unclaimed1

    assert channel0.our_state.amount_locked == channel1.partner_state.amount_locked
    assert channel0.transferred_amount == channel1.partner_state.transferred_amount

    balance0 = channel0.our_state.balance(channel0.partner_state)
    balance1 = channel1.partner_state.balance(channel1.our_state)
    assert balance0 == balance1

    assert channel0.distributable == channel0.our_state.distributable(channel0.partner_state)
    assert channel0.distributable == channel1.partner_state.distributable(channel1.our_state)

    unclaimed1 = merkleroot(channel1.our_state.merkletree)
    unclaimed0 = merkleroot(channel0.partner_state.merkletree)
    assert unclaimed1 == unclaimed0

    assert channel1.our_state.amount_locked == channel0.partner_state.amount_locked
    assert channel1.transferred_amount == channel0.partner_state.transferred_amount

    balance1 = channel1.our_state.balance(channel1.partner_state)
    balance0 = channel0.partner_state.balance(channel0.our_state)
    assert balance1 == balance0

    assert channel1.distributable == channel1.our_state.distributable(channel1.partner_state)
    assert channel1.distributable == channel0.partner_state.distributable(channel0.our_state)


def assert_locked(from_channel, pending_locks):
    """ Assert the locks created from `from_channel`. """
    # a locked transfer is registered in the _partner_ state
    if pending_locks:
        leaves = [sha3(lock.as_bytes) for lock in pending_locks]
        layers = compute_layers(leaves)
        tree = MerkleTreeState(layers)
        root = merkleroot(tree)
    else:
        root = EMPTY_MERKLE_ROOT

    assert len(from_channel.our_state.hashlocks_to_pendinglocks) == len(
        pending_locks
    )
    assert merkleroot(from_channel.our_state.merkletree) == root
    assert from_channel.our_state.amount_locked == sum(lock.amount for lock in pending_locks)
    assert from_channel.locked == sum(lock.amount for lock in pending_locks)

    for lock in pending_locks:
        assert lock.hashlock in from_channel.our_state.hashlocks_to_pendinglocks


def assert_balance(from_channel, balance, outstanding, distributable):
    """ Assert the from_channel overall token values. """
    assert from_channel.balance == balance
    assert from_channel.distributable == distributable
    assert from_channel.outstanding == outstanding

    # the amount of token locked in the partner end of the from_channel is equal to how much
    # we have outstanding
    assert from_channel.partner_state.amount_locked == outstanding

    assert from_channel.balance == from_channel.our_state.balance(from_channel.partner_state)

    distributable = from_channel.our_state.distributable(from_channel.partner_state)
    assert from_channel.distributable == distributable

    assert from_channel.balance >= 0
    assert from_channel.distributable >= 0
    assert from_channel.locked >= 0
    assert from_channel.balance == from_channel.locked + from_channel.distributable


def increase_transferred_amount(from_channel, partner_channel, amount, pkey):
    # increasing the transferred amount by a value larger than distributable
    # would put one end of the channel in a negative balance, which is
    # forbidden
    distributable_from_to = channel.get_distributable(
        from_channel.our_state,
        from_channel.partner_state,
    )
    assert distributable_from_to >= amount, 'operation would end up in a incosistent state'

    identifier = 1
    event = channel.send_directtransfer(
        from_channel,
        amount,
        identifier,
    )

    direct_transfer_message = DirectTransfer.from_event(event)
    address = privatekey_to_address(pkey)
    sign_key = PrivateKey(pkey)
    direct_transfer_message.sign(sign_key, address)

    # if this fails it's not the right key for the current `from_channel`
    assert direct_transfer_message.sender == from_channel.our_state.address

    balance_proof = balanceproof_from_envelope(direct_transfer_message)
    receive_direct = ReceiveTransferDirect2(
        identifier,
        balance_proof,
    )

    channel.handle_receive_directtransfer(
        partner_channel,
        receive_direct,
    )

    return direct_transfer_message


def make_direct_transfer_from_channel(from_channel, partner_channel, amount, pkey):
    """ Helper to create and register a direct transfer from `from_channel` to
    `partner_channel`.
    """
    identifier = channel.get_next_nonce(from_channel.our_state)

    state_change = ActionTransferDirect2(
        from_channel.partner_state.address,
        identifier,
        amount,
    )
    iteration = channel.handle_send_directtransfer(
        from_channel,
        state_change,
    )
    assert isinstance(iteration.events[0], SendDirectTransfer)
    direct_transfer_message = DirectTransfer.from_event(iteration.events[0])

    address = privatekey_to_address(pkey)
    sign_key = PrivateKey(pkey)
    direct_transfer_message.sign(sign_key, address)

    # if this fails it's not the right key for the current `from_channel`
    assert direct_transfer_message.sender == from_channel.our_state.address

    balance_proof = balanceproof_from_envelope(direct_transfer_message)
    receive_direct = ReceiveTransferDirect2(
        identifier,
        balance_proof,
    )

    channel.handle_receive_directtransfer(
        partner_channel,
        receive_direct,
    )

    return direct_transfer_message


def make_mediated_transfer(
        from_channel,
        partner_channel,
        initiator,
        target,
        lock,
        pkey,
        secret=None):
    """ Helper to create and register a mediated transfer from `from_channel` to
    `partner_channel`.
    """
    identifier = channel.get_next_nonce(from_channel.our_state)

    mediatedtransfer = channel.send_mediatedtransfer(
        from_channel,
        initiator,
        target,
        lock.amount,
        identifier,
        lock.expiration,
        lock.hashlock,
    )
    mediated_transfer_msg = MediatedTransfer.from_event(mediatedtransfer)

    address = privatekey_to_address(pkey)
    sign_key = PrivateKey(pkey)
    mediated_transfer_msg.sign(sign_key, address)

    # compute the signature
    balance_proof = balanceproof_from_envelope(mediated_transfer_msg)
    mediatedtransfer.balance_proof = balance_proof

    # if this fails it's not the right key for the current `from_channel`
    assert mediated_transfer_msg.sender == from_channel.our_state.address
    receive_mediatedtransfer = lockedtransfersigned_from_message(mediated_transfer_msg)

    channel.handle_receive_mediatedtransfer(
        partner_channel,
        receive_mediatedtransfer,
    )

    if secret is not None:
        random_sender = make_address()

        from_secretreveal = ReceiveSecretReveal(secret, random_sender)
        channel.handle_receive_secretreveal(from_channel, from_secretreveal)

        partner_secretreveal = ReceiveSecretReveal(secret, random_sender)
        channel.handle_receive_secretreveal(partner_channel, partner_secretreveal)

    return mediated_transfer_msg
