""" Utilities to make and assert transfers. """
from __future__ import print_function

import gevent
from gevent.event import AsyncResult

from raiden.utils import sha3
from raiden.mtree import merkleroot
from raiden.tasks import StartMediatedTransferTask


def channel(app0, app1, token):
    """ Nice to read shortcut to get the channel. """
    token_manager = app0.raiden.managers_by_token_address[token]
    return token_manager.partneraddress_channel[app1.raiden.address]


def sleep(initiator_app, target_app, token, multiplier=1):
    """ Sleep long enough to conclude a transfer from `initiator_app` to
    `target_app`.
    """
    tokenmanager = initiator_app.raiden.managers_by_token_address[token]
    path = list(tokenmanager.channelgraph.get_shortest_paths(
        initiator_app.raiden.address,
        target_app.raiden.address,
    ))

    # 0.2 should be rougly how long it takes to process the transfer in a
    # single node
    sleep_time = 0.2 * len(path) * multiplier
    gevent.sleep(sleep_time)


def get_sent_transfer(app_channel, transfer_number):
    return app_channel.sent_transfers[transfer_number]


def get_received_transfer(app_channel, transfer_number):
    return app_channel.received_transfers[transfer_number]


def transfer(initiator_app, target_app, token, amount, identifier):
    """ Nice to read shortcut to make a transfer.

    The transfer is either a DirectTransfer or a MediatedTransfer, in both
    cases all apps are synched, in the case of a MediatedTransfer the secret
    will be revealed.
    """

    initiator_app.raiden.api.transfer(
        token,
        amount,
        target_app.raiden.address,
        identifier
    )


def direct_transfer(initiator_app, target_app, token, amount, identifier=None):
    """ Nice to read shortcut to make a DirectTransfer. """
    tokenmanager = initiator_app.raiden.managers_by_token_address[token]
    has_channel = target_app.raiden.address in tokenmanager.partneraddress_channel
    assert has_channel, 'there is not a direct channel'

    initiator_app.raiden.api.transfer(
        token,
        amount,
        target_app.raiden.address,
        identifier,
    )


def mediated_transfer(initiator_app, target_app, token, amount, identifier=None):
    """ Nice to read shortcut to make a MediatedTransfer.

    The secret will be revealed and the apps will be synchronized.
    """
    # pylint: disable=too-many-arguments

    tokenmanager = initiator_app.raiden.managers_by_token_address[token]
    has_channel = initiator_app.raiden.address in tokenmanager.partneraddress_channel

    # api.transfer() would do a DirectTransfer
    if has_channel:
        transfermanager = tokenmanager.transfermanager
        # Explicitly call the default identifier creation since this mock
        # function here completely skips the `transfer_async()` call.
        if not identifier:
            identifier = initiator_app.raiden.api.create_default_identifier(
                target_app.raiden.address,
                token
            )

        result = AsyncResult()
        task = StartMediatedTransferTask(
            transfermanager,
            amount,
            identifier,
            target_app.raiden.address,
            result,
        )
        task.start()
        result.wait()
    else:
        initiator_app.raiden.api.transfer(
            token,
            amount,
            target_app.raiden.address,
            identifier
        )


def pending_mediated_transfer(app_chain, token, amount, identifier, expiration):
    """ Nice to read shortcut to make a MediatedTransfer were the secret is
    _not_ revealed.

    While the secret is not revealed all apps will be synchronized, meaning
    they are all going to receive the MediatedTransfer message.

    Returns:
        The secret used to generate the MediatedTransfer
    """
    # pylint: disable=too-many-locals

    if len(app_chain) < 2:
        raise ValueError('Cannot make a MediatedTransfer with less than two apps')

    fee = 0
    secret = None
    hashlock = None
    initiator_app = app_chain[0]
    target_app = app_chain[0]

    for from_app, to_app in zip(app_chain[:-1], app_chain[1:]):
        from_channel = channel(from_app, to_app, token)
        to_channel = channel(to_app, from_app, token)

        # use the initiator channel to generate a secret
        if secret is None:
            address = from_channel.external_state.netting_channel.address
            nonce = str(from_channel.our_state.nonce)
            secret = sha3(address + nonce)
            hashlock = sha3(secret)

        transfer_ = from_channel.create_mediatedtransfer(
            initiator_app.raiden.address,
            target_app.raiden.address,
            fee,
            amount,
            identifier,
            expiration,
            hashlock,
        )
        from_app.raiden.sign(transfer_)
        from_channel.register_transfer(transfer_)
        to_channel.register_transfer(transfer_)

    return secret


def claim_lock(app_chain, token, secret):
    """ Unlock a pending transfer. """
    for from_, to_ in zip(app_chain[:-1], app_chain[1:]):
        channel_ = channel(from_, to_, token)
        withdraw_or_unlock(channel_, secret)

        channel_ = channel(to_, from_, token)
        withdraw_or_unlock(channel_, secret)


def assert_identifier_correct(initiator_app, token, target, expected_id):
    got_id = initiator_app.raiden.api.create_default_identifier(target, token)
    assert got_id == expected_id


def withdraw_or_unlock(channel_, secret):
    hashlock = sha3(secret)

    if channel_.our_state.balance_proof.is_pending(hashlock):
        channel_.withdraw_lock(secret)

    if channel_.partner_state.balance_proof.is_pending(hashlock):
        channel_.release_lock(secret)


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

    assert_locked(channel0, outstanding_locks0)
    assert_locked(channel1, outstanding_locks1)

    assert_mirror(channel0, channel1)


def assert_mirror(channel0, channel1):
    """ Assert that `channel0` has a correct `partner_state` to represent
    `channel1` and vice-versa.
    """
    unclaimed0 = channel0.our_state.balance_proof.merkleroot_for_unclaimed()
    unclaimed1 = channel1.partner_state.balance_proof.merkleroot_for_unclaimed()
    assert unclaimed0 == unclaimed1

    assert channel0.our_state.locked() == channel1.partner_state.locked()
    assert channel0.our_state.transferred_amount == channel1.partner_state.transferred_amount

    balance0 = channel0.our_state.balance(channel0.partner_state)
    balance1 = channel1.partner_state.balance(channel1.our_state)
    assert balance0 == balance1

    assert channel0.distributable == channel0.our_state.distributable(channel0.partner_state)
    assert channel0.distributable == channel1.partner_state.distributable(channel1.our_state)

    unclaimed1 = channel1.our_state.balance_proof.merkleroot_for_unclaimed()
    unclaimed0 = channel0.partner_state.balance_proof.merkleroot_for_unclaimed()
    assert unclaimed1 == unclaimed0

    assert channel1.our_state.locked() == channel0.partner_state.locked()
    assert channel1.our_state.transferred_amount == channel0.partner_state.transferred_amount

    balance1 = channel1.our_state.balance(channel1.partner_state)
    balance0 = channel0.partner_state.balance(channel0.our_state)
    assert balance1 == balance0

    assert channel1.distributable == channel1.our_state.distributable(channel1.partner_state)
    assert channel1.distributable == channel0.partner_state.distributable(channel0.our_state)


def assert_locked(channel0, outstanding_locks):
    """ Assert the locks create from `channel`. """
    # a locked transfer is registered in the _partner_ state
    hashroot = merkleroot(sha3(lock.as_bytes) for lock in outstanding_locks)

    assert len(channel0.our_state.balance_proof.hashlock_pendinglocks) == len(outstanding_locks)
    assert channel0.our_state.balance_proof.merkleroot_for_unclaimed() == hashroot
    assert channel0.our_state.locked() == sum(lock.amount for lock in outstanding_locks)
    assert channel0.outstanding == sum(lock.amount for lock in outstanding_locks)

    for lock in outstanding_locks:
        assert lock.hashlock in channel0.our_state.balance_proof.hashlock_pendinglocks


def assert_balance(channel0, balance, outstanding, distributable):
    """ Assert the channel0 overall token values. """
    assert channel0.balance == balance
    assert channel0.distributable == distributable
    assert channel0.outstanding == outstanding

    # the amount of token locked in our end of the channel is equal to how much
    # we have outstading
    assert channel0.our_state.locked() == outstanding

    assert channel0.balance == channel0.our_state.balance(channel0.partner_state)
    assert channel0.distributable == channel0.our_state.distributable(channel0.partner_state)

    assert channel0.balance >= 0
    assert channel0.distributable >= 0
    assert channel0.locked >= 0
    assert channel0.balance == channel0.locked + channel0.distributable
