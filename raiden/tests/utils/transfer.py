""" Utilities to make and assert transfers. """
from __future__ import print_function

import gevent
from coincurve import PrivateKey

from raiden.mtree import Merkletree
from raiden.utils import sha3, privatekey_to_address
from raiden.channel.netting_channel import Channel


def channel(app0, app1, token):
    """ Nice to read shortcut to get the channel. """
    graph = app0.raiden.channelgraphs[token]
    return graph.partneraddress_channel[app1.raiden.address]


def sleep(initiator_app, target_app, token, multiplier=1):
    """ Sleep long enough to conclude a transfer from `initiator_app` to
    `target_app`.
    """
    graph = initiator_app.raiden.channelgraphs[token]
    path = list(graph.channelgraph.get_shortest_paths(
        initiator_app.raiden.address,
        target_app.raiden.address,
    ))

    # 0.2 should be rougly how long it takes to process the transfer in a
    # single node
    sleep_time = 0.2 * len(path) * multiplier
    gevent.sleep(sleep_time)


def get_sent_transfer(app_channel, transfer_number):
    assert isinstance(app_channel, Channel)
    return app_channel.sent_transfers[transfer_number]


def get_received_transfer(app_channel, transfer_number):
    return app_channel.received_transfers[transfer_number]


def transfer(initiator_app, target_app, token, amount, identifier):
    """ Nice to read shortcut to make a transfer.

    The transfer is either a DirectTransfer or a MediatedTransfer, in both
    cases all apps are synched, in the case of a MediatedTransfer the secret
    will be revealed.
    """

    async_result = initiator_app.raiden.transfer_async(
        token,
        amount,
        target_app.raiden.address,
        identifier
    )
    assert async_result.wait()


def direct_transfer(initiator_app, target_app, token, amount, identifier=None):
    """ Nice to read shortcut to make a DirectTransfer. """
    graph = initiator_app.raiden.channelgraphs[token]
    has_channel = target_app.raiden.address in graph.partneraddress_channel
    assert has_channel, 'there is not a direct channel'

    async_result = initiator_app.raiden.transfer_async(
        token,
        amount,
        target_app.raiden.address,
        identifier,
    )
    assert async_result.wait()


def mediated_transfer(initiator_app, target_app, token, amount, identifier=None):
    """ Nice to read shortcut to make a MediatedTransfer.

    The secret will be revealed and the apps will be synchronized.
    """
    # pylint: disable=too-many-arguments

    graph = initiator_app.raiden.channelgraphs[token]
    has_channel = target_app.raiden.address in graph.partneraddress_channel

    if has_channel:
        raise NotImplementedError(
            "There is a direct channel with the target, skipping mediated transfer."
        )

    else:
        async_result = initiator_app.raiden.transfer_async(
            token,
            amount,
            target_app.raiden.address,
            identifier
        )
        assert async_result.wait()


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
    hashroot = Merkletree(sha3(lock.as_bytes) for lock in outstanding_locks).merkleroot

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


def increase_transferred_amount(from_channel, to_channel, amount):
    """ Helper to increase the transferred_amount of the channels without the
    need of creating/signing/register transfers.
    """
    from_channel.our_state.transferred_amount += amount
    to_channel.partner_state.transferred_amount += amount


def make_direct_transfer_from_channel(channel, partner_channel, amount, pkey):
    """ Helper to create and register a direct transfer from `channel` to
    `partner_channel`.
    """
    identifier = channel.our_state.nonce

    direct_transfer = channel.create_directtransfer(
        amount,
        identifier=identifier,
    )

    address = privatekey_to_address(pkey)
    sign_key = PrivateKey(pkey)
    direct_transfer.sign(sign_key, address)

    # if this fails it's not the right key for the current `channel`
    assert direct_transfer.sender == channel.our_state.address

    channel.register_transfer(direct_transfer)
    partner_channel.register_transfer(direct_transfer)

    return direct_transfer


def make_mediated_transfer(
        channel,
        partner_channel,
        initiator,
        target,
        lock,
        pkey,
        block_number,
        secret=None):
    """ Helper to create and register a mediated transfer from `channel` to
    `partner_channel`.
    """
    identifier = channel.our_state.nonce
    fee = 0

    mediated_transfer = channel.create_mediatedtransfer(
        initiator,
        target,
        fee,
        lock.amount,
        identifier,
        lock.expiration,
        lock.hashlock,
    )

    address = privatekey_to_address(pkey)
    sign_key = PrivateKey(pkey)
    mediated_transfer.sign(sign_key, address)

    channel.block_number = block_number
    partner_channel.block_number = block_number

    # if this fails it's not the right key for the current `channel`
    assert mediated_transfer.sender == channel.our_state.address

    channel.register_transfer(mediated_transfer)
    partner_channel.register_transfer(mediated_transfer)

    if secret is not None:
        channel.register_secret(secret)
        partner_channel.register_secret(secret)

    return mediated_transfer
