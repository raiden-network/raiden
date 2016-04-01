# -*- coding: utf8 -*-
from __future__ import print_function

import time

from raiden.mtree import merkleroot
from raiden.app import create_network
from raiden.utils import sha3

# pylint: disable=too-many-locals


def test_setup():
    apps = create_network(num_nodes=2, num_assets=1, channels_per_node=1)
    app0, app1 = apps  # pylint: disable=unbalanced-tuple-unpacking

    channel0 = app0.raiden.chain.contracts_by_asset_participant(
        app0.raiden.chain.asset_addresses[0],
        app0.raiden.address,
    )
    channel1 = app0.raiden.chain.contracts_by_asset_participant(
        app0.raiden.chain.asset_addresses[0],
        app1.raiden.address,
    )

    assert channel0 and channel1
    assert app0.raiden.assetmanagers.keys() == app1.raiden.assetmanagers.keys()
    assert len(app0.raiden.assetmanagers) == 1


def test_transfer():
    apps = create_network(num_nodes=2, num_assets=1, channels_per_node=1)

    app0, app1 = apps  # pylint: disable=unbalanced-tuple-unpacking
    channel0 = app0.raiden.assetmanagers.values()[0].channels.values()[0]
    channel1 = app1.raiden.assetmanagers.values()[0].channels.values()[0]

    assert channel0.contract == channel1.contract
    assert channel0.balance == channel0.contract.participants[channel0.address]['deposit']
    assert channel1.balance == channel1.contract.participants[channel1.address]['deposit']
    assert channel0.balance == channel0.distributable
    assert channel1.balance == channel1.distributable

    amount = 10
    assert amount < channel0.distributable

    balance0, balance1 = channel0.balance, channel1.balance
    partner_balance0, partner_balance1 = channel0.partner.balance, channel1.partner.balance

    assert balance0 == partner_balance1
    assert balance1 == partner_balance0

    transfer = channel0.create_transfer(amount=amount)
    channel0.raiden.sign(transfer)
    channel0.register_transfer(transfer)
    channel1.register_transfer(transfer)

    assert channel0.balance == balance0 - amount
    assert channel0.balance == channel0.distributable
    assert channel0.balance == channel1.partner.balance
    assert channel0.locked.outstanding == 0

    assert channel1.balance == balance1 + amount
    assert channel1.balance == channel0.partner.balance
    assert channel1.balance == channel1.distributable
    assert channel1.locked.outstanding == 0


def test_locked_transfer():
    apps = create_network(num_nodes=2, num_assets=1, channels_per_node=1)
    app0, app1 = apps  # pylint: disable=unbalanced-tuple-unpacking
    channel0 = app0.raiden.assetmanagers.values()[0].channels.values()[0]
    channel1 = app1.raiden.assetmanagers.values()[0].channels.values()[0]

    amount = 10
    expiration = app0.raiden.chain.block_number + 100

    secret = 'secret'
    hashlock = sha3(secret)

    balance0 = channel0.balance
    balance1 = channel1.balance
    locked_transfer = channel0.create_lockedtransfer(
        amount=amount,
        expiration=expiration,
        hashlock=hashlock,
    )

    channel0.raiden.sign(locked_transfer)
    channel0.register_transfer(locked_transfer)
    channel1.register_transfer(locked_transfer)

    assert hashlock in channel1.locked
    assert hashlock in channel0.partner.locked
    # the locked transfer is only registered in the receiving side
    # assert hashlock in channel0.locked
    # assert hashlock in channel1.partner.locked

    root1 = merkleroot([
        sha3(transaction.lock.asstring)
        for transaction in channel1.locked.locked.values()
    ])

    assert channel0.balance == balance0
    assert channel0.distributable == balance0 - amount
    assert len(channel0.locked) == 0
    assert channel0.locked.outstanding == 0
    assert channel0.locked.root == ''

    assert channel1.balance == balance1
    assert channel1.distributable == balance1
    assert channel1.locked.outstanding == amount
    assert len(channel1.locked) == 1
    assert channel1.locked.root == root1

    assert channel0.partner.balance == balance1
    assert channel0.partner.distributable == balance1
    assert len(channel0.partner.locked) == 1
    assert channel0.partner.locked.outstanding == amount
    assert channel0.partner.locked.root == root1

    assert channel1.partner.balance == balance0
    assert channel1.partner.distributable == balance0 - amount
    assert len(channel1.partner.locked) == 0
    assert channel1.partner.locked.outstanding == 0
    assert channel1.partner.locked.root == ''

    # reveal secret
    channel0.claim_locked(secret)
    channel1.claim_locked(secret)

    assert channel0.balance == balance0 - amount
    assert channel0.distributable == balance0 - amount
    assert len(channel0.locked) == 0
    assert channel0.locked.outstanding == 0
    assert channel0.locked.root == ''

    assert channel1.balance == balance1 + amount
    assert channel1.distributable == balance1 + amount
    assert channel1.locked.outstanding == 0
    assert len(channel1.locked) == 0
    assert channel1.locked.root == ''

    assert channel0.partner.balance == balance1 + amount
    assert channel0.partner.distributable == balance1 + amount
    assert len(channel0.partner.locked) == 0
    assert channel0.partner.locked.outstanding == 0
    assert channel0.partner.locked.root == ''

    assert channel1.partner.balance == balance0 - amount
    assert channel1.partner.distributable == balance0 - amount
    assert len(channel1.partner.locked) == 0
    assert channel1.partner.locked.outstanding == 0
    assert channel1.partner.locked.root == ''


def test_interwoven_transfers(num=100):
    apps = create_network(num_nodes=2, num_assets=1, channels_per_node=1)
    app0, app1 = apps  # pylint: disable=unbalanced-tuple-unpacking
    channel0 = app0.raiden.assetmanagers.values()[0].channels.values()[0]
    channel1 = app1.raiden.assetmanagers.values()[0].channels.values()[0]
    balance0, balance1 = channel0.balance, channel1.balance

    amounts = range(1, num + 1)
    secrets = [str(i) for i in range(num)]
    expiration = app0.raiden.chain.block_number + 100
    claimed = []

    for i, amount in enumerate(amounts):
        hashlock = sha3(secrets[i])
        locked_transfer = channel0.create_lockedtransfer(
            amount=amount,
            expiration=expiration,
            hashlock=hashlock,
        )
        channel0.raiden.sign(locked_transfer)
        channel0.register_transfer(locked_transfer)
        channel1.register_transfer(locked_transfer)

        claimed_amount = sum(amounts[j] for j in claimed)
        distributed_amount = sum(amounts[:i + 1])

        assert channel0.balance == balance0 - claimed_amount
        assert channel0.distributable == balance0 - distributed_amount
        assert channel0.distributable == channel0.balance - distributed_amount + claimed_amount
        assert channel0.locked.outstanding == 0
        assert channel0.partner.locked.root == channel1.locked.root

        assert channel1.balance == channel1.distributable
        assert channel1.balance == balance1 + claimed_amount
        assert channel1.locked.outstanding == channel0.partner.locked.outstanding
        assert channel1.locked.outstanding == distributed_amount - claimed_amount
        assert channel1.partner.locked.outstanding == 0

        if i > 0 and i % 2 == 0:
            idx = i - 1
            claimed.append(idx)
            secret = secrets[idx]
            channel0.claim_locked(secret)
            channel1.claim_locked(secret)


def transfer_speed(num_transfers=100, max_locked=100):

    apps = create_network(num_nodes=2, num_assets=1, channels_per_node=1)
    app0, app1 = apps  # pylint: disable=unbalanced-tuple-unpacking
    channel0 = app0.raiden.assetmanagers.values()[0].channels.values()[0]
    channel1 = app1.raiden.assetmanagers.values()[0].channels.values()[0]

    amounts = [a % 100 + 1 for a in range(1, num_transfers + 1)]
    secrets = [str(i) for i in range(num_transfers)]
    expiration = app0.raiden.chain.block_number + 100

    start = time.time()

    for i, amount in enumerate(amounts):
        hashlock = sha3(secrets[i])
        locked_transfer = channel0.create_lockedtransfer(
            amount=amount,
            expiration=expiration,
            hashlock=hashlock,
        )
        channel0.raiden.sign(locked_transfer)
        channel0.register_transfer(locked_transfer)
        channel1.register_transfer(locked_transfer)

        if i > max_locked:
            idx = i - max_locked
            secret = secrets[idx]
            channel0.claim_locked(secret)
            channel1.claim_locked(secret)

    elapsed = time.time() - start
    print('%d transfers per second' % (num_transfers / elapsed))


if __name__ == '__main__':
    transfer_speed(10000, 100)
