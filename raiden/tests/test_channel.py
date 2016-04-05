# -*- coding: utf8 -*-
from __future__ import print_function

import time

import pytest

from raiden.mtree import merkleroot
from raiden.app import create_network
from raiden.utils import sha3
from raiden.messages import DirectTransfer

# pylint: disable=too-many-locals,too-many-statements,line-too-long


def test_setup():
    apps = create_network(num_nodes=2, num_assets=1, channels_per_node=1)
    app0, app1 = apps  # pylint: disable=unbalanced-tuple-unpacking

    channel0 = app0.raiden.chain.nettingaddresses_by_asset_participant(
        app0.raiden.chain.asset_addresses[0],
        app0.raiden.address,
    )
    channel1 = app0.raiden.chain.nettingaddresses_by_asset_participant(
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

    our_state0 = channel0.our_state
    our_state1 = channel1.our_state

    partner_state0 = channel0.partner_state
    partner_state1 = channel1.partner_state

    address0 = our_state0.address
    address1 = our_state1.address

    balance0 = our_state0.balance
    balance1 = our_state1.balance

    # check agreement on addresses
    assert channel0.asset_address == channel1.asset_address
    assert app0.raiden.assetmanagers.keys()[0] == app1.raiden.assetmanagers.keys()[0]
    assert app0.raiden.assetmanagers.values()[0].channels.keys()[0] == app1.raiden.address
    assert app1.raiden.assetmanagers.values()[0].channels.keys()[0] == app0.raiden.address

    # check balances of channel and contract are equal
    details0 = app0.raiden.chain.netting_contract_detail(
        channel0.asset_address,
        channel0.nettingcontract_address,
        address0,
    )
    details1 = app0.raiden.chain.netting_contract_detail(
        channel1.asset_address,
        channel1.nettingcontract_address,
        address1,
    )
    assert our_state0.initial_balance == details0['our_balance']
    assert our_state1.initial_balance == details1['our_balance']

    # check balances
    assert our_state0.balance == details0['our_balance']
    assert our_state1.balance == details1['our_balance']
    assert our_state0.distributable(partner_state0) == our_state0.balance
    assert our_state1.distributable(partner_state1) == our_state1.balance
    assert our_state0.locked.outstanding == 0
    assert our_state1.locked.outstanding == 0
    assert our_state0.locked.root == ''
    assert our_state1.locked.root == ''

    # check hashlock are empty
    assert len(our_state0.locked) == 0
    assert len(our_state1.locked) == 0
    assert len(partner_state0.locked) == 0
    assert len(partner_state1.locked) == 0

    # check the mirrors
    assert our_state0.balance == partner_state1.balance
    assert our_state1.balance == partner_state0.balance
    assert our_state0.locked.outstanding == partner_state1.locked.outstanding
    assert our_state1.locked.outstanding == partner_state0.locked.outstanding
    assert our_state0.locked.root == partner_state1.locked.root
    assert our_state1.locked.root == partner_state0.locked.root
    assert our_state0.distributable(partner_state0) == partner_state1.distributable(our_state1)
    assert partner_state0.distributable(our_state0) == our_state1.distributable(partner_state1)

    amount = 10
    assert amount < our_state0.distributable(partner_state0)

    direct_transfer = channel0.create_directtransfer(amount=amount)
    app0.raiden.sign(direct_transfer)
    channel0.register_transfer(direct_transfer)
    channel1.register_transfer(direct_transfer)

    # check the contract is intact
    details0 = app0.raiden.chain.netting_contract_detail(
        channel0.asset_address,
        channel0.nettingcontract_address,
        address0,
    )
    details1 = app0.raiden.chain.netting_contract_detail(
        channel1.asset_address,
        channel1.nettingcontract_address,
        address1,
    )
    assert our_state0.initial_balance == details0['our_balance']
    assert our_state1.initial_balance == details1['our_balance']

    # check new balances
    assert our_state0.balance == balance0 - amount
    assert our_state1.balance == balance1 + amount
    assert our_state0.distributable(partner_state0) == our_state0.balance
    assert our_state1.distributable(partner_state1) == our_state1.balance
    assert our_state0.locked.outstanding == 0
    assert our_state1.locked.outstanding == 0
    assert our_state0.locked.root == ''
    assert our_state1.locked.root == ''

    # check hashlock are empty
    assert len(our_state0.locked) == 0
    assert len(our_state1.locked) == 0
    assert len(partner_state0.locked) == 0
    assert len(partner_state1.locked) == 0

    # re-check the mirrors
    assert our_state0.balance == partner_state1.balance
    assert our_state1.balance == partner_state0.balance
    assert our_state0.locked.outstanding == partner_state1.locked.outstanding
    assert our_state1.locked.outstanding == partner_state0.locked.outstanding
    assert our_state0.locked.root == partner_state1.locked.root
    assert our_state1.locked.root == partner_state0.locked.root
    assert our_state0.distributable(partner_state0) == partner_state1.distributable(our_state1)
    assert partner_state0.distributable(our_state0) == our_state1.distributable(partner_state1)


def test_register_invalid_transfer():
    apps = create_network(num_nodes=2, num_assets=1, channels_per_node=1)
    app0, app1 = apps  # pylint: disable=unbalanced-tuple-unpacking

    channel0 = app0.raiden.assetmanagers.values()[0].channels.values()[0]
    channel1 = app1.raiden.assetmanagers.values()[0].channels.values()[0]

    our_state0 = channel0.our_state
    our_state1 = channel1.our_state

    balance0 = channel0.our_state.balance
    balance1 = channel1.our_state.balance

    partner_state0 = channel0.partner_state
    partner_state1 = channel1.partner_state

    amount = 10
    expiration = app0.raiden.chain.block_number + 100

    secret = 'secret'
    hashlock = sha3(secret)

    transfer1 = channel0.create_lockedtransfer(
        amount=amount,
        expiration=expiration,
        hashlock=hashlock,
    )

    # registering a locked transfer from channel0 to channel1, this will add to
    # the channel1's LockedTransfers and the locked amount can be claimed when
    # the lock is received
    app0.raiden.sign(transfer1)
    channel0.register_transfer(transfer1)
    channel1.register_transfer(transfer1)

    locked_root = merkleroot([
        sha3(tx.lock.asstring)
        for tx in channel1.our_state.locked.locked.values()
    ])

    transfer2 = DirectTransfer(
        nonce=our_state0.nonce,
        asset=channel0.asset_address,
        balance=partner_state0.balance + balance0 + amount,
        recipient=partner_state0.address,
        locksroot=partner_state0.locked.root,
        secret='secret',
    )
    app0.raiden.sign(transfer2)

    # this will fail because the allowance is incorrect
    with pytest.raises(Exception):
        channel0.register_transfer(transfer2)

    with pytest.raises(Exception):
        channel1.register_transfer(transfer2)

    # check balances
    assert our_state0.balance == balance0
    assert our_state1.balance == balance1
    assert our_state0.distributable(partner_state0) == balance0 - amount
    assert our_state1.distributable(partner_state1) == balance1
    assert our_state0.locked.outstanding == 0
    assert our_state1.locked.outstanding == amount
    assert our_state0.locked.root == ''
    assert our_state1.locked.root == locked_root

    # check hashlock
    assert len(our_state0.locked) == 0
    assert len(our_state1.locked) == 1
    assert len(partner_state0.locked) == 1
    assert len(partner_state1.locked) == 0
    assert hashlock in partner_state0.locked
    assert hashlock in our_state1.locked
    # the locked transfer is only registered in the receiving side
    assert hashlock not in our_state0.locked
    assert hashlock not in partner_state1.locked

    # check the mirrors
    assert our_state0.balance == partner_state1.balance
    assert our_state1.balance == partner_state0.balance
    assert our_state0.locked.outstanding == partner_state1.locked.outstanding
    assert our_state1.locked.outstanding == partner_state0.locked.outstanding
    assert our_state0.locked.root == partner_state1.locked.root
    assert our_state1.locked.root == partner_state0.locked.root
    assert our_state0.distributable(partner_state0) == partner_state1.distributable(our_state1)
    assert partner_state0.distributable(our_state0) == our_state1.distributable(partner_state1)


def test_locked_transfer():
    apps = create_network(num_nodes=2, num_assets=1, channels_per_node=1)
    app0, app1 = apps  # pylint: disable=unbalanced-tuple-unpacking

    channel0 = app0.raiden.assetmanagers.values()[0].channels.values()[0]
    channel1 = app1.raiden.assetmanagers.values()[0].channels.values()[0]

    our_state0 = channel0.our_state
    our_state1 = channel1.our_state

    partner_state0 = channel0.partner_state
    partner_state1 = channel1.partner_state

    balance0 = channel0.our_state.balance
    balance1 = channel1.our_state.balance

    amount = 10
    expiration = app0.raiden.chain.block_number + 100

    secret = 'secret'
    hashlock = sha3(secret)

    locked_transfer = channel0.create_lockedtransfer(
        amount=amount,
        expiration=expiration,
        hashlock=hashlock,
    )
    app0.raiden.sign(locked_transfer)
    channel0.register_transfer(locked_transfer)
    channel1.register_transfer(locked_transfer)

    locked_root = merkleroot([
        sha3(tx.lock.asstring)
        for tx in channel1.our_state.locked.locked.values()
    ])

    # check balances
    assert our_state0.balance == balance0
    assert our_state1.balance == balance1
    assert our_state0.distributable(partner_state0) == balance0 - amount
    assert our_state1.distributable(partner_state1) == balance1
    assert our_state0.locked.outstanding == 0
    assert our_state1.locked.outstanding == amount
    assert our_state0.locked.root == ''
    assert our_state1.locked.root == locked_root

    # check hashlock
    assert len(our_state0.locked) == 0
    assert len(our_state1.locked) == 1
    assert len(partner_state0.locked) == 1
    assert len(partner_state1.locked) == 0
    assert hashlock in partner_state0.locked
    assert hashlock in our_state1.locked
    # the locked transfer is only registered in the receiving side
    assert hashlock not in our_state0.locked
    assert hashlock not in partner_state1.locked

    # check the mirrors
    assert our_state0.balance == partner_state1.balance
    assert our_state1.balance == partner_state0.balance
    assert our_state0.locked.outstanding == partner_state1.locked.outstanding
    assert our_state1.locked.outstanding == partner_state0.locked.outstanding
    assert our_state0.locked.root == partner_state1.locked.root
    assert our_state1.locked.root == partner_state0.locked.root
    assert our_state0.distributable(partner_state0) == partner_state1.distributable(our_state1)
    assert partner_state0.distributable(our_state0) == our_state1.distributable(partner_state1)

    # reveal secret
    channel0.claim_locked(secret)
    channel1.claim_locked(secret)

    # check new balances
    assert our_state0.balance == balance0 - amount
    assert our_state1.balance == balance1 + amount
    assert our_state0.distributable(partner_state0) == balance0 - amount
    assert our_state1.distributable(partner_state1) == balance1 + amount
    assert our_state0.locked.outstanding == 0
    assert our_state1.locked.outstanding == 0
    assert our_state0.locked.root == ''
    assert our_state1.locked.root == ''

    # check hashlock are empty
    assert len(our_state0.locked) == 0
    assert len(our_state1.locked) == 0
    assert len(partner_state0.locked) == 0
    assert len(partner_state1.locked) == 0

    # check the mirrors
    assert our_state0.balance == partner_state1.balance
    assert our_state1.balance == partner_state0.balance
    assert our_state0.locked.outstanding == partner_state1.locked.outstanding
    assert our_state1.locked.outstanding == partner_state0.locked.outstanding
    assert our_state0.locked.root == partner_state1.locked.root
    assert our_state1.locked.root == partner_state0.locked.root
    assert our_state0.distributable(partner_state0) == partner_state1.distributable(our_state1)
    assert partner_state0.distributable(our_state0) == our_state1.distributable(partner_state1)


def test_interwoven_transfers(num=100):
    apps = create_network(num_nodes=2, num_assets=1, channels_per_node=1)

    app0, app1 = apps  # pylint: disable=unbalanced-tuple-unpacking

    channel0 = app0.raiden.assetmanagers.values()[0].channels.values()[0]
    channel1 = app1.raiden.assetmanagers.values()[0].channels.values()[0]

    our_state0 = channel0.our_state
    our_state1 = channel1.our_state

    partner_state0 = channel0.partner_state
    partner_state1 = channel1.partner_state

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
        app0.raiden.sign(locked_transfer)
        channel0.register_transfer(locked_transfer)
        channel1.register_transfer(locked_transfer)

        claimed_amount = sum(amounts[j] for j in claimed)
        distributed_amount = sum(amounts[:i + 1])

        assert our_state0.balance == our_state0.initial_balance - claimed_amount
        assert our_state0.distributable(partner_state0) == our_state0.initial_balance - distributed_amount
        assert our_state0.distributable(partner_state0) == our_state0.balance - distributed_amount + claimed_amount
        assert our_state0.locked.outstanding == 0

        assert our_state1.balance == our_state1.distributable(partner_state1)
        assert our_state1.balance == our_state1.initial_balance + claimed_amount
        assert our_state1.locked.outstanding == distributed_amount - claimed_amount

        # check the mirrors
        assert our_state0.balance == partner_state1.balance
        assert our_state1.balance == partner_state0.balance
        assert our_state0.locked.outstanding == partner_state1.locked.outstanding
        assert our_state1.locked.outstanding == partner_state0.locked.outstanding
        assert our_state0.locked.root == partner_state1.locked.root
        assert our_state1.locked.root == partner_state0.locked.root
        assert our_state0.distributable(partner_state0) == partner_state1.distributable(our_state1)
        assert partner_state0.distributable(our_state0) == our_state1.distributable(partner_state1)

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
        app0.raiden.sign(locked_transfer)
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
