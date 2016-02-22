from raiden.mtree import merkleroot
from raiden.app import create_network
from raiden.utils import sha3
import time


def test_setup():

    apps = create_network(num_nodes=2, num_assets=1, channels_per_node=1)
    a0, a1 = apps
    s = a0.raiden.chain.channelmanager_by_asset(a0.raiden.chain.asset_addresses[0])
    assert s.nettingcontracts
    assert s.nettingcontracts_by_address(a0.raiden.address)

    assert a0.raiden.assetmanagers.keys() == a1.raiden.assetmanagers.keys()
    assert len(a0.raiden.assetmanagers) == 1


def test_transfer():
    apps = create_network(num_nodes=2, num_assets=1, channels_per_node=1)
    a0, a1 = apps
    c0 = a0.raiden.assetmanagers.values()[0].channels.values()[0]
    c1 = a1.raiden.assetmanagers.values()[0].channels.values()[0]

    assert c0.contract == c1.contract

    assert c0.balance == c0.distributable == c0.contract.participants[c0.address]['deposit']
    assert c1.balance == c1.distributable == c1.contract.participants[c1.address]['deposit']

    amount = 10
    assert amount < c0.distributable

    b0, b1 = c0.balance, c1.balance
    pb0, pb1 = c0.partner.balance, c1.partner.balance
    assert b0 == pb1
    assert b1 == pb0

    t = c0.create_transfer(amount=amount)
    c0.raiden.sign(t)
    c0.register_transfer(t)
    c1.register_transfer(t)

    assert c0.balance == c0.distributable == b0 - amount == c1.partner.balance
    assert c1.balance == c1.distributable == b1 + amount == c0.partner.balance
    assert c0.locked.outstanding == 0
    assert c1.locked.outstanding == 0


def test_locked_transfer():
    apps = create_network(num_nodes=2, num_assets=1, channels_per_node=1)
    a0, a1 = apps
    c0 = a0.raiden.assetmanagers.values()[0].channels.values()[0]
    c1 = a1.raiden.assetmanagers.values()[0].channels.values()[0]

    b0, b1 = c0.balance, c1.balance

    amount = 10
    secret = 'secret'
    expiration = a0.raiden.chain.block_number + 100
    hashlock = sha3(secret)
    t = c0.create_lockedtransfer(amount=amount, expiration=expiration, hashlock=hashlock)
    c0.raiden.sign(t)
    c0.register_transfer(t)
    c1.register_transfer(t)

    assert hashlock in c1.locked
    assert hashlock in c0.partner.locked
    assert len(c0.locked) == 0
    assert len(c0.partner.locked) == 1
    assert len(c1.locked) == 1
    assert len(c1.partner.locked) == 0

    assert c0.balance == b0
    assert c0.distributable == c0.balance - amount
    assert c1.balance == c1.distributable == b1
    assert c0.locked.outstanding == 0
    assert c0.partner.locked.outstanding == amount
    assert c1.locked.outstanding == amount
    assert c1.partner.locked.outstanding == 0

    assert c0.locked.root == ''
    assert c1.partner.locked.root == ''

    assert c1.locked.root == merkleroot(
        [sha3(tx.lock.asstring) for tx in c1.locked.locked.values()])
    assert c0.partner.locked.root == c1.locked.root

    # reveal secret

    c0.claim_locked(secret)
    c1.claim_locked(secret)

    assert c0.balance == b0 - amount
    assert c0.distributable == c0.balance
    assert c1.balance == c1.distributable == b1 + amount
    assert c0.locked.outstanding == 0
    assert c0.partner.locked.outstanding == 0
    assert c1.locked.outstanding == 0
    assert c1.partner.locked.outstanding == 0
    assert len(c0.locked) == 0
    assert len(c0.partner.locked) == 0
    assert len(c1.locked) == 0
    assert len(c1.partner.locked) == 0
    assert c0.locked.root == ''
    assert c1.partner.locked.root == ''
    assert c1.locked.root == ''
    assert c0.partner.locked.root == ''


def test_interwoven_transfers(num=100):
    apps = create_network(num_nodes=2, num_assets=1, channels_per_node=1)
    a0, a1 = apps
    c0 = a0.raiden.assetmanagers.values()[0].channels.values()[0]
    c1 = a1.raiden.assetmanagers.values()[0].channels.values()[0]
    b0, b1 = c0.balance, c1.balance

    amounts = range(1, num + 1)
    secrets = [str(i) for i in range(num)]
    expiration = a0.raiden.chain.block_number + 100
    claimed = []

    for i, amount in enumerate(amounts):
        hashlock = sha3(secrets[i])
        t = c0.create_lockedtransfer(amount=amount, expiration=expiration, hashlock=hashlock)
        c0.raiden.sign(t)
        c0.register_transfer(t)
        c1.register_transfer(t)

        claimed_amount = sum([amounts[j] for j in claimed])
        distributed_amount = sum(amounts[:i + 1])

        # print i, claimed_amount, distributed_amount, amounts[:i + 1]

        assert c0.balance == b0 - claimed_amount
        assert c0.distributable == b0 - distributed_amount
        assert c0.distributable == c0.balance - distributed_amount + claimed_amount
        assert c1.balance == c1.distributable == b1 + claimed_amount
        assert c0.locked.outstanding == 0
        assert c1.locked.outstanding == c0.partner.locked.outstanding == sum(
            amounts[:i + 1]) - claimed_amount
        assert c1.partner.locked.outstanding == 0
        assert c0.partner.locked.root == c1.locked.root

        if i > 0 and i % 2 == 0:
            idx = i - 1
            # print 'claiming', idx, amounts[idx]
            claimed.append(idx)
            secret = secrets[idx]
            c0.claim_locked(secret)
            c1.claim_locked(secret)


def transfer_speed(num_transfers=100, max_locked=100):

    apps = create_network(num_nodes=2, num_assets=1, channels_per_node=1)
    a0, a1 = apps
    c0 = a0.raiden.assetmanagers.values()[0].channels.values()[0]
    c1 = a1.raiden.assetmanagers.values()[0].channels.values()[0]

    amounts = [a % 100 + 1 for a in range(1, num_transfers + 1)]
    secrets = [str(i) for i in range(num_transfers)]
    expiration = a0.raiden.chain.block_number + 100

    st = time.time()

    for i, amount in enumerate(amounts):
        hashlock = sha3(secrets[i])
        t = c0.create_lockedtransfer(amount=amount, expiration=expiration, hashlock=hashlock)
        c0.raiden.sign(t)
        c0.register_transfer(t)
        c1.register_transfer(t)
        if i > max_locked:
            idx = i - max_locked
            secret = secrets[idx]
            c0.claim_locked(secret)
            c1.claim_locked(secret)

    elapsed = time.time() - st
    print '%d transfers per second' % (num_transfers / elapsed)


if __name__ == '__main__':
    transfer_speed(10000, 100)
