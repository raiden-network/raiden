# -*- coding: utf8 -*-
import pytest

from raiden.app import create_network
from raiden.mtree import check_proof
from raiden.tests.utils import setup_messages_cb
from raiden.utils import sha3


@pytest.skip()
def test_settlement():
    apps = create_network(num_nodes=2, num_assets=1, channels_per_node=1)
    a0, a1 = apps
    setup_messages_cb()

    # channels
    am0 = a0.raiden.assetmanagers.values()[0]
    am1 = a1.raiden.assetmanagers.values()[0]

    assert am0.asset_address == am1.asset_address

    c0 = am0.channels[a1.raiden.address]
    c1 = am1.channels[a0.raiden.address]

    b0 = c0.balance
    b1 = c1.balance

    lr0 = c0.locked.root
    lr0p = c0.partner.locked.root
    lr1 = c1.locked.root
    lr1p = c1.partner.locked.root

    amount = 10
    secret = 'secret'
    hashlock = sha3(secret)
    target = a1.raiden.address
    expiration = 10
    assert target in am0.channels

    t = c0.create_lockedtransfer(amount, expiration, hashlock)
    c0.raiden.sign(t)
    c0.register_transfer(t)
    c1.register_transfer(t)

    # balances are unchanged, but locksroot changed

    assert b1 == c1.balance
    assert b0 == c0.balance

    assert c0.locked.root == lr0
    assert c0.partner.locked.root != lr0p

    assert c1.locked.root != lr1
    assert c1.partner.locked.root == lr1p

    assert c1.locked.root == c0.partner.locked.root

    # now Bob learns the secret, but alice did not send a signed updated balance to reflect this
    # Bob wants to settle

    sc = c0.contract
    assert sc == c1.contract

    last_sent_transfers = [t]

    # get proof, that locked transfer was in merkle tree, with locked.root
    assert c1.locked
    merkle_proof = c1.locked.get_proof(t)
    # assert merkle_proof
    # assert merkle_proof[0] == t.locked.asstring
    root = c1.locked.root
    assert check_proof(merkle_proof, root, sha3(t.lock.asstring))

    unlocked = [(merkle_proof, t.lock.asstring, secret)]

    chain = a0.raiden.chain
    chain.block_number = 1

    sc.close(a1.raiden.address, last_sent_transfers, *unlocked)
    chain.block_number += sc.locked_time

    r = sc.settle()
    assert r[c1.address] == b1 + amount
    assert r[c0.address] == b0 - amount
