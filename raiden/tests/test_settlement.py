# -*- coding: utf8 -*-
from raiden.app import create_network
from raiden.mtree import check_proof
from raiden.tests.utils import setup_messages_cb
from raiden.utils import sha3


def test_settlement():
    apps = create_network(num_nodes=2, num_assets=1, channels_per_node=1)
    app0, app1 = apps  # pylint: disable=unbalanced-tuple-unpacking

    setup_messages_cb()

    asset_manager0 = app0.raiden.assetmanagers.values()[0]
    asset_manager1 = app1.raiden.assetmanagers.values()[0]

    assert app1.raiden.address in asset_manager0.channels
    assert asset_manager0.asset_address == asset_manager1.asset_address

    channel0 = asset_manager0.channels[app1.raiden.address]
    channel1 = asset_manager1.channels[app0.raiden.address]

    amount = 10
    expiration = 10

    secret = 'secret'
    hashlock = sha3(secret)

    balance0 = channel0.balance
    balance1 = channel1.balance

    root0 = channel0.locked.root
    root1 = channel1.locked.root
    partner_root0 = channel0.partner.locked.root
    partner_root1 = channel1.partner.locked.root

    transfer = channel0.create_lockedtransfer(amount, expiration, hashlock)
    channel0.raiden.sign(transfer)
    channel0.register_transfer(transfer)
    channel1.register_transfer(transfer)

    # balances are unchanged by registering
    assert balance1 == channel1.balance
    assert balance0 == channel0.balance

    # the transfer needs to be registerd in the receiving end
    assert channel0.locked.root == root0
    assert channel0.partner.locked.root != partner_root0

    assert channel1.locked.root != root1
    assert channel1.partner.locked.root == partner_root1

    assert channel1.locked.root == channel0.partner.locked.root

    # now Bob learns the secret, but alice did not send a signed updated balance to reflect this
    # Bob wants to settle

    sc = channel0.contract
    assert sc == channel1.contract

    last_sent_transfers = [transfer]

    # get proof, that locked transfer was in merkle tree, with locked.root
    assert channel1.locked
    merkle_proof = channel1.locked.get_proof(transfer)
    # assert merkle_proof
    # assert merkle_proof[0] == transfer.locked.asstring
    root = channel1.locked.root
    assert check_proof(merkle_proof, root, sha3(transfer.lock.asstring))

    unlocked = [(merkle_proof, transfer.lock.asstring, secret)]

    chain = app0.raiden.chain
    chain.block_number = 1

    sc.close(app1.raiden.address, last_sent_transfers, *unlocked)
    chain.block_number += sc.locked_time

    r = sc.settle()
    assert r[channel1.address] == balance1 + amount
    assert r[channel0.address] == balance0 - amount
