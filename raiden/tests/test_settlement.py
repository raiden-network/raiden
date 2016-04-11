# -*- coding: utf8 -*-
from raiden.tests.utils import create_network
from raiden.blockchain.net_contract import NettingChannelContract
from raiden.mtree import check_proof, merkleroot
from raiden.tests.utils import setup_messages_cb
from raiden.utils import sha3

# pylint: disable=too-many-locals,too-many-statements


def test_settlement():
    apps = create_network(num_nodes=2, num_assets=1, channels_per_node=1)
    app0, app1 = apps  # pylint: disable=unbalanced-tuple-unpacking

    setup_messages_cb()

    asset_manager0 = app0.raiden.assetmanagers.values()[0]
    asset_manager1 = app1.raiden.assetmanagers.values()[0]

    chain0 = app0.raiden.chain
    asset_address = asset_manager0.asset_address

    channel0 = asset_manager0.channels[app1.raiden.address]
    channel1 = asset_manager1.channels[app0.raiden.address]

    our_state0 = channel0.our_state
    our_state1 = channel1.our_state

    partner_state0 = channel0.partner_state
    partner_state1 = channel1.partner_state

    balance0 = our_state0.balance
    balance1 = our_state1.balance

    amount = 10
    expiration = 10
    secret = 'secret'
    hashlock = sha3(secret)

    assert app1.raiden.address in asset_manager0.channels
    assert asset_manager0.asset_address == asset_manager1.asset_address
    assert channel0.nettingcontract_address == channel1.nettingcontract_address

    transfer = channel0.create_lockedtransfer(amount, expiration, hashlock)
    app0.raiden.sign(transfer)
    channel0.register_transfer(transfer)
    channel1.register_transfer(transfer)

    locked_root = merkleroot([
        sha3(tx.lock.asstring)
        for tx in channel1.our_state.locked.locked.values()
    ])

    # balances are unchanged by registering
    assert balance0 == our_state0.balance
    assert balance1 == our_state1.balance

    # the transfer needs to be registered in the receiving end
    assert our_state0.locked.root == ''
    assert our_state1.locked.root == locked_root

    # check the mirrors
    assert our_state0.balance == partner_state1.balance
    assert our_state1.balance == partner_state0.balance
    assert our_state0.locked.outstanding == partner_state1.locked.outstanding
    assert our_state1.locked.outstanding == partner_state0.locked.outstanding
    assert our_state0.locked.root == partner_state1.locked.root
    assert our_state1.locked.root == partner_state0.locked.root
    assert our_state0.distributable(partner_state0) == partner_state1.distributable(our_state1)
    assert partner_state0.distributable(our_state0) == our_state1.distributable(partner_state1)

    # Bob learns the secret, but Alice did not send a signed updated balance to
    # reflect this Bob wants to settle

    nettingcontract_address = channel0.nettingcontract_address
    last_sent_transfers = [transfer]

    # get proof, that locked transfer was in merkle tree, with locked.root
    assert our_state1.locked
    merkle_proof = our_state1.locked.get_proof(transfer)
    root = our_state1.locked.root
    assert check_proof(merkle_proof, root, sha3(transfer.lock.asstring))

    unlocked = [(merkle_proof, transfer.lock, secret)]

    chain0.close(
        asset_address,
        nettingcontract_address,
        app0.raiden.address,
        last_sent_transfers,
        unlocked,
    )

    for _ in range(NettingChannelContract.locked_time):
        chain0.next_block()

    chain0.settle(asset_address, nettingcontract_address)
