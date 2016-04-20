# -*- coding: utf8 -*-
import pytest

from raiden.blockchain.net_contract import NettingChannelContract
from raiden.mtree import check_proof
from raiden.tests.utils.messages import setup_messages_cb
from raiden.tests.utils.network import create_network, create_sequential_network
from raiden.tests.utils.transfer import (
    assert_synched_channels,
    channel,
    direct_transfer,
    get_received_transfer,
    # get_sent_transfer,
    hidden_mediated_transfer,
    transfer,
)
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

    balance0 = channel0.balance
    balance1 = channel1.balance

    amount = 10
    expiration = 10
    secret = 'secret'
    hashlock = sha3(secret)

    assert app1.raiden.address in asset_manager0.channels
    assert asset_manager0.asset_address == asset_manager1.asset_address
    assert channel0.nettingcontract_address == channel1.nettingcontract_address

    transfermessage = channel0.create_lockedtransfer(amount, expiration, hashlock)
    app0.raiden.sign(transfermessage)
    channel0.register_transfer(transfermessage)
    channel1.register_transfer(transfermessage)

    assert_synched_channels(
        channel0, balance0, [transfermessage.lock],
        channel1, balance1, []
    )

    # Bob learns the secret, but Alice did not send a signed updated balance to
    # reflect this Bob wants to settle

    nettingcontract_address = channel0.nettingcontract_address
    last_sent_transfers = [transfermessage]

    # get proof, that locked transfermessage was in merkle tree, with locked.root
    merkle_proof = channel1.our_state.locked.get_proof(transfermessage)
    root = channel1.our_state.locked.root
    assert check_proof(merkle_proof, root, sha3(transfermessage.lock.asstring))

    unlocked = [(merkle_proof, transfermessage.lock, secret)]

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


@pytest.mark.xfail()
def test_settled_lock():
    """ After a lock has it's secret revealed and a transfer happened, the lock
    cannot be used to net any value with the contract.
    """
    deposit = 100
    asset = sha3('test_settled_lock')[:20]
    amount = 30

    # pylint: disable=unbalanced-tuple-unpacking
    apps = create_sequential_network(num_nodes=4, deposit=deposit, asset=asset)

    # mediated transfer with the secret revealed
    transfer(apps[0], apps[3], asset, amount)

    # create the latest transfer
    direct_transfer(apps[0], apps[1], asset, amount)

    secret = ''  # need to get the secret
    attack_channel = channel(apps[2], apps[1], asset)
    secret_transfer = get_received_transfer(attack_channel, 0)
    last_transfer = get_received_transfer(attack_channel, 1)
    nettingcontract_address = attack_channel.nettingcontract_address

    # create a fake proof
    merkle_proof = attack_channel.our_state.locked.get_proof(secret_transfer)

    # call close giving the secret for a transfer that has being revealed
    apps[1].raiden.chain.close(
        asset,
        nettingcontract_address,
        apps[1].raiden.address,
        [last_transfer],
        [(merkle_proof, secret_transfer.lock, secret)],
    )

    # forward the block number to allow settle
    for _ in range(NettingChannelContract.locked_time):
        apps[2].raiden.chain.next_block()

    apps[1].raiden.chain.settle(asset, nettingcontract_address)

    # check that the attack FAILED
    # contract = apps[1].raiden.chain.asset_hashchannel[asset][nettingcontract_address]


@pytest.mark.xfail()
def test_start_end_attack():
    """ An attacker can try to steal assets from a hub or the last node in a
    path.

    The attacker needs to use two addresses (A1 and A2) and connect both to the
    hub H, once connected a mediated transfer is initialized from A1 to A2
    through H, once the node A2 receives the mediated transfer the attacker
    uses the it's know secret and reveal to close and settles the channel H-A2,
    without revealing the secret to H's raiden node.

    The intention is to make the hub transfer the asset but for him to be
    unable to require the asset A1.
    """
    asset = sha3('test_two_attack')[:20]
    deposit = 100
    amount = 30
    apps = create_sequential_network(num_nodes=3, deposit=deposit, asset=asset)

    # The attacker creates a mediated transfer from it's account A1, to it's
    # account A2, throught the hub H
    secret = hidden_mediated_transfer(apps, asset, amount)

    attack_channel = channel(apps[2], apps[1], asset)
    attack_transfer = get_received_transfer(attack_channel, 0)
    attack_contract = attack_channel.nettingcontract_address
    hub_contract = channel(apps[1], apps[0], asset).nettingcontract_address

    # the attacker can create a merkle proof of the locked transfer
    merkle_proof = attack_channel.our_state.locked.get_proof(attack_transfer)

    # start the settle counter
    apps[2].raiden.chain.close(
        asset,
        attack_contract,
        apps[2].raiden.address,
        [attack_transfer],
        [],
    )

    # wait until the last block to reveal the secret
    for _ in range(attack_transfer.lock.expiration - 1):
        apps[2].raiden.chain.next_block()

    # since the attacker knows the secret he can net the lock
    apps[2].raiden.chain.close(
        asset,
        attack_contract,
        apps[2].raiden.address,
        [attack_transfer],
        [(merkle_proof, attack_transfer.lock, secret)],
    )
    # XXX: verify that the secret was publicized

    # at this point the hub might not know yet the secret, and won't be able to
    # claim the asset from the channel A1 - H

    # the attacker settle the contract
    apps[2].raiden.chain.next_block()
    apps[2].raiden.chain.settle(asset, attack_contract)

    # at this point the attack has the "stolen" funds
    attack_contract = apps[2].raiden.chain.asset_hashchannel[asset][attack_contract]
    assert attack_contract.participants[apps[2].raiden.address]['netted'] == deposit + amount
    assert attack_contract.participants[apps[1].raiden.address]['netted'] == deposit - amount

    # and the hub's channel A1-H doesn't
    hub_contract = apps[1].raiden.chain.asset_hashchannel[asset][hub_contract]
    assert hub_contract.participants[apps[0].raiden.address]['netted'] == deposit
    assert hub_contract.participants[apps[1].raiden.address]['netted'] == deposit

    # to mitigate the attack the Hub _needs_ to use a lower expiration for the
    # locked transfer between H-A2 than A1-H, since for A2 to acquire the asset
    # it needs to make the secret public in the block chain we publish the
    # secret through an event and the Hub will be able to require it's funds
    apps[1].raiden.chain.next_block()

    # XXX: verify that the Hub has found the secret, close and settle the channel

    # the hub has acquired it's asset
    hub_contract = apps[1].raiden.chain.asset_hashchannel[asset][hub_contract]
    assert hub_contract.participants[apps[0].raiden.address]['netted'] == deposit + amount
    assert hub_contract.participants[apps[1].raiden.address]['netted'] == deposit - amount
