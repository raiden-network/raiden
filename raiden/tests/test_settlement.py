# -*- coding: utf8 -*-
import pytest

from raiden.mtree import check_proof
from raiden.tests.utils.messages import setup_messages_cb
from raiden.tests.utils.transfer import (
    assert_synched_channels,
    channel,
    direct_transfer,
    get_received_transfer,
    hidden_mediated_transfer,
    transfer,
)
from raiden.utils import sha3

# pylint: disable=too-many-locals,too-many-statements


@pytest.mark.parametrize('privatekey_seed', ['settlement:{}'])
@pytest.mark.parametrize('number_of_nodes', [2])
def test_settlement(raiden_network, settle_timeout):
    app0, app1 = raiden_network  # pylint: disable=unbalanced-tuple-unpacking

    setup_messages_cb()

    asset_manager0 = app0.raiden.managers_by_asset_address.values()[0]
    asset_manager1 = app1.raiden.managers_by_asset_address.values()[0]

    chain0 = app0.raiden.chain

    channel0 = asset_manager0.partneraddress_channel[app1.raiden.address]
    channel1 = asset_manager1.partneraddress_channel[app0.raiden.address]

    balance0 = channel0.balance
    balance1 = channel1.balance

    amount = 10
    expiration = 10
    secret = 'secret'
    hashlock = sha3(secret)

    assert app1.raiden.address in asset_manager0.partneraddress_channel
    assert asset_manager0.asset_address == asset_manager1.asset_address
    assert channel0.netting_contract.address == channel1.netting_contract.address

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

    # get proof, that locked transfermessage was in merkle tree, with locked.root
    merkle_proof = channel1.our_state.locked.get_proof(transfermessage)
    root = channel1.our_state.locked.root
    assert check_proof(merkle_proof, root, sha3(transfermessage.lock.as_bytes))

    channel0.netting_contract.close(
        app0.raiden.address,
        transfermessage,
        None,
    )

    unlocked = [(merkle_proof, transfermessage.lock, secret)]

    channel0.netting_contract.unlock(
        app0.raiden.address,
        unlocked,
    )

    for _ in range(settle_timeout):
        chain0.next_block()

    channel0.netting_contract.settle()


@pytest.mark.xfail()
@pytest.mark.parametrize('privatekey_seed', ['settled_lock:{}'])
@pytest.mark.parametrize('number_of_nodes', [4])
@pytest.mark.parametrize('channels_per_node', [2])
def test_settled_lock(assets_addresses, raiden_network, settle_timeout):
    """ An attacker cannot reuse a secret to double claim a lock. """
    asset = assets_addresses[0]
    amount = 30

    app0, app1, app2, app3 = raiden_network  # pylint: disable=unbalanced-tuple-unpacking

    # mediated transfer with the secret revealed
    transfer(app0, app3, asset, amount)

    # any new transfer
    direct_transfer(app0, app1, asset, amount)

    import pdb; pdb.set_trace()
    secret = ''
    attack_channel = channel(app2, app1, asset)
    secret_transfer = get_received_transfer(attack_channel, 0)
    last_transfer = get_received_transfer(attack_channel, 1)
    netting_contract_address = attack_channel.netting_contract.address

    # create a fake proof
    merkle_proof = attack_channel.our_state.locked.get_proof(secret_transfer)

    # call close giving the secret for a transfer that has being revealed
    attack_channel.netting_contract.close(
        app1.raiden.address,
        last_transfer,
        None
    )

    attack_channel.netting_contract.unlock(
        app1.raiden.address,
        [(merkle_proof, secret_transfer.lock, secret)],
    )

    # forward the block number to allow settle
    for _ in range(settle_timeout):
        app2.raiden.chain.next_block()

    app1.raiden.chain.settle(asset, netting_contract_address)

    # check that the attack FAILED
    # contract = app1.raiden.chain.asset_hashchannel[asset][netting_contract_address]


@pytest.mark.xfail()
@pytest.mark.parametrize('privatekey_seed', ['start_end_attack:{}'])
@pytest.mark.parametrize('number_of_nodes', [3])
def test_start_end_attack(asset_address, raiden_chain, deposit):
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
    amount = 30

    asset = asset_address[0]
    app0, app1, app2 = raiden_chain  # pylint: disable=unbalanced-tuple-unpacking

    # The attacker creates a mediated transfer from it's account A1, to it's
    # account A2, throught the hub H
    secret = hidden_mediated_transfer(raiden_chain, asset, amount)

    attack_channel = channel(app2, app1, asset)
    attack_transfer = get_received_transfer(attack_channel, 0)
    attack_contract = attack_channel.netting_contract.address
    hub_contract = channel(app1, app0, asset).netting_contract.address

    # the attacker can create a merkle proof of the locked transfer
    merkle_proof = attack_channel.our_state.locked.get_proof(attack_transfer)

    # start the settle counter
    attack_channel.netting_channel.close(
        app2.raiden.address,
        attack_transfer,
        None
    )

    # wait until the last block to reveal the secret
    for _ in range(attack_transfer.lock.expiration - 1):
        app2.raiden.chain.next_block()

    # since the attacker knows the secret he can net the lock
    attack_channel.netting_channel.unlock(
        [(merkle_proof, attack_transfer.lock, secret)],
    )
    # XXX: verify that the secret was publicized

    # at this point the hub might not know yet the secret, and won't be able to
    # claim the asset from the channel A1 - H

    # the attacker settle the contract
    app2.raiden.chain.next_block()

    attack_channel.netting_channel.settle(asset, attack_contract)

    # at this point the attack has the "stolen" funds
    attack_contract = app2.raiden.chain.asset_hashchannel[asset][attack_contract]
    assert attack_contract.participants[app2.raiden.address]['netted'] == deposit + amount
    assert attack_contract.participants[app1.raiden.address]['netted'] == deposit - amount

    # and the hub's channel A1-H doesn't
    hub_contract = app1.raiden.chain.asset_hashchannel[asset][hub_contract]
    assert hub_contract.participants[app0.raiden.address]['netted'] == deposit
    assert hub_contract.participants[app1.raiden.address]['netted'] == deposit

    # to mitigate the attack the Hub _needs_ to use a lower expiration for the
    # locked transfer between H-A2 than A1-H, since for A2 to acquire the asset
    # it needs to make the secret public in the block chain we publish the
    # secret through an event and the Hub will be able to require it's funds
    app1.raiden.chain.next_block()

    # XXX: verify that the Hub has found the secret, close and settle the channel

    # the hub has acquired it's asset
    hub_contract = app1.raiden.chain.asset_hashchannel[asset][hub_contract]
    assert hub_contract.participants[app0.raiden.address]['netted'] == deposit + amount
    assert hub_contract.participants[app1.raiden.address]['netted'] == deposit - amount
