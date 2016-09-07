# -*- coding: utf8 -*-
import gevent
import pytest

from ethereum.utils import sha3

from raiden.tests.utils.transfer import (
    assert_synched_channels,
    channel,
    pending_mediated_transfer,
)
from raiden.tests.utils.blockchain import wait_until_block
from raiden.tests.utils.network import CHAIN


@pytest.mark.parametrize('privatekey_seed', ['event_new_channel:{}'])
@pytest.mark.parametrize('number_of_nodes', [2])
@pytest.mark.parametrize('channels_per_node', [0])
def test_event_new_channel(raiden_chain, deposit, settle_timeout, events_poll_timeout):
    app0, app1 = raiden_chain  # pylint: disable=unbalanced-tuple-unpacking

    asset_address = app0.raiden.chain.default_registry.asset_addresses()[0]

    assert len(app0.raiden.managers_by_asset_address[asset_address].address_channel) == 0
    assert len(app1.raiden.managers_by_asset_address[asset_address].address_channel) == 0

    asset0 = app0.raiden.chain.asset(asset_address)
    manager0 = app0.raiden.chain.manager_by_asset(asset_address)

    asset1 = app1.raiden.chain.asset(asset_address)

    netcontract_address = manager0.new_netting_channel(
        app0.raiden.address,
        app1.raiden.address,
        settle_timeout,
    )

    netting_channel0 = app0.raiden.chain.netting_channel(netcontract_address)
    netting_channel1 = app1.raiden.chain.netting_channel(netcontract_address)

    gevent.sleep(events_poll_timeout)

    # channel is created but not opened and without funds
    assert len(app0.raiden.managers_by_asset_address[asset_address].address_channel) == 1
    assert len(app1.raiden.managers_by_asset_address[asset_address].address_channel) == 1

    channel0 = app0.raiden.managers_by_asset_address[asset_address].address_channel.values()[0]
    channel1 = app1.raiden.managers_by_asset_address[asset_address].address_channel.values()[0]

    assert_synched_channels(
        channel0, 0, [],
        channel1, 0, [],
    )

    asset0.approve(netcontract_address, deposit)
    netting_channel0.deposit(app0.raiden.address, deposit)

    gevent.sleep(events_poll_timeout)

    # channel is open but single funded
    assert len(app0.raiden.managers_by_asset_address[asset_address].address_channel) == 1
    assert len(app1.raiden.managers_by_asset_address[asset_address].address_channel) == 1

    channel0 = app0.raiden.managers_by_asset_address[asset_address].address_channel.values()[0]
    channel1 = app1.raiden.managers_by_asset_address[asset_address].address_channel.values()[0]

    assert_synched_channels(
        channel0, deposit, [],
        channel1, 0, [],
    )

    asset1.approve(netcontract_address, deposit)
    netting_channel1.deposit(app1.raiden.address, deposit)

    gevent.sleep(events_poll_timeout)

    # channel is open and funded by both participants
    assert len(app0.raiden.managers_by_asset_address[asset_address].address_channel) == 1
    assert len(app1.raiden.managers_by_asset_address[asset_address].address_channel) == 1

    channel0 = app0.raiden.managers_by_asset_address[asset_address].address_channel.values()[0]
    channel1 = app1.raiden.managers_by_asset_address[asset_address].address_channel.values()[0]

    assert_synched_channels(
        channel0, deposit, [],
        channel1, deposit, [],
    )


@pytest.mark.xfail(reason='out-of-gas for unlock and settle')
@pytest.mark.parametrize('privatekey_seed', ['event_new_channel:{}'])
@pytest.mark.parametrize('number_of_nodes', [3])
@pytest.mark.parametrize('channels_per_node', [CHAIN])
def test_secret_revealed(raiden_chain, deposit, settle_timeout, events_poll_timeout):
    app0, app1, app2 = raiden_chain

    asset_address = app0.raiden.chain.default_registry.asset_addresses()[0]
    amount = 10

    channel21 = channel(app2, app1, asset_address)
    netting_channel = channel21.external_state.netting_channel

    secret = pending_mediated_transfer(raiden_chain, asset_address, amount)
    hashlock = sha3(secret)

    gevent.sleep(.1)  # wait for the messages

    balance_proof = channel21.our_state.balance_proof
    lock = balance_proof.get_lock_by_hashlock(hashlock)
    proof = balance_proof.compute_proof_for_lock(secret, lock)

    # the secret hasn't been revealed yet (through messages)
    assert len(balance_proof.hashlock_pendinglocks) == 1
    proofs = list(balance_proof.get_known_unlocks())
    assert len(proofs) == 0

    netting_channel.close(app2.raiden.address, balance_proof.transfer, None)

    # reveal it through the blockchain (this needs to emit the SecretRevealed event)
    netting_channel.unlock(
        app2.raiden.address,
        [proof],
    )

    settle_expiration = app0.raiden.chain.block_number() + settle_timeout
    wait_until_block(app0.raiden.chain, settle_expiration)

    channel21.settle_event.wait(timeout=10)

    assert_synched_channels(
        channel(app1, app2, asset_address), deposit - amount, [],
        channel(app2, app1, asset_address), deposit + amount, [],
    )

    assert_synched_channels(
        channel(app0, app1, asset_address), deposit - amount, [],
        channel(app1, app2, asset_address), deposit + amount, [],
    )
