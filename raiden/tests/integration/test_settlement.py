# -*- coding: utf-8 -*-
import pytest

from ethereum import slogging

from raiden.mtree import check_proof
from raiden.tests.utils.blockchain import wait_until_block
from raiden.tests.utils.messages import setup_messages_cb
from raiden.tests.utils.network import CHAIN
from raiden.tests.utils.transfer import (
    assert_synched_channels,
    channel,
    direct_transfer,
    get_received_transfer,
    get_sent_transfer,
    pending_mediated_transfer,
    claim_lock,
)
from raiden.utils import sha3

# pylint: disable=too-many-locals,too-many-statements
slogging.configure(':DEBUG')


@pytest.mark.timeout(240)
@pytest.mark.parametrize('privatekey_seed', ['settlement:{}'])
@pytest.mark.parametrize('number_of_nodes', [2])
def test_settlement(raiden_network, settle_timeout, reveal_timeout):
    app0, app1 = raiden_network  # pylint: disable=unbalanced-tuple-unpacking

    setup_messages_cb()

    token_manager0 = app0.raiden.managers_by_token_address.values()[0]
    token_manager1 = app1.raiden.managers_by_token_address.values()[0]
    assert token_manager0.token_address == token_manager1.token_address

    channel0 = token_manager0.partneraddress_channel[app1.raiden.address]
    channel1 = token_manager1.partneraddress_channel[app0.raiden.address]

    deposit0 = channel0.balance
    deposit1 = channel1.balance

    token = app0.raiden.chain.token(channel0.token_address)

    balance0 = token.balance_of(app0.raiden.address)
    balance1 = token.balance_of(app1.raiden.address)

    chain0 = app0.raiden.chain

    amount = 10
    expiration = app0.raiden.chain.block_number() + reveal_timeout + 1
    secret = 'secretsecretsecretsecretsecretse'
    hashlock = sha3(secret)

    assert app1.raiden.address in token_manager0.partneraddress_channel

    nettingaddress0 = channel0.external_state.netting_channel.address
    nettingaddress1 = channel1.external_state.netting_channel.address
    assert nettingaddress0 == nettingaddress1

    identifier = 1
    fee = 0
    transfermessage = channel0.create_mediatedtransfer(
        app0.raiden.address,
        app1.raiden.address,
        fee,
        amount,
        identifier,
        expiration,
        hashlock,
    )
    app0.raiden.sign(transfermessage)
    channel0.register_transfer(transfermessage)
    channel1.register_transfer(transfermessage)

    assert_synched_channels(
        channel0, deposit0, [],
        channel1, deposit1, [transfermessage.lock],
    )

    # At this point we are assuming the following:
    #
    #    A -> B MediatedTransfer
    #    B -> A SecretRequest
    #    A -> B RevealSecret
    #    - protocol didn't continue
    #
    # B knowns the secret but doesn't have an updated balance proof, B needs to
    # call settle.

    # get proof, that locked transfermessage was in merkle tree, with locked.root
    lock = channel1.our_state.balance_proof.get_lock_by_hashlock(hashlock)
    assert sha3(secret) == hashlock
    unlock_proof = channel1.our_state.balance_proof.compute_proof_for_lock(secret, lock)

    root = channel1.our_state.balance_proof.merkleroot_for_unclaimed()

    assert check_proof(
        unlock_proof.merkle_proof,
        root,
        sha3(transfermessage.lock.as_bytes),
    )
    assert unlock_proof.lock_encoded == transfermessage.lock.as_bytes
    assert unlock_proof.secret == secret

    # a ChannelClose event will be generated, this will be polled by both apps
    # and each must start a task for calling settle
    channel1.external_state.netting_channel.close(
        app1.raiden.address,
        transfermessage,
    )
    wait_until_block(chain0, chain0.block_number() + 1)

    assert channel0.close_event.wait(timeout=15)
    assert channel1.close_event.wait(timeout=15)

    assert channel0.external_state.closed_block != 0
    assert channel1.external_state.closed_block != 0
    assert channel0.external_state.settled_block == 0
    assert channel1.external_state.settled_block == 0

    # unlock will not be called by Channel.channel_closed because we did not
    # register the secret
    assert lock.expiration > app0.raiden.chain.block_number()
    assert lock.hashlock == sha3(secret)

    channel1.external_state.netting_channel.unlock(
        app1.raiden.address,
        [unlock_proof],
    )

    settle_expiration = chain0.block_number() + settle_timeout + 2
    wait_until_block(chain0, settle_expiration)

    assert channel0.settle_event.wait(timeout=15)
    assert channel1.settle_event.wait(timeout=15)
    # settle must be called by the apps triggered by the ChannelClose event,
    # and the channels must update it's state based on the ChannelSettled event
    assert channel0.external_state.settled_block != 0
    assert channel1.external_state.settled_block != 0

    address0 = app0.raiden.address
    address1 = app1.raiden.address

    assert token.balance_of(address0) == balance0 + deposit0 + amount
    assert token.balance_of(address1) == balance1 + deposit1 - amount


@pytest.mark.timeout(240)
@pytest.mark.parametrize('privatekey_seed', ['settled_lock:{}'])
@pytest.mark.parametrize('number_of_nodes', [4])
@pytest.mark.parametrize('channels_per_node', [CHAIN])
# TODO: Need to expose the netted value to use a different blockchain_type
@pytest.mark.parametrize('blockchain_type', ['mock'])
def test_settled_lock(tokens_addresses, raiden_network, settle_timeout, reveal_timeout):
    """ Any transfer following a secret revealed must update the locksroot, so
    that an attacker cannot reuse a secret to double claim a lock.
    """
    token = tokens_addresses[0]
    amount = 30

    app0, app1, app2, _ = raiden_network  # pylint: disable=unbalanced-tuple-unpacking
    address0 = app0.raiden.address
    address1 = app1.raiden.address

    # mediated transfer
    identifier = 1
    expiration = app0.raiden.chain.block_number() + settle_timeout - reveal_timeout
    secret = pending_mediated_transfer(
        raiden_network,
        token,
        amount,
        identifier,
        expiration,
    )
    hashlock = sha3(secret)

    # get a proof for the pending transfer
    back_channel = channel(app1, app0, token)
    secret_transfer = get_received_transfer(back_channel, 0)
    lock = back_channel.our_state.balance_proof.get_lock_by_hashlock(hashlock)
    unlock_proof = back_channel.our_state.balance_proof.compute_proof_for_lock(secret, lock)

    # reveal the secret
    claim_lock(raiden_network, token, secret)

    # a new transfer to update the hashlock
    direct_transfer(app0, app1, token, amount)

    forward_channel = channel(app0, app1, token)
    last_transfer = get_sent_transfer(forward_channel, 1)

    # call close giving the secret for a transfer that has being revealed
    back_channel.external_state.netting_channel.close(
        app1.raiden.address,
        last_transfer,
    )

    # check that the double unlock will failed
    with pytest.raises(Exception):
        back_channel.external_state.netting_channel.unlock(
            app1.raiden.address,
            [(unlock_proof, secret_transfer.lock.as_bytes, secret)],
        )

    # forward the block number to allow settle
    settle_expiration = app2.raiden.chain.block_number() + settle_timeout
    wait_until_block(app2.raiden.chain, settle_expiration)

    back_channel.external_state.netting_channel.settle()

    participant0 = back_channel.external_state.netting_channel.contract.participants[address0]
    participant1 = back_channel.external_state.netting_channel.contract.participants[address1]

    assert participant0.netted == participant0.deposit - amount * 2
    assert participant1.netted == participant1.deposit + amount * 2


@pytest.mark.timeout(240)
@pytest.mark.xfail(reason="test incomplete")
@pytest.mark.parametrize('privatekey_seed', ['start_end_attack:{}'])
@pytest.mark.parametrize('number_of_nodes', [3])
def test_start_end_attack(tokens_addresses, raiden_chain, deposit, reveal_timeout):
    """ An attacker can try to steal tokens from a hub or the last node in a
    path.

    The attacker needs to use two addresses (A1 and A2) and connect both to the
    hub H, once connected a mediated transfer is initialized from A1 to A2
    through H, once the node A2 receives the mediated transfer the attacker
    uses the known secret and reveal to close and settles the channel H-A2,
    without revealing the secret to H's raiden node.

    The intention is to make the hub transfer the token but for him to be
    unable to require the token A1.
    """
    amount = 30

    token = tokens_addresses[0]
    app0, app1, app2 = raiden_chain  # pylint: disable=unbalanced-tuple-unpacking

    # the attacker owns app0 and app2 and creates a transfer through app1
    identifier = 1
    expiration = reveal_timeout + 5
    secret = pending_mediated_transfer(
        raiden_chain,
        token,
        amount,
        identifier,
        expiration
    )
    hashlock = sha3(secret)

    attack_channel = channel(app2, app1, token)
    attack_transfer = get_received_transfer(attack_channel, 0)
    attack_contract = attack_channel.external_state.netting_channel.address
    hub_contract = channel(app1, app0, token).external_state.netting_channel.address

    # the attacker can create a merkle proof of the locked transfer
    lock = attack_channel.our_state.balance_proof.get_lock_by_hashlock(hashlock)
    unlock_proof = attack_channel.our_state.balance_proof.compute_proof_for_lock(secret, lock)

    # start the settle counter
    attack_channel.netting_channel.close(
        app2.raiden.address,
        attack_transfer,
        None
    )

    # wait until the last block to reveal the secret, hopefully we are not
    # missing a block during the test
    wait_until_block(app2.raiden.chain, attack_transfer.lock.expiration - 1)

    # since the attacker knows the secret he can net the lock
    attack_channel.netting_channel.unlock(
        [(unlock_proof, attack_transfer.lock, secret)],
    )
    # XXX: verify that the secret was publicized

    # at this point the hub might not know yet the secret, and won't be able to
    # claim the token from the channel A1 - H

    # the attacker settle the contract
    app2.raiden.chain.next_block()

    attack_channel.netting_channel.settle(token, attack_contract)

    # at this point the attack has the "stolen" funds
    attack_contract = app2.raiden.chain.token_hashchannel[token][attack_contract]
    assert attack_contract.participants[app2.raiden.address]['netted'] == deposit + amount
    assert attack_contract.participants[app1.raiden.address]['netted'] == deposit - amount

    # and the hub's channel A1-H doesn't
    hub_contract = app1.raiden.chain.token_hashchannel[token][hub_contract]
    assert hub_contract.participants[app0.raiden.address]['netted'] == deposit
    assert hub_contract.participants[app1.raiden.address]['netted'] == deposit

    # to mitigate the attack the Hub _needs_ to use a lower expiration for the
    # locked transfer between H-A2 than A1-H, since for A2 to acquire the token
    # it needs to make the secret public in the block chain we publish the
    # secret through an event and the Hub will be able to require it's funds
    app1.raiden.chain.next_block()

    # XXX: verify that the Hub has found the secret, close and settle the channel

    # the hub has acquired its token
    hub_contract = app1.raiden.chain.token_hashchannel[token][hub_contract]
    assert hub_contract.participants[app0.raiden.address]['netted'] == deposit + amount
    assert hub_contract.participants[app1.raiden.address]['netted'] == deposit - amount
