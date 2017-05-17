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
from raiden.transfer.mediated_transfer.state_change import (
    ContractReceiveClosed,
    ContractReceiveWithdraw,
    ContractReceiveSettled,
    ReceiveSecretReveal,
)
from raiden.transfer.state_change import Block
from raiden.utils import sha3, privatekey_to_address

# pylint: disable=too-many-locals,too-many-statements
slogging.configure(':DEBUG')


def assert_secretreveal_or_withdraw(state_change, secret, channel_address, raiden_address):
    if isinstance(state_change, ReceiveSecretReveal):
        assert state_change.secret == secret
        assert state_change.sender == raiden_address
    elif isinstance(state_change, ContractReceiveWithdraw):
        assert state_change.channel_address == channel_address
        assert state_change.secret == secret
        assert state_change.receiver == raiden_address
    else:
        raise ValueError(
            '{} is neither ReceiveSecretReveal or ContractReceiveWithdraw'.format(state_change)
        )


@pytest.mark.parametrize('privatekey_seed', ['settlement:{}'])
@pytest.mark.parametrize('number_of_nodes', [2])
def test_settlement(raiden_network, settle_timeout, reveal_timeout):
    alice_app, bob_app = raiden_network  # pylint: disable=unbalanced-tuple-unpacking

    setup_messages_cb()

    alice_graph = alice_app.raiden.channelgraphs.values()[0]
    bob_graph = bob_app.raiden.channelgraphs.values()[0]
    assert alice_graph.token_address == bob_graph.token_address

    alice_bob_channel = alice_graph.partneraddress_channel[bob_app.raiden.address]
    bob_alice_channel = bob_graph.partneraddress_channel[alice_app.raiden.address]

    alice_deposit = alice_bob_channel.balance
    bob_deposit = bob_alice_channel.balance

    token = alice_app.raiden.chain.token(alice_bob_channel.token_address)

    alice_balance = token.balance_of(alice_app.raiden.address)
    bob_balance = token.balance_of(bob_app.raiden.address)

    alice_chain = alice_app.raiden.chain

    alice_to_bob_amount = 10
    expiration = alice_app.raiden.chain.block_number() + reveal_timeout + 1
    secret = 'secretsecretsecretsecretsecretse'
    hashlock = sha3(secret)

    assert bob_app.raiden.address in alice_graph.partneraddress_channel

    nettingaddress0 = alice_bob_channel.external_state.netting_channel.address
    nettingaddress1 = bob_alice_channel.external_state.netting_channel.address
    assert nettingaddress0 == nettingaddress1

    identifier = 1
    fee = 0
    transfermessage = alice_bob_channel.create_mediatedtransfer(
        alice_app.raiden.address,
        bob_app.raiden.address,
        fee,
        alice_to_bob_amount,
        identifier,
        expiration,
        hashlock,
    )
    alice_app.raiden.sign(transfermessage)
    alice_bob_channel.register_transfer(transfermessage)
    bob_alice_channel.register_transfer(transfermessage)

    assert_synched_channels(
        alice_bob_channel, alice_deposit, [],
        bob_alice_channel, bob_deposit, [transfermessage.lock],
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
    lock = bob_alice_channel.our_state.balance_proof.get_lock_by_hashlock(hashlock)
    assert sha3(secret) == hashlock
    unlock_proof = bob_alice_channel.our_state.balance_proof.compute_proof_for_lock(secret, lock)

    root = bob_alice_channel.our_state.balance_proof.merkleroot_for_unclaimed()

    assert check_proof(
        unlock_proof.merkle_proof,
        root,
        sha3(transfermessage.lock.as_bytes),
    )
    assert unlock_proof.lock_encoded == transfermessage.lock.as_bytes
    assert unlock_proof.secret == secret

    # a ChannelClose event will be generated, this will be polled by both apps
    # and each must start a task for calling settle
    bob_alice_channel.external_state.netting_channel.close(
        bob_app.raiden.address,
        transfermessage,
    )
    wait_until_block(alice_chain, alice_chain.block_number() + 1)

    assert alice_bob_channel.close_event.wait(timeout=15)
    assert bob_alice_channel.close_event.wait(timeout=15)

    assert alice_bob_channel.external_state.closed_block != 0
    assert bob_alice_channel.external_state.closed_block != 0
    assert alice_bob_channel.external_state.settled_block == 0
    assert bob_alice_channel.external_state.settled_block == 0

    # unlock will not be called by Channel.channel_closed because we did not
    # register the secret
    assert lock.expiration > alice_app.raiden.chain.block_number()
    assert lock.hashlock == sha3(secret)

    bob_alice_channel.external_state.netting_channel.withdraw(
        bob_app.raiden.address,
        [unlock_proof],
    )

    settle_expiration = alice_chain.block_number() + settle_timeout + 2
    wait_until_block(alice_chain, settle_expiration)

    assert alice_bob_channel.settle_event.wait(timeout=15)
    assert bob_alice_channel.settle_event.wait(timeout=15)
    # settle must be called by the apps triggered by the ChannelClose event,
    # and the channels must update it's state based on the ChannelSettled event
    assert alice_bob_channel.external_state.settled_block != 0
    assert bob_alice_channel.external_state.settled_block != 0

    address0 = alice_app.raiden.address
    address1 = bob_app.raiden.address

    alice_netted_balance = alice_balance + alice_deposit - alice_to_bob_amount
    bob_netted_balance = bob_balance + bob_deposit + alice_to_bob_amount

    assert token.balance_of(address0) == alice_netted_balance
    assert token.balance_of(address1) == bob_netted_balance

    # Now let's query the WAL to see if the state changes were logged as expected
    state_changes = [
        change[1] for change in alice_app.raiden.transaction_log.get_all_state_changes()
        if not isinstance(change[1], Block)
    ]

    state_change1 = state_changes[0]
    state_change2 = state_changes[1]
    state_change3 = state_changes[2]
    state_change4 = state_changes[3]

    assert(isinstance(state_change1, ContractReceiveClosed))
    assert state_change1.channel_address == nettingaddress0
    assert state_change1.closing_address == bob_app.raiden.address
    assert state_change1.block_number == alice_bob_channel.external_state.closed_block

    # Can't be sure of the order in which we encounter the SecretReveal and the withdraw
    assert_secretreveal_or_withdraw(state_change2, secret, nettingaddress0, bob_app.raiden.address)
    assert_secretreveal_or_withdraw(state_change3, secret, nettingaddress0, bob_app.raiden.address)

    assert(isinstance(state_change4, ContractReceiveSettled))
    assert state_change4.channel_address == nettingaddress0
    assert state_change4.block_number == bob_alice_channel.external_state.settled_block


@pytest.mark.parametrize('privatekey_seed', ['settled_lock:{}'])
@pytest.mark.parametrize('number_of_nodes', [4])
@pytest.mark.parametrize('channels_per_node', [CHAIN])
# TODO: Need to expose the netted value to use a different blockchain_type
@pytest.mark.parametrize('blockchain_type', ['mock'])
def test_settled_lock(token_addresses, raiden_network, settle_timeout, reveal_timeout):
    """ Any transfer following a secret revealed must update the locksroot, so
    that an attacker cannot reuse a secret to double claim a lock.
    """
    token = token_addresses[0]
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

    # check that the double unlock will fail
    with pytest.raises(Exception):
        back_channel.external_state.netting_channel.withdraw(
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


@pytest.mark.xfail(reason="test incomplete")
@pytest.mark.parametrize('privatekey_seed', ['start_end_attack:{}'])
@pytest.mark.parametrize('number_of_nodes', [3])
def test_start_end_attack(token_addresses, raiden_chain, deposit, reveal_timeout):
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

    token = token_addresses[0]
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
    attack_channel.netting_channel.withdraw(
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


@pytest.mark.parametrize('blockchain_type', ['geth'])
@pytest.mark.parametrize('number_of_nodes', [2])
def test_automatic_dispute(raiden_network, deposit, settle_timeout, reveal_timeout):
    app0, app1 = raiden_network
    channel0 = app0.raiden.channelgraphs.values()[0].partneraddress_channel.values()[0]
    channel1 = app1.raiden.channelgraphs.values()[0].partneraddress_channel.values()[0]
    privatekey0 = app0.raiden.private_key
    privatekey1 = app1.raiden.private_key
    address0 = privatekey_to_address(privatekey0.secret)
    address1 = privatekey_to_address(privatekey1.secret)
    token = app0.raiden.chain.token(channel0.token_address)
    initial_balance0 = token.balance_of(address0)
    initial_balance1 = token.balance_of(address1)

    # Alice sends Bob 10 tokens
    amount_alice1 = 10
    alice_first_transfer = channel0.create_directtransfer(
        amount_alice1,
        1  # TODO: fill in identifier
    )
    alice_first_transfer.sign(privatekey0, address0)
    channel0.register_transfer(alice_first_transfer)
    channel1.register_transfer(alice_first_transfer)

    # Bob sends Alice 50 tokens
    amount_bob1 = 50
    bob_first_transfer = channel1.create_directtransfer(
        amount_bob1,
        1  # TODO: fill in identifier
    )
    bob_first_transfer.sign(privatekey1, address1)
    channel0.register_transfer(bob_first_transfer)
    channel1.register_transfer(bob_first_transfer)

    # Finally Alice sends Bob 60 tokens
    amount_alice2 = 60
    alice_second_transfer = channel0.create_directtransfer(
        amount_alice2,
        1  # TODO: fill in identifier
    )
    alice_second_transfer.sign(privatekey0, address0)
    channel0.register_transfer(alice_second_transfer)
    channel1.register_transfer(alice_second_transfer)

    bob_last_transaction = bob_first_transfer

    # Alice can only provide one of Bob's transfer, so she is incetivized to
    # use the one with the largest transferred_amount.
    channel0.external_state.close(
        None,
        bob_last_transaction,
    )
    chain0 = app0.raiden.chain
    wait_until_block(chain0, chain0.block_number() + 1)

    assert channel0.close_event.wait(timeout=25)
    assert channel1.close_event.wait(timeout=25)

    assert channel0.external_state.closed_block != 0
    assert channel1.external_state.closed_block != 0

    # Bob needs to provide a transfer otherwise it's netted balance will be
    # wrong, so he is incetivized to use Alice's transfer with the largest
    # transferred_amount.
    channel1.external_state.update_transfer(
        None,
        alice_second_transfer,
    )

    # wait until the settle timeout has passed
    settle_expiration = chain0.block_number() + settle_timeout
    wait_until_block(chain0, settle_expiration)

    # the settle event must be set
    assert channel0.settle_event.wait(timeout=60)
    assert channel1.settle_event.wait(timeout=60)

    # check that the channel is properly settled and that Bob's client
    # automatically called updateTransfer() to reflect the actual transactions
    assert channel0.external_state.settled_block != 0
    assert channel1.external_state.settled_block != 0
    assert token.balance_of(channel0.external_state.netting_channel.address) == 0
    total_alice = amount_alice1 + amount_alice2
    total_bob = amount_bob1
    assert token.balance_of(address0) == initial_balance0 + deposit - total_alice + total_bob
    assert token.balance_of(address1) == initial_balance1 + deposit + total_alice - total_bob
