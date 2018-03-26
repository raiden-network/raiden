# -*- coding: utf-8 -*-
import pytest

from raiden.tests.utils.events import must_contain_entry
from raiden.tests.utils.blockchain import wait_until_block
from raiden.tests.utils.messages import setup_messages_cb
from raiden.tests.utils.transfer import assert_synched_channels
from raiden.tests.utils.log import get_all_state_changes
from raiden.transfer.mediated_transfer.state_change import (
    ContractReceiveClosed,
    ContractReceiveWithdraw,
    ContractReceiveSettled,
    ReceiveSecretReveal,
)
from raiden.transfer.merkle_tree import validate_proof, merkleroot
from raiden.transfer.state_change import Block
from raiden.utils import sha3, privatekey_to_address

# pylint: disable=too-many-locals,too-many-statements


@pytest.mark.parametrize('number_of_nodes', [2])
def test_settlement(raiden_network, settle_timeout, reveal_timeout):
    alice_app, bob_app = raiden_network  # pylint: disable=unbalanced-tuple-unpacking

    setup_messages_cb()

    alice_graph = list(alice_app.raiden.token_to_channelgraph.values())[0]
    bob_graph = list(bob_app.raiden.token_to_channelgraph.values())[0]
    assert alice_graph.token_address == bob_graph.token_address

    alice_bob_channel = alice_graph.partneraddress_to_channel[bob_app.raiden.address]
    bob_alice_channel = bob_graph.partneraddress_to_channel[alice_app.raiden.address]

    alice_deposit = alice_bob_channel.balance
    bob_deposit = bob_alice_channel.balance

    token = alice_app.raiden.chain.token(alice_bob_channel.token_address)

    alice_balance = token.balance_of(alice_app.raiden.address)
    bob_balance = token.balance_of(bob_app.raiden.address)

    alice_chain = alice_app.raiden.chain

    alice_to_bob_amount = 10
    expiration = alice_app.raiden.chain.block_number() + reveal_timeout + 1
    secret = b'secretsecretsecretsecretsecretse'
    hashlock = sha3(secret)

    assert bob_app.raiden.address in alice_graph.partneraddress_to_channel

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
    alice_bob_channel.register_transfer(
        alice_app.raiden.get_block_number(),
        transfermessage,
    )
    bob_alice_channel.register_transfer(
        bob_app.raiden.get_block_number(),
        transfermessage,
    )

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
    lock = bob_alice_channel.partner_state.get_lock_by_hashlock(hashlock)
    assert sha3(secret) == hashlock
    unlock_proof = bob_alice_channel.partner_state.compute_proof_for_lock(secret, lock)

    root = merkleroot(bob_alice_channel.partner_state.merkletree)

    assert validate_proof(
        unlock_proof.merkle_proof,
        root,
        sha3(transfermessage.lock.as_bytes),
    )
    assert unlock_proof.lock_encoded == transfermessage.lock.as_bytes
    assert unlock_proof.secret == secret

    # a ChannelClose event will be generated, this will be polled by both apps
    # and each must start a task for calling settle
    balance_proof = transfermessage.to_balanceproof()
    bob_alice_channel.external_state.close(balance_proof)
    wait_until_block(alice_chain, alice_chain.block_number() + 1)

    assert alice_bob_channel.external_state.close_event.wait(timeout=15)
    assert bob_alice_channel.external_state.close_event.wait(timeout=15)

    assert alice_bob_channel.external_state.closed_block != 0
    assert bob_alice_channel.external_state.closed_block != 0
    assert alice_bob_channel.external_state.settled_block == 0
    assert bob_alice_channel.external_state.settled_block == 0

    # unlock will not be called by Channel.channel_closed because we did not
    # register the secret
    assert lock.expiration > alice_app.raiden.chain.block_number()
    assert lock.hashlock == sha3(secret)

    bob_alice_channel.external_state.netting_channel.withdraw([unlock_proof])

    settle_expiration = alice_chain.block_number() + settle_timeout + 2
    wait_until_block(alice_chain, settle_expiration)

    assert alice_bob_channel.external_state.settle_event.wait(timeout=15)
    assert bob_alice_channel.external_state.settle_event.wait(timeout=15)
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
        change[1] for change in get_all_state_changes(alice_app.raiden.transaction_log)
        if not isinstance(change[1], Block)
    ]

    assert must_contain_entry(state_changes, ContractReceiveClosed, {
        'channel_address': nettingaddress0,
        'closing_address': bob_app.raiden.address,
        'block_number': alice_bob_channel.external_state.closed_block,
    })

    assert must_contain_entry(state_changes, ReceiveSecretReveal, {
        'secret': secret,
        'sender': bob_app.raiden.address,
    })

    assert must_contain_entry(state_changes, ContractReceiveWithdraw, {
        'channel_address': nettingaddress0,
        'secret': secret,
        'receiver': bob_app.raiden.address,
    })

    assert must_contain_entry(state_changes, ContractReceiveSettled, {
        'channel_address': nettingaddress0,
        'block_number': bob_alice_channel.external_state.settled_block,
    })


@pytest.mark.parametrize('number_of_nodes', [2])
def test_automatic_dispute(raiden_network, deposit, settle_timeout):
    app0, app1 = raiden_network
    channel0 = list(list(app0.raiden.token_to_channelgraph.values())[0].partneraddress_to_channel.values())[0]  # noqa: E501
    channel1 = list(list(app1.raiden.token_to_channelgraph.values())[0].partneraddress_to_channel.values())[0]  # noqa: E501
    privatekey0 = app0.raiden.private_key
    privatekey1 = app1.raiden.private_key
    address0 = privatekey_to_address(privatekey0.secret)
    address1 = privatekey_to_address(privatekey1.secret)
    token = app0.raiden.chain.token(channel0.token_address)
    initial_balance0 = token.balance_of(address0)
    initial_balance1 = token.balance_of(address1)

    # Alice sends Bob 10 tokens
    amount_alice1 = 10
    identifier_alice1 = 1
    alice_first_transfer = channel0.create_directtransfer(
        amount_alice1,
        identifier_alice1,
    )
    alice_first_transfer.sign(privatekey0, address0)
    channel0.register_transfer(
        app0.raiden.get_block_number(),
        alice_first_transfer,
    )
    channel1.register_transfer(
        app1.raiden.get_block_number(),
        alice_first_transfer,
    )

    # Bob sends Alice 50 tokens
    amount_bob1 = 50
    identifier_bob1 = 1
    bob_first_transfer = channel1.create_directtransfer(
        amount_bob1,
        identifier_bob1,
    )
    bob_first_transfer.sign(privatekey1, address1)
    channel0.register_transfer(
        app0.raiden.get_block_number(),
        bob_first_transfer,
    )
    channel1.register_transfer(
        app1.raiden.get_block_number(),
        bob_first_transfer,
    )

    # Finally Alice sends Bob 60 tokens
    identifier_alice2 = 2
    amount_alice2 = 60
    alice_second_transfer = channel0.create_directtransfer(
        amount_alice2,
        identifier_alice2,
    )
    alice_second_transfer.sign(privatekey0, address0)
    channel0.register_transfer(
        app0.raiden.get_block_number(),
        alice_second_transfer,
    )
    channel1.register_transfer(
        app1.raiden.get_block_number(),
        alice_second_transfer,
    )

    # Alice can only provide one of Bob's transfer, so she is incentivized to
    # use the one with the largest transferred_amount.
    channel0.external_state.close(channel0.partner_state.balance_proof)
    chain0 = app0.raiden.chain
    wait_until_block(chain0, chain0.block_number() + 1)

    assert channel0.external_state.close_event.wait(timeout=25)
    assert channel1.external_state.close_event.wait(timeout=25)

    assert channel0.external_state.closed_block != 0
    assert channel1.external_state.closed_block != 0

    # Bob needs to provide a transfer otherwise it's netted balance will be
    # wrong, so he is incetivized to use Alice's transfer with the largest
    # transferred_amount.
    #
    # This is done automatically
    # channel1.external_state.update_transfer(
    #     alice_second_transfer,
    # )

    # wait until the settle timeout has passed
    settle_expiration = chain0.block_number() + settle_timeout
    wait_until_block(chain0, settle_expiration)

    # the settle event must be set
    assert channel0.external_state.settle_event.wait(timeout=60)
    assert channel1.external_state.settle_event.wait(timeout=60)

    # check that the channel is properly settled and that Bob's client
    # automatically called updateTransfer() to reflect the actual transactions
    assert channel0.external_state.settled_block != 0
    assert channel1.external_state.settled_block != 0
    assert token.balance_of(channel0.external_state.netting_channel.address) == 0
    total_alice = amount_alice1 + amount_alice2
    total_bob = amount_bob1
    assert token.balance_of(address0) == initial_balance0 + deposit - total_alice + total_bob
    assert token.balance_of(address1) == initial_balance1 + deposit + total_alice - total_bob
