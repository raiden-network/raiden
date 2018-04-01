# -*- coding: utf-8 -*-
import pytest

from raiden import waiting, udp_message_handler
from raiden.api.python import RaidenAPI2
from raiden.messages import RevealSecret
from raiden.tests.utils.events import must_contain_entry
from raiden.tests.utils.blockchain import wait_until_block
from raiden.tests.utils.network import CHAIN
from raiden.tests.utils.transfer import (
    assert_synched_channel_state,
    claim_lock,
    direct_transfer,
    get_channelstate,
    pending_mediated_transfer,
)
from raiden.transfer import channel
from raiden.transfer.merkle_tree import validate_proof, merkleroot
from raiden.transfer.state_change import (
    ActionForTokenNetwork,
    ContractReceiveChannelWithdraw,
)
from raiden.utils import sha3


@pytest.mark.parametrize('number_of_nodes', [2])
def test_settle_is_automatically_called(raiden_network, token_addresses, deposit):
    """Settle is automatically called by one of the nodes."""
    app0, app1 = raiden_network
    registry_address = app0.raiden.default_registry.address
    token_address = token_addresses[0]
    channel_identifier = get_channelstate(app0, app1, token_address).identifier

    # A ChannelClose event will be generated, this will be polled by both apps
    # and each must start a task for calling settle
    RaidenAPI2(app1.raiden).channel_close(token_address, app0.raiden.address)

    waiting.wait_for_settle(
        app0.raiden,
        registry_address,
        token_address,
        [channel_identifier],
        app0.raiden.alarm.wait_time,
    )

    assert_synched_channel_state(
        token_address,
        app0, deposit, [],
        app1, deposit, [],
    )

    state_changes = app0.raiden.wal.storage.get_statechanges_by_identifier(
        from_identifier=0,
        to_identifier='latest',
    )

    channel_state = get_channelstate(app0, app1, token_address)
    assert channel_state.close_transaction.finished_block_number
    assert channel_state.settle_transaction.finished_block_number

    # ContractReceiveChannelClosed
    assert must_contain_entry(state_changes, ActionForTokenNetwork, {
        'payment_network_identifier': registry_address,
        'token_network_identifier': token_address,
        'sub_state_change': {
            'channel_identifier': channel_identifier,
            'closing_address': app1.raiden.address,
            'closed_block_number': channel_state.close_transaction.finished_block_number,
        }
    })

    # ContractReceiveChannelSettled
    assert must_contain_entry(state_changes, ActionForTokenNetwork, {
        'payment_network_identifier': registry_address,
        'token_network_identifier': token_address,
        'sub_state_change': {
            'channel_identifier': channel_identifier,
            'settle_block_number': channel_state.settle_transaction.finished_block_number,
        }
    })


@pytest.mark.parametrize('number_of_nodes', [2])
def test_withdraw(raiden_network, token_addresses, deposit):
    """Withdraw can be called on a closed channel."""
    alice_app, bob_app = raiden_network
    registry_address = alice_app.raiden.default_registry.address
    token_address = token_addresses[0]
    token_proxy = alice_app.raiden.chain.token(token_address)

    alice_initial_balance = token_proxy.balance_of(alice_app.raiden.address)
    bob_initial_balance = token_proxy.balance_of(bob_app.raiden.address)

    alice_to_bob_amount = 10
    identifier = 1
    secret = pending_mediated_transfer(
        raiden_network,
        token_address,
        alice_to_bob_amount,
        identifier,
    )
    hashlock = sha3(secret)

    # This is the current state of the protocol:
    #
    #    A -> B MediatedTransfer
    #    B -> A SecretRequest
    #    - protocol didn't continue

    alice_bob_channel = get_channelstate(alice_app, bob_app, token_address)
    bob_alice_channel = get_channelstate(bob_app, alice_app, token_address)

    lock = channel.get_lock(alice_bob_channel.our_state, hashlock)
    assert lock

    assert_synched_channel_state(
        token_address,
        alice_app, deposit, [lock],
        bob_app, deposit, [],
    )

    # get proof, that locked transfermessage was in merkle tree, with locked.root
    unlock_proof = channel.compute_proof_for_lock(
        alice_bob_channel.our_state,
        secret,
        lock,
    )

    assert validate_proof(
        unlock_proof.merkle_proof,
        merkleroot(bob_alice_channel.partner_state.merkletree),
        sha3(lock.encoded),
    )
    assert unlock_proof.lock_encoded == lock.encoded
    assert unlock_proof.secret == secret

    # A ChannelClose event will be generated, this will be polled by both apps
    # and each must start a task for calling settle
    RaidenAPI2(bob_app.raiden).channel_close(
        token_address,
        alice_app.raiden.address,
    )

    # Unlock will not be called because the secret was not revealed
    assert lock.expiration > alice_app.raiden.chain.block_number()
    assert lock.hashlock == sha3(secret)

    nettingchannel_proxy = bob_app.raiden.chain.netting_channel(
        bob_alice_channel.identifier,
    )
    nettingchannel_proxy.withdraw([unlock_proof])

    waiting.wait_for_settle(
        alice_app.raiden,
        registry_address,
        token_address,
        [alice_bob_channel.identifier],
        alice_app.raiden.alarm.wait_time,
    )

    alice_bob_channel = get_channelstate(alice_app, bob_app, token_address)
    bob_alice_channel = get_channelstate(bob_app, alice_app, token_address)

    alice_netted_balance = alice_initial_balance + deposit - alice_to_bob_amount
    bob_netted_balance = bob_initial_balance + deposit + alice_to_bob_amount

    assert token_proxy.balance_of(alice_app.raiden.address) == alice_netted_balance
    assert token_proxy.balance_of(bob_app.raiden.address) == bob_netted_balance

    # Now let's query the WAL to see if the state changes were logged as expected
    state_changes = alice_app.raiden.wal.storage.get_statechanges_by_identifier(
        from_identifier=0,
        to_identifier='latest',
    )

    alice_bob_channel = get_channelstate(alice_app, bob_app, token_address)
    bob_alice_channel = get_channelstate(bob_app, alice_app, token_address)

    assert must_contain_entry(state_changes, ContractReceiveChannelWithdraw, {
        'payment_network_identifier': registry_address,
        'token_network_identifier': token_address,
        'channel_identifier': alice_bob_channel.identifier,
        'hashlock': hashlock,
        'secret': secret,
        'receiver': bob_app.raiden.address,
    })


@pytest.mark.parametrize('number_of_nodes', [2])
@pytest.mark.parametrize('channels_per_node', [CHAIN])
def test_settled_lock(token_addresses, raiden_network, deposit):
    """ Any transfer following a secret revealed must update the locksroot, so
    that an attacker cannot reuse a secret to double claim a lock.
    """
    app0, app1 = raiden_network
    token_address = token_addresses[0]
    amount = 30

    address0 = app0.raiden.address
    address1 = app1.raiden.address

    deposit0 = deposit
    deposit1 = deposit

    token_proxy = app0.raiden.chain.token(token_address)
    initial_balance0 = token_proxy.balance_of(address0)
    initial_balance1 = token_proxy.balance_of(address1)

    # Using a pending mediated transfer because this allows us to compute the
    # merkle proof
    identifier = 1
    secret = pending_mediated_transfer(
        raiden_network,
        token_address,
        amount,
        identifier,
    )
    hashlock = sha3(secret)

    # Compute the merkle proof for the pending transfer, and then unlock
    channelstate_0_1 = get_channelstate(app0, app1, token_address)
    lock = channel.get_lock(channelstate_0_1.our_state, hashlock)
    unlock_proof = channel.compute_proof_for_lock(
        channelstate_0_1.our_state,
        secret,
        lock,
    )
    claim_lock(raiden_network, identifier, token_address, secret)

    # Make a new transfer
    direct_transfer(app0, app1, token_address, amount, identifier=1)
    RaidenAPI2(app1.raiden).channel_close(token_address, app0.raiden.address)

    # The direct transfer locksroot must not contain the unlocked lock, the
    # withdraw must fail.
    netting_channel = app1.raiden.chain.netting_channel(channelstate_0_1.identifier)
    with pytest.raises(Exception):
        netting_channel.withdraw([(unlock_proof, lock.encoded, secret)])

    waiting.wait_for_settle(
        app1.raiden,
        app1.raiden.default_registry.address,
        token_address,
        [channelstate_0_1.identifier],
        app1.raiden.alarm.wait_time,
    )

    expected_balance0 = initial_balance0 + deposit0 - amount * 2
    expected_balance1 = initial_balance1 + deposit1 + amount * 2

    assert token_proxy.balance_of(address0) == expected_balance0
    assert token_proxy.balance_of(address1) == expected_balance1


@pytest.mark.parametrize('number_of_nodes', [2])
@pytest.mark.parametrize('channels_per_node', [1])
def test_close_channel_lack_of_balance_proof(
        raiden_chain,
        reveal_timeout,
        deposit,
        token_addresses):

    app0, app1 = raiden_chain
    token_address = token_addresses[0]

    token_proxy = app0.raiden.chain.token(token_address)
    initial_balance0 = token_proxy.balance_of(app0.raiden.address)
    initial_balance1 = token_proxy.balance_of(app1.raiden.address)

    expiration = app0.raiden.get_block_number() + reveal_timeout * 2

    amount = 100
    identifier = 1
    secret = pending_mediated_transfer(
        raiden_chain,
        token_address,
        amount,
        identifier,
    )

    # Stop app0 to avoid sending the unlock
    app0.raiden.protocol.stop_and_wait()

    reveal_secret = RevealSecret(secret)
    app0.raiden.sign(reveal_secret)
    udp_message_handler.on_udp_message(app1.raiden, reveal_secret)

    assert app0.raiden.get_block_number() < expiration, 'increase the expiration'

    channel_state = get_channelstate(app0, app1, token_address)
    waiting.wait_for_settle(
        app0.raiden,
        app0.raiden.default_registry.address,
        token_address,
        [channel_state.identifier],
        app0.raiden.alarm.wait_time,
    )

    expected_balance0 = initial_balance0 + deposit - amount
    expected_balance1 = initial_balance1 + deposit + amount
    assert token_proxy.balance_of(app0.raiden.address) == expected_balance0
    assert token_proxy.balance_of(app1.raiden.address) == expected_balance1


@pytest.mark.xfail(reason='test incomplete')
@pytest.mark.parametrize('number_of_nodes', [3])
def test_start_end_attack(token_addresses, raiden_chain, deposit):
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
    secret = pending_mediated_transfer(
        raiden_chain,
        token,
        amount,
        identifier,
    )
    hashlock = sha3(secret)

    attack_channel = get_channelstate(app2, app1, token)
    attack_transfer = None  # TODO
    attack_contract = attack_channel.external_state.netting_channel.address
    hub_contract = get_channelstate(app1, app0, token).external_state.netting_channel.address

    # the attacker can create a merkle proof of the locked transfer
    lock = attack_channel.partner_state.get_lock_by_hashlock(hashlock)
    unlock_proof = attack_channel.partner_state.compute_proof_for_lock(secret, lock)

    # start the settle counter
    attack_balance_proof = attack_transfer.to_balanceproof()
    attack_channel.netting_channel.channel_close(attack_balance_proof)

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


@pytest.mark.parametrize('number_of_nodes', [2])
def test_automatic_dispute(raiden_network, deposit, token_addresses):
    app0, app1 = raiden_network
    registry_address = app0.raiden.default_registry.address
    token_address = token_addresses[0]

    channel0 = get_channelstate(app0, app1, token_address)
    token_proxy = app0.raiden.chain.token(channel0.token_address)
    initial_balance0 = token_proxy.balance_of(app0.raiden.address)
    initial_balance1 = token_proxy.balance_of(app1.raiden.address)

    amount0_1 = 10
    direct_transfer(
        app0,
        app1,
        token_address,
        amount0_1,
    )

    amount1_1 = 50
    direct_transfer(
        app1,
        app0,
        token_address,
        amount1_1,
    )

    amount0_2 = 60
    direct_transfer(
        app0,
        app1,
        token_address,
        amount0_2,
    )

    # Alice can only provide one of Bob's transfer, so she is incentivized to
    # use the one with the largest transferred_amount.
    RaidenAPI2(app0.raiden).channel_close(token_address, app1.raiden.address)

    # Bob needs to provide a transfer otherwise it's netted balance will be
    # wrong, so he is incetivized to use Alice's transfer with the largest
    # transferred_amount.
    #
    # This is done automatically
    # channel1.external_state.update_transfer(
    #     alice_second_transfer,
    # )

    waiting.wait_for_settle(
        app0.raiden,
        registry_address,
        token_address,
        [channel0.identifier],
        app0.raiden.alarm.wait_time,
    )

    # check that the channel is properly settled and that Bob's client
    # automatically called updateTransfer() to reflect the actual transactions
    assert token_proxy.balance_of(channel0.identifier) == 0
    total0 = amount0_1 + amount0_2
    total1 = amount1_1
    expected_balance0 = initial_balance0 + deposit - total0 + total1
    expected_balance1 = initial_balance1 + deposit + total0 - total1
    assert token_proxy.balance_of(app0.raiden.address) == expected_balance0
    assert token_proxy.balance_of(app1.raiden.address) == expected_balance1
