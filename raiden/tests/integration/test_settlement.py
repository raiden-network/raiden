import random

import gevent
import pytest

from raiden import message_handler, waiting
from raiden.api.python import RaidenAPI
from raiden.constants import UINT64_MAX
from raiden.messages import RevealSecret
from raiden.settings import DEFAULT_NUMBER_OF_CONFIRMATIONS_BLOCK, DEFAULT_RETRY_TIMEOUT
from raiden.storage.restore import channel_state_until_state_change
from raiden.tests.utils.events import must_contain_entry
from raiden.tests.utils.geth import wait_until_block
from raiden.tests.utils.network import CHAIN
from raiden.tests.utils.transfer import (
    assert_synced_channel_state,
    claim_lock,
    direct_transfer,
    get_channelstate,
    pending_mediated_transfer,
)
from raiden.transfer import channel, views
from raiden.transfer.state import UnlockProofState
from raiden.transfer.state_change import (
    ContractReceiveChannelBatchUnlock,
    ContractReceiveChannelClosed,
    ContractReceiveChannelSettled,
)
from raiden.utils import sha3


def wait_for_batch_unlock(app, token_network_id, participant, partner):
    unlock_event = None
    while not unlock_event:
        gevent.sleep(1)

        state_changes = app.raiden.wal.storage.get_statechanges_by_identifier(
            from_identifier=0,
            to_identifier='latest',
        )

        unlock_event = must_contain_entry(state_changes, ContractReceiveChannelBatchUnlock, {
            'token_network_identifier': token_network_id,
            'participant': participant,
            'partner': partner,
        })


@pytest.mark.parametrize('number_of_nodes', [2])
def test_settle_is_automatically_called(raiden_network, token_addresses, deposit):
    """Settle is automatically called by one of the nodes."""
    app0, app1 = raiden_network
    registry_address = app0.raiden.default_registry.address
    token_address = token_addresses[0]
    token_network_identifier = views.get_token_network_identifier_by_token_address(
        views.state_from_app(app0),
        app0.raiden.default_registry.address,
        token_address,
    )
    token_network = views.get_token_network_by_identifier(
        views.state_from_app(app0),
        token_network_identifier,
    )

    channel_identifier = get_channelstate(app0, app1, token_network_identifier).identifier

    assert channel_identifier in token_network.partneraddresses_to_channels[
        app1.raiden.address
    ]

    # A ChannelClose event will be generated, this will be polled by both apps
    # and each must start a task for calling settle
    RaidenAPI(app1.raiden).channel_close(
        registry_address,
        token_address,
        app0.raiden.address,
    )

    waiting.wait_for_close(
        app0.raiden,
        registry_address,
        token_address,
        [channel_identifier],
        app0.raiden.alarm.sleep_time,
    )

    channel_state = views.get_channelstate_for(
        views.state_from_raiden(app0.raiden),
        registry_address,
        token_address,
        app1.raiden.address,
    )

    assert channel_state.close_transaction.finished_block_number

    waiting.wait_for_settle(
        app0.raiden,
        registry_address,
        token_address,
        [channel_identifier],
        app0.raiden.alarm.sleep_time,
    )

    token_network = views.get_token_network_by_identifier(
        views.state_from_app(app0),
        token_network_identifier,
    )

    assert channel_identifier not in token_network.partneraddresses_to_channels[
        app1.raiden.address
    ]

    state_changes = app0.raiden.wal.storage.get_statechanges_by_identifier(
        from_identifier=0,
        to_identifier='latest',
    )

    assert must_contain_entry(state_changes, ContractReceiveChannelClosed, {
        'token_network_identifier': token_network_identifier,
        'channel_identifier': channel_identifier,
        'transaction_from': app1.raiden.address,
        'closed_block_number': channel_state.close_transaction.finished_block_number,
    })

    assert must_contain_entry(state_changes, ContractReceiveChannelSettled, {
        'token_network_identifier': token_network_identifier,
        'channel_identifier': channel_identifier,
    })


@pytest.mark.parametrize('number_of_nodes', [2])
def test_lock_expiry(raiden_network, token_addresses, secret_registry_address, deposit):
    """Test lock expiry and removal."""
    alice_app, bob_app = raiden_network
    token_address = token_addresses[0]
    token_network_identifier = views.get_token_network_identifier_by_token_address(
        views.state_from_app(alice_app),
        alice_app.raiden.default_registry.address,
        token_address,
    )

    token_network = views.get_token_network_by_identifier(
        views.state_from_app(alice_app),
        token_network_identifier,
    )

    channel_state = get_channelstate(alice_app, bob_app, token_network_identifier)
    channel_identifier = channel_state.identifier

    assert channel_identifier in token_network.partneraddresses_to_channels[
        bob_app.raiden.address
    ]

    alice_to_bob_amount = 10
    identifier = 1
    transfer_1_secret = pending_mediated_transfer(
        raiden_network,
        token_network_identifier,
        alice_to_bob_amount,
        identifier,
    )
    transfer_1_secrethash = sha3(transfer_1_secret)

    alice_bob_channel_state = get_channelstate(alice_app, bob_app, token_network_identifier)
    lock = channel.get_lock(alice_bob_channel_state.our_state, transfer_1_secrethash)

    # This is the current state of the protocol:
    #
    #    A -> B LockedTransfer
    #    B -> A SecretRequest
    #    - protocol didn't continue
    assert_synced_channel_state(
        token_network_identifier,
        alice_app, deposit, [lock],
        bob_app, deposit, [],
    )

    # Verify lock is registered in both channel states
    alice_channel_state = get_channelstate(alice_app, bob_app, token_network_identifier)
    assert transfer_1_secrethash in alice_channel_state.our_state.secrethashes_to_lockedlocks

    bob_channel_state = get_channelstate(bob_app, alice_app, token_network_identifier)
    assert transfer_1_secrethash in bob_channel_state.partner_state.secrethashes_to_lockedlocks

    alice_chain_state = views.state_from_raiden(alice_app.raiden)
    assert transfer_1_secrethash in alice_chain_state.payment_mapping.secrethashes_to_task

    # Wait for the expiration to trigger with some additional buffer
    # time for processing (+2) blocks.
    waiting.wait_for_block(
        alice_app.raiden,
        lock.expiration + (DEFAULT_NUMBER_OF_CONFIRMATIONS_BLOCK + 2),
        DEFAULT_RETRY_TIMEOUT,
    )

    alice_channel_state = get_channelstate(alice_app, bob_app, token_network_identifier)
    assert transfer_1_secrethash not in alice_channel_state.our_state.secrethashes_to_lockedlocks

    # Verify Bob received the message and processed the LockExpired message
    bob_channel_state = get_channelstate(bob_app, alice_app, token_network_identifier)
    assert transfer_1_secrethash not in bob_channel_state.partner_state.secrethashes_to_lockedlocks

    alice_chain_state = views.state_from_raiden(alice_app.raiden)
    assert transfer_1_secrethash not in alice_chain_state.payment_mapping.secrethashes_to_task

    # Make another transfer
    alice_to_bob_amount = 10
    identifier = 2
    transfer_2_secret = pending_mediated_transfer(
        raiden_network,
        token_network_identifier,
        alice_to_bob_amount,
        identifier,
    )
    transfer_2_secrethash = sha3(transfer_2_secret)

    # Make sure the other transfer still exists
    alice_chain_state = views.state_from_raiden(alice_app.raiden)
    assert transfer_2_secrethash in alice_chain_state.payment_mapping.secrethashes_to_task

    bob_channel_state = get_channelstate(bob_app, alice_app, token_network_identifier)
    assert transfer_2_secrethash in bob_channel_state.partner_state.secrethashes_to_lockedlocks


@pytest.mark.parametrize('number_of_nodes', [2])
def test_batch_unlock(raiden_network, token_addresses, secret_registry_address, deposit):
    """Batch unlock can be called after the channel is settled."""
    alice_app, bob_app = raiden_network
    registry_address = alice_app.raiden.default_registry.address
    token_address = token_addresses[0]
    token_proxy = alice_app.raiden.chain.token(token_address)
    token_network_identifier = views.get_token_network_identifier_by_token_address(
        views.state_from_app(alice_app),
        alice_app.raiden.default_registry.address,
        token_address,
    )

    # Take a snapshot early on
    alice_app.raiden.wal.snapshot()

    token_network = views.get_token_network_by_identifier(
        views.state_from_app(alice_app),
        token_network_identifier,
    )

    channel_identifier = get_channelstate(alice_app, bob_app, token_network_identifier).identifier

    assert channel_identifier in token_network.partneraddresses_to_channels[
        bob_app.raiden.address
    ]

    alice_initial_balance = token_proxy.balance_of(alice_app.raiden.address)
    bob_initial_balance = token_proxy.balance_of(bob_app.raiden.address)

    # Take snapshot before transfer
    alice_app.raiden.wal.snapshot()

    alice_to_bob_amount = 10
    identifier = 1
    secret = pending_mediated_transfer(
        raiden_network,
        token_network_identifier,
        alice_to_bob_amount,
        identifier,
    )

    secrethash = sha3(secret)

    alice_bob_channel_state = get_channelstate(alice_app, bob_app, token_network_identifier)
    lock = channel.get_lock(alice_bob_channel_state.our_state, secrethash)

    # This is the current state of the protocol:
    #
    #    A -> B LockedTransfer
    #    B -> A SecretRequest
    #    - protocol didn't continue
    assert_synced_channel_state(
        token_network_identifier,
        alice_app, deposit, [lock],
        bob_app, deposit, [],
    )

    # Take a snapshot early on
    alice_app.raiden.wal.snapshot()

    our_balance_proof = alice_bob_channel_state.our_state.balance_proof

    # Test WAL restore to return the latest channel state
    restored_channel_state = channel_state_until_state_change(
        alice_app.raiden,
        token_address,
        token_network_identifier,
        alice_bob_channel_state.identifier,
        'latest',
    )

    our_restored_balance_proof = restored_channel_state.our_state.balance_proof
    assert our_balance_proof == our_restored_balance_proof

    # A ChannelClose event will be generated, this will be polled by both apps
    # and each must start a task for calling settle
    RaidenAPI(bob_app.raiden).channel_close(
        registry_address,
        token_address,
        alice_app.raiden.address,
    )

    secret_registry_proxy = alice_app.raiden.chain.secret_registry(
        secret_registry_address,
    )
    secret_registry_proxy.register_secret(secret)

    assert lock, 'the lock must still be part of the node state'
    msg = 'the secret must be registered before the lock expires'
    assert lock.expiration > alice_app.raiden.get_block_number(), msg
    assert lock.secrethash == sha3(secret)

    waiting.wait_for_settle(
        alice_app.raiden,
        registry_address,
        token_address,
        [alice_bob_channel_state.identifier],
        alice_app.raiden.alarm.sleep_time,
    )

    token_network = views.get_token_network_by_identifier(
        views.state_from_app(bob_app),
        token_network_identifier,
    )

    assert channel_identifier in token_network.partneraddresses_to_channels[
        alice_app.raiden.address
    ]

    # wait for the node to call batch unlock
    with gevent.Timeout(10):
        wait_for_batch_unlock(
            bob_app,
            token_network_identifier,
            alice_bob_channel_state.partner_state.address,
            alice_bob_channel_state.our_state.address,
        )

    token_network = views.get_token_network_by_identifier(
        views.state_from_app(bob_app),
        token_network_identifier,
    )

    assert channel_identifier not in token_network.partneraddresses_to_channels[
        alice_app.raiden.address
    ]

    alice_new_balance = alice_initial_balance + deposit - alice_to_bob_amount
    bob_new_balance = bob_initial_balance + deposit + alice_to_bob_amount

    assert token_proxy.balance_of(alice_app.raiden.address) == alice_new_balance
    assert token_proxy.balance_of(bob_app.raiden.address) == bob_new_balance


@pytest.mark.parametrize('number_of_nodes', [2])
@pytest.mark.parametrize('channels_per_node', [CHAIN])
def test_settled_lock(token_addresses, raiden_network, deposit):
    """ Any transfer following a secret revealed must update the locksroot, so
    hat an attacker cannot reuse a secret to double claim a lock."""
    app0, app1 = raiden_network
    registry_address = app0.raiden.default_registry.address
    token_address = token_addresses[0]
    amount = 30
    token_network_identifier = views.get_token_network_identifier_by_token_address(
        views.state_from_app(app0),
        app0.raiden.default_registry.address,
        token_address,
    )

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
        token_network_identifier,
        amount,
        identifier,
    )

    # Save the merkle tree leaves from the pending transfer, used to test the unlock
    channelstate_0_1 = get_channelstate(app0, app1, token_network_identifier)
    batch_unlock = channel.get_batch_unlock(channelstate_0_1.our_state)
    assert batch_unlock

    claim_lock(raiden_network, identifier, token_network_identifier, secret)

    # Make a new transfer
    direct_transfer(app0, app1, token_network_identifier, amount, identifier=1)
    RaidenAPI(app1.raiden).channel_close(
        registry_address,
        token_address,
        app0.raiden.address,
    )

    waiting.wait_for_settle(
        app1.raiden,
        app1.raiden.default_registry.address,
        token_address,
        [channelstate_0_1.identifier],
        app1.raiden.alarm.sleep_time,
    )

    netting_channel = app1.raiden.chain.payment_channel(
        token_network_identifier,
        channelstate_0_1.identifier,
    )

    # The direct transfer locksroot must not contain the unlocked lock, the
    # unlock must fail.
    with pytest.raises(Exception):
        netting_channel.unlock(
            channelstate_0_1.partner_state.address,
            batch_unlock,
        )

    expected_balance0 = initial_balance0 + deposit0 - amount * 2
    expected_balance1 = initial_balance1 + deposit1 + amount * 2

    assert token_proxy.balance_of(address0) == expected_balance0
    assert token_proxy.balance_of(address1) == expected_balance1


@pytest.mark.parametrize('number_of_nodes', [2])
@pytest.mark.parametrize('channels_per_node', [1])
def test_automatic_secret_registration(raiden_chain, deposit, token_addresses, reveal_timeout):
    app0, app1 = raiden_chain
    token_address = token_addresses[0]
    token_network_identifier = views.get_token_network_identifier_by_token_address(
        views.state_from_app(app0),
        app0.raiden.default_registry.address,
        token_address,
    )

    amount = 100
    identifier = 1
    secret = pending_mediated_transfer(
        raiden_chain,
        token_network_identifier,
        amount,
        identifier,
    )

    # Stop app0 to avoid sending the unlock
    app0.raiden.transport.stop()

    reveal_secret = RevealSecret(
        random.randint(0, UINT64_MAX),
        secret,
    )
    app0.raiden.sign(reveal_secret)
    message_handler.on_message(app1.raiden, reveal_secret)

    chain_state = views.state_from_app(app1)

    secrethash = sha3(secret)
    target_task = chain_state.payment_mapping.secrethashes_to_task[secrethash]
    lock_expiration = target_task.target_state.transfer.lock.expiration
    wait_until_block(app1.raiden.chain, lock_expiration)

    assert app1.raiden.default_secret_registry.check_registered(secrethash)


@pytest.mark.xfail(reason='test incomplete')
@pytest.mark.parametrize('number_of_nodes', [3])
def test_start_end_attack(token_addresses, raiden_chain, deposit):
    """ An attacker can try to steal tokens from a hub or the last node in a
    path.

    The attacker needs to use two addresses (A1 and A2) and connect both to the
    hub H. Once connected a mediated transfer is initialized from A1 to A2
    through H. Once the node A2 receives the mediated transfer the attacker
    uses the known secret and reveal to close and settle the channel H-A2,
    without revealing the secret to H's raiden node.

    The intention is to make the hub transfer the token but for him to be
    unable to require the token A1."""
    amount = 30

    token = token_addresses[0]
    app0, app1, app2 = raiden_chain  # pylint: disable=unbalanced-tuple-unpacking
    token_network_identifier = views.get_token_network_identifier_by_token_address(
        views.state_from_app(app0),
        app0.raiden.default_registry.address,
        token,
    )

    # the attacker owns app0 and app2 and creates a transfer through app1
    identifier = 1
    secret = pending_mediated_transfer(
        raiden_chain,
        token_network_identifier,
        amount,
        identifier,
    )
    secrethash = sha3(secret)

    attack_channel = get_channelstate(app2, app1, token_network_identifier)
    attack_transfer = None  # TODO
    attack_contract = attack_channel.external_state.netting_channel.address
    hub_contract = (
        get_channelstate(app1, app0, token_network_identifier)
        .external_state
        .netting_channel.address
    )

    # the attacker can create a merkle proof of the locked transfer
    lock = attack_channel.partner_state.get_lock_by_secrethash(secrethash)
    unlock_proof = attack_channel.partner_state.compute_proof_for_lock(secret, lock)

    # start the settle counter
    attack_balance_proof = attack_transfer.to_balanceproof()
    attack_channel.netting_channel.channel_close(attack_balance_proof)

    # wait until the last block to reveal the secret, hopefully we are not
    # missing a block during the test
    wait_until_block(app2.raiden.chain, attack_transfer.lock.expiration - 1)

    # since the attacker knows the secret he can net the lock
    attack_channel.netting_channel.unlock(
        UnlockProofState(unlock_proof, attack_transfer.lock, secret),
    )
    # XXX: verify that the secret was publicized

    # at this point the hub might not know the secret yet, and won't be able to
    # claim the token from the channel A1 - H

    # the attacker settles the contract
    app2.raiden.chain.next_block()

    attack_channel.netting_channel.settle(token, attack_contract)

    # at this point the attacker has the "stolen" funds
    attack_contract = app2.raiden.chain.token_hashchannel[token][attack_contract]
    assert attack_contract.participants[app2.raiden.address]['netted'] == deposit + amount
    assert attack_contract.participants[app1.raiden.address]['netted'] == deposit - amount

    # and the hub's channel A1-H doesn't
    hub_contract = app1.raiden.chain.token_hashchannel[token][hub_contract]
    assert hub_contract.participants[app0.raiden.address]['netted'] == deposit
    assert hub_contract.participants[app1.raiden.address]['netted'] == deposit

    # to mitigate the attack the Hub _needs_ to use a lower expiration for the
    # locked transfer between H-A2 than A1-H. For A2 to acquire the token
    # it needs to make the secret public in the blockchain so it publishes the
    # secret through an event and the Hub is able to require its funds
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
    token_network_identifier = views.get_token_network_identifier_by_token_address(
        views.state_from_app(app0),
        app0.raiden.default_registry.address,
        token_address,
    )

    channel0 = get_channelstate(app0, app1, token_network_identifier)
    token_proxy = app0.raiden.chain.token(channel0.token_address)
    initial_balance0 = token_proxy.balance_of(app0.raiden.address)
    initial_balance1 = token_proxy.balance_of(app1.raiden.address)

    amount0_1 = 10
    direct_transfer(
        app0,
        app1,
        token_network_identifier,
        amount0_1,
    )

    amount1_1 = 50
    direct_transfer(
        app1,
        app0,
        token_network_identifier,
        amount1_1,
    )

    amount0_2 = 60
    direct_transfer(
        app0,
        app1,
        token_network_identifier,
        amount0_2,
    )

    # Alice can only provide one of Bob's transfer, so she is incentivized to
    # use the one with the largest transferred_amount.
    RaidenAPI(app0.raiden).channel_close(
        registry_address,
        token_address,
        app1.raiden.address,
    )

    # Bob needs to provide a transfer otherwise its netted balance will be
    # wrong, so he is incentivised to use Alice's transfer with the largest
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
        app0.raiden.alarm.sleep_time,
    )

    # check that the channel is properly settled and that Bob's client
    # automatically called updateTransfer() to reflect the actual transactions
    assert token_proxy.balance_of(token_network_identifier) == 0
    total0 = amount0_1 + amount0_2
    total1 = amount1_1
    expected_balance0 = initial_balance0 + deposit - total0 + total1
    expected_balance1 = initial_balance1 + deposit + total0 - total1
    assert token_proxy.balance_of(app0.raiden.address) == expected_balance0
    assert token_proxy.balance_of(app1.raiden.address) == expected_balance1
