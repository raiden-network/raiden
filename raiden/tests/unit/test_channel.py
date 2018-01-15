# -*- coding: utf-8 -*-
# pylint: disable=too-many-locals,too-many-statements
import pytest
from ethereum import slogging

from raiden.channel import (
    Channel,
    ChannelEndState,
    ChannelExternalState,
)
from raiden.exceptions import (
    InsufficientBalance,
)
from raiden.messages import (
    EMPTY_MERKLE_ROOT,
    Lock,
    LockedTransfer,
    Secret,
    MediatedTransfer,
)
from raiden.tests.utils.factories import make_address, make_privkey_address
from raiden.tests.utils.messages import make_mediated_transfer
from raiden.tests.utils.transfer import assert_synched_channels, channel
from raiden.transfer.merkle_tree import (
    EMPTY_MERKLE_TREE,
    compute_layers,
    merkleroot,
)
from raiden.transfer.state import MerkleTreeState
from raiden.utils import sha3

log = slogging.getLogger(__name__)  # pylint: disable=invalid-name


class NettingChannelMock:
    # pylint: disable=no-self-use

    def __init__(self):
        self.address = b'channeladdresschanne'

    def opened(self):
        return 1

    def closed(self):
        return 0


def make_external_state():
    channel_for_hashlock = list()
    netting_channel = NettingChannelMock()

    external_state = ChannelExternalState(
        lambda *args: channel_for_hashlock.append(args),
        netting_channel,
    )

    return external_state


def test_end_state():
    token_address = make_address()
    privkey1, address1 = make_privkey_address()
    address2 = make_address()
    channel_address = make_address()

    balance1 = 70
    balance2 = 110

    lock_secret = sha3(b'test_end_state')
    lock_amount = 30
    lock_expiration = 10
    lock_hashlock = sha3(lock_secret)

    state1 = ChannelEndState(address1, balance1, None, EMPTY_MERKLE_TREE)
    state2 = ChannelEndState(address2, balance2, None, EMPTY_MERKLE_TREE)

    assert state1.contract_balance == balance1
    assert state2.contract_balance == balance2
    assert state1.balance(state2) == balance1
    assert state2.balance(state1) == balance2

    assert state1.is_locked(lock_hashlock) is False
    assert state2.is_locked(lock_hashlock) is False

    assert merkleroot(state1.merkletree) == EMPTY_MERKLE_ROOT
    assert merkleroot(state2.merkletree) == EMPTY_MERKLE_ROOT

    assert state1.nonce is None
    assert state2.nonce is None

    lock = Lock(
        lock_amount,
        lock_expiration,
        lock_hashlock,
    )
    lock_hash = sha3(lock.as_bytes)

    transferred_amount = 0
    locksroot = state2.compute_merkleroot_with(lock)

    locked_transfer = LockedTransfer(
        1,
        nonce=1,
        token=token_address,
        channel=channel_address,
        transferred_amount=transferred_amount,
        recipient=state2.address,
        locksroot=locksroot,
        lock=lock,
    )

    transfer_target = make_address()
    transfer_initiator = make_address()
    fee = 0
    mediated_transfer = locked_transfer.to_mediatedtransfer(
        transfer_target,
        transfer_initiator,
        fee,
    )
    mediated_transfer.sign(privkey1, address1)

    state1.register_locked_transfer(mediated_transfer)

    assert state1.contract_balance == balance1
    assert state2.contract_balance == balance2
    assert state1.balance(state2) == balance1
    assert state2.balance(state1) == balance2

    assert state1.distributable(state2) == balance1 - lock_amount
    assert state2.distributable(state1) == balance2

    assert state1.amount_locked == lock_amount
    assert state2.amount_locked == 0

    assert state1.is_locked(lock_hashlock) is True
    assert state2.is_locked(lock_hashlock) is False

    assert merkleroot(state1.merkletree) == lock_hash
    assert merkleroot(state2.merkletree) == EMPTY_MERKLE_ROOT

    assert state1.nonce is 1
    assert state2.nonce is None

    with pytest.raises(ValueError):
        state1.update_contract_balance(balance1 - 10)

    state1.update_contract_balance(balance1 + 10)

    assert state1.contract_balance == balance1 + 10
    assert state2.contract_balance == balance2
    assert state1.balance(state2) == balance1 + 10
    assert state2.balance(state1) == balance2

    assert state1.distributable(state2) == balance1 - lock_amount + 10
    assert state2.distributable(state1) == balance2

    assert state1.amount_locked == lock_amount
    assert state2.amount_locked == 0

    assert state1.is_locked(lock_hashlock) is True
    assert state2.is_locked(lock_hashlock) is False

    assert merkleroot(state1.merkletree) == lock_hash
    assert merkleroot(state2.merkletree) == EMPTY_MERKLE_ROOT

    assert state1.nonce is 1
    assert state2.nonce is None

    # registering the secret should not change the locked amount
    state1.register_secret(lock_secret)

    assert state1.contract_balance == balance1 + 10
    assert state2.contract_balance == balance2
    assert state1.balance(state2) == balance1 + 10
    assert state2.balance(state1) == balance2

    assert state1.is_locked(lock_hashlock) is False
    assert state2.is_locked(lock_hashlock) is False

    assert merkleroot(state1.merkletree) == lock_hash
    assert merkleroot(state2.merkletree) == EMPTY_MERKLE_ROOT

    assert state1.nonce is 1
    assert state2.nonce is None

    secret_message = Secret(
        identifier=1,
        nonce=2,
        channel=channel_address,
        transferred_amount=transferred_amount + lock_amount,
        locksroot=EMPTY_MERKLE_ROOT,
        secret=lock_secret,
    )
    secret_message.sign(privkey1, address1)
    state1.register_secretmessage(secret_message)

    assert state1.contract_balance == balance1 + 10
    assert state2.contract_balance == balance2
    assert state1.balance(state2) == balance1 + 10 - lock_amount
    assert state2.balance(state1) == balance2 + lock_amount

    assert state1.distributable(state2) == balance1 + 10 - lock_amount
    assert state2.distributable(state1) == balance2 + lock_amount

    assert state1.amount_locked == 0
    assert state2.amount_locked == 0

    assert state1.is_locked(lock_hashlock) is False
    assert state2.is_locked(lock_hashlock) is False

    assert merkleroot(state1.merkletree) == EMPTY_MERKLE_ROOT
    assert merkleroot(state2.merkletree) == EMPTY_MERKLE_ROOT

    assert state1.nonce is 2
    assert state2.nonce is None


def test_sender_cannot_overspend():
    token_address = make_address()
    privkey1, address1 = make_privkey_address()
    address2 = make_address()

    balance1 = 70
    balance2 = 110

    reveal_timeout = 5
    settle_timeout = 15
    block_number = 10

    our_state = ChannelEndState(address1, balance1, None, EMPTY_MERKLE_TREE)
    partner_state = ChannelEndState(address2, balance2, None, EMPTY_MERKLE_TREE)
    external_state = make_external_state()

    test_channel = Channel(
        our_state,
        partner_state,
        external_state,
        token_address,
        reveal_timeout,
        settle_timeout,
    )

    amount = balance1
    expiration = block_number + settle_timeout
    sent_mediated_transfer0 = test_channel.create_mediatedtransfer(
        address1,
        address2,
        fee=0,
        amount=amount,
        identifier=1,
        expiration=expiration,
        hashlock=sha3(b'test_locked_amount_cannot_be_spent'),
    )
    sent_mediated_transfer0.sign(privkey1, address1)

    test_channel.register_transfer(
        block_number,
        sent_mediated_transfer0,
    )

    lock2 = Lock(
        amount=amount,
        expiration=expiration,
        hashlock=sha3(b'test_locked_amount_cannot_be_spent2'),
    )
    leaves = [
        sha3(sent_mediated_transfer0.lock.as_bytes),
        sha3(lock2.as_bytes),
    ]
    tree2 = MerkleTreeState(compute_layers(leaves))
    locksroot2 = merkleroot(tree2)

    sent_mediated_transfer1 = MediatedTransfer(
        identifier=2,
        nonce=sent_mediated_transfer0.nonce + 1,
        token=token_address,
        channel=test_channel.channel_address,
        transferred_amount=0,
        recipient=address2,
        locksroot=locksroot2,
        lock=lock2,
        target=address2,
        initiator=address1,
        fee=0,
    )
    sent_mediated_transfer1.sign(privkey1, address1)

    # address1 balance is all locked
    with pytest.raises(InsufficientBalance):
        test_channel.register_transfer(
            block_number,
            sent_mediated_transfer1,
        )


def test_receiver_cannot_spend_locked_amount():
    token_address = make_address()
    privkey1, address1 = make_privkey_address()
    privkey2, address2 = make_privkey_address()

    balance1 = 33
    balance2 = 11

    reveal_timeout = 7
    settle_timeout = 21
    block_number = 7

    our_state = ChannelEndState(address1, balance1, None, EMPTY_MERKLE_TREE)
    partner_state = ChannelEndState(address2, balance2, None, EMPTY_MERKLE_TREE)
    external_state = make_external_state()

    test_channel = Channel(
        our_state,
        partner_state,
        external_state,
        token_address,
        reveal_timeout,
        settle_timeout,
    )

    amount1 = balance2
    expiration = block_number + settle_timeout
    receive_mediated_transfer0 = test_channel.create_mediatedtransfer(
        address1,
        address2,
        fee=0,
        amount=amount1,
        identifier=1,
        expiration=expiration,
        hashlock=sha3(b'test_locked_amount_cannot_be_spent'),
    )
    receive_mediated_transfer0.sign(privkey2, address2)

    test_channel.register_transfer(
        block_number,
        receive_mediated_transfer0,
    )

    # trying to send one unit of the locked token
    amount2 = balance1 + 1
    lock2 = Lock(
        amount=amount2,
        expiration=expiration,
        hashlock=sha3(b'test_locked_amount_cannot_be_spent2'),
    )
    layers = compute_layers([sha3(lock2.as_bytes)])
    tree2 = MerkleTreeState(layers)
    locksroot2 = merkleroot(tree2)

    send_mediated_transfer0 = MediatedTransfer(
        identifier=1,
        nonce=1,
        token=token_address,
        channel=test_channel.channel_address,
        transferred_amount=0,
        recipient=address2,
        locksroot=locksroot2,
        lock=lock2,
        target=address2,
        initiator=address1,
        fee=0,
    )
    send_mediated_transfer0.sign(privkey1, address1)

    # address1 balance is all locked
    with pytest.raises(InsufficientBalance):
        test_channel.register_transfer(
            block_number,
            send_mediated_transfer0,
        )


def test_invalid_timeouts():
    token_address = make_address()
    reveal_timeout = 5
    settle_timeout = 15

    address1 = make_address()
    address2 = make_address()
    balance1 = 10
    balance2 = 10

    our_state = ChannelEndState(address1, balance1, None, EMPTY_MERKLE_TREE)
    partner_state = ChannelEndState(address2, balance2, None, EMPTY_MERKLE_TREE)
    external_state = make_external_state()

    # do not allow a reveal timeout larger than the settle timeout
    with pytest.raises(ValueError):
        large_reveal_timeout = 50
        small_settle_timeout = 49

        Channel(
            our_state,
            partner_state,
            external_state,
            token_address,
            large_reveal_timeout,
            small_settle_timeout,
        )

    for invalid_value in (-1, 0, 1.1, 1.0, 'a', [], {}):
        with pytest.raises(ValueError):
            Channel(
                our_state,
                partner_state,
                external_state,
                token_address,
                invalid_value,
                settle_timeout,
            )

        with pytest.raises(ValueError):
            Channel(
                our_state,
                partner_state,
                external_state,
                token_address,
                reveal_timeout,
                invalid_value,
            )


def test_python_channel():
    token_address = make_address()
    privkey1, address1 = make_privkey_address()
    address2 = make_address()

    balance1 = 70
    balance2 = 110

    reveal_timeout = 5
    settle_timeout = 15
    block_number = 10

    our_state = ChannelEndState(address1, balance1, None, EMPTY_MERKLE_TREE)
    partner_state = ChannelEndState(address2, balance2, None, EMPTY_MERKLE_TREE)
    external_state = make_external_state()

    test_channel = Channel(
        our_state,
        partner_state,
        external_state,
        token_address,
        reveal_timeout,
        settle_timeout,
    )

    assert test_channel.contract_balance == our_state.contract_balance
    assert test_channel.transferred_amount == our_state.transferred_amount
    assert test_channel.distributable == our_state.contract_balance
    assert test_channel.outstanding == our_state.amount_locked
    assert test_channel.outstanding == 0
    assert test_channel.locked == partner_state.amount_locked
    assert test_channel.our_state.amount_locked == 0
    assert test_channel.partner_state.amount_locked == 0
    assert test_channel.get_next_nonce() == 1

    with pytest.raises(ValueError):
        test_channel.create_directtransfer(
            -10,
            identifier=1,
        )

    with pytest.raises(ValueError):
        test_channel.create_directtransfer(
            balance1 + 10,
            identifier=1,
        )

    amount1 = 10
    directtransfer = test_channel.create_directtransfer(
        amount1,
        identifier=1,
    )
    directtransfer.sign(privkey1, address1)
    test_channel.register_transfer(
        block_number,
        directtransfer,
    )

    assert test_channel.contract_balance == balance1
    assert test_channel.balance == balance1 - amount1
    assert test_channel.transferred_amount == amount1
    assert test_channel.distributable == balance1 - amount1
    assert test_channel.outstanding == 0
    assert test_channel.locked == 0
    assert test_channel.our_state.amount_locked == 0
    assert test_channel.partner_state.amount_locked == 0
    assert test_channel.get_next_nonce() == 2

    secret = sha3(b'test_channel')
    hashlock = sha3(secret)
    amount2 = 10
    fee = 0
    expiration = block_number + settle_timeout - 5
    identifier = 1
    mediatedtransfer = test_channel.create_mediatedtransfer(
        address1,
        address2,
        fee,
        amount2,
        identifier,
        expiration,
        hashlock,
    )
    mediatedtransfer.sign(privkey1, address1)

    test_channel.register_transfer(
        block_number,
        mediatedtransfer,
    )

    assert test_channel.contract_balance == balance1
    assert test_channel.balance == balance1 - amount1
    assert test_channel.transferred_amount == amount1
    assert test_channel.distributable == balance1 - amount1 - amount2
    assert test_channel.outstanding == 0
    assert test_channel.locked == amount2
    assert test_channel.our_state.amount_locked == amount2
    assert test_channel.partner_state.amount_locked == 0
    assert test_channel.get_next_nonce() == 3

    secret_message = test_channel.create_secret(identifier, secret)
    secret_message.sign(privkey1, address1)
    test_channel.register_transfer(block_number, secret_message)

    assert test_channel.contract_balance == balance1
    assert test_channel.balance == balance1 - amount1 - amount2
    assert test_channel.transferred_amount == amount1 + amount2
    assert test_channel.distributable == balance1 - amount1 - amount2
    assert test_channel.outstanding == 0
    assert test_channel.locked == 0
    assert test_channel.our_state.amount_locked == 0
    assert test_channel.partner_state.amount_locked == 0
    assert test_channel.get_next_nonce() == 4


def test_channel_increase_nonce_and_transferred_amount():
    """ The nonce must increase with each new transfer. """
    token_address = make_address()
    privkey1, address1 = make_privkey_address()
    address2 = make_address()

    balance1 = 70
    balance2 = 110

    reveal_timeout = 5
    settle_timeout = 15

    our_state = ChannelEndState(address1, balance1, None, EMPTY_MERKLE_TREE)
    partner_state = ChannelEndState(address2, balance2, None, EMPTY_MERKLE_TREE)
    external_state = make_external_state()

    test_channel = Channel(
        our_state,
        partner_state,
        external_state,
        token_address,
        reveal_timeout,
        settle_timeout,
    )

    previous_nonce = test_channel.get_next_nonce()
    previous_transferred = test_channel.transferred_amount

    amount = 7
    block_number = 1
    for _ in range(10):
        direct_transfer = test_channel.create_directtransfer(amount, identifier=1)
        direct_transfer.sign(privkey1, address1)
        test_channel.register_transfer(block_number, direct_transfer)

        new_nonce = test_channel.get_next_nonce()
        new_transferred = test_channel.transferred_amount

        assert new_nonce == previous_nonce + 1
        assert new_transferred == previous_transferred + amount

        previous_nonce = new_nonce
        previous_transferred = new_transferred


@pytest.mark.parametrize('number_of_nodes', [2])
def test_setup(raiden_network, deposit, token_addresses):
    app0, app1 = raiden_network  # pylint: disable=unbalanced-tuple-unpacking

    tokens0 = list(app0.raiden.token_to_channelgraph.keys())
    tokens1 = list(app1.raiden.token_to_channelgraph.keys())

    assert len(tokens0) == 1
    assert len(tokens1) == 1
    assert tokens0 == tokens1
    assert tokens0[0] == token_addresses[0]

    token_address = tokens0[0]
    channel0 = channel(app0, app1, token_address)
    channel1 = channel(app1, app0, token_address)

    assert channel0 and channel1

    assert_synched_channels(
        channel0, deposit, [],
        channel1, deposit, [],
    )


@pytest.mark.parametrize('deposit', [2 ** 30])
@pytest.mark.parametrize('number_of_nodes', [2])
@pytest.mark.parametrize('number_of_transfers', [100])
def test_interwoven_transfers(number_of_transfers, raiden_network, settle_timeout):
    """ Can keep doing transactions even if not all secrets have been released. """
    def log_state():
        unclaimed = [
            transfer.lock.amount
            for pos, transfer in enumerate(transfers_list)
            if not transfers_claimed[pos]
        ]

        claimed = [
            transfer.lock.amount
            for pos, transfer in enumerate(transfers_list)
            if transfers_claimed[pos]
        ]
        log.info(
            'interwoven',
            claimed_amount=claimed_amount,
            distributed_amount=distributed_amount,
            claimed=claimed,
            unclaimed=unclaimed,
        )

    app0, app1 = raiden_network  # pylint: disable=unbalanced-tuple-unpacking

    graph0 = list(app0.raiden.token_to_channelgraph.values())[0]
    graph1 = list(app1.raiden.token_to_channelgraph.values())[0]

    channel0 = list(graph0.partneraddress_to_channel.values())[0]
    channel1 = list(graph1.partneraddress_to_channel.values())[0]

    contract_balance0 = channel0.contract_balance
    contract_balance1 = channel1.contract_balance

    unclaimed_locks = []
    transfers_list = []
    transfers_claimed = []

    # start at 1 because we can't use amount=0
    transfers_amount = [i for i in range(1, number_of_transfers + 1)]
    transfers_secret = [
        format(i, '>032')
        for i in range(number_of_transfers)
    ]

    claimed_amount = 0
    distributed_amount = 0

    for i, (amount, secret) in enumerate(zip(transfers_amount, transfers_secret)):
        block_number = app0.raiden.chain.block_number()
        expiration = block_number + settle_timeout - 1
        identifier = i
        mediated_transfer = channel0.create_mediatedtransfer(
            transfer_initiator=app0.raiden.address,
            transfer_target=app1.raiden.address,
            fee=0,
            amount=amount,
            identifier=identifier,
            expiration=expiration,
            hashlock=sha3(secret.encode()),
        )

        # synchronized registration
        app0.raiden.sign(mediated_transfer)
        channel0.register_transfer(
            block_number,
            mediated_transfer,
        )
        channel1.register_transfer(
            block_number,
            mediated_transfer,
        )

        # update test state
        distributed_amount += amount
        transfers_claimed.append(False)
        transfers_list.append(mediated_transfer)
        unclaimed_locks.append(mediated_transfer.lock)

        log_state()

        # test the synchronization and values
        assert_synched_channels(
            channel0, contract_balance0 - claimed_amount, [],
            channel1, contract_balance1 + claimed_amount, unclaimed_locks,
        )
        assert channel0.distributable == contract_balance0 - distributed_amount

        # claim a transaction at every other iteration, leaving the current one
        # in place
        if i > 0 and i % 2 == 0:
            transfer = transfers_list[i - 1]
            secret = transfers_secret[i - 1]

            # synchronized claiming
            secret_message = channel0.create_secret(
                identifier,
                secret.encode(),
            )
            app0.raiden.sign(secret_message)
            channel0.register_transfer(block_number, secret_message)
            channel1.register_transfer(block_number, secret_message)

            # update test state
            claimed_amount += transfer.lock.amount
            transfers_claimed[i - 1] = True
            unclaimed_locks = [
                unclaimed_transfer.lock
                for pos, unclaimed_transfer in enumerate(transfers_list)
                if not transfers_claimed[pos]
            ]

            log_state()

            # test the state of the channels after the claim
            assert_synched_channels(
                channel0, contract_balance0 - claimed_amount, [],
                channel1, contract_balance1 + claimed_amount, unclaimed_locks,
            )
            assert channel0.distributable == contract_balance0 - distributed_amount


@pytest.mark.parametrize('number_of_nodes', [2])
def test_transfer(raiden_network, token_addresses):
    app0, app1 = raiden_network  # pylint: disable=unbalanced-tuple-unpacking

    channel0 = channel(app0, app1, token_addresses[0])
    channel1 = channel(app1, app0, token_addresses[0])

    contract_balance0 = channel0.contract_balance
    contract_balance1 = channel1.contract_balance

    app0_token = list(app0.raiden.token_to_channelgraph.keys())[0]
    app1_token = list(app1.raiden.token_to_channelgraph.keys())[0]

    graph0 = list(app0.raiden.token_to_channelgraph.values())[0]
    graph1 = list(app1.raiden.token_to_channelgraph.values())[0]

    app0_partners = list(graph0.partneraddress_to_channel.keys())
    app1_partners = list(graph1.partneraddress_to_channel.keys())

    assert channel0.token_address == channel1.token_address
    assert app0_token == app1_token
    assert app1.raiden.address in app0_partners
    assert app0.raiden.address in app1_partners

    netting_address = channel0.external_state.netting_channel.address
    netting_channel = app0.raiden.chain.netting_channel(netting_address)

    # check balances of channel and contract are equal
    details0 = netting_channel.detail()
    details1 = netting_channel.detail()

    assert contract_balance0 == details0['our_balance']
    assert contract_balance1 == details1['our_balance']

    assert_synched_channels(
        channel0, contract_balance0, [],
        channel1, contract_balance1, [],
    )

    amount = 10
    direct_transfer = channel0.create_directtransfer(
        amount,
        identifier=1,
    )
    app0.raiden.sign(direct_transfer)
    channel0.register_transfer(
        app0.raiden.get_block_number(),
        direct_transfer,
    )
    channel1.register_transfer(
        app1.raiden.get_block_number(),
        direct_transfer,
    )

    # check the contract is intact
    assert details0 == netting_channel.detail()
    assert details1 == netting_channel.detail()

    assert channel0.contract_balance == contract_balance0
    assert channel1.contract_balance == contract_balance1

    assert_synched_channels(
        channel0, contract_balance0 - amount, [],
        channel1, contract_balance1 + amount, [],
    )


@pytest.mark.parametrize('number_of_nodes', [2])
def test_locked_transfer(raiden_network, settle_timeout):
    app0, app1 = raiden_network  # pylint: disable=unbalanced-tuple-unpacking

    graph0 = list(app0.raiden.token_to_channelgraph.values())[0]
    graph1 = list(app1.raiden.token_to_channelgraph.values())[0]

    channel0 = list(graph0.partneraddress_to_channel.values())[0]
    channel1 = list(graph1.partneraddress_to_channel.values())[0]

    balance0 = channel0.balance
    balance1 = channel1.balance

    amount = 10

    # reveal_timeout <= expiration < contract.lock_time
    block_number = app0.raiden.chain.block_number()
    expiration = block_number + settle_timeout - 1

    secret = b'secretsecretsecretsecretsecretse'
    hashlock = sha3(secret)

    identifier = 1
    mediated_transfer = channel0.create_mediatedtransfer(
        transfer_initiator=app0.raiden.address,
        transfer_target=app1.raiden.address,
        fee=0,
        amount=amount,
        identifier=identifier,
        expiration=expiration,
        hashlock=hashlock,
    )
    app0.raiden.sign(mediated_transfer)
    channel0.register_transfer(
        app0.raiden.chain.block_number(),
        mediated_transfer,
    )
    channel1.register_transfer(
        app1.raiden.chain.block_number(),
        mediated_transfer,
    )

    # don't update balances but update the locked/distributable/outstanding
    # values
    assert_synched_channels(
        channel0, balance0, [],
        channel1, balance1, [mediated_transfer.lock],
    )

    secret_message = channel0.create_secret(identifier, secret)
    app0.raiden.sign(secret_message)
    channel0.register_transfer(
        app0.raiden.chain.block_number(),
        secret_message,
    )
    channel1.register_transfer(
        app1.raiden.get_block_number(),
        secret_message,
    )

    # upon revelation of the secret both balances are updated
    assert_synched_channels(
        channel0, balance0 - amount, [],
        channel1, balance1 + amount, [],
    )


def test_channel_must_accept_expired_locks():
    """ A node may go offline for an undetermined period of time, and when it
    comes back online it must accept the messages that are waiting, otherwise
    the partner node won't make progress with its queue.

    If a N node goes offline for a number B of blocks, and the partner does not
    close the channel, when N comes back online some of the messages from its
    partner may become expired. Neverthless these messages are ordered and must
    be accepted for the partner to make progress with its queue.

    Note: Accepting a message with an expired lock does *not* imply the token
    transfer happened, and the receiver node must *not* forward the transfer,
    only accept the message allowing the partner to progress with its message
    queue.
    """
    balance1 = 70
    balance2 = 110
    reveal_timeout = 5
    settle_timeout = 15
    privkey1, address1 = make_privkey_address()
    privkey2, address2 = make_privkey_address()
    token_address = make_address()

    our_state = ChannelEndState(
        address1,
        balance1,
        None,
        EMPTY_MERKLE_TREE,
    )
    partner_state = ChannelEndState(
        address2,
        balance2,
        None,
        EMPTY_MERKLE_TREE,
    )
    external_state = make_external_state()

    test_channel = Channel(
        our_state,
        partner_state,
        external_state,
        token_address,
        reveal_timeout,
        settle_timeout,
    )

    block_number = 10
    transfer = make_mediated_transfer(
        nonce=test_channel.get_next_nonce(),
        token=test_channel.token_address,
        channel=test_channel.channel_address,
        expiration=block_number + settle_timeout,
        recipient=address1,
    )
    transfer.sign(privkey2, address2)

    test_channel.register_transfer(
        block_number + settle_timeout + 1,
        transfer,
    )


def test_channel_close_called_only_once():
    class MockCheckCallsToClose:
        def __init__(self):
            self.address = 'mockcheckcallstoclosemockcheckcallstoclo'
            self.close_calls = 0

        def opened(self):
            return 1

        def closed(self):
            return 0

        def close(self, nonce, transferred_amount, locksroot, extra_hash, signature):
            self.close_calls += 1

    netting_channel = NettingChannelMock()
    token_address = make_address()
    privkey1, address1 = make_privkey_address()
    address2 = make_address()

    balance1 = 70
    balance2 = 110

    reveal_timeout = 5
    settle_timeout = 15

    our_state = ChannelEndState(address1, balance1, None, EMPTY_MERKLE_TREE)
    partner_state = ChannelEndState(address2, balance2, None, EMPTY_MERKLE_TREE)

    channel_for_hashlock = list()
    netting_channel = MockCheckCallsToClose()

    external_state = ChannelExternalState(
        lambda *args: channel_for_hashlock.append(args),
        netting_channel,
    )

    test_channel = Channel(
        our_state,
        partner_state,
        external_state,
        token_address,
        reveal_timeout,
        settle_timeout,
    )

    test_channel.external_state.close(None)
    test_channel.external_state.close(None)

    assert netting_channel.close_calls == 1
