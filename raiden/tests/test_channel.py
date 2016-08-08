# -*- coding: utf8 -*-
import pytest

from ethereum import slogging

from raiden.channel import Channel, ChannelEndState, ChannelExternalState
from raiden.messages import DirectTransfer, Lock, LockedTransfer
from raiden.tests.utils.transfer import assert_synched_channels, channel
from raiden.utils import sha3, make_address, make_privkey_address

log = slogging.getLogger(__name__)  # pylint: disable=invalid-name
slogging.configure(':debug')


def test_end_state():
    asset_address = make_address()
    privkey1, address1 = make_privkey_address()
    address2 = make_address()

    balance1 = 70
    balance2 = 110

    lock_secret = sha3('test_end_state')
    lock_amount = 30
    lock_expiration = 10
    lock_hashlock = sha3(lock_secret)

    state1 = ChannelEndState(address1, balance1)
    state2 = ChannelEndState(address2, balance2)

    assert state1.contract_balance == balance1
    assert state2.contract_balance == balance2
    assert state1.balance(state2) == balance1
    assert state2.balance(state1) == balance2

    assert state1.distributable(state2) == balance1
    assert state2.distributable(state1) == balance2

    assert state1.locked() == 0
    assert state2.locked() == 0

    assert state1.balance_proof.is_pending(lock_hashlock) is False
    assert state2.balance_proof.is_pending(lock_hashlock) is False

    with pytest.raises(KeyError):
        assert state1.balance_proof.get_pending_lock(lock_hashlock)

    with pytest.raises(KeyError):
        assert state2.balance_proof.get_pending_lock(lock_hashlock)

    assert state1.compute_merkleroot() == ''
    assert state2.compute_merkleroot() == ''

    lock = Lock(
        lock_amount,
        lock_expiration,
        lock_hashlock,
    )
    lock_hash = sha3(lock.as_bytes)

    transfered_amount = 0
    locksroot = state2.compute_merkleroot_with(lock)

    locked_transfer = LockedTransfer(
        nonce=state1.nonce,
        asset=asset_address,
        transfered_amount=transfered_amount,
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
    mediated_transfer.sign(privkey1)

    state2.register_locked_transfer(mediated_transfer)

    assert state1.contract_balance == balance1
    assert state2.contract_balance == balance2
    assert state1.balance(state2) == balance1
    assert state2.balance(state1) == balance2

    assert state1.distributable(state2) == balance1 - lock_amount
    assert state2.distributable(state1) == balance2

    assert state1.locked() == 0
    assert state2.locked() == lock_amount

    assert state1.balance_proof.is_pending(lock_hashlock) is False
    assert state2.balance_proof.is_pending(lock_hashlock) is True

    with pytest.raises(KeyError):
        assert state1.balance_proof.get_pending_lock(lock_hashlock)

    assert state2.balance_proof.get_pending_lock(lock_hashlock) is lock

    assert state1.compute_merkleroot() == ''
    assert state2.compute_merkleroot() == lock_hash

    with pytest.raises(ValueError):
        state1.update_contract_balance(balance1 - 10)

    state1.update_contract_balance(balance1 + 10)

    assert state1.contract_balance == balance1 + 10
    assert state2.contract_balance == balance2
    assert state1.balance(state2) == balance1 + 10
    assert state2.balance(state1) == balance2

    assert state1.distributable(state2) == balance1 - lock_amount + 10
    assert state2.distributable(state1) == balance2

    assert state1.locked() == 0
    assert state2.locked() == lock_amount

    assert state1.balance_proof.is_pending(lock_hashlock) is False
    assert state2.balance_proof.is_pending(lock_hashlock) is True

    with pytest.raises(KeyError):
        assert state1.balance_proof.get_pending_lock(lock_hashlock)

    assert state2.balance_proof.get_pending_lock(lock_hashlock) is lock

    assert state1.compute_merkleroot() == ''
    assert state2.compute_merkleroot() == lock_hash

    state2.register_secret(state1, lock_secret)

    assert state1.contract_balance == balance1 + 10
    assert state2.contract_balance == balance2
    assert state1.balance(state2) == balance1 + 10 - lock_amount
    assert state2.balance(state1) == balance2 + lock_amount

    assert state1.distributable(state2) == balance1 + 10 - lock_amount
    assert state2.distributable(state1) == balance2 + lock_amount

    assert state1.locked() == 0
    assert state2.locked() == 0

    assert state1.balance_proof.is_pending(lock_hashlock) is False
    assert state2.balance_proof.is_pending(lock_hashlock) is False

    with pytest.raises(KeyError):
        assert state1.balance_proof.get_pending_lock(lock_hashlock)

    with pytest.raises(KeyError):
        assert state2.balance_proof.get_pending_lock(lock_hashlock)

    assert state1.compute_merkleroot() == ''
    assert state2.compute_merkleroot() == ''


def test_channel():
    class NettingChannelMock(object):
        def opened(self):
            return 1

        def closed(self):
            return 0

        def settled(self):
            return 0

    asset_address = make_address()
    privkey1, address1 = make_privkey_address()
    address2 = make_address()

    balance1 = 70
    balance2 = 110

    reveal_timeout = 5
    settle_timeout = 15

    our_state = ChannelEndState(address1, balance1)
    partner_state = ChannelEndState(address2, balance2)

    block_alarm = list()
    channel_for_hashlock = list()
    netting_channel = NettingChannelMock()

    external_state = ChannelExternalState(
        block_alarm.append,
        lambda *args: channel_for_hashlock.append(args),
        lambda: 1,
        netting_channel,
    )

    channel = Channel(
        our_state, partner_state, external_state,
        asset_address, reveal_timeout, settle_timeout,
    )

    assert channel.contract_balance == our_state.contract_balance
    assert channel.balance == our_state.balance(partner_state)
    assert channel.transfered_amount == our_state.transfered_amount
    assert channel.distributable == our_state.distributable(partner_state)
    assert channel.outstanding == our_state.locked()
    assert channel.outstanding == 0
    assert channel.locked == partner_state.locked()
    assert channel.our_state.locked() == 0
    assert channel.partner_state.locked() == 0

    with pytest.raises(ValueError):
        channel.create_directtransfer(-10)

    with pytest.raises(ValueError):
        channel.create_directtransfer(balance1 + 10)

    amount1 = 10
    directtransfer = channel.create_directtransfer(amount1)
    directtransfer.sign(privkey1)
    channel.register_transfer(directtransfer)

    assert channel.contract_balance == balance1
    assert channel.balance == balance1 - amount1
    assert channel.transfered_amount == amount1
    assert channel.distributable == balance1 - amount1
    assert channel.outstanding == 0
    assert channel.locked == 0
    assert channel.our_state.locked() == 0
    assert channel.partner_state.locked() == 0

    secret = sha3('test_channel')
    hashlock = sha3(secret)
    amount2 = 10
    fee = 0
    expiration = settle_timeout - 5
    mediatedtransfer = channel.create_mediatedtransfer(
        address1,
        address2,
        fee,
        amount2,
        expiration,
        hashlock,
    )
    mediatedtransfer.sign(privkey1)

    channel.register_transfer(mediatedtransfer)

    assert channel.contract_balance == balance1
    assert channel.balance == balance1 - amount1
    assert channel.transfered_amount == amount1
    assert channel.distributable == balance1 - amount1 - amount2
    assert channel.outstanding == 0
    assert channel.locked == amount2
    assert channel.our_state.locked() == 0
    assert channel.partner_state.locked() == amount2

    channel.register_secret(secret)

    assert channel.contract_balance == balance1
    assert channel.balance == balance1 - amount1 - amount2
    assert channel.transfered_amount == amount1 + amount2
    assert channel.distributable == balance1 - amount1 - amount2
    assert channel.outstanding == 0
    assert channel.locked == 0
    assert channel.our_state.locked() == 0
    assert channel.partner_state.locked() == 0


@pytest.mark.parametrize('privatekey_seed', ['setup:{}'])
@pytest.mark.parametrize('number_of_nodes', [2])
def test_setup(raiden_network, deposit, assets_addresses):
    app0, app1 = raiden_network  # pylint: disable=unbalanced-tuple-unpacking

    assets0 = app0.raiden.managers_by_asset_address.keys()
    assets1 = app1.raiden.managers_by_asset_address.keys()

    assert len(assets0) == 1
    assert len(assets1) == 1
    assert assets0 == assets1
    assert assets0[0] == assets_addresses[0]

    asset_address = assets0[0]
    channel0 = channel(app0, app1, asset_address)
    channel1 = channel(app1, app0, asset_address)

    assert channel0 and channel1

    assert_synched_channels(
        channel0, deposit, [],
        channel1, deposit, [],
    )


@pytest.mark.parametrize('privatekey_seed', ['transfer:{}'])
@pytest.mark.parametrize('number_of_nodes', [2])
def test_transfer(raiden_network, assets_addresses):
    app0, app1 = raiden_network  # pylint: disable=unbalanced-tuple-unpacking

    channel0 = channel(app0, app1, assets_addresses[0])
    channel1 = channel(app1, app0, assets_addresses[0])

    contract_balance0 = channel0.contract_balance
    contract_balance1 = channel1.contract_balance

    # check agreement on addresses
    address0 = channel0.our_state.address
    address1 = channel1.our_state.address
    assert channel0.asset_address == channel1.asset_address
    assert app0.raiden.managers_by_asset_address.keys()[0] == app1.raiden.managers_by_asset_address.keys()[0]
    assert app0.raiden.managers_by_asset_address.values()[0].partneraddress_channel.keys()[0] == app1.raiden.address
    assert app1.raiden.managers_by_asset_address.values()[0].partneraddress_channel.keys()[0] == app0.raiden.address

    netting_address = channel0.external_state.netting_channel.address
    netting_channel = app0.raiden.chain.netting_channel(netting_address)

    # check balances of channel and contract are equal
    details0 = netting_channel.detail(address0)
    details1 = netting_channel.detail(address1)

    assert contract_balance0 == details0['our_balance']
    assert contract_balance1 == details1['our_balance']

    assert_synched_channels(
        channel0, contract_balance0, [],
        channel1, contract_balance1, [],
    )

    amount = 10

    direct_transfer = channel0.create_directtransfer(amount=amount)
    app0.raiden.sign(direct_transfer)
    channel0.register_transfer(direct_transfer)
    channel1.register_transfer(direct_transfer)

    # check the contract is intact
    assert details0 == netting_channel.detail(address0)
    assert details1 == netting_channel.detail(address1)

    assert channel0.contract_balance == contract_balance0
    assert channel1.contract_balance == contract_balance1

    assert_synched_channels(
        channel0, contract_balance0 - amount, [],
        channel1, contract_balance1 + amount, [],
    )


@pytest.mark.parametrize('privatekey_seed', ['locked_transfer:{}'])
@pytest.mark.parametrize('number_of_nodes', [2])
def test_locked_transfer(raiden_network):
    app0, app1 = raiden_network  # pylint: disable=unbalanced-tuple-unpacking

    channel0 = app0.raiden.managers_by_asset_address.values()[0].partneraddress_channel.values()[0]
    channel1 = app1.raiden.managers_by_asset_address.values()[0].partneraddress_channel.values()[0]

    balance0 = channel0.balance
    balance1 = channel1.balance

    amount = 10

    # reveal_timeout <= expiration < contract.lock_time
    expiration = app0.raiden.chain.block_number() + 5

    secret = 'secret'
    hashlock = sha3(secret)

    locked_transfer = channel0.create_lockedtransfer(
        amount=amount,
        expiration=expiration,
        hashlock=hashlock,
    )
    app0.raiden.sign(locked_transfer)
    channel0.register_transfer(locked_transfer)
    channel1.register_transfer(locked_transfer)

    # don't update balances but update the locked/distributable/outstanding
    # values
    assert_synched_channels(
        channel0, balance0, [],
        channel1, balance1, [locked_transfer.lock],
    )

    channel0.register_secret(secret)
    channel1.register_secret(secret)

    # upon revelation of the secret both balances are updated
    assert_synched_channels(
        channel0, balance0 - amount, [],
        channel1, balance1 + amount, [],
    )


@pytest.mark.parametrize('privatekey_seed', ['interwoven_transfers:{}'])
@pytest.mark.parametrize('deposit', [2 ** 30])
@pytest.mark.parametrize('number_of_nodes', [2])
@pytest.mark.parametrize('number_of_transfers', [100])
def test_interwoven_transfers(number_of_transfers, raiden_network):  # pylint: disable=too-many-locals
    """ Can keep doing transaction even if not all secrets have been released. """
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

    channel0 = app0.raiden.managers_by_asset_address.values()[0].partneraddress_channel.values()[0]
    channel1 = app1.raiden.managers_by_asset_address.values()[0].partneraddress_channel.values()[0]

    contract_balance0 = channel0.contract_balance
    contract_balance1 = channel1.contract_balance

    expiration = app0.raiden.chain.block_number() + 5

    unclaimed_locks = []
    transfers_list = []
    transfers_claimed = []

    # start at 1 because we can't use amount=0
    transfers_amount = [i for i in range(1, number_of_transfers + 1)]
    transfers_secret = [str(i) for i in range(number_of_transfers)]

    claimed_amount = 0
    distributed_amount = 0

    for i, (amount, secret) in enumerate(zip(transfers_amount, transfers_secret)):
        locked_transfer = channel0.create_lockedtransfer(
            amount=amount,
            expiration=expiration,
            hashlock=sha3(secret),
        )

        # synchronized registration
        app0.raiden.sign(locked_transfer)
        channel0.register_transfer(locked_transfer)
        channel1.register_transfer(locked_transfer)

        # update test state
        distributed_amount += amount
        transfers_claimed.append(False)
        transfers_list.append(locked_transfer)
        unclaimed_locks.append(locked_transfer.lock)

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

            # synchronized clamining
            channel0.register_secret(secret)
            channel1.register_secret(secret)

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


@pytest.mark.parametrize('privatekey_seed', ['register_invalid_transfer:{}'])
@pytest.mark.parametrize('number_of_nodes', [2])
def test_register_invalid_transfer(raiden_network):
    """ Regression test for registration of invalid transfer.

    The bug occurred if a transfer with an invalid allowance but a valid secret
    was registered, when the local end registered the transfer it would
    "unlock" the partners asset, but the transfer wouldn't be sent because the
    allowance check failed, leaving the channel in an inconsistent state.
    """
    app0, app1 = raiden_network  # pylint: disable=unbalanced-tuple-unpacking

    channel0 = app0.raiden.managers_by_asset_address.values()[0].partneraddress_channel.values()[0]
    channel1 = app1.raiden.managers_by_asset_address.values()[0].partneraddress_channel.values()[0]

    balance0 = channel0.balance
    balance1 = channel1.balance

    amount = 10
    expiration = app0.raiden.chain.block_number() + 5

    secret = 'secret'
    hashlock = sha3(secret)

    transfer1 = channel0.create_lockedtransfer(
        amount=amount,
        expiration=expiration,
        hashlock=hashlock,
    )

    # register a locked transfer
    app0.raiden.sign(transfer1)
    channel0.register_transfer(transfer1)
    channel1.register_transfer(transfer1)

    # assert the locked transfer is registered
    assert_synched_channels(
        channel0, balance0, [],
        channel1, balance1, [transfer1.lock],
    )

    # handcrafted transfer because channel.create_transfer won't create it
    transfer2 = DirectTransfer(
        nonce=channel0.our_state.nonce,
        asset=channel0.asset_address,
        transfered_amount=channel1.balance + balance0 + amount,
        recipient=channel0.partner_state.address,
        locksroot=channel0.partner_state.compute_merkleroot(),
        secret=secret,
    )
    app0.raiden.sign(transfer2)

    # this need to fail because the allowance is incorrect
    with pytest.raises(Exception):
        channel0.register_transfer(transfer2)

    with pytest.raises(Exception):
        channel1.register_transfer(transfer2)

    # the registration of a bad transfer need fail equaly on both channels
    assert_synched_channels(
        channel0, balance0, [],
        channel1, balance1, [transfer1.lock],
    )
