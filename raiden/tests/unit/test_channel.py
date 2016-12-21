# -*- coding: utf-8 -*-
from __future__ import division

import pytest
from ethereum import slogging

from raiden.channel import Channel, ChannelEndState, ChannelExternalState
from raiden.messages import DirectTransfer, Lock, LockedTransfer
from raiden.utils import sha3, make_address, make_privkey_address
from raiden.tests.utils.transfer import assert_synched_channels, channel

log = slogging.getLogger(__name__)  # pylint: disable=invalid-name
slogging.configure(':DEBUG')

# pylint: disable=too-many-locals,too-many-statements


class NettingChannelMock(object):
    # pylint: disable=no-self-use
    def opened(self):
        return 1

    def closed(self):
        return 0

    def settled(self):
        return 0


def make_external_state():
    block_alarm = list()
    channel_for_hashlock = list()
    netting_channel = NettingChannelMock()

    external_state = ChannelExternalState(
        block_alarm.append,
        lambda *args: channel_for_hashlock.append(args),
        lambda: 1,
        netting_channel,
    )

    return external_state


def test_end_state():
    netting_channel = NettingChannelMock()
    asset_address = make_address()
    privkey1, address1 = make_privkey_address()
    address2 = make_address()

    balance1 = 70
    balance2 = 110

    lock_secret = sha3('test_end_state')
    lock_amount = 30
    lock_expiration = 10
    lock_hashlock = sha3(lock_secret)

    state1 = ChannelEndState(address1, balance1, netting_channel.opened)
    state2 = ChannelEndState(address2, balance2, netting_channel.opened)

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

    assert state1.balance_proof.merkleroot_for_unclaimed() == ''
    assert state2.balance_proof.merkleroot_for_unclaimed() == ''

    lock = Lock(
        lock_amount,
        lock_expiration,
        lock_hashlock,
    )
    lock_hash = sha3(lock.as_bytes)

    transferred_amount = 0
    locksroot = state2.compute_merkleroot_with(lock)

    locked_transfer = LockedTransfer(
        1,  # TODO: fill in identifier
        nonce=state1.nonce,
        asset=asset_address,
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

    assert state1.balance_proof.merkleroot_for_unclaimed() == ''
    assert state2.balance_proof.merkleroot_for_unclaimed() == lock_hash

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

    assert state1.balance_proof.merkleroot_for_unclaimed() == ''
    assert state2.balance_proof.merkleroot_for_unclaimed() == lock_hash

    # registering the secret should not change the locked amount
    state2.register_secret(lock_secret)

    assert state1.contract_balance == balance1 + 10
    assert state2.contract_balance == balance2
    assert state1.balance(state2) == balance1 + 10
    assert state2.balance(state1) == balance2

    assert state1.distributable(state2) == balance1 - lock_amount + 10
    assert state2.distributable(state1) == balance2

    assert state1.locked() == 0
    assert state2.locked() == lock_amount

    assert state1.balance_proof.is_pending(lock_hashlock) is False
    assert state2.balance_proof.is_pending(lock_hashlock) is False

    assert state1.balance_proof.merkleroot_for_unclaimed() == ''
    assert state2.balance_proof.merkleroot_for_unclaimed() == lock_hash

    state2.release_lock(state1, lock_secret)

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

    assert state1.balance_proof.merkleroot_for_unclaimed() == ''
    assert state2.balance_proof.merkleroot_for_unclaimed() == ''


def test_invalid_timeouts():
    netting_channel = NettingChannelMock()
    asset_address = make_address()
    reveal_timeout = 5
    settle_timeout = 15

    address1 = make_address()
    address2 = make_address()
    balance1 = 10
    balance2 = 10

    our_state = ChannelEndState(address1, balance1, netting_channel.opened)
    partner_state = ChannelEndState(address2, balance2, netting_channel.opened)
    external_state = make_external_state()

    # do not allow a reveal timeout larger than the settle timeout
    with pytest.raises(ValueError):
        large_reveal_timeout = 50
        small_settle_timeout = 49

        Channel(
            our_state,
            partner_state,
            external_state,
            asset_address,
            large_reveal_timeout,
            small_settle_timeout,
        )

    for invalid_value in (-1, 0, 1.1, 1.0, 'a', [], {}):
        with pytest.raises(ValueError):
            Channel(
                our_state,
                partner_state,
                external_state,
                asset_address,
                invalid_value,
                settle_timeout,
            )

        with pytest.raises(ValueError):
            Channel(
                our_state,
                partner_state,
                external_state,
                asset_address,
                reveal_timeout,
                invalid_value,
            )


def test_python_channel():
    netting_channel = NettingChannelMock()
    asset_address = make_address()
    privkey1, address1 = make_privkey_address()
    address2 = make_address()

    balance1 = 70
    balance2 = 110

    reveal_timeout = 5
    settle_timeout = 15

    our_state = ChannelEndState(address1, balance1, netting_channel.opened)
    partner_state = ChannelEndState(address2, balance2, netting_channel.opened)
    external_state = make_external_state()

    test_channel = Channel(
        our_state, partner_state, external_state,
        asset_address, reveal_timeout, settle_timeout,
    )

    assert test_channel.contract_balance == our_state.contract_balance
    assert test_channel.balance == our_state.balance(partner_state)
    assert test_channel.transferred_amount == our_state.transferred_amount
    assert test_channel.distributable == our_state.distributable(partner_state)
    assert test_channel.outstanding == our_state.locked()
    assert test_channel.outstanding == 0
    assert test_channel.locked == partner_state.locked()
    assert test_channel.our_state.locked() == 0
    assert test_channel.partner_state.locked() == 0

    with pytest.raises(ValueError):
        test_channel.create_directtransfer(
            -10,
            1  # TODO: fill in identifier
        )

    with pytest.raises(ValueError):
        test_channel.create_directtransfer(
            balance1 + 10,
            1  # TODO: fill in identifier
        )

    amount1 = 10
    directtransfer = test_channel.create_directtransfer(
        amount1,
        1  # TODO: fill in identifier
    )
    directtransfer.sign(privkey1, address1)
    test_channel.register_transfer(directtransfer)

    assert test_channel.contract_balance == balance1
    assert test_channel.balance == balance1 - amount1
    assert test_channel.transferred_amount == amount1
    assert test_channel.distributable == balance1 - amount1
    assert test_channel.outstanding == 0
    assert test_channel.locked == 0
    assert test_channel.our_state.locked() == 0
    assert test_channel.partner_state.locked() == 0

    secret = sha3('test_channel')
    hashlock = sha3(secret)
    amount2 = 10
    fee = 0
    expiration = settle_timeout - 5
    mediatedtransfer = test_channel.create_mediatedtransfer(
        address1,
        address2,
        fee,
        amount2,
        1,  # TODO: fill in identifier
        expiration,
        hashlock,
    )
    mediatedtransfer.sign(privkey1, address1)

    test_channel.register_transfer(mediatedtransfer)

    assert test_channel.contract_balance == balance1
    assert test_channel.balance == balance1 - amount1
    assert test_channel.transferred_amount == amount1
    assert test_channel.distributable == balance1 - amount1 - amount2
    assert test_channel.outstanding == 0
    assert test_channel.locked == amount2
    assert test_channel.our_state.locked() == 0
    assert test_channel.partner_state.locked() == amount2

    test_channel.release_lock(secret)

    assert test_channel.contract_balance == balance1
    assert test_channel.balance == balance1 - amount1 - amount2
    assert test_channel.transferred_amount == amount1 + amount2
    assert test_channel.distributable == balance1 - amount1 - amount2
    assert test_channel.outstanding == 0
    assert test_channel.locked == 0
    assert test_channel.our_state.locked() == 0
    assert test_channel.partner_state.locked() == 0


# The following tests need more than one raiden app with different keys to test
# the channels, but don't interact with a smart contact, so the mock
# implementation is sufficient


@pytest.mark.parametrize('blockchain_type', ['mock'])
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


@pytest.mark.parametrize('blockchain_type', ['mock'])
@pytest.mark.parametrize('deposit', [2 ** 30])
@pytest.mark.parametrize('number_of_nodes', [2])
@pytest.mark.parametrize('number_of_transfers', [100])
def test_interwoven_transfers(number_of_transfers, raiden_network,
                              settle_timeout):
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

    unclaimed_locks = []
    transfers_list = []
    transfers_claimed = []

    # start at 1 because we can't use amount=0
    transfers_amount = [i for i in range(1, number_of_transfers + 1)]
    transfers_secret = [str(i) for i in range(number_of_transfers)]

    claimed_amount = 0
    distributed_amount = 0

    for i, (amount, secret) in enumerate(zip(transfers_amount, transfers_secret)):
        expiration = app0.raiden.chain.block_number() + settle_timeout - 1
        locked_transfer = channel0.create_lockedtransfer(
            amount=amount,
            identifier=1,  # TODO: fill in identifier
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
            channel0.release_lock(secret)
            channel1.withdraw_lock(secret)

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


@pytest.mark.parametrize('blockchain_type', ['mock'])
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

    app0_asset = app0.raiden.managers_by_asset_address.keys()[0]
    app1_asset = app1.raiden.managers_by_asset_address.keys()[0]

    app0_partners = app0.raiden.managers_by_asset_address.values()[0].partneraddress_channel.keys()
    app1_partners = app1.raiden.managers_by_asset_address.values()[0].partneraddress_channel.keys()

    assert channel0.asset_address == channel1.asset_address
    assert app0_asset == app1_asset
    assert app1.raiden.address in app0_partners
    assert app0.raiden.address in app1_partners

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

    direct_transfer = channel0.create_directtransfer(
        amount,
        1  # TODO: fill in identifier
    )
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


@pytest.mark.parametrize('blockchain_type', ['mock'])
@pytest.mark.parametrize('number_of_nodes', [2])
def test_locked_transfer(raiden_network, settle_timeout):
    app0, app1 = raiden_network  # pylint: disable=unbalanced-tuple-unpacking

    channel0 = app0.raiden.managers_by_asset_address.values()[0].partneraddress_channel.values()[0]
    channel1 = app1.raiden.managers_by_asset_address.values()[0].partneraddress_channel.values()[0]

    balance0 = channel0.balance
    balance1 = channel1.balance

    amount = 10

    # reveal_timeout <= expiration < contract.lock_time
    expiration = app0.raiden.chain.block_number() + settle_timeout - 1

    secret = 'secret'
    hashlock = sha3(secret)

    locked_transfer = channel0.create_lockedtransfer(
        amount=amount,
        identifier=1,  # TODO: fill in identifier
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

    channel0.release_lock(secret)
    channel1.withdraw_lock(secret)

    # upon revelation of the secret both balances are updated
    assert_synched_channels(
        channel0, balance0 - amount, [],
        channel1, balance1 + amount, [],
    )


@pytest.mark.parametrize('blockchain_type', ['mock'])
@pytest.mark.parametrize('number_of_nodes', [2])
def test_register_invalid_transfer(raiden_network, settle_timeout):
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
    expiration = app0.raiden.chain.block_number() + settle_timeout - 1

    secret = 'secret'
    hashlock = sha3(secret)

    transfer1 = channel0.create_lockedtransfer(
        amount=amount,
        identifier=1,  # TODO: fill in identifier
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
        1,  # TODO: fill in identifier
        nonce=channel0.our_state.nonce,
        asset=channel0.asset_address,
        transferred_amount=channel1.balance + balance0 + amount,
        recipient=channel0.partner_state.address,
        locksroot=channel0.partner_state.balance_proof.merkleroot_for_unclaimed(),
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
