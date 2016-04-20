# -*- coding: utf8 -*-
import pytest

from ethereum import slogging

from raiden.messages import DirectTransfer
from raiden.tests.utils.network import create_network
from raiden.tests.utils.transfer import assert_synched_channels
from raiden.utils import sha3

log = slogging.getLogger(__name__)  # pylint: disable=invalid-name
slogging.configure(':debug')


def test_setup():
    apps = create_network(num_nodes=2, num_assets=1, channels_per_node=1)
    app0, app1 = apps  # pylint: disable=unbalanced-tuple-unpacking

    channel0 = app0.raiden.chain.nettingaddresses_by_asset_participant(
        app0.raiden.chain.asset_addresses[0],
        app0.raiden.address,
    )
    channel1 = app0.raiden.chain.nettingaddresses_by_asset_participant(
        app0.raiden.chain.asset_addresses[0],
        app1.raiden.address,
    )

    assert channel0 and channel1
    assert app0.raiden.assetmanagers.keys() == app1.raiden.assetmanagers.keys()
    assert len(app0.raiden.assetmanagers) == 1


def test_transfer():
    apps = create_network(num_nodes=2, num_assets=1, channels_per_node=1)

    app0, app1 = apps  # pylint: disable=unbalanced-tuple-unpacking

    channel0 = app0.raiden.assetmanagers.values()[0].channels.values()[0]
    channel1 = app1.raiden.assetmanagers.values()[0].channels.values()[0]

    initial_balance0 = channel0.initial_balance
    initial_balance1 = channel1.initial_balance

    # check agreement on addresses
    address0 = channel0.our_state.address
    address1 = channel1.our_state.address
    assert channel0.asset_address == channel1.asset_address
    assert app0.raiden.assetmanagers.keys()[0] == app1.raiden.assetmanagers.keys()[0]
    assert app0.raiden.assetmanagers.values()[0].channels.keys()[0] == app1.raiden.address
    assert app1.raiden.assetmanagers.values()[0].channels.keys()[0] == app0.raiden.address

    # check balances of channel and contract are equal
    details0 = app0.raiden.chain.netting_contract_detail(
        channel0.asset_address,
        channel0.nettingcontract_address,
        address0,
    )
    details1 = app0.raiden.chain.netting_contract_detail(
        channel1.asset_address,
        channel1.nettingcontract_address,
        address1,
    )
    assert initial_balance0 == details0['our_balance']
    assert initial_balance1 == details1['our_balance']

    assert_synched_channels(
        channel0, initial_balance0, [],
        channel1, initial_balance1, [],
    )

    amount = 10

    direct_transfer = channel0.create_directtransfer(amount=amount)
    app0.raiden.sign(direct_transfer)
    channel0.register_transfer(direct_transfer)
    channel1.register_transfer(direct_transfer)

    # check the contract is intact
    assert details0 == app0.raiden.chain.netting_contract_detail(
        channel0.asset_address,
        channel0.nettingcontract_address,
        address0,
    )
    assert details1 == app0.raiden.chain.netting_contract_detail(
        channel1.asset_address,
        channel1.nettingcontract_address,
        address1,
    )
    assert channel0.initial_balance == initial_balance0
    assert channel1.initial_balance == initial_balance1

    assert_synched_channels(
        channel0, initial_balance0 - amount, [],
        channel1, initial_balance1 + amount, [],
    )


def test_locked_transfer():
    """ Simple locked transfer test. """
    apps = create_network(num_nodes=2, num_assets=1, channels_per_node=1)
    app0, app1 = apps  # pylint: disable=unbalanced-tuple-unpacking

    channel0 = app0.raiden.assetmanagers.values()[0].channels.values()[0]
    channel1 = app1.raiden.assetmanagers.values()[0].channels.values()[0]

    balance0 = channel0.balance
    balance1 = channel1.balance

    amount = 10
    expiration = app0.raiden.chain.block_number + 15  # min_locktime <= expiration < contract.lock_time

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
        channel0, balance0, [locked_transfer.lock],
        channel1, balance1, [],
    )

    channel0.claim_locked(secret)
    channel1.claim_locked(secret)

    # upon revelation of the secret both balances are updated
    assert_synched_channels(
        channel0, balance0 - amount, [],
        channel1, balance1 + amount, [],
    )


def test_interwoven_transfers(num=100):  # pylint: disable=too-many-locals
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

    apps = create_network(num_nodes=2, num_assets=1, channels_per_node=1)

    app0, app1 = apps  # pylint: disable=unbalanced-tuple-unpacking

    channel0 = app0.raiden.assetmanagers.values()[0].channels.values()[0]
    channel1 = app1.raiden.assetmanagers.values()[0].channels.values()[0]

    initial_balance0 = channel0.initial_balance
    initial_balance1 = channel1.initial_balance

    expiration = app0.raiden.chain.block_number + 15

    unclaimed_locks = []
    transfers_list = []
    transfers_amount = [i for i in range(1, num + 1)]  # start at 1 because we can't use amount=0
    transfers_secret = [str(i) for i in range(num)]
    transfers_claimed = []

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
            channel0, initial_balance0 - claimed_amount, unclaimed_locks,
            channel1, initial_balance1 + claimed_amount, [],
        )
        assert channel0.distributable == initial_balance0 - distributed_amount

        # claim a transaction at every other iteration, leaving the current one
        # in place
        if i > 0 and i % 2 == 0:
            transfer = transfers_list[i - 1]
            secret = transfers_secret[i - 1]

            # synchronized clamining
            channel0.claim_locked(secret)
            channel1.claim_locked(secret)

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
                channel0, initial_balance0 - claimed_amount, unclaimed_locks,
                channel1, initial_balance1 + claimed_amount, [],
            )
            assert channel0.distributable == initial_balance0 - distributed_amount


def test_register_invalid_transfer():
    """ Regression test for registration of invalid transfer.

    Bhe bug occurred if a transfer with an invalid allowance but a valid secret
    was registered, when the local end registered the transfer it would
    "unlock" the partners asset, but the transfer wouldn't be sent because the
    allowance check failed, leaving the channel in an inconsistent state.
    """
    apps = create_network(num_nodes=2, num_assets=1, channels_per_node=1)
    app0, app1 = apps  # pylint: disable=unbalanced-tuple-unpacking

    channel0 = app0.raiden.assetmanagers.values()[0].channels.values()[0]
    channel1 = app1.raiden.assetmanagers.values()[0].channels.values()[0]

    balance0 = channel0.our_state.balance
    balance1 = channel1.our_state.balance

    amount = 10
    expiration = app0.raiden.chain.block_number + 15

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
        channel0, balance0, [transfer1.lock],
        channel1, balance1, [],
    )

    # handcrafted transfer because channel.create_transfer won't create it
    transfer2 = DirectTransfer(
        nonce=channel0.our_state.nonce,
        asset=channel0.asset_address,
        balance=channel0.partner_state.balance + balance0 + amount,
        recipient=channel0.partner_state.address,
        locksroot=channel0.partner_state.locked.root,
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
        channel0, balance0, [transfer1.lock],
        channel1, balance1, []
    )
