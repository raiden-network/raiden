# -*- coding: utf8 -*-
from __future__ import division

import pytest
from ethereum import abi, tester, slogging
from ethereum.tester import ABIContract, TransactionFailed
from ethereum.utils import encode_hex

from raiden.messages import Lock, DirectTransfer, MediatedTransfer
from raiden.mtree import merkleroot
from raiden.raiden_service import DEFAULT_REVEAL_TIMEOUT
from raiden.utils import sha3
from raiden.tests.utils.tester_client import ChannelExternalStateTester
from raiden.tests.utils.tester import channel_from_nettingcontract, new_channelmanager, new_nettingcontract

log = slogging.getLogger(__name__)  # pylint: disable=invalid-name


@pytest.mark.parametrize('tester_blockgas_limit', [10 ** 10])
def test_channeldeposit(asset_amount, settle_timeout, tester_state,
                        tester_token, tester_events, tester_registry):

    address0 = tester.DEFAULT_ACCOUNT
    address1 = tester.a1
    privatekey0 = tester.DEFAULT_KEY
    privatekey1 = tester.k1
    unknow_key = tester.k3

    amount1 = asset_amount // 2
    assert tester_token.transfer(address1, amount1, sender=privatekey0) is True
    assert tester_token.balanceOf(address1, sender=privatekey0) == amount1

    total_amount = tester_token.balanceOf(address0, sender=privatekey0)
    deposit_amount = total_amount // 10

    channel_manager = new_channelmanager(
        privatekey0,
        tester_state,
        tester_events,
        tester_registry,
        tester_token,
    )

    channel = new_nettingcontract(
        privatekey0,
        privatekey1,
        tester_state,
        tester_events,
        channel_manager,
        settle_timeout,
    )

    # check initial state, needs to be zeroed out
    assert channel.settleTimeout(sender=privatekey0) == settle_timeout
    assert channel.assetAddress(sender=privatekey0) == encode_hex(tester_token.address)
    assert channel.opened(sender=privatekey0) == 0
    assert channel.closed(sender=privatekey0) == 0
    assert channel.settled(sender=privatekey0) == 0

    assert channel.addressAndBalance(sender=privatekey0)[0] == encode_hex(address0)
    assert channel.addressAndBalance(sender=privatekey0)[1] == 0
    assert channel.addressAndBalance(sender=privatekey0)[2] == encode_hex(address1)
    assert channel.addressAndBalance(sender=privatekey0)[3] == 0

    # try to make invalid deposits
    with pytest.raises(TransactionFailed):
        channel.deposit(1, sender=unknow_key)  # not participant

    assert tester_token.approve(channel.address, deposit_amount * 2, sender=privatekey0) is True

    assert channel.deposit(deposit_amount * 2 + 1, sender=privatekey0) is False

    with pytest.raises(abi.ValueOutOfBounds):
        channel.deposit(-1, sender=privatekey0)

    # create a first deposit with half of the allowance
    assert channel.deposit(deposit_amount, sender=privatekey0) is True

    assert tester_token.balanceOf(channel.address, sender=privatekey0) == deposit_amount
    assert tester_token.balanceOf(address0, sender=privatekey0) == total_amount - deposit_amount
    assert channel.opened(sender=privatekey0) == tester_state.block.number

    assert channel.addressAndBalance(sender=privatekey0)[0] == encode_hex(address0)
    assert channel.addressAndBalance(sender=privatekey0)[1] == deposit_amount
    assert channel.addressAndBalance(sender=privatekey0)[2] == encode_hex(address1)
    assert channel.addressAndBalance(sender=privatekey0)[3] == 0

    # check a second depoist with the rest of the allowance
    assert channel.deposit(deposit_amount, sender=privatekey0) is True

    assert tester_token.balanceOf(channel.address, sender=privatekey0) == deposit_amount * 2
    assert tester_token.balanceOf(address0, sender=privatekey0) == total_amount - deposit_amount * 2
    assert channel.opened(sender=privatekey0) == tester_state.block.number

    assert channel.addressAndBalance(sender=privatekey0)[0] == encode_hex(address0)
    assert channel.addressAndBalance(sender=privatekey0)[1] == deposit_amount * 2
    assert channel.addressAndBalance(sender=privatekey0)[2] == encode_hex(address1)
    assert channel.addressAndBalance(sender=privatekey0)[3] == 0

    # allowance zeroed, we cant make a new deposit
    assert channel.deposit(deposit_amount, sender=privatekey0) is False

    # needs to be able to add aditional asset
    assert tester_token.approve(channel.address, deposit_amount, sender=privatekey0) is True
    assert channel.deposit(deposit_amount, sender=privatekey0) is True

    assert tester_token.balanceOf(channel.address, sender=privatekey0) == deposit_amount * 3
    assert tester_token.balanceOf(address0, sender=privatekey0) == total_amount - deposit_amount * 3
    assert channel.opened(sender=privatekey0) == tester_state.block.number

    assert channel.addressAndBalance(sender=privatekey0)[0] == encode_hex(address0)
    assert channel.addressAndBalance(sender=privatekey0)[1] == deposit_amount * 3
    assert channel.addressAndBalance(sender=privatekey0)[2] == encode_hex(address1)
    assert channel.addressAndBalance(sender=privatekey0)[3] == 0


@pytest.mark.parametrize('tester_blockgas_limit', [10 ** 10])
def test_channelnewbalance_event(asset_amount, tester_state, tester_events,
                                 tester_token, tester_registry,
                                 settle_timeout):
    privatekey0 = tester.DEFAULT_KEY
    privatekey1 = tester.k1
    address0 = tester.DEFAULT_ACCOUNT
    address0_hex = encode_hex(address0)
    address1_hex = encode_hex(address1)

    channel_manager = new_channelmanager(
        privatekey0,
        tester_state,
        tester_events,
        tester_registry,
        tester_token,
    )

    nettingchannel = new_nettingcontract(
        privatekey0,
        privatekey1,
        tester_state,
        tester_events,
        channel_manager,
        settle_timeout,
    )

    deposit_amount = asset_amount // 10

    assert tester_token.approve(nettingchannel.address, deposit_amount, sender=privatekey0) is True
    assert tester_token.transfer(address1, deposit_amount, sender=privatekey0)
    assert tester_token.approve(nettingchannel.address, deposit_amount, sender=privatekey1) is True

    previous_events = list(tester_events)
    assert nettingchannel.deposit(deposit_amount, sender=privatekey0) is True
    block_number = tester_state.block.number

    assert len(previous_events) + 2 == len(tester_events)
    transfer_event = tester_events[-2]
    newbalance_event = tester_events[-1]

    assert transfer_event['_from'] == address0_hex
    assert transfer_event['_to'] == nettingchannel.address
    assert transfer_event['_value'] == deposit_amount

    assert newbalance_event['_event_type'] == 'ChannelNewBalance'
    assert newbalance_event['assetAddress'] == encode_hex(tester_token.address)
    assert newbalance_event['participant'] == address0_hex
    assert newbalance_event['balance'] == deposit_amount
    assert newbalance_event['blockNumber'] == block_number

    previous_events = list(tester_events)
    assert nettingchannel.deposit(deposit_amount, sender=privatekey1) is True
    block_number = tester_state.block.number

    assert len(previous_events) + 2 == len(tester_events)
    transfer_event = tester_events[-2]
    newbalance_event = tester_events[-1]

    assert transfer_event['_from'] == address1_hex
    assert transfer_event['_to'] == nettingchannel.address
    assert transfer_event['_value'] == deposit_amount

    assert newbalance_event['_event_type'] == 'ChannelNewBalance'
    assert newbalance_event['assetAddress'] == encode_hex(tester_token.address)
    assert newbalance_event['participant'] == address1_hex
    assert newbalance_event['balance'] == deposit_amount
    assert newbalance_event['blockNumber'] == block_number


@pytest.mark.xfail(reason='to be implemented')
@pytest.mark.parametrize('tester_blockgas_limit', [10 ** 10])
def test_closewithouttransfer_settle(tester_state, asset_amount,
                                     settle_timeout, tester_token,
                                     tester_events, tester_registry):

    address0 = tester.DEFAULT_ACCOUNT
    address1 = tester.a1
    privatekey0 = tester.DEFAULT_KEY
    privatekey1 = tester.k1
    unknow_key = tester.k3

    channel_manager = new_channelmanager(
        privatekey0,
        tester_state,
        tester_events,
        tester_registry,
        tester_token,
    )

    nettingchannel = new_nettingcontract(
        privatekey0,
        privatekey1,
        tester_state,
        tester_events,
        channel_manager,
        settle_timeout,
    )

    amount = asset_amount // 2
    deposit_amount = 100

    assert tester_token.transfer(address1, amount, sender=privatekey0) is True

    assert tester_token.approve(nettingchannel.address, deposit_amount, sender=privatekey0) is True
    assert tester_token.approve(nettingchannel.address, deposit_amount, sender=privatekey1) is True

    initial_balance0 = tester_token.balanceOf(address0, sender=privatekey0)
    initial_balance1 = tester_token.balanceOf(address1, sender=privatekey1)

    assert nettingchannel.deposit(deposit_amount, sender=privatekey0) is True
    assert nettingchannel.deposit(deposit_amount, sender=privatekey1) is True

    with pytest.raises(TransactionFailed):
        nettingchannel.closeWithoutTransfers(sender=unknow_key)

    # this method needs to be implemetned, the name could be changed
    previous_events = list(tester_events)
    nettingchannel.closeWithoutTransfers(sender=privatekey0)
    block_number = tester_state.block.number

    close_event = tester_events[-1]
    assert len(previous_events) + 1 == len(tester_events)
    assert close_event['_event_type'] == 'ChannelClosed'
    assert close_event['closingAddress'] == encode_hex(address0)
    assert close_event['blockNumber'] == block_number
    assert nettingchannel.closed() == block_number
    assert nettingchannel.closingAddress() == encode_hex(address0)

    tester_state.mine(number_of_blocks=settle_timeout + 1)

    previous_events = list(tester_events)
    nettingchannel.settle(sender=privatekey0)
    block_number = tester_state.block.number

    assert len(previous_events) + 3 == len(tester_events)
    transfer0_event = tester_events[-3]
    transfer1_event = tester_events[-2]
    settle_event = tester_events[-1]

    assert transfer0_event['_from'] == nettingchannel.address
    assert transfer0_event['_to'] == encode_hex(address0)
    assert transfer0_event['_value'] == deposit_amount

    assert transfer1_event['_from'] == nettingchannel.address
    assert transfer1_event['_to'] == encode_hex(address1)
    assert transfer1_event['_value'] == deposit_amount

    assert settle_event['_event_type'] == 'ChannelSettled'
    assert settle_event['blockNumber'] == block_number

    assert tester_token.balanceOf(address0, sender=privatekey0) == initial_balance0
    assert tester_token.balanceOf(address1, sender=privatekey1) == initial_balance1


@pytest.mark.parametrize('tester_blockgas_limit', [10 ** 10])
def test_closesingle_settle(asset_amount, settle_timeout, tester_state,
                            tester_events, tester_token, tester_registry):
    address0 = tester.DEFAULT_ACCOUNT
    address1 = tester.a1
    privatekey0 = tester.DEFAULT_KEY
    privatekey1 = tester.k1
    unknow_key = tester.k3

    channel_manager = new_channelmanager(
        privatekey0,
        tester_state,
        tester_events,
        tester_registry,
        tester_token,
    )

    nettingchannel = new_nettingcontract(
        privatekey0,
        privatekey1,
        tester_state,
        tester_events,
        channel_manager,
        settle_timeout,
    )

    deposit_amount = asset_amount // 10
    assert tester_token.approve(nettingchannel.address, asset_amount, sender=privatekey0) is True

    initial_balance0 = tester_token.balanceOf(address0, sender=privatekey0)
    initial_balance1 = tester_token.balanceOf(address1, sender=privatekey1)

    assert nettingchannel.deposit(deposit_amount, sender=privatekey0) is True

    # instantiate channel only after the transfer is made so that the balances
    # are up-to-date
    externalstate0 = ChannelExternalStateTester(
        tester_state,
        privatekey0,
        nettingchannel.address,
    )
    channel0 = channel_from_nettingcontract(
        privatekey0,
        nettingchannel,
        externalstate0,
        DEFAULT_REVEAL_TIMEOUT,
    )

    transfer_amount = 10
    direct_transfer = channel0.create_directtransfer(transfer_amount)
    direct_transfer.sign(privatekey0)
    direct_transfer_data = str(direct_transfer.packed().data)

    with pytest.raises(TransactionFailed):
        nettingchannel.closeSingleTransfer(sender=unknow_key)

    previous_events = list(tester_events)
    nettingchannel.closeSingleTransfer(direct_transfer_data, sender=privatekey0)
    block_number = tester_state.block.number

    close_event = tester_events[-1]
    assert len(previous_events) + 1 == len(tester_events)
    assert close_event['_event_type'] == 'ChannelClosed'
    assert close_event['closingAddress'] == encode_hex(address0)
    assert close_event['blockNumber'] == block_number
    assert nettingchannel.closed(sender=privatekey0) == block_number
    assert nettingchannel.closingAddress(sender=privatekey0) == encode_hex(address0)

    tester_state.mine(number_of_blocks=settle_timeout + 1)

    previous_events = list(tester_events)
    nettingchannel.settle(sender=privatekey0)
    block_number = tester_state.block.number

    assert len(previous_events) + 3 == len(tester_events)
    transfer0_event = tester_events[-3]
    transfer1_event = tester_events[-2]
    settle_event = tester_events[-1]

    assert transfer0_event['_from'] == nettingchannel.address
    assert transfer0_event['_to'] == encode_hex(address0)
    assert transfer0_event['_value'] == deposit_amount - transfer_amount

    assert transfer1_event['_from'] == nettingchannel.address
    assert transfer1_event['_to'] == encode_hex(address1)
    assert transfer1_event['_value'] == transfer_amount

    assert settle_event['_event_type'] == 'ChannelSettled'
    assert settle_event['blockNumber'] == block_number

    assert tester_token.balanceOf(address0, sender=privatekey0) == initial_balance0 - transfer_amount
    assert tester_token.balanceOf(address1, sender=privatekey1) == initial_balance1 + transfer_amount


@pytest.mark.parametrize('tester_blockgas_limit', [10 ** 10])
def test_close_settle(asset_amount, settle_timeout, tester_state,
                      tester_events, tester_token, tester_registry):

    address0 = tester.DEFAULT_ACCOUNT
    address1 = tester.a1
    privatekey0 = tester.DEFAULT_KEY
    privatekey1 = tester.k1
    unknow_key = tester.k3

    channel_manager = new_channelmanager(
        privatekey0,
        tester_state,
        tester_events,
        tester_registry,
        tester_token,
    )

    nettingchannel = new_nettingcontract(
        privatekey0,
        privatekey1,
        tester_state,
        tester_events,
        channel_manager,
        settle_timeout,
    )

    asset_amount = tester_token.balanceOf(address0, sender=privatekey0)
    deposit_amount = asset_amount // 10

    assert tester_token.transfer(address1, deposit_amount, sender=privatekey0) is True

    assert tester_token.approve(nettingchannel.address, asset_amount, sender=privatekey0) is True
    assert tester_token.approve(nettingchannel.address, asset_amount, sender=privatekey1) is True

    initial_balance0 = tester_token.balanceOf(address0, sender=privatekey0)
    initial_balance1 = tester_token.balanceOf(address1, sender=privatekey1)

    assert nettingchannel.deposit(deposit_amount, sender=privatekey0) is True
    assert nettingchannel.deposit(deposit_amount, sender=privatekey1) is True

    # instantiate channel only after the transfer is made so that the balances
    # are up-to-date
    externalstate0 = ChannelExternalStateTester(
        tester_state,
        privatekey0,
        nettingchannel.address,
    )
    channel0 = channel_from_nettingcontract(
        privatekey0,
        nettingchannel,
        externalstate0,
        DEFAULT_REVEAL_TIMEOUT,
    )

    transfer_amount0 = 10
    direct_transfer0 = channel0.create_directtransfer(transfer_amount0)
    direct_transfer0.sign(privatekey0)

    externalstate1 = ChannelExternalStateTester(
        tester_state,
        privatekey1,
        nettingchannel.address,
    )
    channel1 = channel_from_nettingcontract(
        privatekey1,
        nettingchannel,
        externalstate1,
        DEFAULT_REVEAL_TIMEOUT,
    )

    transfer_amount1 = 30
    direct_transfer1 = channel1.create_directtransfer(transfer_amount1)
    direct_transfer1.sign(privatekey1)

    with pytest.raises(TransactionFailed):
        nettingchannel.close(
            str(direct_transfer0.packed().data),
            str(direct_transfer1.packed().data),
            sender=unknow_key,
        )

    previous_events = list(tester_events)
    nettingchannel.close(
        str(direct_transfer0.packed().data),
        str(direct_transfer1.packed().data),
        sender=privatekey0,
    )
    block_number = tester_state.block.number

    close_event = tester_events[-1]
    assert len(previous_events) + 1 == len(tester_events)
    assert close_event['_event_type'] == 'ChannelClosed'
    assert close_event['closingAddress'] == encode_hex(address0)
    assert close_event['blockNumber'] == block_number
    assert nettingchannel.closed(sender=privatekey0) == block_number
    assert nettingchannel.closingAddress(sender=privatekey0) == encode_hex(address0)

    tester_state.mine(number_of_blocks=settle_timeout + 1)

    previous_events = list(tester_events)
    nettingchannel.settle(sender=privatekey0)
    block_number = tester_state.block.number

    assert len(previous_events) + 3 == len(tester_events)
    transfer0_event = tester_events[-3]
    transfer1_event = tester_events[-2]
    settle_event = tester_events[-1]

    assert transfer0_event['_from'] == nettingchannel.address
    assert transfer0_event['_to'] == encode_hex(address0)
    assert transfer0_event['_value'] == deposit_amount - transfer_amount0 + transfer_amount1

    assert transfer1_event['_from'] == nettingchannel.address
    assert transfer1_event['_to'] == encode_hex(address1)
    assert transfer1_event['_value'] == deposit_amount + transfer_amount0 - transfer_amount1

    assert settle_event['_event_type'] == 'ChannelSettled'
    assert settle_event['blockNumber'] == block_number

    assert tester_token.balanceOf(address0, sender=privatekey0) == initial_balance0 - transfer_amount0 + transfer_amount1
    assert tester_token.balanceOf(address1, sender=privatekey1) == initial_balance1 + transfer_amount0 - transfer_amount1


@pytest.mark.parametrize('tester_blockgas_limit', [10 ** 10])
def test_two_messages_mediated_transfer(tester_state, tester_token, channel, events):
    address0 = tester.DEFAULT_ACCOUNT
    address1 = tester.a1
    privatekey0 = tester.DEFAULT_KEY
    privatekey1 = tester.k1
    unknow_key = tester.k3

    channel_manager = new_channelmanager(
        privatekey0,
        tester_state,
        tester_events,
        tester_registry,
        tester_token,
    )

    nettingchannel = new_nettingcontract(
        privatekey0,
        privatekey1,
        tester_state,
        tester_events,
        channel_manager,
        settle_timeout,
    )

    deposit_amount = asset_amount // 10
    assert tester_token.approve(nettingchannel.address, asset_amount, sender=privatekey0) is True

    initial_balance0 = tester_token.balanceOf(address0, sender=privatekey0)
    initial_balance1 = tester_token.balanceOf(address1, sender=privatekey1)

    assert nettingchannel.deposit(deposit_amount, sender=privatekey0) is True
    assert nettingchannel.deposit(deposit_amount, sender=privatekey1) is True

    # instantiate channel only after the transfer is made so that the balances
    # are up-to-date
    externalstate0 = ChannelExternalStateTester(
        tester_state,
        privatekey0,
        nettingchannel.address,
    )
    channel0 = channel_from_nettingcontract(
        privatekey0,
        nettingchannel,
        externalstate0,
        DEFAULT_REVEAL_TIMEOUT,
    )

    transfer_amount0 = 10
    direct_transfer0 = channel0.create_directtransfer(transfer_amount0)
    direct_transfer0.sign(privatekey0)

    externalstate1 = ChannelExternalStateTester(
        tester_state,
        privatekey1,
        nettingchannel.address,
    )
    channel1 = channel_from_nettingcontract(
        privatekey1,
        nettingchannel,
        externalstate1,
        DEFAULT_REVEAL_TIMEOUT,
    )

    transfer_amount1 = 30
    direct_transfer1 = channel1.create_directtransfer(transfer_amount1)
    direct_transfer1.sign(privatekey1)

    hashlock1 = sha3(tester.k0)
    lock_amount1 = 29
    lock_expiration1 = 31
    lock1 = Lock(lock_amount1, lock_expiration1, hashlock1)
    locksroot1 = merkleroot([
        sha3(lock1.as_bytes),
    ])

    hashlock2 = sha3(tester.k1)
    lock_amount2 = 29
    lock_expiration2 = 31
    lock2 = Lock(lock_amount2, lock_expiration2, hashlock2)
    locksroot2 = merkleroot([
        sha3(lock2.as_bytes),
    ])

    nonce = 1
    asset = tester_token.address
    transfered_amount = 3
    recipient = tester.a2
    locksroot = locksroot1
    target = tester.a1
    initiator = tester.a0

    msg1 = MediatedTransfer(
        nonce,
        asset,
        transfered_amount,
        recipient,
        locksroot,
        lock1,
        target,
        initiator,
        fee=0,
    )
    msg1.sign(tester.k0)
    packed = msg1.packed()
    mediated_transfer1 = str(packed.data)

    nonce = 2
    asset = tester_token.address
    transfered_amount = 4
    recipient = tester.a2
    locksroot = locksroot2
    target = tester.a0
    initiator = tester.a1

    msg2 = MediatedTransfer(
        nonce,
        asset,
        transfered_amount,
        recipient,
        locksroot,
        lock2,
        target,
        initiator,
        fee=0,
    )
    msg2.sign(tester.k1)
    packed = msg2.packed()
    mediated_transfer2 = str(packed.data)

    channel.close(mediated_transfer1, mediated_transfer2)

    # Test with message sender tester.a0
    assert channel.closed() == tester_state.block.number
    assert channel.closingAddress() == tester.a0.encode('hex')
    # assert channel.participants(0)[10] == 1
    # assert channel.participants(0)[11] == token.address.encode('hex')
    # assert channel.participants(0)[9] == tester.a0.encode('hex')
    # assert channel.participants(0)[12] == tester.a1.encode('hex')
    # assert channel.participants(0)[3] == 1
    # assert channel.participants(0)[13] == locksroot1
    # assert channel.participants(0)[7] == '\x00' * 32

    # Test with message sender tester.a1
    assert channel.closed() == tester_state.block.number
    assert channel.closingAddress() == tester.a0.encode('hex')
    # assert channel.participants(1)[10] == 2
    # assert channel.participants(1)[11] == token.address.encode('hex')
    # assert channel.participants(1)[9] == tester.a1.encode('hex')
    # assert channel.participants(1)[12] == tester.a0.encode('hex')
    # assert channel.participants(1)[3] == 3
    # assert channel.participants(1)[13] == locksroot2
    # assert channel.participants(1)[7] == '\x00' * 32


@pytest.mark.parametrize('asset_amount', [100])
@pytest.mark.parametrize('tester_blockgas_limit', [10 ** 10])
def test_all_asset(asset_amount, tester_state, channel, tester_token, tester_events):
    half_amount = asset_amount / 2
    assert tester_token.transfer(tester.a1, half_amount) is True

    token1 = ABIContract(
        tester_state,
        tester_token.translator,
        tester_token.address,
        default_key=tester.k1,
    )
    assert tester_token.approve(channel.address, half_amount) is True
    assert token1.approve(channel.address, half_amount) is True

    channel1 = ABIContract(
        tester_state,
        channel.translator,
        channel.address,
        default_key=tester.k1,
    )
    assert channel.deposit(half_amount) is True
    assert channel1.deposit(half_amount) is True

    _, deposit1, _, deposit2 = channel.addressAndBalance()

    assert deposit1 == half_amount
    assert deposit2 == half_amount

    assert tester_token.balanceOf(channel.address) == asset_amount
    assert tester_token.balanceOf(tester.a0) == 0
    assert tester_token.balanceOf(tester.a1) == 0


@pytest.mark.parametrize('tester_blockgas_limit', [10 ** 10])
def test_update_direct_transfer(tester_state, tester_token, channel, tester_events):
    # test global variables
    assert channel.settleTimeout() == 30
    assert channel.assetAddress() == tester_token.address.encode('hex')
    assert channel.opened() == 0
    assert channel.closed() == 0
    assert channel.settled() == 0

    hashlock1 = sha3(tester.k0)
    lock_amount1 = 29
    lock_expiration1 = 31
    lock1 = Lock(
        lock_amount1,
        lock_expiration1,
        hashlock1,
    )
    locksroot1 = merkleroot([
        sha3(lock1.as_bytes),
    ])

    nonce = 1
    asset = tester_token.address
    transfered_amount = 1
    recipient = tester.a1
    locksroot = locksroot1

    msg1 = DirectTransfer(
        nonce,
        asset,
        transfered_amount,
        recipient,
        locksroot,
    )
    msg1.sign(tester.k0)
    packed = msg1.packed()
    direct_transfer1 = str(packed.data)

    hashlock2 = sha3(tester.k1)
    lock_amount2 = 29
    lock_expiration2 = 31
    lock2 = Lock(lock_amount2, lock_expiration2, hashlock2)
    locksroot2 = merkleroot([
        sha3(lock2.as_bytes),
    ])

    locksroot = locksroot2

    nonce = 2
    transfered_amount = 3
    recipient = tester.a0
    msg2 = DirectTransfer(
        nonce,
        tester_token.address,
        transfered_amount,
        recipient,
        locksroot,
    )
    msg2.sign(tester.k1)
    packed = msg2.packed()
    direct_transfer2 = str(packed.data)

    # not yet closed
    with pytest.raises(TransactionFailed):
        channel.updateTransfer(direct_transfer1, sender=tester.k1)

    channel.close(direct_transfer1, direct_transfer2)

    # Test with message sender tester.a0
    assert channel.closed() == tester_state.block.number
    assert channel.closingAddress() == tester.a0.encode('hex')
    # assert channel.participants(0)[10] == 1
    # assert channel.participants(0)[11] == token.address.encode('hex')
    # assert channel.participants(0)[9] == tester.a0.encode('hex')
    # assert channel.participants(0)[12] == tester.a1.encode('hex')
    # assert channel.participants(0)[3] == 1
    # assert channel.participants(0)[13] == locksroot1
    # assert channel.participants(0)[7] == '\x00' * 32

    # Test with message sender tester.a1
    assert channel.closed() == tester_state.block.number
    assert channel.closingAddress() == tester.a0.encode('hex')
    # assert channel.participants(1)[10] == 2
    # assert channel.participants(1)[11] == token.address.encode('hex')
    # assert channel.participants(1)[9] == tester.a1.encode('hex')
    # assert channel.participants(1)[12] == tester.a0.encode('hex')
    # assert channel.participants(1)[3] == 3
    # assert channel.participants(1)[13] == locksroot2
    # assert channel.participants(1)[7] == '\x00' * 32

    hashlock3 = sha3(tester.k1)
    lock_amount3 = 29
    lock_expiration3 = 31
    lock3 = Lock(lock_amount3, lock_expiration3, hashlock3)
    locksroot3 = merkleroot([
        sha3(lock3.as_bytes),
    ])

    locksroot = locksroot3

    nonce = 3
    transfered_amount = 5
    recipient = tester.a0
    msg3 = DirectTransfer(
        nonce,
        tester_token.address,
        transfered_amount,
        recipient,
        locksroot,
    )
    msg3.sign(tester.k1)
    packed = msg3.packed()
    direct_transfer3 = str(packed.data)

    # closingAddress == getSender(message)
    with pytest.raises(TransactionFailed):
        channel.updateTransfer(direct_transfer1)

    channel.updateTransfer(direct_transfer3, sender=tester.k1)

    # Test with message sender tester.a1
    # assert channel.participants(1)[10] == 3
    # assert channel.participants(1)[11] == token.address.encode('hex')
    # assert channel.participants(1)[9] == tester.a1.encode('hex')
    # assert channel.participants(1)[12] == tester.a0.encode('hex')
    # assert channel.participants(1)[3] == 5
    # assert channel.participants(1)[13] == locksroot3
    # assert channel.participants(1)[7] == '\x00' * 32

    nonce = 1
    transfered_amount = 5
    recipient = tester.a0
    msg4 = DirectTransfer(
        nonce,
        tester_token.address,
        transfered_amount,
        recipient,
        locksroot,
    )
    msg4.sign(tester.k1)
    packed = msg4.packed()
    direct_transfer4 = str(packed.data)

    # nonce too low
    with pytest.raises(TransactionFailed):
        channel.updateTransfer(direct_transfer4, sender=tester.k1)

    # settleTimeout overdue
    tester_state.block.number = 1158041

    with pytest.raises(TransactionFailed):
        channel.updateTransfer(direct_transfer3, sender=tester.k1)

    assert len(tester_events) == 1
    assert tester_events[0]['_event_type'] == 'ChannelClosed'
    assert tester_events[0]['blockNumber'] == 1158002
    assert tester_events[0]['closingAddress'] == tester.a0.encode('hex')


@pytest.mark.parametrize('tester_blockgas_limit', [10 ** 10])
def test_update_mediated_transfer(tester_state, tester_token, channel, tester_events):
    # test global variables
    assert channel.settleTimeout() == 30
    assert channel.assetAddress() == tester_token.address.encode('hex')
    assert channel.opened() == 0
    assert channel.closed() == 0
    assert channel.settled() == 0

    hashlock1 = sha3(tester.k0)
    lock_amount1 = 29
    lock_expiration1 = 31
    lock1 = Lock(lock_amount1, lock_expiration1, hashlock1)
    locksroot1 = merkleroot([
        sha3(lock1.as_bytes),
    ])

    hashlock2 = sha3(tester.k1)
    lock_amount2 = 29
    lock_expiration2 = 31
    lock2 = Lock(lock_amount2, lock_expiration2, hashlock2)
    locksroot2 = merkleroot([
        sha3(lock2.as_bytes),
    ])

    nonce = 1
    asset = tester_token.address
    transfered_amount = 3
    recipient = tester.a2
    locksroot = locksroot1
    target = tester.a1
    initiator = tester.a0

    msg1 = MediatedTransfer(
        nonce,
        asset,
        transfered_amount,
        recipient,
        locksroot,
        lock1,
        target,
        initiator,
        fee=0,
    )
    msg1.sign(tester.k0)
    packed = msg1.packed()
    mediated_transfer1 = str(packed.data)

    nonce = 2
    asset = tester_token.address
    transfered_amount = 4
    recipient = tester.a2
    locksroot = locksroot2
    target = tester.a0
    initiator = tester.a1

    msg2 = MediatedTransfer(
        nonce,
        asset,
        transfered_amount,
        recipient,
        locksroot,
        lock2,
        target,
        initiator,
        fee=0,
    )
    msg2.sign(tester.k1)
    packed = msg2.packed()
    mediated_transfer2 = str(packed.data)

    # not yet closed
    with pytest.raises(TransactionFailed):
        channel.updateTransfer(mediated_transfer1, sender=tester.k1)

    channel.close(mediated_transfer1, mediated_transfer2)

    # Test with message sender tester.a0
    assert channel.closed() == tester_state.block.number
    assert channel.closingAddress() == tester.a0.encode('hex')
    # assert channel.participants(0)[10] == 1
    # assert channel.participants(0)[11] == token.address.encode('hex')
    # assert channel.participants(0)[9] == tester.a0.encode('hex')
    # assert channel.participants(0)[12] == tester.a1.encode('hex')
    # assert channel.participants(0)[3] == 1
    # assert channel.participants(0)[13] == locksroot1
    # assert channel.participants(0)[7] == '\x00' * 32

    # Test with message sender tester.a1
    assert channel.closed() == tester_state.block.number
    assert channel.closingAddress() == tester.a0.encode('hex')
    # assert channel.participants(1)[10] == 2
    # assert channel.participants(1)[11] == token.address.encode('hex')
    # assert channel.participants(1)[9] == tester.a1.encode('hex')
    # assert channel.participants(1)[12] == tester.a0.encode('hex')
    # assert channel.participants(1)[3] == 3
    # assert channel.participants(1)[13] == locksroot2
    # assert channel.participants(1)[7] == '\x00' * 32

    hashlock3 = sha3(tester.k1)
    lock_amount3 = 29
    lock_expiration3 = 31
    lock3 = Lock(lock_amount3, lock_expiration3, hashlock3)
    locksroot3 = merkleroot([
        sha3(lock3.as_bytes),
    ])

    nonce = 3
    asset = tester_token.address
    transfered_amount = 4
    recipient = tester.a2
    locksroot = locksroot3
    target = tester.a0
    initiator = tester.a1

    msg3 = MediatedTransfer(
        nonce,
        asset,
        transfered_amount,
        recipient,
        locksroot,
        lock3,
        target,
        initiator,
        fee=0,
    )
    msg3.sign(tester.k1)
    packed = msg3.packed()
    mediated_transfer3 = str(packed.data)
    # closingAddress == getSender(message)
    with pytest.raises(TransactionFailed):
        channel.updateTransfer(mediated_transfer1)

    channel.updateTransfer(mediated_transfer3, sender=tester.k1)

    # Test with message sender tester.a1
    # assert channel.participants(1)[10] == 3
    # assert channel.participants(1)[11] == token.address.encode('hex')
    # assert channel.participants(1)[9] == tester.a1.encode('hex')
    # assert channel.participants(1)[12] == tester.a0.encode('hex')
    # assert channel.participants(1)[3] == 5
    # assert channel.participants(1)[13] == locksroot3
    # assert channel.participants(1)[7] == '\x00' * 32

    nonce = 1
    transfered_amount = 5
    recipient = tester.a0
    msg4 = DirectTransfer(
        nonce,
        tester_token.address,
        transfered_amount,
        recipient,
        locksroot,
    )
    msg4.sign(tester.k1)
    packed = msg4.packed()
    direct_transfer4 = str(packed.data)

    # nonce too low
    with pytest.raises(TransactionFailed):
        channel.updateTransfer(direct_transfer4, sender=tester.k1)

    # settleTimeout overdue
    tester_state.block.number = 1158041

    with pytest.raises(TransactionFailed):
        channel.updateTransfer(mediated_transfer3, sender=tester.k1)

    assert len(tester_events) == 1
    assert tester_events[0]['_event_type'] == 'ChannelClosed'
    assert tester_events[0]['blockNumber'] == 1158002
    assert tester_events[0]['closingAddress'] == tester.a0.encode('hex')


@pytest.mark.parametrize('tester_blockgas_limit', [10 ** 10])
def test_unlock(tester_token, channel, tester_events, tester_state):
    secret1 = 'x' * 32
    hashlock1 = sha3(secret1)
    lock_amount1 = 29
    lock_expiration1 = 1158003
    lock1 = Lock(lock_amount1, lock_expiration1, hashlock1)
    lockhash1 = sha3(lock1.as_bytes)
    merkleproof1 = [lockhash1]
    locksroot1 = merkleroot([lockhash1], merkleproof1)

    nonce = 10
    asset = tester_token.address
    transfered_amount = 1
    recipient = tester.a1

    msg1 = DirectTransfer(
        nonce,
        asset,
        transfered_amount,
        recipient,
        locksroot1,
    )
    msg1.sign(tester.k0)
    packed = msg1.packed()
    direct_transfer1 = str(packed.data)

    secret2 = 'y' * 32
    hashlock2 = sha3(secret2)
    lock_amount2 = 20
    lock_expiration2 = 1158030
    lock2 = Lock(lock_amount2, lock_expiration2, hashlock2)
    lockhash2 = sha3(lock2.as_bytes)
    merkleproof2 = [lockhash2]
    # locksroot2 = merkleroot([lockhash2], merkleproof2)

    msg2 = DirectTransfer(
        2,              # nonce
        asset,
        3,              # transfered_amount
        tester.a0,      # recipient
        '',
    )
    msg2.sign(tester.k1)
    packed = msg2.packed()
    direct_transfer2 = str(packed.data)

    channel.close(direct_transfer1, direct_transfer2)

    channel.unlock(
        str(lock1.as_bytes),
        ''.join(merkleproof1),
        secret1,
    )

    # TODO: it must not be possible to unlock the same lock twice
    # with pytest.raises(TransactionFailed):
    #     channel.unlock(
    #         str(lock1.as_bytes),
    #         ''.join(merkleproof1),
    #         secret1,
    #     )

    # expiration has passed, should fail
    tester_state.block.number = 1158031
    with pytest.raises(TransactionFailed):
        channel.unlock(
            str(lock2.as_bytes),
            ''.join(merkleproof2),
            secret2,
        )


@pytest.mark.parametrize('asset_amount', [100])
@pytest.mark.parametrize('tester_blockgas_limit', [10 ** 10])
def test_settle(tester_state, channel, tester_token, asset_amount, tester_events):
    half_amount = asset_amount / 2
    assert tester_token.transfer(tester.a1, half_amount) is True

    token1 = ABIContract(
        tester_state,
        tester_token.translator,
        tester_token.address,
        default_key=tester.k1,
    )
    assert tester_token.approve(channel.address, half_amount) is True
    assert token1.approve(channel.address, half_amount) is True

    channel1 = ABIContract(
        tester_state,
        channel.translator,
        channel.address,
        default_key=tester.k1,
    )
    assert channel.deposit(half_amount) is True
    assert channel1.deposit(half_amount) is True

    assert tester_events[0]['_event_type'] == 'ChannelNewBalance'
    assert tester_events[0]['assetAddress'] == tester_token.address.encode('hex')
    assert tester_events[0]['participant'] == tester.a0.encode('hex')
    assert tester_events[0]['balance'] == 50
    assert tester_events[1]['_event_type'] == 'ChannelNewBalance'
    assert tester_events[1]['assetAddress'] == tester_token.address.encode('hex')
    assert tester_events[1]['participant'] == tester.a1.encode('hex')
    assert tester_events[1]['balance'] == 50

    secret1 = 'x' * 32
    hashlock1 = sha3(secret1)
    lock_amount1 = 29
    lock_expiration1 = 1158003
    lock1 = Lock(lock_amount1, lock_expiration1, hashlock1)
    lockhash1 = sha3(lock1.as_bytes)
    merkleproof1 = [lockhash1]
    locksroot1 = merkleroot([lockhash1], merkleproof1)

    nonce1 = 1
    asset = tester_token.address
    transfered_amount1 = 1
    recipient = tester.a1
    locksroot = locksroot1

    msg1 = DirectTransfer(
        nonce1,
        asset,
        transfered_amount1,
        recipient,
        locksroot,
    )
    msg1.sign(tester.k0)
    packed = msg1.packed()
    direct_transfer1 = str(packed.data)

    secret2 = 'y' * 32
    hashlock2 = sha3(secret2)
    lock_amount2 = 20
    lock_expiration2 = 1158005
    lock2 = Lock(lock_amount2, lock_expiration2, hashlock2)
    lockhash2 = sha3(lock2.as_bytes)
    merkleproof2 = [lockhash2]
    locksroot2 = merkleroot([lockhash2], merkleproof2)

    locksroot = locksroot2
    nonce2 = 2
    transfered_amount2 = 3
    recipient = tester.a0
    msg2 = DirectTransfer(
        nonce2,
        tester_token.address,
        transfered_amount2,
        recipient,
        locksroot,
    )
    msg2.sign(tester.k1)
    packed = msg2.packed()
    direct_transfer2 = str(packed.data)

    # not yet closed. should fail
    with pytest.raises(TransactionFailed):
        channel.settle()

    channel.close(direct_transfer1, direct_transfer2)

    assert tester_events[2]['_event_type'] == 'ChannelClosed'
    assert tester_events[2]['closingAddress'] == tester.a0.encode('hex')
    assert tester_events[2]['blockNumber'] == tester_state.block.number

    channel.unlock(
        str(lock1.as_bytes),
        ''.join(merkleproof1),
        secret1,
    )
    channel.unlock(
        str(lock2.as_bytes),
        ''.join(merkleproof2),
        secret2,
        sender=tester.k1
    )

    assert tester_events[3]['_event_type'] == 'ChannelSecretRevealed'
    assert tester_events[3]['secret'] == 'x' * 32
    assert tester_events[4]['_event_type'] == 'ChannelSecretRevealed'
    assert tester_events[4]['secret'] == 'y' * 32

    secret4 = 'k' * 32
    hashlock4 = sha3(secret4)
    lock_amount4 = 23
    lock_expiration4 = 31
    lock4 = Lock(lock_amount4, lock_expiration4, hashlock4)
    hashlock4 = sha3(lock4.as_bytes)
    merkleproof4 = [hashlock4]

    # has now message, should fail
    with pytest.raises(TransactionFailed):
        channel.unlock(
            str(lock4.as_bytes),
            ''.join(merkleproof4),
            secret4,
            sender=tester.k1,
        )

    # still timeout
    with pytest.raises(TransactionFailed):
        channel.settle()

    tester_state.block.number = tester_state.block.number + 40  # timeout over
    channel.settle()

    assert tester_events[5]['_event_type'] == 'ChannelSettled'
    assert tester_events[5]['blockNumber'] == tester_state.block.number

    balance1 = half_amount + (transfered_amount2 - transfered_amount1) + lock_amount1 - lock_amount2
    balance2 = half_amount + (transfered_amount1 - transfered_amount2) - lock_amount1 + lock_amount2
    assert tester_token.balanceOf(tester.a0) == balance1
    assert tester_token.balanceOf(tester.a1) == balance2

    # can settle only once
    with pytest.raises(TransactionFailed):
        channel.settle()

    assert len(tester_events) == 6


def test_unlock(tester_state, channel, tester_token, asset_address, reveal_timeout, settle_timeout):
    block_alarm = list()
    original_mine = tester_state.mine

    def wrap_mine(*args, **kwargs):
        original_mine(*args, **kwargs)

        block_number = get_block_number()
        for callback in block_alarm:
            callback(block_number)

    def register_block_alarm(callback):
        block_alarm.append(callback)

    def get_block_number():
        return len(tester_state.blocks)

    tester_state.mine = wrap_mine

    address0 = tester.a0
    address1 = tester.a1

    privatekey1 = tester.k1

    token0 = tester_token
    token1 = tester.ABIContract(
        tester_state,
        tester_token.translator,
        tester_token.address,
        default_key=privatekey1,
    )

    netting_channel0 = channel
    netting_channel1 = tester.ABIContract(
        tester_state,
        channel.translator,
        channel.address,
        default_key=privatekey1,
    )

    # setup asset and open the channel
    half_balance = token0.balanceOf(address1) // 2
    token0.transfer(address1, half_balance)

    balance0 = token0.balanceOf(address0)
    token0.approve(netting_channel0.address, balance0)

    balance1 = token1.balanceOf(tester.a1)
    token1.approve(netting_channel1.address, balance1)

    assert netting_channel0.deposit(balance0) is True
    assert netting_channel1.deposit(balance1) is True

    # setup python's channels
    our_state0 = ChannelEndState(address0, balance0)
    partner_state0 = ChannelEndState(address1, balance1)
    channel_for_hashlock0 = list()
    external_state0 = ChannelExternalState(
        register_block_alarm,
        lambda *args: channel_for_hashlock0.append(args),
        get_block_number,
        netting_channel0,
    )
    channel0 = Channel(
        our_state0, partner_state0, external_state0,
        asset_address, reveal_timeout, settle_timeout,
    )

    our_state1 = ChannelEndState(address1, balance1)
    partner_state1 = ChannelEndState(address0, balance0)
    channel_for_hashlock1 = list()
    external_state1 = ChannelExternalState(
        register_block_alarm,
        lambda *args: channel_for_hashlock1.append(args),
        get_block_number,
        netting_channel1,
    )
    channel1 = Channel(
        our_state1, partner_state1, external_state1,
        asset_address, reveal_timeout, settle_timeout,
    )
