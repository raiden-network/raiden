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
from raiden.tests.utils.tester import channel_from_nettingcontract, new_nettingcontract

log = slogging.getLogger(__name__)  # pylint: disable=invalid-name


def test_channelnewbalance_event(tester_state, tester_events, tester_token,
                                 tester_registry, settle_timeout):
    privatekey0 = tester.DEFAULT_KEY
    privatekey1 = tester.k1
    address0 = tester.DEFAULT_ACCOUNT
    address0_hex = encode_hex(address0)

    tester_registry.addAsset(
        tester_token.address,
        sender=privatekey0,
    )
    tester_state.mine(number_of_blocks=1)

    netting = new_nettingcontract(
        privatekey0,
        privatekey1,
        tester_state,
        tester_events,
    )

    asset_amount = tester_token.balanceOf(address0, sender=privatekey0)
    deposit_amount = asset_amount // 10

    assert tester_token.approve(netting.address, asset_amount, sender=privatekey0) is True
    assert tester_token.approve(netting.address, asset_amount, sender=privatekey1) is True

    previous_events = list(tester_events)
    assert netting.deposit(deposit_amountsender=privatekey0) is True
    block_number = tester_state.block.number

    assert len(previous_events) + 2 == len(tester_events)
    transfer_event = tester_events[-2]
    newbalance_event = tester_events[-1]

    assert transfer_event['_from'] == address0_hex
    assert transfer_event['_to'] == netting.address
    assert transfer_event['_value'] == deposit_amount

    assert newbalance_event['_event_type'] == 'ChannelNewBalance'
    assert newbalance_event['assetAddress'] == encode_hex(tester_token.address)
    assert newbalance_event['participant'] == address0_hex
    assert newbalance_event['balance'] == deposit_amount
    assert newbalance_event['blockNumber'] == block_number

    previous_events = list(tester_events)
    assert netting.deposit(deposit_amount, sender=privatekey1) is True
    block_number = tester_state.block.number

    assert len(previous_events) + 2 == len(tester_events)
    transfer_event = tester_events[-2]
    newbalance_event = tester_events[-1]

    assert transfer_event['_from'] == address0_hex
    assert transfer_event['_to'] == netting.address
    assert transfer_event['_value'] == deposit_amount

    assert newbalance_event['_event_type'] == 'ChannelNewBalance'
    assert newbalance_event['assetAddress'] == encode_hex(tester_token.address)
    assert newbalance_event['participant'] == address0_hex
    assert newbalance_event['balance'] == deposit_amount
    assert newbalance_event['blockNumber'] == block_number


@pytest.mark.parametrize('tester_blockgas_limit', [10 ** 10])
def test_channel_events(asset_amount, tester_state, tester_events,
                        netting_channel_abi, settle_timeout, tester_token,
                        tester_default_channel_manager):
    manager = tester_default_channel_manager

    address0 = tester.DEFAULT_ACCOUNT
    address1 = tester.a1
    address0_hex = encode_hex(address0)
    privatekey0 = tester.DEFAULT_KEY

    netting_channel_address0_hex = manager.newChannel(
        address1,
        settle_timeout,
    )

    nettingchannel_translator = tester.ContractTranslator(netting_channel_abi)
    nettingchannel0 = tester.ABIContract(
        tester_state,
        nettingchannel_translator,
        netting_channel_address0_hex,
        log_listener=tester_events.append,
    )

    asset_amount = tester_token.balanceOf(address0)
    deposit_amount = int(asset_amount / 10)
    assert tester_token.approve(netting_channel_address0_hex, asset_amount) is True

    previous_events = list(tester_events)
    assert nettingchannel0.deposit(deposit_amount) is True
    block_number = tester_state.block.number

    assert len(previous_events) + 2 == len(tester_events)
    transfer_event = tester_events[-2]
    newbalance_event = tester_events[-1]

    assert transfer_event['_from'] == address0_hex
    assert transfer_event['_to'] == netting_channel_address0_hex
    assert transfer_event['_value'] == deposit_amount

    # TODO: multiple deposits
    assert newbalance_event['_event_type'] == 'ChannelNewBalance'
    assert newbalance_event['assetAddress'] == encode_hex(tester_token.address)
    assert newbalance_event['participant'] == address0_hex
    assert newbalance_event['balance'] == deposit_amount
    assert newbalance_event['blockNumber'] == block_number

    # instantiate channel only after the transfer is made so that the balances
    # are up-to-date
    externalstate0 = ChannelExternalStateTester(
        tester_state,
        privatekey0,
        netting_channel_address0_hex,
    )
    channel0 = channel_from_nettingcontract(
        address0,
        nettingchannel0,
        externalstate0,
        DEFAULT_REVEAL_TIMEOUT,
    )

    amount = 10
    direct_transfer = channel0.create_directtransfer(amount)
    direct_transfer.sign(privatekey0)
    direct_transfer_data = str(direct_transfer.packed().data)

    previous_events = list(tester_events)
    nettingchannel0.closeSingleTransfer(direct_transfer_data)

    last_event = tester_events[-1]
    assert len(previous_events) + 1 == len(tester_events)
    assert last_event['_event_type'] == 'ChannelClosed'
    assert last_event['closingAddress'] == encode_hex(address0)
    assert last_event['blockNumber'] == tester_state.block.number

    # TODO:
    # - ChannelSecretRevealed
    # - ChannelSettled


@pytest.mark.parametrize('tester_blockgas_limit', [10 ** 10])
def test_channel_openning(tester_state, asset_amount, settle_timeout,
                          netting_channel_abi, tester_token, tester_events,
                          tester_default_channel_manager):

    address0 = tester.DEFAULT_ACCOUNT
    address1 = tester.a1
    unknow_key = tester.k3

    manager = tester_default_channel_manager

    amount1 = asset_amount // 2
    assert tester_token.transfer(address1, amount1) is True
    assert tester_token.balanceOf(address1) == amount1

    # load balance from the contract to acount for rouding of //
    amount0 = tester_token.balanceOf(address0)

    netting_channel_address1_hex = manager.newChannel(
        address1,
        settle_timeout,
    )

    nettingchannel_translator = tester.ContractTranslator(netting_channel_abi)
    channel0 = tester.ABIContract(
        tester_state,
        nettingchannel_translator,
        netting_channel_address1_hex,
        log_listener=tester_events.append,
    )

    assert channel0.settleTimeout() == settle_timeout
    assert channel0.assetAddress() == encode_hex(tester_token.address)
    assert channel0.opened() == 0
    assert channel0.closed() == 0
    assert channel0.settled() == 0

    assert channel0.addressAndBalance()[0] == encode_hex(address0)
    assert channel0.addressAndBalance()[1] == 0
    assert channel0.addressAndBalance()[2] == encode_hex(address1)
    assert channel0.addressAndBalance()[3] == 0

    with pytest.raises(TransactionFailed):
        channel0.deposit(1, sender=unknow_key)  # not participant

    assert tester_token.approve(channel0.address, amount0) is True

    with pytest.raises(TransactionFailed):
        channel0.deposit(amount0 + 1)

    with pytest.raises(abi.ValueOutOfBounds):
        channel0.deposit(-1)

    channel0.deposit(amount0)

    assert tester_token.balanceOf(channel0.address) == amount0
    assert tester_token.balanceOf(address0) == 0
    assert channel0.opened() == tester_state.block.number

    assert channel0.addressAndBalance()[0] == encode_hex(address0)
    assert channel0.addressAndBalance()[1] == amount0
    assert channel0.addressAndBalance()[2] == encode_hex(address1)
    assert channel0.addressAndBalance()[3] == 0


@pytest.mark.parametrize('tester_blockgas_limit', [10 ** 10])
def test_close_single_direct_transfer(tester_state, asset_amount,
                                      settle_timeout, netting_channel_abi,
                                      tester_token, tester_events,
                                      tester_default_channel_manager):
    # pylint: disable=too-many-locals,too-many-statements

    private_key0 = tester.k0
    address0 = tester.a0
    address1 = tester.a1
    unknow_key = tester.k3

    asset_address = tester_token.address

    nonce = 1
    transfered_amount = 1
    recipient = address1
    locksroot = ''

    netting_channel_address1_hex = tester_default_channel_manager.newChannel(
        address1,
        settle_timeout,
    )

    nettingchannel_translator = tester.ContractTranslator(netting_channel_abi)
    channel0 = tester.ABIContract(
        tester_state,
        nettingchannel_translator,
        netting_channel_address1_hex,
        log_listener=tester_events.append,
    )

    msg = DirectTransfer(
        nonce,
        asset_address,
        transfered_amount,
        recipient,
        locksroot,
    )
    msg.sign(private_key0)
    packed = msg.packed()
    direct_transfer = str(packed.data)

    channel0.deposit(asset_amount)
    assert channel0.opened() == tester_state.block.number
    tester_state.mine()

    with pytest.raises(TransactionFailed):
        channel0.closeSingleTransfer(direct_transfer, sender=unknow_key)  # not participant

    channel0.closeSingleTransfer(direct_transfer)

    assert channel0.closed() == tester_state.block.number
    assert channel0.closingAddress() == encode_hex(address0)


@pytest.mark.parametrize('tester_blockgas_limit', [10 ** 10])
def test_two_messages_direct_transfer(tester_state, tester_token, channel, events):
    assert tester_token.transfer(tester.a1, 5000) is True

    hashlock1 = sha3(tester.k0)
    lock_amount1 = 29
    lock_expiration1 = 31
    lock1 = Lock(lock_amount1, lock_expiration1, hashlock1)
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

    channel.close(direct_transfer1, direct_transfer2)

    with pytest.raises(TransactionFailed):
        # not participant
        channel.close(
            direct_transfer1,
            direct_transfer2,
            sender=tester.k2
        )

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


@pytest.mark.parametrize('tester_blockgas_limit', [10 ** 10])
def test_two_messages_mediated_transfer(tester_state, tester_token, channel, events):
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
    channel.deposit(half_amount)
    channel1.deposit(half_amount)

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
    channel.deposit(half_amount)
    channel1.deposit(half_amount)

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
