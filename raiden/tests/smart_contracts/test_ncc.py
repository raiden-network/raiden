# -*- coding: utf8 -*-
import pytest

from ethereum import tester
from ethereum import slogging
from ethereum.tester import ABIContract, TransactionFailed

from raiden.messages import Lock, DirectTransfer, MediatedTransfer
from raiden.mtree import merkleroot
from raiden.utils import privtoaddr, sha3

log = slogging.getLogger(__name__)  # pylint: disable=invalid-name


def test_close_single_direct_transfer(state, channel, token, events):  # pylint: disable=too-many-locals,too-many-statements
    # test tokens and distribute tokens
    assert token.balanceOf(tester.a0) == 10000
    assert token.balanceOf(tester.a1) == 0
    assert token.transfer(tester.a1, 5000) is True
    assert token.balanceOf(tester.a0) == 5000
    assert token.balanceOf(tester.a1) == 5000

    # test global variables
    assert channel.settleTimeout() == 30
    assert channel.assetAddress() == token.address.encode('hex')
    assert channel.opened() == 0
    assert channel.closed() == 0
    assert channel.settled() == 0

    # test participants variables changed when constructing
    assert channel.addressAndBalance()[0] == tester.a0.encode('hex')
    assert channel.addressAndBalance()[2] == tester.a1.encode('hex')

    # test atIndex()
    # private must be removed from the function in order to work
    # assert channel.atIndex(sha3('address1')[:20]) == 0
    # assert channel.atIndex(sha3('address2')[:20]) == 1

    # test deposit(uint)
    with pytest.raises(TransactionFailed):
        channel.deposit(30, sender=tester.k2)  # not participant

    assert token.balanceOf(channel.address) == 0
    assert token.approve(channel.address, 30) is True # allow the contract do deposit
    assert channel.addressAndBalance()[1] == 0
    with pytest.raises(TransactionFailed):
        channel.deposit(5001)
    channel.deposit(30)
    assert channel.addressAndBalance()[1] == 30
    assert token.balanceOf(channel.address) == 30
    assert token.balanceOf(tester.a0) == 4970
    assert channel.opened() == state.block.number

    # test open()
    # private must be removed from the function in order to work
    # assert channel.opened() == 0  # channel is not yet opened
    # channel.open()
    # assert channel.opened() > 0
    # assert channel.opened() <= state.block.number

    # test partner(address)
    # private must be removed from the function in order to work
    # assert channel.partner(sha3('address1')[:20]) == sha3('address2')[:20].encode('hex')
    # assert channel.partner(sha3('address2')[:20]) == sha3('address1')[:20].encode('hex')

    # test addressAndBalance()
    a1, d1, a2, d2 = channel.addressAndBalance()
    assert a1 == tester.a0.encode('hex')
    assert a2 == tester.a1.encode('hex')
    assert d1 == 30
    assert d2 == 0

    # test close(message)

    initiator_privkey = tester.k0

    recipient_privkey = tester.k1
    recipient_address = privtoaddr(recipient_privkey)

    asset_address = token.address

    hashlock = sha3(initiator_privkey)
    lock_amount = 29
    lock_expiration = 31
    lock = Lock(lock_amount, lock_expiration, hashlock)
    locksroot = merkleroot([
        sha3(lock.as_bytes),
    ])

    nonce = 1
    asset = asset_address
    transfered_amount = 1
    recipient = recipient_address
    locksroot = locksroot

    msg = DirectTransfer(
        nonce,
        asset,
        transfered_amount,
        recipient,
        locksroot,
    )
    msg.sign(initiator_privkey)
    packed = msg.packed()
    direct_transfer = str(packed.data)

    channel.closeSingleTransfer(direct_transfer)

    with pytest.raises(TransactionFailed):
        channel.closeSingleTransfer(direct_transfer, sender=tester.k2) # not participant

    assert channel.closed() == state.block.number
    assert channel.closingAddress() == tester.a0.encode('hex')
    # assert channel.participants(0)[10] == 1
    # assert channel.participants(0)[11] == token.address.encode('hex')
    # assert channel.participants(0)[9] == tester.a0.encode('hex')
    # assert channel.participants(0)[12] == tester.a1.encode('hex')
    # assert channel.participants(0)[3] == 1
    # assert channel.participants(0)[13] == locksroot
    # assert channel.participants(0)[7] == '\x00' * 32

    assert len(events) == 2
    assert events[0]['_event_type'] == 'ChannelNewBalance'
    assert events[0]['assetAddress'] == token.address.encode('hex')
    assert events[0]['balance'] == 30
    assert events[0]['participant'] == tester.a0.encode('hex')
    assert events[1]['_event_type'] == 'ChannelClosed'
    assert events[1]['closingAddress'] == tester.a0.encode('hex')
    assert events[1]['blockNumber'] == state.block.number


def test_two_messages_direct_transfer(state, token, channel, events):
    # test tokens and distribute tokens
    assert token.balanceOf(tester.a0) == 10000
    assert token.balanceOf(tester.a1) == 0
    assert token.transfer(tester.a1, 5000) is True
    assert token.balanceOf(tester.a0) == 5000
    assert token.balanceOf(tester.a1) == 5000

    # test global variables
    assert channel.settleTimeout() == 30
    assert channel.assetAddress() == token.address.encode('hex')
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

    nonce = 1
    asset = token.address
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

    msg2 = DirectTransfer(
        2,  # nonce
        token.address,  # asset
        3,  # transfered_amount
        tester.a0,  # recipient
        locksroot,
    )
    msg2.sign(tester.k1)
    packed = msg2.packed()
    direct_transfer2 = str(packed.data)

    channel.close(direct_transfer1, direct_transfer2)

    assert len(events) == 1
    assert events[0]['_event_type'] == 'ChannelClosed'
    assert events[0]['closingAddress'] == tester.a0.encode('hex')
    assert events[0]['blockNumber'] == state.block.number

    with pytest.raises(TransactionFailed):
        # not participant
        channel.close(
            direct_transfer1,
            direct_transfer2,
            sender=tester.k2
        )

    # Test with message sender tester.a0
    assert channel.closed() == state.block.number
    assert channel.closingAddress() == tester.a0.encode('hex')
    # assert channel.participants(0)[10] == 1
    # assert channel.participants(0)[11] == token.address.encode('hex')
    # assert channel.participants(0)[9] == tester.a0.encode('hex')
    # assert channel.participants(0)[12] == tester.a1.encode('hex')
    # assert channel.participants(0)[3] == 1
    # assert channel.participants(0)[13] == locksroot1
    # assert channel.participants(0)[7] == '\x00' * 32

    # Test with message sender tester.a1
    assert channel.closed() == state.block.number
    assert channel.closingAddress() == tester.a0.encode('hex')
    # assert channel.participants(1)[10] == 2
    # assert channel.participants(1)[11] == token.address.encode('hex')
    # assert channel.participants(1)[9] == tester.a1.encode('hex')
    # assert channel.participants(1)[12] == tester.a0.encode('hex')
    # assert channel.participants(1)[3] == 3
    # assert channel.participants(1)[13] == locksroot2
    # assert channel.participants(1)[7] == '\x00' * 32


def test_two_messages_mediated_transfer(state, token, channel, events):
    # test tokens and distribute tokens
    assert token.balanceOf(tester.a0) == 10000
    assert token.balanceOf(tester.a1) == 0
    assert token.transfer(tester.a1, 5000) is True
    assert token.balanceOf(tester.a0) == 5000
    assert token.balanceOf(tester.a1) == 5000

    # test global variables
    assert channel.settleTimeout() == 30
    assert channel.assetAddress() == token.address.encode('hex')
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
    asset = token.address
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
    asset = token.address
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
    assert channel.closed() == state.block.number
    assert channel.closingAddress() == tester.a0.encode('hex')
    # assert channel.participants(0)[10] == 1
    # assert channel.participants(0)[11] == token.address.encode('hex')
    # assert channel.participants(0)[9] == tester.a0.encode('hex')
    # assert channel.participants(0)[12] == tester.a1.encode('hex')
    # assert channel.participants(0)[3] == 1
    # assert channel.participants(0)[13] == locksroot1
    # assert channel.participants(0)[7] == '\x00' * 32

    # Test with message sender tester.a1
    assert channel.closed() == state.block.number
    assert channel.closingAddress() == tester.a0.encode('hex')
    # assert channel.participants(1)[10] == 2
    # assert channel.participants(1)[11] == token.address.encode('hex')
    # assert channel.participants(1)[9] == tester.a1.encode('hex')
    # assert channel.participants(1)[12] == tester.a0.encode('hex')
    # assert channel.participants(1)[3] == 3
    # assert channel.participants(1)[13] == locksroot2
    # assert channel.participants(1)[7] == '\x00' * 32


@pytest.mark.parametrize('asset_amount', [100])
def test_all_asset(asset_amount, state, channel, token, events):
    half_amount = asset_amount / 2
    assert token.transfer(tester.a1, half_amount) is True

    token1 = ABIContract(
        state,
        token.translator,
        token.address,
        default_key=tester.k1,
    )
    assert token.approve(channel.address, half_amount) is True
    assert token1.approve(channel.address, half_amount) is True

    channel1 = ABIContract(
        state,
        channel.translator,
        channel.address,
        default_key=tester.k1,
    )
    channel.deposit(half_amount)
    channel1.deposit(half_amount)

    _, deposit1, _, deposit2 = channel.addressAndBalance()

    assert deposit1 == half_amount
    assert deposit2 == half_amount

    assert token.balanceOf(channel.address) == asset_amount
    assert token.balanceOf(tester.a0) == 0
    assert token.balanceOf(tester.a1) == 0


def test_update_direct_transfer(state, token, channel, events):
    # test tokens and distribute tokens
    assert token.balanceOf(tester.a0) == 10000
    assert token.balanceOf(tester.a1) == 0
    assert token.transfer(tester.a1, 5000) is True
    assert token.balanceOf(tester.a0) == 5000
    assert token.balanceOf(tester.a1) == 5000

    # test global variables
    assert channel.settleTimeout() == 30
    assert channel.assetAddress() == token.address.encode('hex')
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

    nonce = 1
    asset = token.address
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

    msg2 = DirectTransfer(
        2,  # nonce
        token.address,  # asset
        3,  # transfered_amount
        tester.a0,  # recipient
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
    assert channel.closed() == state.block.number
    assert channel.closingAddress() == tester.a0.encode('hex')
    # assert channel.participants(0)[10] == 1
    # assert channel.participants(0)[11] == token.address.encode('hex')
    # assert channel.participants(0)[9] == tester.a0.encode('hex')
    # assert channel.participants(0)[12] == tester.a1.encode('hex')
    # assert channel.participants(0)[3] == 1
    # assert channel.participants(0)[13] == locksroot1
    # assert channel.participants(0)[7] == '\x00' * 32

    # Test with message sender tester.a1
    assert channel.closed() == state.block.number
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

    msg3 = DirectTransfer(
        3,  # nonce
        token.address,  # asset
        5,  # transfered_amount
        tester.a0,  # recipient
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

    msg4 = DirectTransfer(
        1,  # nonce
        token.address,  # asset
        5,  # transfered_amount
        tester.a0,  # recipient
        locksroot,
    )
    msg4.sign(tester.k1)
    packed = msg4.packed()
    direct_transfer4 = str(packed.data)

    # nonce too low
    with pytest.raises(TransactionFailed):
        channel.updateTransfer(direct_transfer4, sender=tester.k1)

    # settleTimeout overdue
    state.block.number = 1158041

    with pytest.raises(TransactionFailed):
        channel.updateTransfer(direct_transfer3, sender=tester.k1)

    assert len(events) == 1
    assert events[0]['_event_type'] == 'ChannelClosed'
    assert events[0]['blockNumber'] == 1158002
    assert events[0]['closingAddress'] == tester.a0.encode('hex')


def test_update_mediated_transfer(state, token, channel, events):
    # test tokens and distribute tokens
    assert token.balanceOf(tester.a0) == 10000
    assert token.balanceOf(tester.a1) == 0
    assert token.transfer(tester.a1, 5000) is True
    assert token.balanceOf(tester.a0) == 5000
    assert token.balanceOf(tester.a1) == 5000

    # test global variables
    assert channel.settleTimeout() == 30
    assert channel.assetAddress() == token.address.encode('hex')
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
    asset = token.address
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
    asset = token.address
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
    assert channel.closed() == state.block.number
    assert channel.closingAddress() == tester.a0.encode('hex')
    # assert channel.participants(0)[10] == 1
    # assert channel.participants(0)[11] == token.address.encode('hex')
    # assert channel.participants(0)[9] == tester.a0.encode('hex')
    # assert channel.participants(0)[12] == tester.a1.encode('hex')
    # assert channel.participants(0)[3] == 1
    # assert channel.participants(0)[13] == locksroot1
    # assert channel.participants(0)[7] == '\x00' * 32

    # Test with message sender tester.a1
    assert channel.closed() == state.block.number
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
    asset = token.address
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

    msg4 = DirectTransfer(
        1,  # nonce
        token.address,  # asset
        5,  # transfered_amount
        tester.a0,  # recipient
        locksroot,
    )
    msg4.sign(tester.k1)
    packed = msg4.packed()
    direct_transfer4 = str(packed.data)

    # nonce too low
    with pytest.raises(TransactionFailed):
        channel.updateTransfer(direct_transfer4, sender=tester.k1)

    # settleTimeout overdue
    state.block.number = 1158041

    with pytest.raises(TransactionFailed):
        channel.updateTransfer(mediated_transfer3, sender=tester.k1)

    assert len(events) == 1
    assert events[0]['_event_type'] == 'ChannelClosed'
    assert events[0]['blockNumber'] == 1158002
    assert events[0]['closingAddress'] == tester.a0.encode('hex')


def test_unlock(token, channel, events, state):
    secret1 = 'x' * 32
    hashlock1 = sha3(secret1)
    lock_amount1 = 29
    lock_expiration1 = 1158003
    lock1 = Lock(lock_amount1, lock_expiration1, hashlock1)
    lockhash1 = sha3(lock1.as_bytes)
    merkleproof1 = [lockhash1]
    locksroot1 = merkleroot([lockhash1,], merkleproof1)

    nonce = 10
    asset = token.address
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
    locksroot2 = merkleroot([lockhash2,], merkleproof2)

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

    # TODO: it must not be possible to unlock the same lock twive
    # with pytest.raises(TransactionFailed):
        # channel.unlock(
            # str(lock1.as_bytes),
            # ''.join(merkleproof1),
            # secret1,
        # )

    # expiration has passed, should fail
    state.block.number = 1158031
    with pytest.raises(TransactionFailed):
        channel.unlock(
            str(lock2.as_bytes),
            ''.join(merkleproof2),
            secret2,
        )


@pytest.mark.parametrize('asset_amount', [100])
def test_settle(state, channel, token, asset_amount, events):
    half_amount = asset_amount / 2
    assert token.transfer(tester.a1, half_amount) is True

    token1 = ABIContract(
        state,
        token.translator,
        token.address,
        default_key=tester.k1,
    )
    assert token.approve(channel.address, half_amount) is True
    assert token1.approve(channel.address, half_amount) is True

    channel1 = ABIContract(
        state,
        channel.translator,
        channel.address,
        default_key=tester.k1,
    )
    channel.deposit(half_amount)
    channel1.deposit(half_amount)

    secret1 = 'x' * 32
    hashlock1 = sha3(secret1)
    lock_amount1 = 29
    lock_expiration1 = 31
    lock1 = Lock(lock_amount1, lock_expiration1, hashlock1)
    lockhash1 = sha3(lock1.as_bytes)
    merkleproof1 = [lockhash1]
    locksroot1 = merkleroot([lockhash1], merkleproof1)

    nonce1 = 1
    asset = token.address
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
    lock_expiration2 = 31
    lock2 = Lock(lock_amount2, lock_expiration2, hashlock2)
    lockhash2 = sha3(lock2.as_bytes)
    merkleproof2 = [lockhash2]
    locksroot2 = merkleroot([lockhash2], merkleproof2)

    locksroot = locksroot2
    nonce2 = 2
    transfered_amount2 = 3

    msg2 = DirectTransfer(
        nonce2,
        token.address,  # asset
        transfered_amount2,
        tester.a0,  # recipient
        locksroot,
    )
    msg2.sign(tester.k1)
    packed = msg2.packed()
    direct_transfer2 = str(packed.data)

    # not yet closed. should fail
    with pytest.raises(TransactionFailed):
        channel.settle()

    channel.close(direct_transfer1, direct_transfer2)

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

    channel.settle()

    balance1 = half_amount + (transfered_amount2 - transfered_amount1) + lock_amount1 - lock_amount2
    balance2 = half_amount + (transfered_amount1 - transfered_amount2) - lock_amount1 + lock_amount2
    assert token.balanceOf(tester.a0) == balance1
    assert token.balanceOf(tester.a1) == balance2

    # can settle only once
    with pytest.raises(TransactionFailed):
        channel.settle()

    assert len(events) == 6
    assert events[0]['_event_type'] == 'ChannelNewBalance'
    assert events[0]['assetAddress'] == token.address.encode('hex')
    assert events[0]['participant'] == tester.a0.encode('hex')
    assert events[0]['balance'] == 50
    assert events[1]['_event_type'] == 'ChannelNewBalance'
    assert events[1]['assetAddress'] == token.address.encode('hex')
    assert events[1]['participant'] == tester.a1.encode('hex')
    assert events[1]['balance'] == 50
    assert events[2]['_event_type'] == 'ChannelClosed'
    assert events[2]['closingAddress'] == tester.a0.encode('hex')
    assert events[2]['blockNumber'] == state.block.number
    assert events[3]['_event_type'] == 'ChannelSecretRevealed'
    assert events[3]['secret'] == 'x' * 32
    assert events[4]['_event_type'] == 'ChannelSecretRevealed'
    assert events[4]['secret'] == 'y' * 32
    assert events[5]['_event_type'] == 'ChannelSettled'
    assert events[5]['blockNumber'] == state.block.number
