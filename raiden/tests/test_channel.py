# -*- coding: utf8 -*-
import pytest
from ethereum import slogging

from raiden.channel import Channel, ChannelEndState, ChannelExternalState
from raiden.messages import Lock, LockedTransfer
from raiden.utils import sha3, make_address, make_privkey_address

log = slogging.getLogger(__name__)  # pylint: disable=invalid-name
slogging.configure(':DEBUG')


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
