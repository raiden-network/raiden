# -*- coding: utf-8 -*-
from __future__ import division

import pytest
from ethereum import abi, tester, slogging
from ethereum.tester import TransactionFailed
from ethereum.utils import encode_hex
from secp256k1 import PrivateKey

from raiden.encoding.signing import GLOBAL_CTX
from raiden.raiden_service import DEFAULT_REVEAL_TIMEOUT
from raiden.utils import sha3, privatekey_to_address
from raiden.tests.utils.tester import (
    new_channelmanager,
    new_nettingcontract,
)

log = slogging.getLogger(__name__)  # pylint: disable=invalid-name


def test_channeldeposit(private_keys, settle_timeout, tester_state,
                        tester_token, tester_events, tester_registry):
    """ Guarantee the correct tracking of each participant deposits, checks the
    initial state (pre-deposit) and state changes for each deposits.
    """

    # not using the tester_nettingcontracts fixture to control the
    # transfer/deposits

    privatekey0 = private_keys[0]
    privatekey1 = private_keys[1]
    address0 = privatekey_to_address(privatekey0)
    address1 = privatekey_to_address(privatekey1)
    unknow_key = tester.k3

    channel_manager = new_channelmanager(
        privatekey0,
        tester_state,
        tester_events.append,
        tester_registry,
        tester_token,
    )

    channel = new_nettingcontract(
        privatekey0,
        privatekey1,
        tester_state,
        tester_events.append,
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

    initial_balance0 = tester_token.balanceOf(address0, sender=privatekey0)
    deposit_amount = initial_balance0 // 10

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
    assert tester_token.balanceOf(address0, sender=privatekey0) == initial_balance0 - deposit_amount  # noqa
    assert channel.opened(sender=privatekey0) == tester_state.block.number

    assert channel.addressAndBalance(sender=privatekey0)[0] == encode_hex(address0)
    assert channel.addressAndBalance(sender=privatekey0)[1] == deposit_amount
    assert channel.addressAndBalance(sender=privatekey0)[2] == encode_hex(address1)
    assert channel.addressAndBalance(sender=privatekey0)[3] == 0

    # check a second depoist with the rest of the allowance
    assert channel.deposit(deposit_amount, sender=privatekey0) is True

    assert tester_token.balanceOf(channel.address, sender=privatekey0) == deposit_amount * 2
    assert tester_token.balanceOf(address0, sender=privatekey0) == initial_balance0 - deposit_amount * 2  # noqa
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
    assert tester_token.balanceOf(address0, sender=privatekey0) == initial_balance0 - deposit_amount * 3  # noqa
    assert channel.opened(sender=privatekey0) == tester_state.block.number

    assert channel.addressAndBalance(sender=privatekey0)[0] == encode_hex(address0)
    assert channel.addressAndBalance(sender=privatekey0)[1] == deposit_amount * 3
    assert channel.addressAndBalance(sender=privatekey0)[2] == encode_hex(address1)
    assert channel.addressAndBalance(sender=privatekey0)[3] == 0


def test_channelnewbalance_event(private_keys, settle_timeout, tester_state,
                                 tester_events, tester_token, tester_registry):
    """ Check the correct events are generated for deposit calls. """

    privatekey0 = private_keys[0]
    privatekey1 = private_keys[1]
    address0 = privatekey_to_address(privatekey0)
    address1 = privatekey_to_address(privatekey1)

    channel_manager = new_channelmanager(
        privatekey0,
        tester_state,
        tester_events.append,
        tester_registry,
        tester_token,
    )

    nettingchannel = new_nettingcontract(
        privatekey0,
        privatekey1,
        tester_state,
        tester_events.append,
        channel_manager,
        settle_timeout,
    )

    initial_balance0 = tester_token.balanceOf(address0, sender=privatekey0)
    deposit_amount = initial_balance0 // 10

    assert tester_token.approve(nettingchannel.address, deposit_amount, sender=privatekey0) is True
    assert tester_token.approve(nettingchannel.address, deposit_amount, sender=privatekey1) is True

    previous_events = list(tester_events)
    assert nettingchannel.deposit(deposit_amount, sender=privatekey0) is True
    assert len(previous_events) + 2 == len(tester_events)

    block_number = tester_state.block.number

    transfer_event = tester_events[-2]
    assert transfer_event == {
        '_event_type': 'Transfer',
        '_from': encode_hex(address0),
        '_to': nettingchannel.address,
        '_value': deposit_amount,
    }

    newbalance_event = tester_events[-1]
    assert newbalance_event == {
        '_event_type': 'ChannelNewBalance',
        'asset_address': encode_hex(tester_token.address),
        'participant': encode_hex(address0),
        'balance': deposit_amount,
        'block_number': block_number,
    }

    previous_events = list(tester_events)
    assert nettingchannel.deposit(deposit_amount, sender=privatekey1) is True
    assert len(previous_events) + 2 == len(tester_events)

    block_number = tester_state.block.number

    transfer_event = tester_events[-2]
    assert transfer_event == {
        '_event_type': 'Transfer',
        '_from': encode_hex(address1),
        '_to': nettingchannel.address,
        '_value': deposit_amount,
    }

    newbalance_event = tester_events[-1]
    assert newbalance_event == {
        '_event_type': 'ChannelNewBalance',
        'asset_address': encode_hex(tester_token.address),
        'participant': encode_hex(address1),
        'balance': deposit_amount,
        'block_number': block_number,
    }


def test_closewithouttransfer_settle(
        deposit,
        settle_timeout,
        tester_state,
        tester_events,
        tester_nettingcontracts,
        tester_token):

    privatekey0, privatekey1, nettingchannel = tester_nettingcontracts[0]
    address0 = privatekey_to_address(privatekey0)
    address1 = privatekey_to_address(privatekey1)
    unknown_key = tester.k3

    initial_balance0 = tester_token.balanceOf(address0, sender=privatekey0)
    initial_balance1 = tester_token.balanceOf(address1, sender=privatekey1)

    with pytest.raises(TransactionFailed):
        nettingchannel.closeWithoutTransfer(sender=unknown_key)

    previous_events = list(tester_events)
    nettingchannel.closeWithoutTransfer(sender=privatekey0)
    assert len(previous_events) + 1 == len(tester_events)

    block_number = tester_state.block.number

    close_event = tester_events[-1]
    assert close_event == {
        '_event_type': 'ChannelClosed',
        'closing_address': encode_hex(address0),
        'block_number': block_number,
    }

    assert nettingchannel.closed(sender=privatekey0) == block_number
    assert nettingchannel.closingAddress(sender=privatekey0) == encode_hex(address0)

    tester_state.mine(number_of_blocks=settle_timeout + 1)

    previous_events = list(tester_events)
    # Anyone can call settle(), not just channel participants
    nettingchannel.settle(sender=unknown_key)
    block_number = tester_state.block.number

    assert len(previous_events) + 3 == len(tester_events)

    transfer0_event = tester_events[-3]
    assert transfer0_event == {
        '_event_type': 'Transfer',
        '_from': nettingchannel.address,
        '_to': encode_hex(address1),
        '_value': deposit,
    }

    transfer1_event = tester_events[-2]
    assert transfer1_event == {
        '_event_type': 'Transfer',
        '_from': nettingchannel.address,
        '_to': encode_hex(address0),
        '_value': deposit,
    }

    settle_event = tester_events[-1]
    assert settle_event == {
        '_event_type': 'ChannelSettled',
        'block_number': block_number,
    }

    assert tester_token.balanceOf(address0, sender=privatekey0) == initial_balance0 + deposit
    assert tester_token.balanceOf(address1, sender=privatekey1) == initial_balance1 + deposit
    assert tester_token.balanceOf(nettingchannel.address, sender=privatekey1) == 0


@pytest.mark.parametrize('both_participants_deposit', [False])
@pytest.mark.parametrize('deposit', [100])
def test_closewithouttransfer_badalice(
        deposit,
        settle_timeout,
        tester_state,
        tester_events,
        tester_channels,
        tester_token):
    privatekeyA_raw, privatekeyB_raw, nettingchannel, channelAB, channelBA = tester_channels[0]
    privatekeyA = PrivateKey(privatekeyA_raw, ctx=GLOBAL_CTX, raw=True)
    privatekeyB = PrivateKey(privatekeyB_raw, ctx=GLOBAL_CTX, raw=True)
    addressA = privatekey_to_address(privatekeyA_raw)
    addressB = privatekey_to_address(privatekeyB_raw)

    initial_balanceA = tester_token.balanceOf(addressA, sender=privatekeyA_raw)
    initial_balanceB = tester_token.balanceOf(addressB, sender=privatekeyB_raw)

    transfer_amount = 50
    AB_Transfer0 = channelAB.create_directtransfer(
        transfer_amount,
        1  # TODO: fill in identifier
    )
    AB_Transfer0.sign(privatekeyA, addressA)
    channelAB.register_transfer(AB_Transfer0)
    channelBA.register_transfer(AB_Transfer0)

    transfer_amount = 40
    BA_Transfer0 = channelBA.create_directtransfer(
        transfer_amount,
        1  # TODO: fill in identifier
    )
    BA_Transfer0.sign(privatekeyB, addressB)
    channelAB.register_transfer(BA_Transfer0)
    channelBA.register_transfer(BA_Transfer0)

    transfer_amount = 90
    AB_Transfer1 = channelAB.create_directtransfer(
        transfer_amount,
        1  # TODO: fill in identifier
    )
    AB_Transfer1.sign(privatekeyA, addressA)
    channelAB.register_transfer(AB_Transfer1)
    channelBA.register_transfer(AB_Transfer1)
    AB_Transfer1_data = str(AB_Transfer1.packed().data)

    nettingchannel.closeWithoutTransfer(sender=privatekeyA_raw)

    nettingchannel.updateTransfer(
        AB_Transfer1_data,
        sender=privatekeyB_raw,
    )

    tester_state.mine(number_of_blocks=settle_timeout + 1)
    nettingchannel.settle(sender=privatekeyB_raw)
    tester_state.mine(number_of_blocks=2)

    assert tester_token.balanceOf(nettingchannel.address, sender=privatekeyA_raw) == 0
    assert tester_token.balanceOf(addressB, sender=privatekeyA_raw) == initial_balanceB + 100
    assert tester_token.balanceOf(addressA, sender=privatekeyA_raw) == initial_balanceA + deposit - 100


def test_closesingle_settle(
        deposit,
        settle_timeout,
        tester_channels,
        tester_state,
        tester_events,
        tester_token):

    privatekey0_raw, privatekey1_raw, nettingchannel, channel0, channel1 = tester_channels[0]

    privatekey0 = PrivateKey(privatekey0_raw, ctx=GLOBAL_CTX, raw=True)
    address0 = privatekey_to_address(privatekey0_raw)
    address1 = privatekey_to_address(privatekey1_raw)
    unknown_key = tester.k3

    initial_balance0 = tester_token.balanceOf(address0, sender=privatekey0_raw)
    initial_balance1 = tester_token.balanceOf(address1, sender=privatekey1_raw)

    transfer_amount = 10
    direct_transfer = channel0.create_directtransfer(
        transfer_amount,
        1  # TODO: fill in identifier
    )
    direct_transfer.sign(privatekey0, address0)
    direct_transfer_data = str(direct_transfer.packed().data)

    with pytest.raises(TransactionFailed):
        nettingchannel.closeSingleTransfer(sender=unknown_key)

    previous_events = list(tester_events)
    nettingchannel.closeSingleTransfer(direct_transfer_data, sender=privatekey1_raw)
    assert len(previous_events) + 1 == len(tester_events)

    block_number = tester_state.block.number

    close_event = tester_events[-1]
    assert close_event == {
        '_event_type': 'ChannelClosed',
        'closing_address': encode_hex(address1),
        'block_number': block_number,
    }

    assert nettingchannel.closed(sender=privatekey0_raw) == block_number
    assert nettingchannel.closingAddress(sender=privatekey0_raw) == encode_hex(address1)

    tester_state.mine(number_of_blocks=settle_timeout + 1)

    previous_events = list(tester_events)
    nettingchannel.settle(sender=privatekey0_raw)
    assert len(previous_events) + 3 == len(tester_events)

    block_number = tester_state.block.number

    transfer0_event = tester_events[-3]
    assert transfer0_event == {
        '_event_type': 'Transfer',
        '_from': nettingchannel.address,
        '_to': encode_hex(address0),
        '_value': deposit - transfer_amount,
    }

    transfer1_event = tester_events[-2]
    assert transfer1_event == {
        '_event_type': 'Transfer',
        '_from': nettingchannel.address,
        '_to': encode_hex(address1),
        '_value': deposit + transfer_amount,
    }

    settle_event = tester_events[-1]
    assert settle_event == {
        '_event_type': 'ChannelSettled',
        'block_number': block_number,
    }

    assert tester_token.balanceOf(address0, sender=privatekey0_raw) == initial_balance0 + deposit - transfer_amount  # noqa
    assert tester_token.balanceOf(address1, sender=privatekey1_raw) == initial_balance1 + deposit + transfer_amount  # noqa
    assert tester_token.balanceOf(nettingchannel.address, sender=privatekey1_raw) == 0


def test_close_settle(
        deposit,
        settle_timeout,
        tester_state,
        tester_channels,
        tester_events,
        tester_token):

    privatekey0_raw, privatekey1_raw, nettingchannel, channel0, channel1 = tester_channels[0]
    privatekey0 = PrivateKey(privatekey0_raw, ctx=GLOBAL_CTX, raw=True)
    privatekey1 = PrivateKey(privatekey1_raw, ctx=GLOBAL_CTX, raw=True)
    address0 = privatekey_to_address(privatekey0_raw)
    address1 = privatekey_to_address(privatekey1_raw)
    unknown_key = tester.k3

    initial_balance0 = tester_token.balanceOf(address0, sender=privatekey0_raw)
    initial_balance1 = tester_token.balanceOf(address1, sender=privatekey1_raw)

    transfer_amount0 = 10
    direct_transfer0 = channel0.create_directtransfer(
        transfer_amount0,
        1  # TODO: fill in identifier
    )
    direct_transfer0.sign(privatekey0, address0)

    transfer_amount1 = 30
    direct_transfer1 = channel1.create_directtransfer(
        transfer_amount1,
        1  # TODO: fill in identifier
    )
    direct_transfer1.sign(privatekey1, address1)

    # random people can't close the channel
    with pytest.raises(TransactionFailed):
        nettingchannel.close(
            str(direct_transfer0.packed().data),
            str(direct_transfer1.packed().data),
            sender=unknown_key,
        )
    # the closing party should be the one that provides the first transfer
    with pytest.raises(TransactionFailed):
        nettingchannel.close(
            str(direct_transfer0.packed().data),
            str(direct_transfer1.packed().data),
            sender=privatekey0_raw,
        )

    previous_events = list(tester_events)
    nettingchannel.close(
        str(direct_transfer0.packed().data),
        str(direct_transfer1.packed().data),
        sender=privatekey1_raw,
    )
    assert len(previous_events) + 1 == len(tester_events)

    block_number = tester_state.block.number

    close_event = tester_events[-1]
    assert close_event == {
        '_event_type': 'ChannelClosed',
        'closing_address': encode_hex(address1),
        'block_number': block_number,
    }

    assert nettingchannel.closed(sender=privatekey0_raw) == block_number
    assert nettingchannel.closingAddress(sender=privatekey0_raw) == encode_hex(address1)

    tester_state.mine(number_of_blocks=settle_timeout + 1)

    previous_events = list(tester_events)
    nettingchannel.settle(sender=privatekey0_raw)
    assert len(previous_events) + 3 == len(tester_events)

    block_number = tester_state.block.number

    transfer0_event = tester_events[-3]
    assert transfer0_event == {
        '_event_type': 'Transfer',
        '_from': nettingchannel.address,
        '_to': encode_hex(address0),
        '_value': deposit - transfer_amount0 + transfer_amount1,
    }

    transfer1_event = tester_events[-2]
    assert transfer1_event == {
        '_event_type': 'Transfer',
        '_from': nettingchannel.address,
        '_to': encode_hex(address1),
        '_value': deposit + transfer_amount0 - transfer_amount1,
    }

    settle_event = tester_events[-1]
    assert settle_event == {
        '_event_type': 'ChannelSettled',
        'block_number': block_number,
    }

    assert tester_token.balanceOf(address0, sender=privatekey0_raw) == initial_balance0 + deposit - transfer_amount0 + transfer_amount1  # noqa
    assert tester_token.balanceOf(address1, sender=privatekey1_raw) == initial_balance1 + deposit + transfer_amount0 - transfer_amount1  # noqa
    assert tester_token.balanceOf(nettingchannel.address, sender=privatekey1_raw) == 0


def test_two_messages_mediated_transfer(deposit, settle_timeout, tester_state,
                                        tester_channels, tester_token,
                                        tester_events):

    privatekey0_raw, privatekey1_raw, nettingchannel, channel0, channel1 = tester_channels[0]
    privatekey0 = PrivateKey(privatekey0_raw, ctx=GLOBAL_CTX, raw=True)
    privatekey1 = PrivateKey(privatekey1_raw, ctx=GLOBAL_CTX, raw=True)
    address0 = privatekey_to_address(privatekey0_raw)
    address1 = privatekey_to_address(privatekey1_raw)
    unknown_key = tester.k3

    initial_balance0 = tester_token.balanceOf(address0, sender=privatekey0_raw)
    initial_balance1 = tester_token.balanceOf(address1, sender=privatekey1_raw)

    lock_amount0 = 29
    lock_expiration0 = tester_state.block.number + DEFAULT_REVEAL_TIMEOUT + 3
    hashlock0 = sha3(tester.k0)

    mediated_transfer0 = channel0.create_mediatedtransfer(
        transfer_initiator=address0,
        transfer_target=address1,
        fee=0,
        amount=lock_amount0,
        identifier=1,  # TODO: fill in identifier
        expiration=lock_expiration0,
        hashlock=hashlock0,
    )
    mediated_transfer0.sign(privatekey0, address0)

    lock_amount1 = 29
    lock_expiration1 = tester_state.block.number + DEFAULT_REVEAL_TIMEOUT + 5
    hashlock1 = sha3(tester.k1)

    mediated_transfer1 = channel1.create_mediatedtransfer(
        transfer_initiator=address1,
        transfer_target=address0,
        fee=0,
        amount=lock_amount1,
        identifier=1,  # TODO: fill in identifier
        expiration=lock_expiration1,
        hashlock=hashlock1,
    )
    mediated_transfer1.sign(privatekey1, address1)

    with pytest.raises(TransactionFailed):
        nettingchannel.close(
            str(mediated_transfer0.packed().data),
            str(mediated_transfer1.packed().data),
            sender=unknown_key,
        )

    previous_events = list(tester_events)
    nettingchannel.close(
        str(mediated_transfer0.packed().data),
        str(mediated_transfer1.packed().data),
        sender=privatekey1_raw,
    )
    assert len(previous_events) + 1 == len(tester_events)

    block_number = tester_state.block.number

    close_event = tester_events[-1]
    assert close_event == {
        '_event_type': 'ChannelClosed',
        'closing_address': encode_hex(address1),
        'block_number': block_number,
    }
    assert nettingchannel.closed(sender=privatekey0_raw) == block_number
    assert nettingchannel.closingAddress(sender=privatekey0_raw) == encode_hex(address1)

    tester_state.mine(number_of_blocks=settle_timeout + 1)

    previous_events = list(tester_events)
    nettingchannel.settle(sender=privatekey0_raw)
    block_number = tester_state.block.number

    assert len(previous_events) + 3 == len(tester_events)

    transfer0_event = tester_events[-3]
    assert transfer0_event == {
        '_event_type': 'Transfer',
        '_from': nettingchannel.address,
        '_to': encode_hex(address0),
        '_value': deposit,
    }

    transfer1_event = tester_events[-2]
    assert transfer1_event == {
        '_event_type': 'Transfer',
        '_from': nettingchannel.address,
        '_to': encode_hex(address1),
        '_value': deposit,
    }

    settle_event = tester_events[-1]
    assert settle_event == {
        '_event_type': 'ChannelSettled',
        'block_number': block_number,
    }

    assert tester_token.balanceOf(address0, sender=privatekey0_raw) == initial_balance0 + deposit  # noqa
    assert tester_token.balanceOf(address1, sender=privatekey1_raw) == initial_balance1 + deposit  # noqa
    assert tester_token.balanceOf(nettingchannel.address, sender=privatekey1_raw) == 0


def test_update_direct_transfer(settle_timeout, tester_state, tester_channels, tester_events):
    privatekey0_raw, privatekey1_raw, nettingchannel, channel0, channel1 = tester_channels[0]
    privatekey0 = PrivateKey(privatekey0_raw, ctx=GLOBAL_CTX, raw=True)
    privatekey1 = PrivateKey(privatekey1_raw, ctx=GLOBAL_CTX, raw=True)
    address0 = privatekey_to_address(privatekey0_raw)
    address1 = privatekey_to_address(privatekey1_raw)

    transfer_amount = 3
    first_direct_transfer0 = channel0.create_directtransfer(
        transfer_amount,
        1  # TODO: fill in identifier
    )
    first_direct_transfer0.sign(privatekey0, address0)
    first_direct_transfer0_data = str(first_direct_transfer0.packed().data)

    channel0.register_transfer(first_direct_transfer0)
    channel1.register_transfer(first_direct_transfer0)

    transfer_amount = 5
    second_direct_transfer0 = channel0.create_directtransfer(
        transfer_amount,
        1  # TODO: fill in identifier
    )
    second_direct_transfer0.sign(privatekey0, address0)
    second_direct_transfer0_data = str(second_direct_transfer0.packed().data)

    channel0.register_transfer(second_direct_transfer0)
    channel1.register_transfer(second_direct_transfer0)

    transfer_amount = 7
    third_direct_transfer0 = channel0.create_directtransfer(
        transfer_amount,
        1  # TODO: fill in identifier
    )
    third_direct_transfer0.sign(privatekey0, address0)
    third_direct_transfer0_data = str(third_direct_transfer0.packed().data)

    channel0.register_transfer(third_direct_transfer0)
    channel1.register_transfer(third_direct_transfer0)

    transfer_amount = 11
    fourth_direct_transfer0 = channel0.create_directtransfer(
        transfer_amount,
        1  # TODO: fill in identifier
    )
    fourth_direct_transfer0.sign(privatekey0, address0)
    fourth_direct_transfer0_data = str(fourth_direct_transfer0.packed().data)

    channel0.register_transfer(fourth_direct_transfer0)
    channel1.register_transfer(fourth_direct_transfer0)

    transfer_amount = 13
    direct_transfer1 = channel1.create_directtransfer(
        transfer_amount,
        1  # TODO: fill in identifier
    )
    direct_transfer1.sign(privatekey1, address1)
    direct_transfer1_data = str(direct_transfer1.packed().data)

    channel0.register_transfer(direct_transfer1)
    channel1.register_transfer(direct_transfer1)

    # not yet closed
    with pytest.raises(TransactionFailed):
        nettingchannel.updateTransfer(
            second_direct_transfer0_data,
            sender=privatekey0_raw,
        )

    nettingchannel.close(
        second_direct_transfer0_data,
        direct_transfer1_data,
        sender=privatekey1_raw,
    )

    # who closes the channel cannot call updateTransfer
    with pytest.raises(TransactionFailed):
        nettingchannel.updateTransfer(
            third_direct_transfer0_data,
            sender=privatekey1_raw,
        )

    # nonce too low
    with pytest.raises(TransactionFailed):
        nettingchannel.updateTransfer(
            first_direct_transfer0_data,
            sender=privatekey0_raw,
        )

    nettingchannel.updateTransfer(
        third_direct_transfer0_data,
        sender=privatekey0_raw,
    )

    transfer1_event = tester_events[-1]
    assert transfer1_event == {
        '_event_type': 'TransferUpdated',
        'node_address': address1.encode('hex'),
        'block_number': tester_state.block.number,
    }

    tester_state.mine(number_of_blocks=settle_timeout + 1)

    # settle time passed
    with pytest.raises(TransactionFailed):
        nettingchannel.updateTransfer(
            fourth_direct_transfer0_data,
            sender=privatekey0_raw,
        )

    # TODO:
    # - asert the resulting balances correspond to the updated trnasfer
    # - assert that Transfer and Settle events are correct
    # - change the hashroot and check older locks are not freed
    # - add locked amounts and assert that they are respected


def test_update_mediated_transfer(settle_timeout, tester_state, tester_channels, tester_events):
    privatekey0_raw, privatekey1_raw, nettingchannel, channel0, channel1 = tester_channels[0]
    privatekey0 = PrivateKey(privatekey0_raw, ctx=GLOBAL_CTX, raw=True)
    privatekey1 = PrivateKey(privatekey1_raw, ctx=GLOBAL_CTX, raw=True)
    address0 = privatekey_to_address(privatekey0_raw)
    address1 = privatekey_to_address(privatekey1_raw)

    transfer_amount = 3
    direct_transfer0 = channel0.create_directtransfer(
        transfer_amount,
        1  # TODO: fill in identifier
    )
    direct_transfer0.sign(privatekey0, address0)
    direct_transfer0_data = str(direct_transfer0.packed().data)

    channel0.register_transfer(direct_transfer0)
    channel1.register_transfer(direct_transfer0)

    target = tester.a0
    initiator = tester.a1
    lock_amount = 5
    lock_expiration = tester_state.block.number + DEFAULT_REVEAL_TIMEOUT + 3
    lock_hashlock = sha3('secret')
    mediated_transfer0 = channel0.create_mediatedtransfer(
        transfer_initiator=initiator,
        transfer_target=target,
        fee=0,
        amount=lock_amount,
        identifier=1,  # TODO: fill in identifier
        expiration=lock_expiration,
        hashlock=lock_hashlock,
    )
    mediated_transfer0.sign(privatekey0, address0)
    mediated_transfer0_data = str(mediated_transfer0.packed().data)

    channel0.register_transfer(mediated_transfer0)
    channel1.register_transfer(mediated_transfer0)

    transfer_amount = 13
    direct_transfer1 = channel1.create_directtransfer(
        transfer_amount,
        1  # TODO: fill in identifier
    )
    direct_transfer1.sign(privatekey1, address1)
    direct_transfer1_data = str(direct_transfer1.packed().data)

    channel0.register_transfer(direct_transfer1)
    channel1.register_transfer(direct_transfer1)

    nettingchannel.close(
        direct_transfer0_data,
        direct_transfer1_data,
        sender=privatekey1_raw,
    )

    nettingchannel.updateTransfer(
        mediated_transfer0_data,
        sender=privatekey0_raw,
    )

    tester_state.mine(number_of_blocks=settle_timeout + 1)

    # TODO:
    # - asert the resulting balances correspond to the updated trnasfer
    # - assert that Transfer and Settle events are correct
    # - add locked amounts and assert that they are respected


def test_unlock(tester_token, tester_channels, tester_events, tester_state):
    privatekey0_raw, privatekey1_raw, nettingchannel, channel0, channel1 = tester_channels[0]
    privatekey0 = PrivateKey(privatekey0_raw, ctx=GLOBAL_CTX, raw=True)
    privatekey1 = PrivateKey(privatekey1_raw, ctx=GLOBAL_CTX, raw=True)
    address0 = privatekey_to_address(privatekey0_raw)

    target = tester.a0
    initiator = tester.a1

    lock_amount0 = 5
    lock_timeout0 = DEFAULT_REVEAL_TIMEOUT + 5
    lock_expiration0 = tester_state.block.number + lock_timeout0
    secret0 = 'expiredlockexpiredlockexpiredloc'
    lock_hashlock0 = sha3(secret0)
    mediated_transfer0 = channel0.create_mediatedtransfer(
        transfer_initiator=initiator,
        transfer_target=target,
        fee=0,
        amount=lock_amount0,
        identifier=1,  # TODO: fill in identifier
        expiration=lock_expiration0,
        hashlock=lock_hashlock0,
    )
    mediated_transfer0.sign(privatekey0, address0)

    channel0.register_transfer(mediated_transfer0)
    channel1.register_transfer(mediated_transfer0)

    # expire the first lock
    tester_state.mine(number_of_blocks=lock_timeout0 + 1)

    lock_amount1 = 5
    lock_timeout1 = DEFAULT_REVEAL_TIMEOUT + 3
    lock_expiration1 = tester_state.block.number + lock_timeout1
    secret1 = 'secretsecretsecretsecretsecretse'
    lock_hashlock1 = sha3(secret1)
    mediated_transfer1 = channel0.create_mediatedtransfer(
        transfer_initiator=initiator,
        transfer_target=target,
        fee=0,
        amount=lock_amount1,
        identifier=1,  # TODO: fill in identifier
        expiration=lock_expiration1,
        hashlock=lock_hashlock1,
    )
    mediated_transfer1.sign(privatekey0, address0)
    mediated_transfer1_data = str(mediated_transfer1.packed().data)

    channel0.register_transfer(mediated_transfer1)
    channel1.register_transfer(mediated_transfer1)

    channel1.register_secret(secret1)

    nettingchannel.closeSingleTransfer(
        mediated_transfer1_data,
        sender=privatekey0_raw,
    )

    unlockproof0 = channel1.our_state.balance_proof.compute_proof_for_lock(
        secret0,
        mediated_transfer0.lock,
    )

    # expiration has passed, should fail
    with pytest.raises(TransactionFailed):
        nettingchannel.unlock(
            str(unlockproof0.lock_encoded),
            ''.join(unlockproof0.merkle_proof),
            unlockproof0.secret,
            sender=privatekey1_raw,
        )

    unlock_proofs = list(channel1.our_state.balance_proof.get_known_unlocks())

    assert len(unlock_proofs) == 1

    channel1.external_state.unlock(channel1.our_state.address, unlock_proofs)

    # already unlock, shoud fail
    with pytest.raises(TransactionFailed):
        proof = unlock_proofs[0]

        nettingchannel.unlock(
            proof.lock_encoded,
            ''.join(proof.merkle_proof),
            proof.secret,
            sender=privatekey0_raw,
        )
