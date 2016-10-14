# -*- coding: utf-8 -*-
import pytest

from ethereum import tester
from ethereum.utils import encode_hex, sha3
from raiden.utils import get_contract_path, privatekey_to_address
from raiden.encoding.signing import GLOBAL_CTX
from ethereum.tester import ABIContract, ContractTranslator, TransactionFailed
from secp256k1 import PrivateKey

from raiden.tests.utils.tester import channel_from_nettingcontract
from raiden.tests.utils.tester import new_channelmanager


def test_channelnew_event(settle_timeout, tester_state, tester_events,
                          tester_registry, tester_token):

    privatekey0 = tester.DEFAULT_KEY
    address0 = tester.DEFAULT_ACCOUNT
    address1 = tester.a1

    channel_manager = new_channelmanager(
        privatekey0,
        tester_state,
        tester_events.append,
        tester_registry,
        tester_token,
    )

    netting_channel_address1_hex = channel_manager.newChannel(
        address1,
        settle_timeout,
        sender=privatekey0,
    )

    last_event = tester_events[-1]
    assert last_event == {
        '_event_type': 'ChannelNew',
        'netting_channel': netting_channel_address1_hex,
        'participant1': encode_hex(address0),
        'participant2': encode_hex(address1),
        'settle_timeout': settle_timeout,
    }


def test_channelmanager(tester_state, tester_token, tester_events,
                        tester_channelmanager_library_address, settle_timeout,
                        netting_channel_abi):
    # pylint: disable=too-many-locals,too-many-statements

    address0 = tester.DEFAULT_ACCOUNT
    address1 = tester.a1
    address2 = tester.a2
    inexisting_address = sha3('this_does_not_exist')[:20]

    channelmanager_path = get_contract_path('ChannelManagerContract.sol')
    channel_manager = tester_state.abi_contract(
        None,
        path=channelmanager_path,
        language='solidity',
        constructor_parameters=[tester_token.address],
        contract_name='ChannelManagerContract',
        log_listener=tester_events.append,
        libraries={
            'ChannelManagerLibrary': tester_channelmanager_library_address.encode('hex'),
        }
    )

    participants_count = len(channel_manager.getChannelsParticipants())
    assert participants_count == 0, 'newly deployed contract must be empty'

    netting_channel_translator = ContractTranslator(netting_channel_abi)

    previous_events = list(tester_events)
    netting_channel_address1_hex = channel_manager.newChannel(
        address1,
        settle_timeout,
    )
    assert len(previous_events) + 1 == len(tester_events), 'ChannelNew event must be fired.'

    channelnew_event = tester_events[-1]
    assert channelnew_event == {
        '_event_type': 'ChannelNew',
        'participant1': address0.encode('hex'),
        'participant2': address1.encode('hex'),
        'netting_channel': netting_channel_address1_hex,
        'settle_timeout': settle_timeout,
    }

    # should fail if settleTimeout is too low
    with pytest.raises(TransactionFailed):
        channel_manager.newChannel(address1, 5)

    # cannot have two channels at the same time
    with pytest.raises(TransactionFailed):
        channel_manager.newChannel(address1, settle_timeout)

    # should trow if there is no channel for the given address
    with pytest.raises(TransactionFailed):
        channel_manager.getChannelWith(inexisting_address)

    assert len(channel_manager.getChannelsParticipants()) == 2

    netting_contract_proxy1 = ABIContract(
        tester_state,
        netting_channel_translator,
        netting_channel_address1_hex,
    )

    assert netting_contract_proxy1.settleTimeout() == settle_timeout

    previous_events = list(tester_events)
    netting_channel_address2_hex = channel_manager.newChannel(
        address2,
        settle_timeout,
    )
    assert len(previous_events) + 1 == len(tester_events), 'ChannelNew event must be fired.'

    assert channel_manager.getChannelWith(address1) == netting_channel_address1_hex
    assert channel_manager.getChannelWith(address2) == netting_channel_address2_hex

    msg_sender_channels = channel_manager.nettingContractsByAddress(tester.DEFAULT_ACCOUNT)
    address1_channels = channel_manager.nettingContractsByAddress(address1)
    inexisting_channels = channel_manager.nettingContractsByAddress(inexisting_address)

    assert len(msg_sender_channels) == 2
    assert len(address1_channels) == 1
    assert len(inexisting_channels) == 0

    assert len(channel_manager.getChannelsParticipants()) == 4

    channelnew_event = tester_events[-1]
    assert channelnew_event == {
        '_event_type': 'ChannelNew',
        'participant1': address0.encode('hex'),
        'participant2': address2.encode('hex'),
        'netting_channel': netting_channel_address2_hex,
        'settle_timeout': settle_timeout,
    }


def test_deleteChannel(tester_state, tester_channelmanager, tester_channels, settle_timeout,
                       netting_channel_abi):
    privatekey0_raw, privatekey1_raw, nettingchannel, channel0, _ = tester_channels[0]

    privatekey0 = PrivateKey(privatekey0_raw, ctx=GLOBAL_CTX, raw=True)
    address0 = privatekey_to_address(privatekey0_raw)
    address1 = privatekey_to_address(privatekey1_raw)

    # We need to close the channel before it can be deleted, to do so we need
    # one transfer to call closeSingleTransfer(0
    transfer_amount = 10
    identifier = 1
    direct_transfer = channel0.create_directtransfer(
        transfer_amount,
        identifier,
    )
    direct_transfer.sign(privatekey0, address0)
    direct_transfer_data = str(direct_transfer.packed().data)

    should_be_nonce = nettingchannel.opened(sender=privatekey0_raw) * (2**32)
    should_be_nonce_plus_one = (nettingchannel.opened(sender=privatekey0_raw) + 1) * (2**32)
    assert should_be_nonce <= direct_transfer.nonce
    assert should_be_nonce_plus_one > direct_transfer.nonce

    # settle the channel should not change the channel manager state
    nettingchannel.closeSingleTransfer(
        direct_transfer_data,
        sender=privatekey0_raw,
    )
    tester_state.mine(number_of_blocks=settle_timeout + 1)

    # delete the channel needs to update the manager's state
    number_of_channels = len(tester_channelmanager.getChannelsAddresses(sender=privatekey0_raw))

    nettingchannel.settle(sender=privatekey0_raw)

    tester_state.mine(1)

    # try to open a new channel should fail
    with pytest.raises(TransactionFailed):
        tester_channelmanager.newChannel(
            address1,
            settle_timeout,
            sender=privatekey0_raw,
        )

    tester_channelmanager.deleteChannel(
        address1,
        nettingchannel.address,
        sender=privatekey0_raw,
    )
    assert len(tester_channelmanager.getChannelsAddresses(sender=privatekey0_raw)) == number_of_channels - 1

    # now a single new channel can be open
    netting_channel_address1_hex = tester_channelmanager.newChannel(
        address1,
        settle_timeout,
        sender=privatekey0_raw,
    )

    netting_channel_translator = ContractTranslator(netting_channel_abi)

    netting_contract_proxy1 = ABIContract(
        tester_state,
        netting_channel_translator,
        netting_channel_address1_hex,
    )

    with pytest.raises(TransactionFailed):
        netting_contract_proxy1.closeSingleTransfer(
            direct_transfer_data,
            sender=privatekey0_raw,
        )

    with pytest.raises(TransactionFailed):
        tester_channelmanager.newChannel(
            address1,
            settle_timeout,
            sender=privatekey0_raw,
        )
