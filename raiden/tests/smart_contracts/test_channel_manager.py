# -*- coding: utf8 -*-
import pytest

from ethereum import tester
from ethereum.utils import encode_hex, sha3
from ethereum.tester import ABIContract, ContractTranslator, TransactionFailed

from raiden.blockchain.abi import get_contract_path
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
        'nettingChannel': netting_channel_address1_hex,
        'participant1': encode_hex(address0),
        'participant2': encode_hex(address1),
        'settleTimeout': settle_timeout,
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

    assert len(channel_manager.getChannelsParticipants()) == 0, 'newly deployed contract must be empty'

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
        'nettingChannel': netting_channel_address1_hex,
        'settleTimeout': settle_timeout,
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
        'nettingChannel': netting_channel_address2_hex,
        'settleTimeout': settle_timeout,
    }

    # uncomment private in function to run test
    # assert channel_manager.numberOfItems(netting_channel_creator1) == 2
    # assert channel_manager.numberOfItems(sha3('address1')[:20]) == 1
    # assert channel_manager.numberOfItems(sha3('iDontExist')[:20]) == 0
    # vs = sorted((sha3('address1')[:20], sha3('address2')[:20]))
    # k0 = channel_manager.key(sha3('address1')[:20], sha3('address2')[:20])
    # assert k0 == sha3(vs[0] + vs[1])
    # k1 = channel_manager.key(sha3('address2')[:20], sha3('address1')[:20])
    # assert k1 == sha3(vs[0] + vs[1])
    # with pytest.raises(TransactionFailed):
    #    channel_manager.key(sha3('address1')[:20], sha3('address1')[:20])
