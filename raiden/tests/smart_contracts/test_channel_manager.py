# -*- coding: utf8 -*-
import pytest

from ethereum import tester
from ethereum.utils import sha3
from ethereum.tester import ABIContract, ContractTranslator, TransactionFailed

from raiden.blockchain.abi import get_contract_path


def test_channelmanager(tester_state, tester_token, tester_events,
                        tester_channelmanager_library_address, settle_timeout,
                        netting_channel_abi):
    # pylint: disable=too-many-locals,too-many-statements

    address0 = tester.DEFAULT_ACCOUNT
    address1 = tester.a1
    address2 = tester.a2
    inexisting_address = sha3('this_does_not_exist')[:20]

    channelmanager_path = get_contract_path('ChannelManagerContract.sol')
    channelmanager = tester_state.abi_contract(
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

    initial_events = list(tester_events)
    assert len(channelmanager.getChannelsParticipants()) == 0, 'newly deployed contract must be empty'

    netting_channel_translator = ContractTranslator(netting_channel_abi)
    netting_channel_address1_hex = channelmanager.newChannel(
        address1,
        settle_timeout,
    )

    assert len(tester_events) > len(initial_events), 'ChannelNew event must be fired.'

    event = tester_events[-1]
    assert event['_event_type'] == 'ChannelNew'
    assert event['participant1'] == address0.encode('hex')
    assert event['participant2'] == address1.encode('hex')

    # should fail if settleTimeout is too low
    with pytest.raises(TransactionFailed):
        channelmanager.newChannel(address1, 5)

    # cannot have two channels at the same time
    with pytest.raises(TransactionFailed):
        channelmanager.newChannel(address1, settle_timeout)

    # should trow if there is no channel for the given address
    with pytest.raises(TransactionFailed):
        channelmanager.getChannelWith(inexisting_address)

    assert len(channelmanager.getChannelsParticipants()) == 2

    netting_contract_proxy1 = ABIContract(
        tester_state,
        netting_channel_translator,
        netting_channel_address1_hex,
    )

    assert netting_contract_proxy1.settleTimeout() == settle_timeout

    netting_channel_address2_hex = channelmanager.newChannel(
        address2,
        settle_timeout,
    )

    assert channelmanager.getChannelWith(address1) == netting_channel_address1_hex
    assert channelmanager.getChannelWith(address2) == netting_channel_address2_hex

    msg_sender_channels = channelmanager.nettingContractsByAddress(tester.DEFAULT_ACCOUNT)
    address1_channels = channelmanager.nettingContractsByAddress(address1)
    inexisting_channels = channelmanager.nettingContractsByAddress(inexisting_address)

    assert len(msg_sender_channels) == 2
    assert len(address1_channels) == 1
    assert len(inexisting_channels) == 0

    assert len(channelmanager.getChannelsParticipants()) == 4

    assert len(tester_events) == 2
    assert tester_events[0]['_event_type'] == 'ChannelNew'
    assert tester_events[0]['participant1'] == address0.encode('hex')
    assert tester_events[0]['participant2'] == address1.encode('hex')
    assert tester_events[0]['nettingChannel'] == netting_channel_address1_hex
    assert tester_events[0]['settleTimeout'] == settle_timeout

    assert tester_events[1]['_event_type'] == 'ChannelNew'
    assert tester_events[1]['participant1'] == address0.encode('hex')
    assert tester_events[1]['participant2'] == address2.encode('hex')
    assert tester_events[1]['nettingChannel'] == netting_channel_address2_hex
    assert tester_events[1]['settleTimeout'] == settle_timeout

    # uncomment private in function to run test
    # assert manager.numberOfItems(netting_channel_creator1) == 2
    # assert manager.numberOfItems(sha3('address1')[:20]) == 1
    # assert manager.numberOfItems(sha3('iDontExist')[:20]) == 0
    # vs = sorted((sha3('address1')[:20], sha3('address2')[:20]))
    # k0 = manager.key(sha3('address1')[:20], sha3('address2')[:20])
    # assert k0 == sha3(vs[0] + vs[1])
    # k1 = manager.key(sha3('address2')[:20], sha3('address1')[:20])
    # assert k1 == sha3(vs[0] + vs[1])
    # with pytest.raises(TransactionFailed):
    #    manager.key(sha3('address1')[:20], sha3('address1')[:20])
