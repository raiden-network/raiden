# -*- coding: utf8 -*-
import pytest

from ethereum import tester
from ethereum.utils import sha3
from ethereum.tester import ABIContract, ContractTranslator, TransactionFailed
from ethereum.slogging import configure

# pylint: disable=no-member
configure(':DEBUG')


# TODO: test events
def test_cmc(state, settle_timeout, netting_channel_abi, manager, events):  # pylint: disable=too-many-locals,too-many-statements
    address1 = sha3('address1')[:20]
    address3 = sha3('address3')[:20]
    inexisting_address = sha3('this_does_not_exist')[:20]

    netting_channel_translator = ContractTranslator(netting_channel_abi)

    assert len(manager.getChannelsParticipants()) == 0

    netting_channel_address1 = manager.newChannel(
        address1,
        settle_timeout,
    )

    # cannot have two channels at the same time
    with pytest.raises(TransactionFailed):
        manager.newChannel(address1, settle_timeout)

    # should trow if there is no channel for the given address
    with pytest.raises(TransactionFailed):
        manager.getChannelWith(inexisting_address)

    assert len(manager.getChannelsParticipants()) == 2

    netting_contract_proxy1 = ABIContract(
        state,
        netting_channel_translator,
        netting_channel_address1,
    )

    assert netting_contract_proxy1.settleTimeout() == settle_timeout

    netting_channel_address2 = manager.newChannel(
        address3,
        settle_timeout,
    )

    assert manager.getChannelWith(address1) == netting_channel_address1
    assert manager.getChannelWith(address3) == netting_channel_address2

    msg_sender_channels = manager.nettingContractsByAddress(tester.DEFAULT_ACCOUNT)
    address1_channels = manager.nettingContractsByAddress(address1)
    inexisting_channels = manager.nettingContractsByAddress(inexisting_address)

    assert len(msg_sender_channels) == 2
    assert len(address1_channels) == 1
    assert len(inexisting_channels) == 0

    assert len(manager.getChannelsParticipants()) == 4

    assert len(events) == 2
    assert events[0]['_event_type'] == 'ChannelNew'
    assert events[0]['participant1'] == tester.a0.encode('hex')
    assert events[0]['participant2'] == address1.encode('hex')
    assert events[0]['nettingChannel'] == manager.address.encode('hex')
    assert events[0]['settleTimeout'] == 30
    assert events[1]['_event_type'] == 'ChannelNew'
    assert events[1]['participant1'] == tester.a0.encode('hex')
    assert events[1]['participant2'] == address3.encode('hex')
    assert events[1]['nettingChannel'] == manager.address.encode('hex')
    assert events[1]['settleTimeout'] == 30

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
