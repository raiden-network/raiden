# -*- coding: utf-8 -*-
import pytest
from ethereum.tester import TransactionFailed
from ethereum.utils import encode_hex, sha3

from raiden.utils import privatekey_to_address
from raiden.tests.utils.tester import (
    new_channelmanager,
    new_nettingcontract,
)


def test_channelnew_event(
        settle_timeout,
        private_keys,
        tester_state,
        tester_events,
        tester_registry,
        tester_token):
    """ When a new channel is created the channel new event must be emitted. """

    pkey0 = private_keys[0]
    address0 = privatekey_to_address(pkey0)
    address1 = privatekey_to_address(private_keys[1])

    channel_manager = new_channelmanager(
        pkey0,
        tester_state,
        tester_events.append,
        tester_registry,
        tester_token,
    )

    # pylint: disable=no-member
    netting_channel_address1_hex = channel_manager.newChannel(
        address1,
        settle_timeout,
        sender=pkey0,
    )

    last_event = tester_events[-1]
    assert last_event == {
        '_event_type': 'ChannelNew',
        'netting_channel': netting_channel_address1_hex,
        'participant1': encode_hex(address0),
        'participant2': encode_hex(address1),
        'settle_timeout': settle_timeout,
    }


def test_channeldeleted_event(
        settle_timeout,
        tester_channelmanager,
        tester_events,
        tester_nettingcontracts,
        tester_state):
    """ A channel deleted event must be emmited when the channel is cleaned.

    This happens once a *new* channel with *the same parties* is created,
    overwritting the old one. This behavior may be unexpected due to the weird
    timming.
    """
    pkey0, pkey1, nettingchannel = tester_nettingcontracts[0]
    address0 = privatekey_to_address(pkey0)
    address1 = privatekey_to_address(pkey1)

    nettingchannel.close('', sender=pkey0)
    tester_state.mine(number_of_blocks=settle_timeout + 1)
    nettingchannel.settle(sender=pkey0)

    # old entry will be deleted when calling newChannel
    tester_channelmanager.newChannel(
        address1,
        settle_timeout,
        sender=pkey0,
    )

    channeldelete_event = tester_events[-2]
    assert channeldelete_event == {
        '_event_type': 'ChannelDeleted',
        'caller_address': address0.encode('hex'),
        'partner': address1.encode('hex')
    }


def test_newchannel_fails_until_channel_is_settled(
        settle_timeout,
        tester_state,
        tester_channelmanager,
        tester_nettingcontracts):
    """ A call to newChannel must fail if both participants have an existing
    channel open, that is not settled.

    This is required since because the channel manager tracks only one channel
    per participants pair, and the channel address information must be
    available until the settlement is over to provide the required channel
    information to the client. It's not assumed the client will cache the data
    locally.
    """
    pkey0, pkey1, nettingchannel = tester_nettingcontracts[0]
    address1 = privatekey_to_address(pkey1)

    # the channel exists and it's open
    with pytest.raises(TransactionFailed):
        tester_channelmanager.newChannel(
            address1,
            settle_timeout,
            sender=pkey0,
        )

    nettingchannel.close('', sender=pkey0)

    # the old channel is closed but not settled yet
    with pytest.raises(TransactionFailed):
        tester_channelmanager.newChannel(
            address1,
            settle_timeout,
            sender=pkey0,
        )

    tester_state.mine(number_of_blocks=settle_timeout + 1)

    # the settlement period is over but the channel is not settled yet
    with pytest.raises(TransactionFailed):
        tester_channelmanager.newChannel(
            address1,
            settle_timeout,
            sender=pkey0,
        )

    nettingchannel.settle(sender=pkey0)

    # now a new channel can be open
    new_nettingchannel = tester_channelmanager.newChannel(
        address1,
        settle_timeout,
        sender=pkey0,
    )

    assert new_nettingchannel != nettingchannel.address


@pytest.mark.parametrize('number_of_nodes', [10])
def test_getchannelwith_must_return_zero_for_inexisting_channels(
        tester_channelmanager,
        private_keys,
        settle_timeout):
    """ Queries to the channel manager for an unexisting channel with a partner
    must return zero.
    """
    addresses = map(privatekey_to_address, private_keys)

    test_key = private_keys[0]
    test_addr = privatekey_to_address(test_key)
    for addr in addresses:
        if addr == test_addr:
            continue

        channel_address = tester_channelmanager.getChannelWith(addr, sender=test_key)
        assert channel_address == '0' * 40

        tester_channelmanager.newChannel(addr, settle_timeout, sender=test_key)


def test_channelmanager_start_with_zero_entries(
        private_keys,
        tester_events,
        tester_registry,
        tester_state,
        tester_token):
    """ A new channel manager must start empty. """

    pkey0 = private_keys[0]
    channel_manager = new_channelmanager(
        pkey0,
        tester_state,
        tester_events.append,
        tester_registry,
        tester_token,
    )

    # pylint: disable=no-member
    assert not channel_manager.getChannelsAddresses(sender=pkey0)
    assert not channel_manager.getChannelsParticipants(sender=pkey0)


def test_channelmanager(private_keys, settle_timeout, tester_channelmanager):
    # pylint: disable=too-many-locals,too-many-statements

    pkey0 = private_keys[0]
    address0 = privatekey_to_address(private_keys[0])
    address1 = privatekey_to_address(private_keys[1])
    address2 = privatekey_to_address(private_keys[2])

    total_pairs = 0
    for addr in [address1, address2]:
        channel_address_hex = tester_channelmanager.newChannel(
            addr,
            settle_timeout,
            sender=pkey0,
        )

        assert tester_channelmanager.getChannelWith(addr, sender=pkey0) == channel_address_hex

        total_pairs += 2
        participant_pairs = tester_channelmanager.getChannelsParticipants(sender=pkey0)
        assert len(participant_pairs) == total_pairs

    # pylint: disable=no-member
    addr0_channels = tester_channelmanager.nettingContractsByAddress(address0, sender=pkey0)
    addr1_channels = tester_channelmanager.nettingContractsByAddress(address1, sender=pkey0)

    nonexisting_address = sha3('this_does_not_exist')[:20]
    nonaddr_channels = tester_channelmanager.nettingContractsByAddress(
        nonexisting_address,
        sender=pkey0,
    )

    assert len(addr0_channels) == 2
    assert len(addr1_channels) == 1
    assert not nonaddr_channels


def test_reopen_channel(
        settle_timeout,
        tester_channelmanager,
        tester_nettingcontracts,
        tester_state):
    """ Reopen must be possible after settlement. """

    pkey0, pkey1, nettingchannel = tester_nettingcontracts[0]
    address1 = privatekey_to_address(pkey1)

    nettingchannel.close('', sender=pkey0)
    tester_state.mine(number_of_blocks=settle_timeout + 1)
    nettingchannel.settle(sender=pkey0)

    tester_state.mine(1)

    # now a single new channel can be opened
    # if channel with address is settled a new can be opened
    # old entry will be deleted when calling newChannel
    tester_channelmanager.newChannel(
        address1,
        settle_timeout,
        sender=pkey0,
    )


@pytest.mark.parametrize('number_of_nodes', [2])
def test_new_channel_state(private_keys, tester_state, tester_channelmanager):
    """ Tests the state of a newly created netting channel. """
    pkey0, pkey1 = private_keys

    events = list()
    settle_timeout = 10
    channel = new_nettingcontract(
        pkey0,
        pkey1,
        tester_state,
        events.append,
        tester_channelmanager,
        settle_timeout,
    )

    # pylint: disable=no-member
    assert channel.settleTimeout(sender=pkey0) == settle_timeout
    assert channel.tokenAddress(sender=pkey0) == tester_channelmanager.tokenAddress(sender=pkey0)
    assert channel.opened(sender=pkey0) == tester_state.block.number - 1
    assert channel.closed(sender=pkey0) == 0
    assert channel.settled(sender=pkey0) == 0

    address_and_balances = channel.addressAndBalance(sender=pkey0)
    address0 = privatekey_to_address(pkey0)
    address1 = privatekey_to_address(pkey1)

    assert address_and_balances[0] == encode_hex(address0)
    assert address_and_balances[1] == 0
    assert address_and_balances[2] == encode_hex(address1)
    assert address_and_balances[3] == 0
