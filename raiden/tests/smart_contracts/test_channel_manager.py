# -*- coding: utf-8 -*-
import itertools

import pytest
from ethereum.tester import TransactionFailed
from ethereum.utils import encode_hex

from raiden.utils import privatekey_to_address, sha3
from raiden.tests.utils.tester import (
    new_channelmanager,
    new_nettingcontract,
    create_nettingchannel_proxy,
)


def netting_channel_settled(tester_state, nettingchannel, pkey, settle_timeout):
    nettingchannel.close(sender=pkey)
    tester_state.mine(number_of_blocks=settle_timeout + 1)
    nettingchannel.settle(sender=pkey)
    tester_state.mine(1)


def test_channelnew_event(
        settle_timeout,
        tester_channelmanager,
        private_keys,
        tester_events):
    """ When a new channel is created the channel new event must be emitted. """

    pkey0 = private_keys[0]
    address0 = privatekey_to_address(pkey0)
    address1 = privatekey_to_address(private_keys[1])

    # pylint: disable=no-member
    netting_channel_address1_hex = tester_channelmanager.newChannel(
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
    timing.
    """
    pkey0, pkey1, nettingchannel = tester_nettingcontracts[0]
    address0 = privatekey_to_address(pkey0)
    address1 = privatekey_to_address(pkey1)

    netting_channel_settled(
        tester_state,
        nettingchannel,
        pkey0,
        settle_timeout,
    )

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
    channel open with each other, that is not settled.

    This is required because the channel manager tracks only one channel
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

    nettingchannel.close(sender=pkey0)

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

    # now a new channel can be opened
    new_nettingchannel = tester_channelmanager.newChannel(
        address1,
        settle_timeout,
        sender=pkey0,
    )

    assert new_nettingchannel != nettingchannel.address


@pytest.mark.parametrize('number_of_nodes', [10])
def test_getchannelwith_must_return_zero_for_non_existing_channels(
        tester_channelmanager,
        private_keys,
        settle_timeout):
    """ Queries to the channel manager for a non-existing channel with a partner
    must return zero.
    """
    addresses = map(privatekey_to_address, private_keys)

    sender_key = private_keys[0]
    sender_addr = privatekey_to_address(sender_key)
    null_addr = '0' * 40

    for addr in addresses:
        channel_address = tester_channelmanager.getChannelWith(addr, sender=sender_key)
        assert channel_address == null_addr

        # can not open a channel with itself
        if addr != sender_addr:
            tester_channelmanager.newChannel(addr, settle_timeout, sender=sender_key)
        else:
            with pytest.raises(TransactionFailed):
                tester_channelmanager.newChannel(addr, settle_timeout, sender=sender_key)


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
        tester_token.address,
    )

    # pylint: disable=no-member
    assert not channel_manager.getChannelsAddresses(sender=pkey0)
    assert not channel_manager.getChannelsParticipants(sender=pkey0)


def test_channelmanager(private_keys, settle_timeout, tester_channelmanager):
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


@pytest.mark.parametrize('number_of_nodes', [10])
def test_for_issue_892(
        private_keys,
        settle_timeout,
        tester_channelmanager,
        tester_state,
        tester_events):
    """
    This is a regression test for issue #892 (https://github.com/raiden-network/raiden/issues/892)
    where the `getChannelsParticipants()` call was returning an empty list if one channel from
    the channel manager has been settled
    """

    pairs = itertools.combinations(private_keys, 2)

    participant_pairs = []
    first_pair = True
    for pkey0, pkey1 in pairs:
        address0 = privatekey_to_address(pkey0)
        address1 = privatekey_to_address(pkey1)

        channel_address_hex = tester_channelmanager.newChannel(
            address1,
            settle_timeout,
            sender=pkey0,
        )

        assert tester_channelmanager.getChannelWith(address1, sender=pkey0) == channel_address_hex
        assert tester_channelmanager.getChannelWith(address0, sender=pkey1) == channel_address_hex

        if first_pair:
            first_pair = False
            nettingchannel = create_nettingchannel_proxy(
                tester_state,
                channel_address_hex,
                tester_events.append,
            )
            nettingchannel.close(sender=pkey0)
            tester_state.mine(number_of_blocks=settle_timeout + 2)
            nettingchannel.settle(sender=pkey1)

        else:
            # this is brittle, relying on an implicit ordering of addresses
            participant_pairs.extend((
                address0.encode('hex'),
                address1.encode('hex'),
            ))

        assert participant_pairs == tester_channelmanager.getChannelsParticipants(sender=pkey0)


def test_reopen_channel(
        private_keys,
        settle_timeout,
        tester_channelmanager,
        tester_state):
    """ A new channel can be opened after the old one is settled. When this
    happens the channel manager must update its internal data structures to
    point to the new channel address.
    """

    log = list()
    pkey = private_keys[0]

    channels = list()
    old_channel_addresses = list()
    for partner_pkey in private_keys[1:]:
        nettingcontract = new_nettingcontract(
            pkey, partner_pkey, tester_state, log.append, tester_channelmanager, settle_timeout,
        )
        channels.append(nettingcontract)

        address = privatekey_to_address(partner_pkey)
        channel_address = tester_channelmanager.getChannelWith(
            address,
            sender=pkey,
        )
        old_channel_addresses.append(channel_address)

    for nettingchannel in channels:
        netting_channel_settled(
            tester_state,
            nettingchannel,
            pkey,
            settle_timeout,
        )

    channels = list()
    for partner_pkey in private_keys[1:]:
        nettingcontract = new_nettingcontract(
            pkey, partner_pkey, tester_state, log.append, tester_channelmanager, settle_timeout,
        )
        channels.append(nettingcontract)

    # there must be a single entry for each participant
    for partner_pkey in private_keys[1:]:
        address = privatekey_to_address(partner_pkey)
        channel_address = tester_channelmanager.getChannelWith(
            address,
            sender=pkey,
        )
        assert channel_address
        assert channel_address not in old_channel_addresses


@pytest.mark.parametrize('number_of_nodes', [5])
def test_reopen_regression_bad_index_update(
        private_keys,
        settle_timeout,
        tester_channelmanager,
        tester_state):
    """ deleteChannel used the wrong address to update the node_index mapping.
        Correct usage would be

        (addr0, addr1) => channel_idx

    But instead of overwriting the existing index, a new entry was added as:

        (addr0, channel_addr) => channel_idx
    """
    pkey0 = private_keys[0]
    pkey1 = private_keys[1]
    pkey2 = private_keys[2]
    addr1 = privatekey_to_address(pkey1)

    tester_channelmanager.newChannel(
        addr1,
        settle_timeout,
        sender=pkey0,
    )

    log = list()
    nettingchannel = new_nettingcontract(
        pkey0, pkey2, tester_state, log.append, tester_channelmanager, settle_timeout,
    )

    netting_channel_settled(
        tester_state,
        nettingchannel,
        pkey0,
        settle_timeout,
    )

    nettingchannel = new_nettingcontract(
        pkey0, pkey2, tester_state, log.append, tester_channelmanager, settle_timeout,
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
