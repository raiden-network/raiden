# -*- coding: utf-8 -*-
from raiden.network.channelgraph import ChannelGraph, ChannelDetails
from raiden.tests.utils.factories import make_address


class ParticipantStateMock:
    def __init__(self, address):
        self.address = address


class NettingChannelMock:
    def __init__(self, address):
        self.address = address


class ExternalStateMock:
    def __init__(self, netting_channel):
        self.netting_channel = netting_channel
        self.settled_block = 0
        self.closed_block = 0
        self.opened_block = 0


def test_addchannel_must_not_overwrite():  # pylint: disable=too-many-locals
    """ Calling add_channel for an existing channel must not overwrite it. """
    our_address = make_address()
    partner_address = make_address()
    channel_manager_address = make_address()
    token_address = make_address()
    channel_address = make_address()

    our_state = ParticipantStateMock(our_address)
    partner_state = ParticipantStateMock(partner_address)
    netting_channel = NettingChannelMock(channel_address)
    external_state = ExternalStateMock(netting_channel)
    reveal_timeout = 5
    settle_timeout = 10

    channel_detail = ChannelDetails(
        channel_address,
        our_state,
        partner_state,
        external_state,
        reveal_timeout,
        settle_timeout,
    )

    edge_list = []
    channel_detail_list = [channel_detail]

    graph = ChannelGraph(
        our_address,
        channel_manager_address,
        token_address,
        edge_list,
        channel_detail_list,
    )

    first_instance = graph.address_to_channel[channel_address]

    graph.add_channel(channel_detail)

    assert first_instance is graph.address_to_channel[channel_address]
