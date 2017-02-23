# -*- coding: utf-8 -*-
import json
from raiden.utils import make_address
from raiden.channel import Channel, ChannelEndState, ChannelExternalState
from raiden.api.objects import ChannelList
from raiden.api.v1.encoding import (
    EventsListSchema,
    ChannelSchema,
    ChannelListSchema
)


# TODO: this is ripped from unit/test_channel.py. Abstract it out somewhere.
class NettingChannelMock(object):
    # pylint: disable=no-self-use
    def opened(self):
        return 1

    def closed(self):
        return 0

    def settled(self):
        return 0


def decode_response(response):
    return json.loads(json.loads(response._content))


class ApiTestContext():

    def __init__(self):
        self.channels = []
        self.channel_schema = ChannelSchema()
        self.channel_list_schema = ChannelListSchema()
        self.events_list_schema = EventsListSchema()

    def make_channel(self):
        our_address = make_address()
        partner_address = make_address()
        token_address = make_address()
        our_balance = 10
        partner_balance = 10
        reveal_timeout = 20
        settle_timeout = 800
        our_state = ChannelEndState(our_address, our_balance, 1)
        partner_state = ChannelEndState(partner_address, partner_balance, 1)

        block_alarm = list()
        channel_for_hashlock = list()
        netting_channel = NettingChannelMock()
        external_state = ChannelExternalState(
            block_alarm.append,
            lambda *args: channel_for_hashlock.append(args),
            lambda: 1,
            netting_channel,
        )
        self.channels.append(Channel(
            our_state,
            partner_state,
            external_state,
            token_address,
            reveal_timeout,
            settle_timeout,
        ))

    def query_channels(self, token_address=None, partner_address=None):
        return self.channels

    def expect_channels(self):
        channel_list = ChannelList(self.channels)
        return json.loads(self.channel_list_schema.dumps(channel_list).data)
