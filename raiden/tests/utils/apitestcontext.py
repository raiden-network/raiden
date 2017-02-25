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


class NettingChannelMock(object):

    def __init__(self, channel_address):
        self.address = channel_address
        self.state = 'open'

    # pylint: disable=no-self-use
    def opened(self):
        return self.state == 'open'

    def closed(self):
        return self.state == 'closed' or self.state == 'settled'

    def settled(self):
        return self.state == 'settled'


def decode_response(response):
    return json.loads(json.loads(response._content))


class ApiTestContext():

    def __init__(self, reveal_timeout):
        self.channels = []
        self.channel_schema = ChannelSchema()
        self.channel_list_schema = ChannelListSchema()
        self.events_list_schema = EventsListSchema()
        self.reveal_timeout = reveal_timeout

    def make_channel(
            self,
            token_address=make_address(),
            partner_address=make_address(),
            reveal_timeout=20,
            settle_timeout=800,
            balance=0,
    ):
        our_address = make_address()
        our_balance = balance
        partner_balance = balance
        our_state = ChannelEndState(our_address, our_balance, 1)
        partner_state = ChannelEndState(partner_address, partner_balance, 1)

        block_alarm = list()
        channel_for_hashlock = list()
        netting_channel = NettingChannelMock(make_address())
        external_state = ChannelExternalState(
            block_alarm.append,
            lambda *args: channel_for_hashlock.append(args),
            lambda: 1,
            netting_channel,
        )
        return Channel(
            our_state,
            partner_state,
            external_state,
            token_address,
            reveal_timeout,
            settle_timeout,
        )

    def make_channel_and_add(self):
        channel = self.make_channel()
        self.channels.append(channel)

    def find_channel(self, token_address, partner_address):
        for channel in self.channels:
            if (channel.token_address == token_address and
                    channel.partner_state.address == partner_address):
                return channel

        raise ValueError("Could not find channel")

    def query_channels(self, token_address=None, partner_address=None):
        return self.channels

    def expect_channels(self):
        channel_list = ChannelList(self.channels)
        return json.loads(self.channel_list_schema.dumps(channel_list).data)

    def open_channel(
            self,
            token_address,
            partner_address,
            settle_timeout=None,
            reveal_timeout=None):

        reveal_value = reveal_timeout if reveal_timeout is not None else self.reveal_timeout
        channel = self.make_channel(
            token_address=token_address,
            partner_address=partner_address,
            settle_timeout=settle_timeout,
            reveal_timeout=reveal_value
        )
        self.channels.append(channel)
        return channel

    def deposit(self, token_address, partner_address, amount):
        channel = self.find_channel(token_address, partner_address)
        channel.our_state.contract_balance += amount
        return channel
