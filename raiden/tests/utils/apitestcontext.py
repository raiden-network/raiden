# -*- coding: utf-8 -*-
import json
from raiden.utils import make_address
from raiden.channel import Channel, ChannelEndState, ChannelExternalState
from raiden.api.objects import ChannelList
from raiden.api.v1.encoding import (
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
        self.events = list()
        self.channels = []
        self.tokens = set()
        self.channel_schema = ChannelSchema()
        self.channel_list_schema = ChannelListSchema()
        self.reveal_timeout = reveal_timeout

    def add_events(self, events):
        self.events += events

    def get_token_added_events(self, from_block, to_block):
        return_list = list()
        for event in self.events:
            if (
                    event['_event_type'] == 'TokenAdded' and
                    event['block_number'] >= from_block and
                    event['block_number'] <= to_block
            ):
                return_list.append(event)

        return return_list

    def get_channel_new_events(self, token_address, from_block, to_block):
        return_list = list()
        for event in self.events:
            if (
                    event['_event_type'] == 'ChannelNew' and
                    event['block_number'] >= from_block and
                    event['block_number'] <= to_block
            ):
                return_list.append(event)

        return return_list

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
        self.tokens.add(token_address)
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

    def find_channel_by_address(self, channel_address):
        for channel in self.channels:
            if channel.channel_address == channel_address:
                return channel

        raise ValueError("Could not find channel")

    def query_channels(self, token_address=None, partner_address=None):
        if not token_address:
            return self.channels

        new_list = []
        for channel in self.channels:
            if channel.token_address == token_address:
                new_list.append(channel)

        return new_list

    def query_tokens(self):
        return list(self.tokens)

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

    def close(self, token_address, partner_address):
        channel = self.find_channel(token_address, partner_address)
        channel.external_state.netting_channel.state = 'closed'
        channel.external_state._closed_block = 1
        return channel

    def settle(self, token_address, partner_address):
        channel = self.find_channel(token_address, partner_address)
        channel.external_state.netting_channel.state = 'settled'
        channel.external_state._settled_block = 1
        return channel

    def get_channel(self, channel_address):
        return self.find_channel_by_address(channel_address)
