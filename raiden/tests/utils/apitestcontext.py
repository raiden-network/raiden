# -*- coding: utf-8 -*-
import json

from raiden.api.objects import ChannelList
from raiden.api.v1.encoding import (
    ChannelSchema,
    ChannelListSchema
)
from raiden.channel import (
    Channel,
    ChannelEndState,
    ChannelExternalState,
)
from raiden.constants import NETTINGCHANNEL_SETTLE_TIMEOUT_MIN, NETTINGCHANNEL_SETTLE_TIMEOUT_MAX
from raiden.exceptions import (
    InvalidAddress,
    InvalidSettleTimeout,
    UnknownTokenAddress,
)
from raiden.tests.utils.factories import make_address
from raiden.transfer.merkle_tree import EMPTY_MERKLE_TREE
from raiden.transfer.state import (
    CHANNEL_STATE_OPENED,
    CHANNEL_STATE_CLOSED,
    CHANNEL_STATE_SETTLED,
)
from raiden.utils import (
    address_decoder,
    isaddress,
    pex,
)


class NettingChannelMock:

    def __init__(self, channel_address):
        self.address = channel_address
        self.state = CHANNEL_STATE_OPENED

    # pylint: disable=no-self-use
    def opened(self):
        return self.state == CHANNEL_STATE_OPENED

    def closed(self):
        return self.state == CHANNEL_STATE_CLOSED or self.state == CHANNEL_STATE_SETTLED


class ConnectionManagerMock:
    def __init__(self, token_address, funds):
        self.token_address = token_address
        self.funds = funds
        self.sum_deposits = funds
        self.open_channels = []


class ApiTestContext:

    def __init__(self, reveal_timeout):
        self.events = list()
        self.channels = []
        self.tokens = set()
        self.channel_schema = ChannelSchema()
        self.channel_list_schema = ChannelListSchema()
        self.reveal_timeout = reveal_timeout
        self.tokens_to_manager_address = dict()
        self.connection_managers = []

    def add_events(self, events):
        self.events += events

    def specify_token_for_channelnew(self, token_address):
        """Since it's not part of the event but part of the querying and we
        mock the interface we should check that the token address properly makes
        it through the REST api"""
        self.token_for_channelnew = address_decoder(token_address)

    def specify_channel_for_events(self, channel_address):
        """Since it's not part of the event but part of the querying and we
        mock the interface we should check that the channel address properly
        makes it through the REST api"""
        self.channel_for_events = address_decoder(channel_address)

    def specify_tokenswap_input(self, tokenswap_input, target_address, identifier):
        """We don't test the actual tokenswap but only that the input makes it
        to the backend in the expected format"""
        self.tokenswap_input = dict(tokenswap_input)
        self.tokenswap_input['sending_token'] = address_decoder(
            self.tokenswap_input['sending_token']
        )
        self.tokenswap_input['receiving_token'] = address_decoder(
            self.tokenswap_input['receiving_token']
        )
        self.tokenswap_input['identifier'] = identifier
        self.tokenswap_input['target_address'] = address_decoder(target_address)

    def get_network_events(self, from_block, to_block):
        return_list = list()
        for event in self.events:
            expected_event_type = event['_event_type'] == b'TokenAdded'
            in_block_range = (
                event['block_number'] >= from_block and
                event['block_number'] <= to_block
            )
            if expected_event_type and in_block_range:
                return_list.append(event)

        return return_list

    def get_token_network_events(self, token_address, from_block, to_block):
        return_list = list()
        # if this happens the token hasn't been registered yet
        # in the API the lookup would fail with a UnknownTokenAddress, return the same here
        if not hasattr(self, 'token_for_channelnew') or token_address != self.token_for_channelnew:
            raise UnknownTokenAddress(
                'Unexpected token address: "{}"  during channelnew '
                'query'.format(pex(token_address))
            )
        for event in self.events:
            expected_event_type = event['_event_type'] == b'ChannelNew'
            in_block_range = (
                event['block_number'] >= from_block and
                event['block_number'] <= to_block
            )
            if expected_event_type and in_block_range:
                return_list.append(event)

        return return_list

    def get_channel_events(self, channel_address, from_block, to_block):
        return_list = list()
        if channel_address != self.channel_for_events:
            raise ValueError(
                'Unexpected channel address: "{}"  during channel events '
                'query'.format(pex(channel_address))
            )

        for event in self.events:
            is_channel_event = (
                event['_event_type'] == b'ChannelNewBalance' or
                event['_event_type'] == b'ChannelClosed' or
                event['_event_type'] == b'TransferUpdated' or
                event['_event_type'] == b'ChannelSettled' or
                event['_event_type'] == b'ChannelSecretRevealed'
            )
            in_block_range = (
                event['block_number'] >= from_block and
                event['block_number'] <= to_block
            )
            if is_channel_event and in_block_range:
                return_list.append(event)

        return return_list

    def make_channel(
            self,
            token_address=make_address(),
            partner_address=make_address(),
            reveal_timeout=20,
            settle_timeout=800,
            balance=0,
            block_number=1):

        our_address = make_address()
        our_balance = balance
        partner_balance = balance
        our_state = ChannelEndState(
            our_address,
            our_balance,
            None,
            EMPTY_MERKLE_TREE,
        )
        partner_state = ChannelEndState(
            partner_address,
            partner_balance,
            None,
            EMPTY_MERKLE_TREE,
        )

        channel_for_hashlock = list()
        netting_channel = NettingChannelMock(make_address())
        external_state = ChannelExternalState(
            lambda *args: channel_for_hashlock.append(args),
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

    def register_token(self, token_address):
        self.tokens.add(token_address)
        manager_address = make_address()
        self.tokens_to_manager_address[token_address] = manager_address
        return manager_address

    def manager_address_if_token_registered(self, token_address):
        if token_address not in self.tokens:
            return None

        return self.tokens_to_manager_address[token_address]

    def make_channel_and_add(self):
        channel = self.make_channel()
        self.channels.append(channel)

    def find_channel(self, token_address, partner_address):
        for channel in self.channels:
            if (channel.token_address == token_address and
                    channel.partner_state.address == partner_address):
                return channel

        raise ValueError('Could not find channel')

    def find_channel_by_address(self, channel_address):
        for channel in self.channels:
            if channel.channel_address == channel_address:
                return channel

        raise ValueError('Could not find channel')

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

        invalid_timeout = (
            settle_timeout < NETTINGCHANNEL_SETTLE_TIMEOUT_MIN or
            settle_timeout > NETTINGCHANNEL_SETTLE_TIMEOUT_MAX
        )
        if invalid_timeout:
            raise InvalidSettleTimeout('`settle_timeout` should be in range [{}, {}].'.format(
                NETTINGCHANNEL_SETTLE_TIMEOUT_MIN, NETTINGCHANNEL_SETTLE_TIMEOUT_MAX
            ))

        if not isaddress(token_address):
            raise InvalidAddress('Expected binary address format for token in channel open')

        if not isaddress(partner_address):
            raise InvalidAddress('Expected binary address format for partner in channel open')

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
        channel.external_state.netting_channel.state = CHANNEL_STATE_CLOSED
        channel.external_state._closed_block = 1
        return channel

    def settle(self, token_address, partner_address):
        channel = self.find_channel(token_address, partner_address)
        channel.external_state.netting_channel.state = CHANNEL_STATE_SETTLED
        channel.external_state._settled_block = 1
        return channel

    def get_channel(self, channel_address):
        return self.find_channel_by_address(channel_address)

    def _check_tokenswap_input(self, argname, input_argname, kwargs):
        if kwargs[argname] != self.tokenswap_input[input_argname]:
            raise ValueError(
                'Expected "{}" for {} but got "{}"'.format(
                    self.tokenswap_input[input_argname],
                    input_argname,
                    kwargs[argname])
            )

    def token_swap(self, **kwargs):
        self._check_tokenswap_input('maker_token', 'sending_token', kwargs)
        self._check_tokenswap_input('maker_amount', 'sending_amount', kwargs)
        self._check_tokenswap_input('taker_token', 'receiving_token', kwargs)
        self._check_tokenswap_input('taker_amount', 'receiving_amount', kwargs)

    def expect_token_swap(self, **kwargs):
        self._check_tokenswap_input('identifier', 'identifier', kwargs)
        self._check_tokenswap_input('maker_token', 'receiving_token', kwargs)
        self._check_tokenswap_input('maker_amount', 'receiving_amount', kwargs)
        self._check_tokenswap_input('taker_token', 'sending_token', kwargs)
        self._check_tokenswap_input('taker_amount', 'sending_amount', kwargs)

    def transfer(self, token_address, amount, target, identifier):
        # Do nothing. These tests only test the api endpoints, so nothing to do here
        pass

    def connect(
            self,
            token_address,
            funds,
            initial_channel_target,
            joinable_funds_target):

        if not isaddress(token_address):
            raise InvalidAddress('not an address %s' % pex(token_address))

        funding = int((funds * joinable_funds_target) / initial_channel_target)
        for i in range(0, initial_channel_target):
            channel = self.make_channel(token_address=token_address, balance=funding)
            self.channels.append(channel)

        connection_manager = ConnectionManagerMock(token_address, funds)
        self.connection_managers.append(connection_manager)

    def leave(self, token_address, only_receiving):
        if not isaddress(token_address):
            raise InvalidAddress('not an address %s' % pex(token_address))

        # for the mocking purposes let's just ignore only_receiving_ but keep its
        # value in the mock context for checking
        self.last_only_receiving = only_receiving

        channels = self.get_all_channels_for_token(token_address)
        for channel in channels:
            channel.external_state.netting_channel.state = CHANNEL_STATE_SETTLED
            channel.external_state._settled_block = 1

        return channels

    def get_connection_managers_info(self):
        token_addresses = {}

        for connection_manager in self.connection_managers:
            token_addresses[connection_manager.token_address] = {
                'funds': connection_manager.funds,
                'sum_deposits': connection_manager.sum_deposits,
                'channels': len(connection_manager.open_channels),
            }

        return token_addresses

    def get_all_channels_for_token(self, token_address):
        channels = [channel for channel in self.channels if channel.token_address == token_address]

        if len(channels) > 0:
            return channels
        else:
            raise ValueError('Could not find channel')
