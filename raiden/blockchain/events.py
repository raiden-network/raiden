# -*- coding: utf-8 -*-
import itertools
from collections import namedtuple, defaultdict

from ethereum import slogging

from raiden.blockchain.abi import (
    CONTRACT_MANAGER,
    CONTRACT_CHANNEL_MANAGER,
    CONTRACT_NETTING_CHANNEL,
    CONTRACT_REGISTRY,
)
from raiden.exceptions import (
    AddressWithoutCode,
    EthNodeCommunicationError,
)
from raiden.network.rpc.filters import get_filter_events
from raiden.utils import address_decoder, pex

EventListener = namedtuple(
    'EventListener',
    ('event_name', 'filter', 'translator', 'filter_creation_function'),
)
Proxies = namedtuple(
    'Proxies',
    ('registry', 'channel_managers', 'channelmanager_nettingchannels'),
)

# `new_filter` uses None to signal the absence of topics filters
ALL_EVENTS = None
log = slogging.get_logger(__name__)  # pylint: disable=invalid-name


def poll_event_listener(eth_filter, translator):
    result = list()

    for log_event in eth_filter.changes():
        decoded_event = translator.decode_event(
            log_event['topics'],
            log_event['data'],
        )

        if decoded_event is not None:
            decoded_event['block_number'] = log_event.get('block_number')
            event = Event(
                log_event['address'],
                decoded_event,
            )
            result.append(event)

    return result


def get_contract_events(
        chain,
        translator,
        contract_address,
        topics,
        from_block,
        to_block):
    """ Query the blockchain for all events of the smart contract at
    `contract_address` that match the filters `topics`, `from_block`, and
    `to_block`.
    """
    # Note: Issue #452 (https://github.com/raiden-network/raiden/issues/452)
    # tracks a suggested TODO, which will reduce the 3 RPC calls here to only
    # one using `eth_getLogs`. It will require changes in all testing frameworks
    # to be implemented though.

    events = get_filter_events(
        chain.client,
        contract_address,
        topics=topics,
        from_block=from_block,
        to_block=to_block
    )

    result = []
    for event in events:
        decoded_event = translator.decode_event(event['topics'], event['data'])
        if event.get('block_number'):
            decoded_event['block_number'] = event['block_number']
        result.append(decoded_event)
    return result


# These helpers have a better descriptive name and provide the translator for
# the caller.

def get_all_channel_manager_events(
        chain,
        channel_manager_address,
        events=ALL_EVENTS,
        from_block=0,
        to_block='latest'):
    """ Helper to get all events of the ChannelManagerContract at
    `token_address`.
    """

    return get_contract_events(
        chain,
        CONTRACT_MANAGER.get_translator(CONTRACT_CHANNEL_MANAGER),
        channel_manager_address,
        events,
        from_block,
        to_block,
    )


def get_all_registry_events(
        chain,
        registry_address,
        events=ALL_EVENTS,
        from_block=0,
        to_block='latest'):
    """ Helper to get all events of the Registry contract at
    `registry_address`.
    """
    return get_contract_events(
        chain,
        CONTRACT_MANAGER.get_translator(CONTRACT_REGISTRY),
        registry_address,
        events,
        from_block,
        to_block,
    )


def get_all_netting_channel_events(
        chain,
        netting_channel_address,
        events=ALL_EVENTS,
        from_block=0,
        to_block='latest'):
    """ Helper to get all events of a NettingChannelContract at
    `channel_identifier`.
    """

    return get_contract_events(
        chain,
        CONTRACT_MANAGER.get_translator(CONTRACT_NETTING_CHANNEL),
        netting_channel_address,
        events,
        from_block,
        to_block,
    )


def get_channel_proxies(chain, node_address, channel_manager):
    participating_channels = channel_manager.channels_by_participant(node_address)
    netting_channels = []
    for channel_identifier in participating_channels:
        # FIXME: implement proper cleanup of self-killed channel after close+settle
        try:
            netting_channels.append(chain.netting_channel(channel_identifier))
        except AddressWithoutCode:
            log.debug(
                'Settled channel found when starting raiden. Safely ignored',
                channel_identifier=pex(channel_identifier)
            )
    return netting_channels


def get_relevant_proxies(chain, node_address, registry_address):
    registry = chain.registry(registry_address)

    channel_managers = list()
    manager_channels = defaultdict(list)

    for channel_manager_address in registry.manager_addresses():
        channel_manager = registry.manager(channel_manager_address)
        channel_managers.append(channel_manager)

        netting_channel_proxies = get_channel_proxies(chain, node_address, channel_manager)
        manager_channels[channel_manager_address] = netting_channel_proxies

    proxies = Proxies(
        registry,
        channel_managers,
        manager_channels,
    )

    return proxies


def decode_event(event):
    """ Enforce the binary encoding of address for internal usage. """
    data = event.event_data
    assert isinstance(data['_event_type'], bytes)

    # Note: All addresses inside the event_data must be decoded.
    if data['_event_type'] == b'TokenAdded':
        data['channel_manager_address'] = address_decoder(data['channel_manager_address'])
        data['token_address'] = address_decoder(data['token_address'])

    elif data['_event_type'] == b'ChannelNew':
        data['participant1'] = address_decoder(data['participant1'])
        data['participant2'] = address_decoder(data['participant2'])
        data['netting_channel'] = address_decoder(data['netting_channel'])

    elif data['_event_type'] == b'ChannelNewBalance':
        data['token_address'] = address_decoder(data['token_address'])
        data['participant'] = address_decoder(data['participant'])

    elif data['_event_type'] == b'ChannelClosed':
        data['closing_address'] = address_decoder(data['closing_address'])

    elif data['_event_type'] == b'ChannelSecretRevealed':
        data['receiver_address'] = address_decoder(data['receiver_address'])

    return event


class Event:
    def __init__(self, originating_contract, event_data):
        self.originating_contract = originating_contract
        self.event_data = event_data

    def __repr__(self):
        return '<Event contract: {} event: {}>'.format(
            pex(self.originating_contract),
            self.event_data,
        )


class BlockchainEvents:
    """ Events polling. """

    def __init__(self):
        self.event_listeners = list()

    def poll_all_event_listeners(self, from_block=None):
        result = list()
        reinstalled_filters = False

        while True:
            try:
                for event_listener in self.event_listeners:
                    decoded_events = poll_event_listener(
                        event_listener.filter,
                        event_listener.translator,
                    )
                    result.extend(decoded_events)
                break
            except EthNodeCommunicationError as e:
                # If the eth client has restarted and we reconnected to it then
                # filters will no longer exist there. In that case we will need
                # to recreate all the filters.
                if not reinstalled_filters and str(e) == 'filter not found':
                    result = list()
                    reinstalled_filters = True
                    updated_event_listerners = list()

                    for event_listener in self.event_listeners:
                        new_listener = EventListener(
                            event_listener.event_name,
                            event_listener.filter_creation_function(from_block=from_block),
                            event_listener.translator,
                            event_listener.filter_creation_function,
                        )
                        updated_event_listerners.append(new_listener)

                    self.event_listeners = updated_event_listerners
                else:
                    raise e

        return result

    def poll_blockchain_events(self, from_block=None):
        for event in self.poll_all_event_listeners(from_block):
            yield decode_event(event)

    def uninstall_all_event_listeners(self):
        for listener in self.event_listeners:
            listener.filter.uninstall()

        self.event_listeners = list()

    def add_event_listener(self, event_name, eth_filter, translator, filter_creation_function):
        event = EventListener(
            event_name,
            eth_filter,
            translator,
            filter_creation_function,
        )
        self.event_listeners.append(event)

        return poll_event_listener(eth_filter, translator)

    def add_registry_listener(self, registry_proxy):
        tokenadded = registry_proxy.tokenadded_filter()
        registry_address = registry_proxy.address

        self.add_event_listener(
            'Registry {}'.format(pex(registry_address)),
            tokenadded,
            CONTRACT_MANAGER.get_translator(CONTRACT_REGISTRY),
            registry_proxy.tokenadded_filter,
        )

    def add_channel_manager_listener(self, channel_manager_proxy):
        channelnew = channel_manager_proxy.channelnew_filter()
        manager_address = channel_manager_proxy.address

        self.add_event_listener(
            'ChannelManager {}'.format(pex(manager_address)),
            channelnew,
            CONTRACT_MANAGER.get_translator('channel_manager'),
            channel_manager_proxy.channelnew_filter,
        )

    def add_netting_channel_listener(self, netting_channel_proxy):
        netting_channel_events = netting_channel_proxy.all_events_filter()
        channel_address = netting_channel_proxy.address

        self.add_event_listener(
            'NettingChannel Event {}'.format(pex(channel_address)),
            netting_channel_events,
            CONTRACT_MANAGER.get_translator('netting_channel'),
            netting_channel_proxy.all_events_filter,
        )

    def add_proxies_listeners(self, proxies):
        self.add_registry_listener(proxies.registry)

        for manager in proxies.channel_managers:
            self.add_channel_manager_listener(manager)

        all_netting_channels = itertools.chain(
            *proxies.channelmanager_nettingchannels.values()
        )
        for channel in all_netting_channels:
            self.add_netting_channel_listener(channel)
