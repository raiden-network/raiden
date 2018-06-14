# -*- coding: utf-8 -*-
import itertools
from collections import namedtuple, defaultdict

import structlog
from eth_utils import to_canonical_address

from raiden.blockchain.abi import (
    CONTRACT_MANAGER,
    CONTRACT_CHANNEL_MANAGER,
    CONTRACT_NETTING_CHANNEL,
    CONTRACT_REGISTRY,
    CONTRACT_TOKEN_NETWORK,
    EVENT_TOKEN_ADDED,
    EVENT_TOKEN_ADDED2,
    EVENT_CHANNEL_NEW,
    EVENT_CHANNEL_NEW2,
    EVENT_CHANNEL_NEW_BALANCE,
    EVENT_CHANNEL_NEW_BALANCE2,
    EVENT_CHANNEL_WITHDRAW,
    EVENT_CHANNEL_UNLOCK,
    EVENT_BALANCE_PROOF_UPDATED,
    EVENT_CHANNEL_CLOSED,
    EVENT_CHANNEL_SETTLED,
    EVENT_CHANNEL_SECRET_REVEALED,
)
from raiden.exceptions import AddressWithoutCode
from raiden.utils import pex
from raiden.network.rpc.smartcontract_proxy import decode_event

EventListener = namedtuple(
    'EventListener',
    ('event_name', 'filter', 'abi', 'filter_creation_function'),
)
Proxies = namedtuple(
    'Proxies',
    ('registry', 'channel_managers', 'channelmanager_nettingchannels'),
)
Proxies2 = namedtuple(
    'Proxies',
    ('token_registry', 'token_networks'),
)

# `new_filter` uses None to signal the absence of topics filters
ALL_EVENTS = None
log = structlog.get_logger(__name__)  # pylint: disable=invalid-name


def get_contract_events(
        chain,
        abi,
        contract_address,
        topics,
        from_block,
        to_block):
    """ Query the blockchain for all events of the smart contract at
    `contract_address` that match the filters `topics`, `from_block`, and
    `to_block`.
    """
    events = chain.client.get_filter_events(
        contract_address,
        topics=topics,
        from_block=from_block,
        to_block=to_block,
    )

    result = []
    for event in events:
        decoded_event = dict(decode_event(abi, event))
        if event.get('blockNumber'):
            decoded_event['block_number'] = event['blockNumber']
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
        CONTRACT_MANAGER.get_contract_abi(CONTRACT_CHANNEL_MANAGER),
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
        CONTRACT_MANAGER.get_contract_abi(CONTRACT_REGISTRY),
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
        CONTRACT_MANAGER.get_contract_abi(CONTRACT_NETTING_CHANNEL),
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
                channel_identifier=pex(channel_identifier),
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


def decode_event_to_internal(event):
    """ Enforce the binary encoding of address for internal usage. """
    data = event.event_data

    # Note: All addresses inside the event_data must be decoded.
    if data['event'] == EVENT_TOKEN_ADDED:
        data['registry_address'] = to_canonical_address(data['args']['registry_address'])
        data['channel_manager_address'] = to_canonical_address(
            data['args']['channel_manager_address'],
        )
        data['token_address'] = to_canonical_address(data['args']['token_address'])

    elif data['event'] == EVENT_CHANNEL_NEW:
        data['registry_address'] = to_canonical_address(data['args']['registry_address'])
        data['participant1'] = to_canonical_address(data['args']['participant1'])
        data['participant2'] = to_canonical_address(data['args']['participant2'])
        data['netting_channel'] = to_canonical_address(data['args']['netting_channel'])

    elif data['event'] == EVENT_CHANNEL_NEW_BALANCE:
        data['registry_address'] = to_canonical_address(data['args']['registry_address'])
        data['token_address'] = to_canonical_address(data['args']['token_address'])
        data['participant'] = to_canonical_address(data['args']['participant'])

    elif data['event'] == EVENT_CHANNEL_CLOSED:
        data['registry_address'] = to_canonical_address(data['args']['registry_address'])
        data['closing_address'] = to_canonical_address(data['args']['closing_address'])

    elif data['event'] == EVENT_CHANNEL_SECRET_REVEALED:
        data['registry_address'] = to_canonical_address(data['args']['registry_address'])
        data['receiver_address'] = to_canonical_address(data['args']['receiver_address'])

    elif data['event'] == EVENT_CHANNEL_SETTLED:
        data['registry_address'] = to_canonical_address(data['args']['registry_address'])

    return event


def decode_event_to_internal2(event):
    """ Enforce the binary encoding of address for internal usage. """
    data = event.event_data

    # Note: All addresses inside the event_data must be decoded.
    if data['event'] == EVENT_TOKEN_ADDED2:
        data['token_network_address'] = to_canonical_address(data['args']['token_network_address'])
        data['token_address'] = to_canonical_address(data['args']['token_address'])

    elif data['event'] == EVENT_CHANNEL_NEW2:
        data['participant1'] = to_canonical_address(data['args']['participant1'])
        data['participant2'] = to_canonical_address(data['args']['participant2'])

    elif data['event'] == EVENT_CHANNEL_NEW_BALANCE2:
        data['participant'] = to_canonical_address(data['args']['participant'])

    elif data['event'] == EVENT_CHANNEL_WITHDRAW:
        data['participant'] = to_canonical_address(data['args']['participant'])

    elif data['event'] == EVENT_CHANNEL_UNLOCK:
        data['participant'] = to_canonical_address(data['args']['participant'])

    elif data['event'] == EVENT_BALANCE_PROOF_UPDATED:
        data['closing_participant'] = to_canonical_address(data['args']['closing_participant'])

    elif data['event'] == EVENT_CHANNEL_CLOSED:
        data['closing_participant'] = to_canonical_address(data['args']['closing_participant'])

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

    def poll_blockchain_events(self):
        for event_listener in self.event_listeners:
            for log_event in event_listener.filter.get_new_entries():
                decoded_event = dict(decode_event(
                    event_listener.abi,
                    log_event,
                ))

                if decoded_event is not None:
                    decoded_event['block_number'] = log_event.get('blockNumber', 0)
                    event = Event(
                        to_canonical_address(log_event['address']),
                        decoded_event,
                    )
                    yield decode_event_to_internal(event)

    def uninstall_all_event_listeners(self):
        for listener in self.event_listeners:
            listener.filter.web3.eth.uninstallFilter(listener.filter.filter_id)

        self.event_listeners = list()

    def add_event_listener(self, event_name, eth_filter, abi, filter_creation_function):
        event = EventListener(
            event_name,
            eth_filter,
            abi,
            filter_creation_function,
        )
        self.event_listeners.append(event)

    def add_registry_listener(self, registry_proxy, from_block=None):
        tokenadded = registry_proxy.tokenadded_filter(from_block)
        registry_address = registry_proxy.address

        self.add_event_listener(
            'Registry {}'.format(pex(registry_address)),
            tokenadded,
            CONTRACT_MANAGER.get_contract_abi(CONTRACT_REGISTRY),
            registry_proxy.tokenadded_filter,
        )

    def add_channel_manager_listener(self, channel_manager_proxy, from_block=None):
        channelnew = channel_manager_proxy.channelnew_filter(from_block)
        manager_address = channel_manager_proxy.address

        self.add_event_listener(
            'ChannelManager {}'.format(pex(manager_address)),
            channelnew,
            CONTRACT_MANAGER.get_contract_abi(CONTRACT_CHANNEL_MANAGER),
            channel_manager_proxy.channelnew_filter,
        )

    def add_token_network_listener(self, token_network_proxy, from_block=None):
        channel_new_filter = token_network_proxy.channelnew_filter(from_block=from_block)
        token_network_address = token_network_proxy.address

        self.add_event_listener(
            'TokenNetwork {}'.format(pex(token_network_address)),
            channel_new_filter,
            CONTRACT_MANAGER.get_contract_abi(CONTRACT_TOKEN_NETWORK),
            token_network_proxy.channelnew_filter,
        )

    def add_netting_channel_listener(self, netting_channel_proxy, from_block=None):
        netting_channel_events = netting_channel_proxy.all_events_filter(from_block)
        channel_address = netting_channel_proxy.address

        self.add_event_listener(
            'NettingChannel Event {}'.format(pex(channel_address)),
            netting_channel_events,
            CONTRACT_MANAGER.get_contract_abi(CONTRACT_NETTING_CHANNEL),
            netting_channel_proxy.all_events_filter,
        )

    def add_proxies_listeners(self, proxies, from_block=None):
        self.add_registry_listener(proxies.registry, from_block)

        for manager in proxies.channel_managers:
            self.add_channel_manager_listener(manager, from_block)

        all_netting_channels = itertools.chain(
            *proxies.channelmanager_nettingchannels.values(),
        )

        for channel in all_netting_channels:
            self.add_netting_channel_listener(channel, from_block)
