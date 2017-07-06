# -*- coding: utf-8 -*-
import itertools
from collections import namedtuple, defaultdict

from pyethapp.jsonrpc import address_decoder

from raiden.blockchain.abi import (
    REGISTRY_TRANSLATOR,
    CHANNEL_MANAGER_TRANSLATOR,
    NETTING_CHANNEL_TRANSLATOR,
)
from raiden.utils import pex
from raiden.network.rpc.client import new_filter, Filter

from raiden.transfer.mediated_transfer.state_change import (
    ContractReceiveTokenAdded,
    ContractReceiveBalance,
    ContractReceiveClosed,
    ContractReceiveNewChannel,
    ContractReceiveSettled,
    ContractReceiveWithdraw,
)

PyethappEventListener = namedtuple(
    'EventListener',
    ('event_name', 'pyethapp_filter', 'translator'),
)
PyethappEvent = namedtuple(
    'BlockchainEvent',
    ('originating_contract', 'event_data'),
)
PyethappProxies = namedtuple(
    'PyethappProxies',
    ('registry', 'channel_managers', 'channelmanager_nettingchannels'),
)

# Pyethapp's `new_filter` uses None to signal the absence of topics filters
ALL_EVENTS = None


def poll_event_listener(pyethapp_filter, translator):
    result = list()

    for log_event in pyethapp_filter.changes():
        decoded_event = translator.decode_event(
            log_event['topics'],
            log_event['data'],
        )

        if decoded_event is not None:
            pyethapp_event = PyethappEvent(
                log_event['address'],
                decoded_event,
            )
            result.append(pyethapp_event)

    return result


def get_contract_events(
        pyethapp_chain,
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

    filter_ = None
    pyethapp_client = pyethapp_chain.client
    try:
        filter_id_raw = new_filter(
            pyethapp_client,
            contract_address,
            topics=topics,
            from_block=from_block,
            to_block=to_block
        )
        filter_ = Filter(pyethapp_client, filter_id_raw)
        events = filter_.getall()
    finally:
        if filter_ is not None:
            filter_.uninstall()

    return [
        translator.decode_event(event['topics'], event['data'])
        for event in events
    ]


# These helpers have a better descriptive name and provide the translator for
# the caller.

def get_all_channel_manager_events(
        pyethapp_chain,
        channel_manager_address,
        events=ALL_EVENTS,
        from_block=0,
        to_block='latest'):
    """ Helper to get all events of the ChannelManagerContract at
    `token_address`.
    """

    return get_contract_events(
        pyethapp_chain,
        CHANNEL_MANAGER_TRANSLATOR,
        channel_manager_address,
        events,
        from_block,
        to_block,
    )


def get_all_registry_events(
        pyethapp_chain,
        registry_address,
        events=ALL_EVENTS,
        from_block=0,
        to_block='latest'):
    """ Helper to get all events of the Registry contract at
    `registry_address`.
    """
    return get_contract_events(
        pyethapp_chain,
        REGISTRY_TRANSLATOR,
        registry_address,
        events,
        from_block,
        to_block,
    )


def get_all_netting_channel_events(
        pyethapp_chain,
        netting_channel_address,
        events=ALL_EVENTS,
        from_block=0,
        to_block='latest'):
    """ Helper to get all events of a NettingChannelContract at
    `netting_channel_address`.
    """

    return get_contract_events(
        pyethapp_chain,
        NETTING_CHANNEL_TRANSLATOR,
        netting_channel_address,
        events,
        from_block,
        to_block,
    )


def get_relevant_proxies(pyethapp_chain, node_address, registry_address):
    registry = pyethapp_chain.registry(registry_address)

    channel_managers = list()
    manager_channels = defaultdict(list)

    for channel_manager_address in registry.manager_addresses():
        channel_manager = pyethapp_chain.manager(channel_manager_address)
        channel_managers.append(channel_manager)

        participating_channels = channel_manager.channels_by_participant(node_address)
        netting_channels = [
            pyethapp_chain.netting_channel(channel_address)
            for channel_address in participating_channels
        ]
        manager_channels[channel_manager_address] = netting_channels

    proxies = PyethappProxies(
        registry,
        channel_managers,
        manager_channels,
    )

    return proxies


def pyethapp_event_to_state_change(pyethapp_event):  # pylint: disable=too-many-return-statements
    contract_address = pyethapp_event.originating_contract
    event = pyethapp_event.event_data

    # Raiden uses the binary representation of address internally, pyethapp
    # keeps the addresses in hex representation inside the events, so all
    # addresses inside the event_data must be decoded.

    if event['_event_type'] == 'TokenAdded':
        return ContractReceiveTokenAdded(
            contract_address,
            address_decoder(event['token_address']),
            address_decoder(event['channel_manager_address']),
        )

    elif event['_event_type'] == 'ChannelNew':
        return ContractReceiveNewChannel(
            contract_address,
            address_decoder(event['netting_channel']),
            address_decoder(event['participant1']),
            address_decoder(event['participant2']),
            event['settle_timeout'],
        )

    elif event['_event_type'] == 'ChannelNewBalance':
        return ContractReceiveBalance(
            contract_address,
            address_decoder(event['token_address']),
            address_decoder(event['participant']),
            event['balance'],
            event['block_number'],
        )

    elif event['_event_type'] == 'ChannelClosed':
        return ContractReceiveClosed(
            contract_address,
            address_decoder(event['closing_address']),
            event['block_number'],
        )

    elif event['_event_type'] == 'ChannelSettled':
        return ContractReceiveSettled(
            contract_address,
            event['block_number'],
        )

    elif event['_event_type'] == 'ChannelSecretRevealed':
        return ContractReceiveWithdraw(
            contract_address,
            event['secret'],
            address_decoder(event['receiver_address']),
        )

    else:
        return None


class PyethappBlockchainEvents(object):
    """ Pyethapp events polling. """

    def __init__(self):
        self.event_listeners = list()

    def poll_all_event_listeners(self):
        result = list()

        for event_listener in self.event_listeners:
            decoded_events = poll_event_listener(
                event_listener.pyethapp_filter,
                event_listener.translator,
            )
            result.extend(decoded_events)

        return result

    def poll_state_change(self):
        for event in self.poll_all_event_listeners():
            yield pyethapp_event_to_state_change(event)

    def uninstall_all_event_listeners(self):
        for listener in self.event_listeners:
            listener.pyethapp_filter.uninstall()

        self.event_listeners = list()

    def add_event_listener(self, event_name, pyethapp_filter, translator):
        event = PyethappEventListener(
            event_name,
            pyethapp_filter,
            translator,
        )
        self.event_listeners.append(event)

        return poll_event_listener(pyethapp_filter, translator)

    def add_registry_listener(self, registry_proxy):
        tokenadded = registry_proxy.tokenadded_filter()
        registry_address = registry_proxy.address

        self.add_event_listener(
            'Registry {}'.format(pex(registry_address)),
            tokenadded,
            REGISTRY_TRANSLATOR,
        )

    def add_channel_manager_listener(self, channel_manager_proxy):
        channelnew = channel_manager_proxy.channelnew_filter()
        manager_address = channel_manager_proxy.address

        self.add_event_listener(
            'ChannelManager {}'.format(pex(manager_address)),
            channelnew,
            CHANNEL_MANAGER_TRANSLATOR,
        )

    def add_netting_channel_listener(self, netting_channel_proxy):
        channel_address = netting_channel_proxy.address
        netting_channel_events = netting_channel_proxy.all_events_filter()

        self.add_event_listener(
            'NettingChannel Event {}'.format(pex(channel_address)),
            netting_channel_events,
            NETTING_CHANNEL_TRANSLATOR,
        )

    def add_proxies_listeners(self, pyethapp_proxies):
        self.add_registry_listener(pyethapp_proxies.registry)

        for manager in pyethapp_proxies.channel_managers:
            self.add_channel_manager_listener(manager)

        all_netting_channels = itertools.chain(
            *pyethapp_proxies.channelmanager_nettingchannels.itervalues()
        )
        for channel in all_netting_channels:
            self.add_netting_channel_listener(channel)
