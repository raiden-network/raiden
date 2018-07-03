import itertools
from collections import namedtuple, defaultdict
from typing import List, Dict

import structlog
from eth_utils import to_canonical_address
from raiden_contracts.constants import CONTRACT_SECRET_REGISTRY, EVENT_SECRET_REVEALED
import raiden_contracts.contract_manager

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
from raiden.network.blockchain_service import BlockChainService
from raiden.network.proxies import PaymentChannel
from raiden.exceptions import AddressWithoutCode
from raiden.utils import pex, typing
from raiden.utils.filters import decode_event
from raiden.utils.typing import Address, BlockSpecification

EventListener = namedtuple(
    'EventListener',
    ('event_name', 'filter', 'abi', 'first_run'),
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
        chain: BlockChainService,
        abi: Dict,
        contract_address: Address,
        topics: List[str],
        from_block: BlockSpecification,
        to_block: BlockSpecification,
) -> List[Dict]:
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
        chain: BlockChainService,
        channel_manager_address: Address,
        events: List[str] = ALL_EVENTS,
        from_block: BlockSpecification = 0,
        to_block: BlockSpecification = 'latest',
) -> List[Dict]:
    """ Helper to get all events of the ChannelManagerContract at `token_address`. """

    return get_contract_events(
        chain,
        CONTRACT_MANAGER.get_contract_abi(CONTRACT_CHANNEL_MANAGER),
        channel_manager_address,
        events,
        from_block,
        to_block,
    )


def get_all_registry_events(
        chain: BlockChainService,
        registry_address: Address,
        events: List[str] = ALL_EVENTS,
        from_block: BlockSpecification = 0,
        to_block: BlockSpecification = 'latest',
) -> List[Dict]:
    """ Helper to get all events of the Registry contract at `registry_address`. """
    return get_contract_events(
        chain,
        CONTRACT_MANAGER.get_contract_abi(CONTRACT_REGISTRY),
        registry_address,
        events,
        from_block,
        to_block,
    )


def get_all_netting_channel_events(
        chain: BlockChainService,
        netting_channel_address: Address,
        events: List[str] = ALL_EVENTS,
        from_block: BlockSpecification = 0,
        to_block: BlockSpecification = 'latest',
) -> List[Dict]:
    """ Helper to get all events of a NettingChannelContract. """

    return get_contract_events(
        chain,
        CONTRACT_MANAGER.get_contract_abi(CONTRACT_NETTING_CHANNEL),
        netting_channel_address,
        events,
        from_block,
        to_block,
    )


def get_all_secret_registry_events(
        chain: BlockChainService,
        secret_registry_address: Address,
        events: List[str] = ALL_EVENTS,
        from_block: BlockSpecification = 0,
        to_block: BlockSpecification = 'latest',
) -> List[Dict]:
    """ Helper to get all events of a SecretRegistry. """

    return get_contract_events(
        chain,
        raiden_contracts.contract_manager.CONTRACT_MANAGER.get_contract_abi(
            CONTRACT_SECRET_REGISTRY,
        ),
        secret_registry_address,
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

    elif data['event'] == EVENT_SECRET_REVEALED:
        data['secrethash'] = data['args']['secrethash']
        data['secret'] = data['args']['secret']

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
        self.first_run = True

    def reset(self):
        self.first_run = True

    def poll_blockchain_events(self):
        # When we test with geth if the contracts have already been deployed
        # before the filter creation we need to use `get_all_entries` to make
        # sure we get all the events. With tester this is not required.

        for event_listener in self.event_listeners:
            query_fn = 'get_new_entries'
            if event_listener.first_run is True:
                query_fn = 'get_all_entries'
                index = self.event_listeners.index(event_listener)
                self.event_listeners[index] = event_listener._replace(first_run=False)
            for log_event in getattr(event_listener.filter, query_fn)():
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

    def add_event_listener(self, event_name, eth_filter, abi):
        existing_listeners = [x.event_name for x in self.event_listeners]
        if event_name in existing_listeners:
            return
        event = EventListener(
            event_name,
            eth_filter,
            abi,
            True,
        )
        self.event_listeners.append(event)

    def add_registry_listener(
            self,
            registry_proxy,
            from_block: typing.BlockSpecification = 'latest',
    ):
        tokenadded = registry_proxy.tokenadded_filter(from_block)
        registry_address = registry_proxy.address

        self.add_event_listener(
            'Registry {}'.format(pex(registry_address)),
            tokenadded,
            CONTRACT_MANAGER.get_contract_abi(CONTRACT_REGISTRY),
        )

    def add_channel_manager_listener(
            self,
            channel_manager_proxy,
            from_block: typing.BlockSpecification = 'latest',
    ):
        channelnew = channel_manager_proxy.channelnew_filter(from_block=from_block)
        manager_address = channel_manager_proxy.address

        self.add_event_listener(
            'ChannelManager {}'.format(pex(manager_address)),
            channelnew,
            CONTRACT_MANAGER.get_contract_abi(CONTRACT_CHANNEL_MANAGER),
        )

    def add_token_network_listener(
            self,
            token_network_proxy,
            from_block: typing.BlockSpecification = 'latest',
    ):
        channel_new_filter = token_network_proxy.channelnew_filter(from_block=from_block)
        token_network_address = token_network_proxy.address

        self.add_event_listener(
            'TokenNetwork {}'.format(pex(token_network_address)),
            channel_new_filter,
            CONTRACT_MANAGER.get_contract_abi(CONTRACT_TOKEN_NETWORK),
        )

    def add_netting_channel_listener(
            self,
            netting_channel_proxy,
            from_block: typing.BlockSpecification = 'latest',
    ):
        netting_channel_events = netting_channel_proxy.all_events_filter(from_block=from_block)
        channel_address = netting_channel_proxy.address

        self.add_event_listener(
            'NettingChannel Event {}'.format(pex(channel_address)),
            netting_channel_events,
            CONTRACT_MANAGER.get_contract_abi(CONTRACT_NETTING_CHANNEL),
        )

    def add_payment_channel_listener(
        self,
        payment_channel_proxy: PaymentChannel,
        from_block: typing.BlockSpecification = 'latest',
    ):
        payment_channel_filter = payment_channel_proxy.all_events_filter(from_block=from_block)
        channel_identifier = payment_channel_proxy.channel_identifier()

        self.add_event_listener(
            f'PaymentChannel event {channel_identifier}',
            payment_channel_filter,
            raiden_contracts.contract_manager.CONTRACT_MANAGER.get_contract_abi(
                CONTRACT_TOKEN_NETWORK,
            ),
        )

    def add_proxies_listeners(self, proxies, from_block: typing.BlockSpecification = 'latest'):
        self.add_registry_listener(proxies.registry, from_block)

        for manager in proxies.channel_managers:
            self.add_channel_manager_listener(manager, from_block)

        all_netting_channels = itertools.chain(
            *proxies.channelmanager_nettingchannels.values(),
        )

        for channel in all_netting_channels:
            self.add_netting_channel_listener(channel, from_block)
