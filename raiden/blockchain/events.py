from collections import namedtuple
from typing import Dict, List

import structlog
from eth_utils import encode_hex, event_abi_to_log_topic, to_canonical_address

from raiden.constants import UINT64_MAX
from raiden.exceptions import InvalidBlockNumberInput
from raiden.network.blockchain_service import BlockChainService
from raiden.network.proxies import SecretRegistry
from raiden.utils import pex, typing
from raiden.utils.filters import (
    StatelessFilter,
    decode_event,
    get_filter_args_for_all_events_from_channel,
)
from raiden.utils.typing import Address, BlockSpecification, ChannelID
from raiden_contracts.constants import (
    CONTRACT_SECRET_REGISTRY,
    CONTRACT_TOKEN_NETWORK,
    CONTRACT_TOKEN_NETWORK_REGISTRY,
    EVENT_SECRET_REVEALED,
    EVENT_TOKEN_NETWORK_CREATED,
    ChannelEvent,
)
from raiden_contracts.contract_manager import CONTRACT_MANAGER


def verify_block_number(number: typing.BlockSpecification, argname: str):
    if isinstance(number, int) and (number < 0 or number > UINT64_MAX):
        raise InvalidBlockNumberInput(
            'Provided block number {} for {} is invalid. Has to be in the range '
            'of [0, UINT64_MAX]'.format(number, argname),
        )


EventListener = namedtuple(
    'EventListener',
    ('event_name', 'filter', 'abi', 'first_run'),
)
Proxies = namedtuple(
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
    verify_block_number(from_block, 'from_block')
    verify_block_number(to_block, 'to_block')
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
            del decoded_event['blockNumber']
        result.append(decoded_event)
    return result


# These helpers have a better descriptive name and provide the translator for
# the caller.


def get_token_network_registry_events(
        chain: BlockChainService,
        token_network_registry_address: Address,
        events: List[str] = ALL_EVENTS,
        from_block: BlockSpecification = 0,
        to_block: BlockSpecification = 'latest',
) -> List[Dict]:
    """ Helper to get all events of the Registry contract at `registry_address`. """
    return get_contract_events(
        chain,
        CONTRACT_MANAGER.get_contract_abi(CONTRACT_TOKEN_NETWORK_REGISTRY),
        token_network_registry_address,
        events,
        from_block,
        to_block,
    )


def get_token_network_events(
        chain: BlockChainService,
        token_network_address: Address,
        events: List[str] = ALL_EVENTS,
        from_block: BlockSpecification = 0,
        to_block: BlockSpecification = 'latest',
) -> List[Dict]:
    """ Helper to get all events of the ChannelManagerContract at `token_address`. """

    return get_contract_events(
        chain,
        CONTRACT_MANAGER.get_contract_abi(CONTRACT_TOKEN_NETWORK),
        token_network_address,
        events,
        from_block,
        to_block,
    )


def get_all_netting_channel_events(
        chain: BlockChainService,
        token_network_address: Address,
        netting_channel_identifier: ChannelID,
        events: List[str] = ALL_EVENTS,
        from_block: BlockSpecification = 0,
        to_block: BlockSpecification = 'latest',
) -> List[Dict]:
    """ Helper to get all events of a NettingChannelContract. """

    filter_args = get_filter_args_for_all_events_from_channel(
        token_network_address=token_network_address,
        channel_identifier=netting_channel_identifier,
        from_block=from_block,
        to_block=to_block,
    )

    return get_contract_events(
        chain,
        CONTRACT_MANAGER.get_contract_abi(CONTRACT_TOKEN_NETWORK),
        token_network_address,
        filter_args['topics'],
        from_block,
        to_block,
    )


def get_netting_channel_closed_events(
        chain: BlockChainService,
        token_network_address: Address,
        netting_channel_identifier: ChannelID,
        events: List[str] = ALL_EVENTS,
        from_block: BlockSpecification = 0,
        to_block: BlockSpecification = 'latest',
) -> List[Dict]:
    closed_event_abi = CONTRACT_MANAGER.get_event_abi(
        CONTRACT_TOKEN_NETWORK,
        ChannelEvent.CLOSED,
    )
    closed_event_id = encode_hex(event_abi_to_log_topic(closed_event_abi))
    closed_topics = [closed_event_id]

    return get_contract_events(
        chain,
        CONTRACT_MANAGER.get_contract_abi(CONTRACT_TOKEN_NETWORK),
        token_network_address,
        closed_topics,
        from_block,
        to_block,
    )


def get_netting_channel_deposit_events(
        chain: BlockChainService,
        token_network_address: Address,
        netting_channel_identifier: ChannelID,
        events: List[str] = ALL_EVENTS,
        from_block: BlockSpecification = 0,
        to_block: BlockSpecification = 'latest',
) -> List[Dict]:
    deposit_event_abi = CONTRACT_MANAGER.get_event_abi(
        CONTRACT_TOKEN_NETWORK,
        ChannelEvent.DEPOSIT,
    )
    deposit_event_id = encode_hex(event_abi_to_log_topic(deposit_event_abi))
    deposit_topics = [deposit_event_id]

    return get_contract_events(
        chain,
        CONTRACT_MANAGER.get_contract_abi(CONTRACT_TOKEN_NETWORK),
        token_network_address,
        deposit_topics,
        from_block,
        to_block,
    )


def get_netting_channel_settled_events(
        chain: BlockChainService,
        token_network_address: Address,
        netting_channel_identifier: ChannelID,
        events: List[str] = ALL_EVENTS,
        from_block: BlockSpecification = 0,
        to_block: BlockSpecification = 'latest',
) -> List[Dict]:
    settled_event_abi = CONTRACT_MANAGER.get_event_abi(
        CONTRACT_TOKEN_NETWORK,
        ChannelEvent.SETTLED,
    )
    settled_event_id = encode_hex(event_abi_to_log_topic(settled_event_abi))
    settled_topics = [settled_event_id]

    return get_contract_events(
        chain,
        CONTRACT_MANAGER.get_contract_abi(CONTRACT_TOKEN_NETWORK),
        token_network_address,
        settled_topics,
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
        CONTRACT_MANAGER.get_contract_abi(
            CONTRACT_SECRET_REGISTRY,
        ),
        secret_registry_address,
        events,
        from_block,
        to_block,
    )


def decode_event_to_internal(event):
    """ Enforce the binary encoding of address for internal usage. """
    data = event.event_data

    if data['args'].get('channel_identifier'):
        data['channel_identifier'] = data['args'].get('channel_identifier')

    # Note: All addresses inside the event_data must be decoded.
    if data['event'] == EVENT_TOKEN_NETWORK_CREATED:
        data['token_network_address'] = to_canonical_address(data['args']['token_network_address'])
        data['token_address'] = to_canonical_address(data['args']['token_address'])

    elif data['event'] == ChannelEvent.OPENED:
        data['participant1'] = to_canonical_address(data['args']['participant1'])
        data['participant2'] = to_canonical_address(data['args']['participant2'])
        data['settle_timeout'] = data['args']['settle_timeout']

    elif data['event'] == ChannelEvent.DEPOSIT:
        data['deposit'] = data['args']['total_deposit']
        data['participant'] = to_canonical_address(data['args']['participant'])

    elif data['event'] == ChannelEvent.WITHDRAW:
        data['withdrawn_amount'] = data['args']['withdrawn_amount']
        data['participant'] = to_canonical_address(data['args']['participant'])

    elif data['event'] == ChannelEvent.BALANCE_PROOF_UPDATED:
        data['closing_participant'] = to_canonical_address(data['args']['closing_participant'])

    elif data['event'] == ChannelEvent.CLOSED:
        data['closing_participant'] = to_canonical_address(data['args']['closing_participant'])

    elif data['event'] == ChannelEvent.SETTLED:
        data['participant1_amount'] = data['args']['participant1_amount']
        data['participant2_amount'] = data['args']['participant2_amount']

    elif data['event'] == ChannelEvent.UNLOCKED:
        data['unlocked_amount'] = data['args']['unlocked_amount']
        data['returned_tokens'] = data['args']['returned_tokens']
        data['participant'] = to_canonical_address(data['args']['participant'])
        data['partner'] = to_canonical_address(data['args']['partner'])
        data['locksroot'] = data['args']['locksroot']

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

    def reset(self):
        listeners = [
            event_listener._replace(first_run=True)
            for event_listener in self.event_listeners
        ]
        self.event_listeners = listeners

    def poll_blockchain_events(self, block_number: int = None):
        # When we test with geth if the contracts have already been deployed
        # before the filter creation we need to use `get_all_entries` to make
        # sure we get all the events. With tester this is not required.

        for event_listener in self.event_listeners:
            if isinstance(event_listener.filter, StatelessFilter):
                events = event_listener.filter.get_new_entries(block_number)
            elif event_listener.first_run is True:
                events = event_listener.filter.get_all_entries()
                index = self.event_listeners.index(event_listener)
                self.event_listeners[index] = event_listener._replace(first_run=False)
            else:
                events = event_listener.filter.get_new_entries()

            for log_event in events:
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
            if listener.filter.filter_id:
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

    def add_token_network_registry_listener(
            self,
            token_network_registry_proxy,
            from_block: typing.BlockSpecification = 'latest',
    ):
        token_new_filter = token_network_registry_proxy.tokenadded_filter(from_block=from_block)
        token_network_registry_address = token_network_registry_proxy.address

        self.add_event_listener(
            'TokenNetwork {}'.format(pex(token_network_registry_address)),
            token_new_filter,
            CONTRACT_MANAGER.get_contract_abi(CONTRACT_TOKEN_NETWORK_REGISTRY),
        )

    def add_token_network_listener(
            self,
            token_network_proxy,
            from_block: typing.BlockSpecification = 'latest',
    ):
        _filter = token_network_proxy.all_events_filter(from_block=from_block)
        token_network_address = token_network_proxy.address

        self.add_event_listener(
            'TokenNetwork {}'.format(pex(token_network_address)),
            _filter,
            CONTRACT_MANAGER.get_contract_abi(CONTRACT_TOKEN_NETWORK),
        )

    def add_secret_registry_listener(
            self,
            secret_registry_proxy: SecretRegistry,
            from_block: typing.BlockSpecification = 'latest',
    ):
        secret_registry_filter = secret_registry_proxy.secret_registered_filter(
            from_block=from_block,
        )
        secret_registry_address = secret_registry_proxy.address
        self.add_event_listener(
            'SecretRegistry {}'.format(pex(secret_registry_address)),
            secret_registry_filter,
            CONTRACT_MANAGER.get_contract_abi(CONTRACT_SECRET_REGISTRY),
        )
