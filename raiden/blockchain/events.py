from collections import namedtuple
from typing import List, Dict

import structlog
from eth_utils import to_canonical_address
from raiden_contracts.constants import (
    CONTRACT_SECRET_REGISTRY,
    CONTRACT_TOKEN_NETWORK,
    CONTRACT_TOKEN_NETWORK_REGISTRY,
    EVENT_CHANNEL_BALANCE_PROOF_UPDATED,
    EVENT_CHANNEL_CLOSED,
    EVENT_CHANNEL_DEPOSIT,
    EVENT_CHANNEL_OPENED,
    EVENT_CHANNEL_WITHDRAW,
    EVENT_SECRET_REVEALED,
    EVENT_TOKEN_NETWORK_CREATED,
)
from raiden_contracts.contract_manager import CONTRACT_MANAGER

from raiden.network.blockchain_service import BlockChainService
from raiden.network.proxies import PaymentChannel
from raiden.utils import pex, typing
from raiden.utils.filters import (
    decode_event,
    get_filter_args_for_all_events_from_channel,
)
from raiden.utils.typing import Address, BlockSpecification, ChannelID

EventListener = namedtuple(
    'EventListener',
    ('event_name', 'filter', 'abi'),
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
        netting_channel_identifier,
        filter_args['topics'],
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

    # Note: All addresses inside the event_data must be decoded.
    if data['event'] == EVENT_TOKEN_NETWORK_CREATED:
        data['token_network_address'] = to_canonical_address(data['args']['token_network_address'])
        data['token_address'] = to_canonical_address(data['args']['token_address'])

    elif data['event'] == EVENT_CHANNEL_OPENED:
        data['participant1'] = to_canonical_address(data['args']['participant1'])
        data['participant2'] = to_canonical_address(data['args']['participant2'])

    elif data['event'] == EVENT_CHANNEL_DEPOSIT:
        data['participant'] = to_canonical_address(data['args']['participant'])

    elif data['event'] == EVENT_CHANNEL_WITHDRAW:
        data['participant'] = to_canonical_address(data['args']['participant'])

    elif data['event'] == EVENT_CHANNEL_BALANCE_PROOF_UPDATED:
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
        if self.first_run:
            query_fn = 'get_all_entries'
            self.first_run = False
        else:
            query_fn = 'get_new_entries'

        for event_listener in self.event_listeners:
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
        channel_new_filter = token_network_proxy.channelnew_filter(from_block=from_block)
        token_network_address = token_network_proxy.address

        self.add_event_listener(
            'TokenNetwork {}'.format(pex(token_network_address)),
            channel_new_filter,
            CONTRACT_MANAGER.get_contract_abi(CONTRACT_TOKEN_NETWORK),
        )

    def add_payment_channel_listener(
        self,
        payment_channel_proxy: PaymentChannel,
        from_block: typing.BlockSpecification = 'latest',
    ):
        payment_channel_filter = payment_channel_proxy.all_events_filter(from_block=from_block)
        channel_identifier = payment_channel_proxy.channel_identifier

        self.add_event_listener(
            f'PaymentChannel event {channel_identifier}',
            payment_channel_filter,
            CONTRACT_MANAGER.get_contract_abi(
                CONTRACT_TOKEN_NETWORK,
            ),
        )
