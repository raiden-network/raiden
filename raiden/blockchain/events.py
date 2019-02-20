from collections import namedtuple
from typing import Dict, List

from eth_utils import to_canonical_address

from raiden.constants import GENESIS_BLOCK_NUMBER, UINT64_MAX
from raiden.exceptions import InvalidBlockNumberInput, UnknownEventType
from raiden.network.blockchain_service import BlockChainService
from raiden.network.proxies import SecretRegistry
from raiden.utils import pex, typing
from raiden.utils.filters import (
    StatelessFilter,
    decode_event,
    get_filter_args_for_all_events_from_channel,
)
from raiden.utils.typing import (
    Address,
    BlockSpecification,
    ChannelID,
    PaymentNetworkID,
    TokenNetworkAddress,
)
from raiden_contracts.constants import (
    CONTRACT_SECRET_REGISTRY,
    CONTRACT_TOKEN_NETWORK,
    CONTRACT_TOKEN_NETWORK_REGISTRY,
    EVENT_TOKEN_NETWORK_CREATED,
    ChannelEvent,
)
from raiden_contracts.contract_manager import ContractManager

EventListener = namedtuple(
    'EventListener',
    ('event_name', 'filter', 'abi'),
)

# `new_filter` uses None to signal the absence of topics filters
ALL_EVENTS = None


def verify_block_number(number: typing.BlockSpecification, argname: str):
    if isinstance(number, int) and (number < 0 or number > UINT64_MAX):
        raise InvalidBlockNumberInput(
            'Provided block number {} for {} is invalid. Has to be in the range '
            'of [0, UINT64_MAX]'.format(number, argname),
        )


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


def get_token_network_registry_events(
        chain: BlockChainService,
        token_network_registry_address: PaymentNetworkID,
        contract_manager: ContractManager,
        events: List[str] = ALL_EVENTS,
        from_block: BlockSpecification = GENESIS_BLOCK_NUMBER,
        to_block: BlockSpecification = 'latest',
) -> List[Dict]:
    """ Helper to get all events of the Registry contract at `registry_address`. """
    return get_contract_events(
        chain,
        contract_manager.get_contract_abi(CONTRACT_TOKEN_NETWORK_REGISTRY),
        Address(token_network_registry_address),
        events,
        from_block,
        to_block,
    )


def get_token_network_events(
        chain: BlockChainService,
        token_network_address: Address,
        contract_manager: ContractManager,
        events: List[str] = ALL_EVENTS,
        from_block: BlockSpecification = GENESIS_BLOCK_NUMBER,
        to_block: BlockSpecification = 'latest',
) -> List[Dict]:
    """ Helper to get all events of the ChannelManagerContract at `token_address`. """

    return get_contract_events(
        chain,
        contract_manager.get_contract_abi(CONTRACT_TOKEN_NETWORK),
        token_network_address,
        events,
        from_block,
        to_block,
    )


def get_all_netting_channel_events(
        chain: BlockChainService,
        token_network_address: TokenNetworkAddress,
        netting_channel_identifier: ChannelID,
        contract_manager: ContractManager,
        from_block: BlockSpecification = GENESIS_BLOCK_NUMBER,
        to_block: BlockSpecification = 'latest',
) -> List[Dict]:
    """ Helper to get all events of a NettingChannelContract. """

    filter_args = get_filter_args_for_all_events_from_channel(
        token_network_address=token_network_address,
        channel_identifier=netting_channel_identifier,
        contract_manager=contract_manager,
        from_block=from_block,
        to_block=to_block,
    )

    return get_contract_events(
        chain,
        contract_manager.get_contract_abi(CONTRACT_TOKEN_NETWORK),
        typing.Address(token_network_address),
        filter_args['topics'],
        from_block,
        to_block,
    )


def decode_event_to_internal(abi, log_event):
    """ Enforce the binary for internal usage. """
    # Note: All addresses inside the event_data must be decoded.

    decoded_event = decode_event(abi, log_event)

    if not decoded_event:
        raise UnknownEventType()

    # copy the attribute dict because that data structure is immutable
    data = dict(decoded_event)
    args = dict(data['args'])

    data['args'] = args
    # translate from web3's to raiden's name convention
    data['block_number'] = log_event.pop('blockNumber')
    data['transaction_hash'] = log_event.pop('transactionHash')
    data['block_hash'] = bytes(log_event.pop('blockHash'))

    assert data['block_number'], 'The event must have the block_number'
    assert data['transaction_hash'], 'The event must have the transaction hash field'

    event = data['event']
    if event == EVENT_TOKEN_NETWORK_CREATED:
        args['token_network_address'] = to_canonical_address(args['token_network_address'])
        args['token_address'] = to_canonical_address(args['token_address'])

    elif event == ChannelEvent.OPENED:
        args['participant1'] = to_canonical_address(args['participant1'])
        args['participant2'] = to_canonical_address(args['participant2'])

    elif event == ChannelEvent.DEPOSIT:
        args['participant'] = to_canonical_address(args['participant'])

    elif event == ChannelEvent.BALANCE_PROOF_UPDATED:
        args['closing_participant'] = to_canonical_address(args['closing_participant'])

    elif event == ChannelEvent.CLOSED:
        args['closing_participant'] = to_canonical_address(args['closing_participant'])

    elif event == ChannelEvent.UNLOCKED:
        args['participant'] = to_canonical_address(args['participant'])
        args['partner'] = to_canonical_address(args['partner'])

    return Event(
        originating_contract=to_canonical_address(log_event['address']),
        event_data=data,
    )


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

    def poll_blockchain_events(self, block_number: typing.BlockNumber):
        """ Poll for new blockchain events up to `block_number`. """

        for event_listener in self.event_listeners:
            assert isinstance(event_listener.filter, StatelessFilter)

            for log_event in event_listener.filter.get_new_entries(block_number):
                yield decode_event_to_internal(event_listener.abi, log_event)

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
        )
        self.event_listeners.append(event)

    def add_token_network_registry_listener(
            self,
            token_network_registry_proxy,
            contract_manager,
            from_block: typing.BlockSpecification = 'latest',
    ):
        token_new_filter = token_network_registry_proxy.tokenadded_filter(from_block=from_block)
        token_network_registry_address = token_network_registry_proxy.address

        self.add_event_listener(
            'TokenNetworkRegistry {}'.format(pex(token_network_registry_address)),
            token_new_filter,
            contract_manager.get_contract_abi(CONTRACT_TOKEN_NETWORK_REGISTRY),
        )

    def add_token_network_listener(
            self,
            token_network_proxy,
            contract_manager: ContractManager,
            from_block: typing.BlockSpecification = 'latest',
    ):
        token_network_filter = token_network_proxy.all_events_filter(from_block=from_block)
        token_network_address = token_network_proxy.address

        self.add_event_listener(
            'TokenNetwork {}'.format(pex(token_network_address)),
            token_network_filter,
            contract_manager.get_contract_abi(CONTRACT_TOKEN_NETWORK),
        )

    def add_secret_registry_listener(
            self,
            secret_registry_proxy: SecretRegistry,
            contract_manager: ContractManager,
            from_block: typing.BlockSpecification = 'latest',
    ):
        secret_registry_filter = secret_registry_proxy.secret_registered_filter(
            from_block=from_block,
        )
        secret_registry_address = secret_registry_proxy.address
        self.add_event_listener(
            'SecretRegistry {}'.format(pex(secret_registry_address)),
            secret_registry_filter,
            contract_manager.get_contract_abi(CONTRACT_SECRET_REGISTRY),
        )
