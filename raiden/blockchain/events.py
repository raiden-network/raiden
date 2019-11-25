from dataclasses import dataclass
from datetime import datetime

import structlog
from eth_utils import to_canonical_address, to_checksum_address

from raiden.blockchain.exceptions import UnknownRaidenEventType
from raiden.blockchain.filters import (
    StatelessFilter,
    decode_event,
    get_filter_args_for_all_events_from_channel,
)
from raiden.constants import GENESIS_BLOCK_NUMBER, UINT64_MAX
from raiden.exceptions import InvalidBlockNumberInput
from raiden.network.proxies.proxy_manager import ProxyManager
from raiden.network.proxies.secret_registry import SecretRegistry
from raiden.network.proxies.token_network import TokenNetwork
from raiden.network.proxies.token_network_registry import TokenNetworkRegistry
from raiden.utils.typing import (
    ABI,
    Address,
    Any,
    BlockchainEvent,
    BlockHash,
    BlockNumber,
    BlockSpecification,
    ChainID,
    ChannelID,
    Dict,
    Iterable,
    List,
    Optional,
    TokenNetworkAddress,
    TokenNetworkRegistryAddress,
    TransactionHash,
)
from raiden_contracts.constants import (
    CONTRACT_SECRET_REGISTRY,
    CONTRACT_TOKEN_NETWORK,
    CONTRACT_TOKEN_NETWORK_REGISTRY,
    EVENT_TOKEN_NETWORK_CREATED,
    ChannelEvent,
)
from raiden_contracts.contract_manager import ContractManager

log = structlog.get_logger(__name__)

# `new_filter` uses None to signal the absence of topics filters
ALL_EVENTS = None


@dataclass(frozen=True)
class EventListener:
    event_name: str
    filter: StatelessFilter
    abi: ABI


@dataclass(frozen=True)
class DecodedEvent:
    """A confirmed event with the data decoded to conform with Raiden's internals.

    Raiden prefers bytes for addresses and hashes, and it uses snake_case as a
    naming convention. Instances of this class are created at the edges of the
    code base to conform with the internal data types, i.e. this type describes
    is used at the IO boundaries to conform with the sandwich encoding.
    """

    chain_id: ChainID
    block_number: BlockNumber
    block_hash: BlockHash
    transaction_hash: TransactionHash
    originating_contract: Address
    event_data: BlockchainEvent


def verify_block_number(number: BlockSpecification, argname: str) -> None:
    if isinstance(number, int) and (number < 0 or number > UINT64_MAX):
        raise InvalidBlockNumberInput(
            "Provided block number {} for {} is invalid. Has to be in the range "
            "of [0, UINT64_MAX]".format(number, argname)
        )


def get_contract_events(
    proxy_manager: ProxyManager,
    abi: ABI,
    contract_address: Address,
    topics: Optional[List[str]],
    from_block: BlockSpecification,
    to_block: BlockSpecification,
) -> List[Dict]:
    """ Query the blockchain for all events of the smart contract at
    `contract_address` that match the filters `topics`, `from_block`, and
    `to_block`.
    """
    verify_block_number(from_block, "from_block")
    verify_block_number(to_block, "to_block")
    events = proxy_manager.client.get_filter_events(
        contract_address, topics=topics, from_block=from_block, to_block=to_block
    )

    result = []
    for event in events:
        decoded_event = dict(decode_event(abi, event))
        if event.get("blockNumber"):
            decoded_event["block_number"] = event["blockNumber"]
            del decoded_event["blockNumber"]
        result.append(decoded_event)
    return result


def get_token_network_registry_events(
    proxy_manager: ProxyManager,
    token_network_registry_address: TokenNetworkRegistryAddress,
    contract_manager: ContractManager,
    events: Optional[List[str]] = ALL_EVENTS,
    from_block: BlockSpecification = GENESIS_BLOCK_NUMBER,
    to_block: BlockSpecification = "latest",
) -> List[Dict]:  # pragma: no unittest
    """ Helper to get all events of the Registry contract at `registry_address`. """
    return get_contract_events(
        proxy_manager=proxy_manager,
        abi=contract_manager.get_contract_abi(CONTRACT_TOKEN_NETWORK_REGISTRY),
        contract_address=Address(token_network_registry_address),
        topics=events,
        from_block=from_block,
        to_block=to_block,
    )


def get_token_network_events(
    proxy_manager: ProxyManager,
    token_network_address: TokenNetworkAddress,
    contract_manager: ContractManager,
    events: Optional[List[str]] = ALL_EVENTS,
    from_block: BlockSpecification = GENESIS_BLOCK_NUMBER,
    to_block: BlockSpecification = "latest",
) -> List[Dict]:  # pragma: no unittest
    """ Helper to get all events of the ChannelManagerContract at `token_address`. """

    return get_contract_events(
        proxy_manager,
        contract_manager.get_contract_abi(CONTRACT_TOKEN_NETWORK),
        Address(token_network_address),
        events,
        from_block,
        to_block,
    )


def get_all_netting_channel_events(
    proxy_manager: ProxyManager,
    token_network_address: TokenNetworkAddress,
    netting_channel_identifier: ChannelID,
    contract_manager: ContractManager,
    from_block: BlockSpecification = GENESIS_BLOCK_NUMBER,
    to_block: BlockSpecification = "latest",
) -> List[Dict]:  # pragma: no unittest
    """ Helper to get all events of a NettingChannelContract. """

    filter_args = get_filter_args_for_all_events_from_channel(
        token_network_address=token_network_address,
        channel_identifier=netting_channel_identifier,
        contract_manager=contract_manager,
        from_block=from_block,
        to_block=to_block,
    )

    return get_contract_events(
        proxy_manager,
        contract_manager.get_contract_abi(CONTRACT_TOKEN_NETWORK),
        Address(token_network_address),
        filter_args["topics"],
        from_block,
        to_block,
    )


def decode_raiden_event_to_internal(
    abi: ABI, chain_id: ChainID, log_event: BlockchainEvent
) -> DecodedEvent:
    """Enforce the sandwich encoding. Converts the JSON RPC/web3 data types
    to the internal representation.

    Note::

        This function must only on confirmed data.
    """
    # Note: All addresses inside the event_data must be decoded.

    decoded_event = decode_event(abi, log_event)

    if not decoded_event:
        raise UnknownRaidenEventType()

    # copy the attribute dict because that data structure is immutable
    data = dict(decoded_event)
    args = dict(data["args"])

    data["args"] = args
    # translate from web3's to raiden's name convention
    data["block_number"] = log_event.pop("blockNumber")
    data["transaction_hash"] = log_event.pop("transactionHash")
    data["block_hash"] = bytes(log_event.pop("blockHash"))

    assert data["block_number"], "The event must have the block_number"
    assert data["transaction_hash"], "The event must have the transaction hash field"
    assert data["block_hash"], "The event must have the block_hash"

    event = data["event"]
    if event == EVENT_TOKEN_NETWORK_CREATED:
        args["token_network_address"] = to_canonical_address(args["token_network_address"])
        args["token_address"] = to_canonical_address(args["token_address"])

    elif event == ChannelEvent.OPENED:
        args["participant1"] = to_canonical_address(args["participant1"])
        args["participant2"] = to_canonical_address(args["participant2"])

    elif event == ChannelEvent.DEPOSIT:
        args["participant"] = to_canonical_address(args["participant"])

    elif event == ChannelEvent.WITHDRAW:
        args["participant"] = to_canonical_address(args["participant"])

    elif event == ChannelEvent.BALANCE_PROOF_UPDATED:
        args["closing_participant"] = to_canonical_address(args["closing_participant"])

    elif event == ChannelEvent.CLOSED:
        args["closing_participant"] = to_canonical_address(args["closing_participant"])

    elif event == ChannelEvent.UNLOCKED:
        args["receiver"] = to_canonical_address(args["receiver"])
        args["sender"] = to_canonical_address(args["sender"])

    return DecodedEvent(
        chain_id=chain_id,
        originating_contract=to_canonical_address(log_event["address"]),
        event_data=data,
        block_number=data["block_number"],
        block_hash=data["block_hash"],
        transaction_hash=data["transaction_hash"],
    )


class BlockchainEvents:
    """ Events polling. """

    def __init__(self, chain_id: ChainID):
        self.chain_id = chain_id
        self.event_listeners: List[EventListener] = list()
        self.last_log_time: Optional[datetime] = None
        self.last_log_block: BlockNumber = BlockNumber(0)

    def _log_sync_progress(self, to_block: BlockNumber) -> None:
        """
        In case we have fallen far behind with synchronizing blockchain events,
        display a sync progress message every few seconds.
        """
        log_later = (
            self.last_log_time is not None
            and (datetime.now() - self.last_log_time).total_seconds() < 5.0
        )
        if log_later:
            return

        if not self.event_listeners:
            return
        from_block = min(listener.filter.from_block_number() for listener in self.event_listeners)
        blocks_to_sync = to_block - from_block
        if blocks_to_sync <= 100:
            return

        if self.last_log_time is None:
            self.last_log_time = datetime.now()
            self.last_log_block = from_block
            log.info("Synchronizing blockchain events", blocks_left=blocks_to_sync)
        else:
            now = datetime.now()
            elapsed = (now - self.last_log_time).total_seconds()
            blocks_per_second = (from_block - self.last_log_block) / elapsed
            log.info(
                "Synchronizing blockchain events",
                blocks_left=blocks_to_sync,
                blocks_per_second=blocks_per_second,
            )
            self.last_log_time = now
            self.last_log_block = from_block

    def poll_blockchain_events(self, block_number: BlockNumber) -> Iterable[DecodedEvent]:
        """ Poll for new blockchain events up to `block_number`. """
        for event_listener in self.event_listeners:
            assert isinstance(event_listener.filter, StatelessFilter)

            for log_event in event_listener.filter.get_new_entries(block_number):
                self._log_sync_progress(block_number)
                yield decode_raiden_event_to_internal(event_listener.abi, self.chain_id, log_event)

    def uninstall_all_event_listeners(self) -> None:
        self.event_listeners = list()

    def add_event_listener(
        self, event_name: str, eth_filter: StatelessFilter, abi: List[Dict[str, Any]]
    ) -> None:
        existing_listeners = [x.event_name for x in self.event_listeners]
        if event_name in existing_listeners:
            return
        event = EventListener(event_name, eth_filter, abi)
        self.event_listeners.append(event)

    def add_token_network_registry_listener(
        self,
        token_network_registry_proxy: TokenNetworkRegistry,
        contract_manager: ContractManager,
        from_block: BlockNumber,
    ) -> None:
        token_new_filter = token_network_registry_proxy.tokenadded_filter(from_block=from_block)
        token_network_registry_address = token_network_registry_proxy.address

        self.add_event_listener(
            "TokenNetworkRegistry {}".format(to_checksum_address(token_network_registry_address)),
            token_new_filter,
            contract_manager.get_contract_abi(CONTRACT_TOKEN_NETWORK_REGISTRY),
        )

    def add_token_network_listener(
        self,
        token_network_proxy: TokenNetwork,
        contract_manager: ContractManager,
        from_block: BlockNumber,
    ) -> None:
        token_network_filter = token_network_proxy.all_events_filter(from_block=from_block)
        token_network_address = token_network_proxy.address

        self.add_event_listener(
            "TokenNetwork {}".format(to_checksum_address(token_network_address)),
            token_network_filter,
            contract_manager.get_contract_abi(CONTRACT_TOKEN_NETWORK),
        )

    def add_secret_registry_listener(
        self,
        secret_registry_proxy: SecretRegistry,
        contract_manager: ContractManager,
        from_block: BlockNumber,
    ) -> None:
        secret_registry_filter = secret_registry_proxy.secret_registered_filter(
            from_block=from_block
        )
        secret_registry_address = secret_registry_proxy.address
        self.add_event_listener(
            "SecretRegistry {}".format(to_checksum_address(secret_registry_address)),
            secret_registry_filter,
            contract_manager.get_contract_abi(CONTRACT_SECRET_REGISTRY),
        )
