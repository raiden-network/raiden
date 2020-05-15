import time
from dataclasses import dataclass
from typing import Tuple

import structlog
from eth_utils import to_canonical_address
from gevent.lock import Semaphore
from requests.exceptions import ReadTimeout
from web3 import Web3
from web3.types import LogReceipt, RPCEndpoint

from raiden.blockchain.exceptions import EthGetLogsTimeout, UnknownRaidenEventType
from raiden.blockchain.filters import decode_event, get_filter_args_for_all_events_from_channel
from raiden.blockchain.utils import BlockBatchSizeAdjuster
from raiden.constants import (
    BLOCK_ID_LATEST,
    ETH_GET_LOGS_THRESHOLD_FAST,
    ETH_GET_LOGS_THRESHOLD_SLOW,
    GENESIS_BLOCK_NUMBER,
    UINT64_MAX,
)
from raiden.exceptions import InvalidBlockNumberInput
from raiden.network.proxies.proxy_manager import ProxyManager
from raiden.settings import BlockBatchSizeConfig
from raiden.utils.formatting import to_checksum_address
from raiden.utils.typing import (
    ABI,
    Address,
    Any,
    BlockGasLimit,
    BlockHash,
    BlockIdentifier,
    BlockNumber,
    ChainID,
    ChannelID,
    Dict,
    Iterable,
    List,
    Optional,
    SecretRegistryAddress,
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
class SmartContractEvents:
    """All the events from `contract_address` are queried and decoded with
    `abi`.

    This does not support filtering events by design, since this is more
    performant and removes ordering problems with the event processing.
    """

    contract_address: Address
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
    event_data: Dict[str, Any]


@dataclass(frozen=True)
class PollResult:
    """Result of a poll request. The block number is provided so that the
    caller can confirm it in its storage.
    """

    polled_block_number: BlockNumber
    polled_block_hash: BlockHash
    polled_block_gas_limit: BlockGasLimit
    events: List[DecodedEvent]


def verify_block_number(number: BlockIdentifier, argname: str) -> None:
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
    from_block: BlockIdentifier,
    to_block: BlockIdentifier,
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
    from_block: BlockIdentifier = GENESIS_BLOCK_NUMBER,
    to_block: BlockIdentifier = BLOCK_ID_LATEST,
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
    from_block: BlockIdentifier = GENESIS_BLOCK_NUMBER,
    to_block: BlockIdentifier = BLOCK_ID_LATEST,
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
    from_block: BlockIdentifier = GENESIS_BLOCK_NUMBER,
    to_block: BlockIdentifier = BLOCK_ID_LATEST,
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
        filter_args["topics"],  # type: ignore
        from_block,
        to_block,
    )


def get_secret_registry_events(
    proxy_manager: ProxyManager,
    secret_registry_address: SecretRegistryAddress,
    contract_manager: ContractManager,
    events: Optional[List[str]] = ALL_EVENTS,
    from_block: BlockIdentifier = GENESIS_BLOCK_NUMBER,
    to_block: BlockIdentifier = BLOCK_ID_LATEST,
) -> List[Dict]:  # pragma: no unittest
    """ Helper to get all events of a SecretRegistry contract. """

    return get_contract_events(
        proxy_manager,
        contract_manager.get_contract_abi(CONTRACT_SECRET_REGISTRY),
        Address(secret_registry_address),
        events,
        from_block,
        to_block,
    )


def decode_raiden_event_to_internal(
    abi: ABI, chain_id: ChainID, log_event: LogReceipt
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
    args = dict(decoded_event["args"])

    data["args"] = args
    # translate from web3's to raiden's name convention
    data["block_number"] = log_event["blockNumber"]
    data["transaction_hash"] = log_event["transactionHash"]
    data["block_hash"] = bytes(log_event["blockHash"])

    # Remove the old names
    del data["blockNumber"]
    del data["transactionHash"]
    del data["blockHash"]

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
        block_number=log_event["blockNumber"],
        block_hash=BlockHash(log_event["blockHash"]),
        transaction_hash=TransactionHash(log_event["transactionHash"]),
    )


def token_network_registry_events(
    token_network_registry_address: TokenNetworkRegistryAddress, contract_manager: ContractManager
) -> SmartContractEvents:
    return SmartContractEvents(
        contract_address=Address(token_network_registry_address),
        abi=contract_manager.get_contract_abi(CONTRACT_TOKEN_NETWORK_REGISTRY),
    )


def token_network_events(
    token_network_address: TokenNetworkAddress, contract_manager: ContractManager
) -> SmartContractEvents:
    return SmartContractEvents(
        contract_address=Address(token_network_address),
        abi=contract_manager.get_contract_abi(CONTRACT_TOKEN_NETWORK),
    )


def secret_registry_events(
    secret_registry_address: SecretRegistryAddress, contract_manager: ContractManager
) -> SmartContractEvents:
    return SmartContractEvents(
        contract_address=Address(secret_registry_address),
        abi=contract_manager.get_contract_abi(CONTRACT_SECRET_REGISTRY),
    )


def new_filters_from_events(
    contract_manager: ContractManager, events: List[DecodedEvent]
) -> Iterable[SmartContractEvents]:
    for entry in events:
        if entry.event_data["event"] == EVENT_TOKEN_NETWORK_CREATED:
            yield token_network_events(
                entry.event_data["args"]["token_network_address"], contract_manager
            )


def filters_to_rpc(
    filters: Iterable[SmartContractEvents], from_block: BlockNumber, to_block: BlockNumber
) -> Dict:
    # Payload is specified at
    # https://github.com/ethereum/wiki/wiki/JSON-RPC#eth_getlogs
    return {
        "fromBlock": from_block,
        "toBlock": to_block,
        "address": [event_filter.contract_address for event_filter in filters],
        # This interface exists to query multiple smart contracts with a single
        # query, therefore topics cannot be supported. Because the address can
        # be different types of smart contract, the topics are likely
        # different. Additionally, not having topics here will result in a
        # slight performance gain (read documentation above for why).
        # "topics": None,
    }


def fetch_all_events_for_a_deployment(
    contract_manager: ContractManager,
    web3: Web3,
    token_network_registry_address: TokenNetworkRegistryAddress,
    secret_registry_address: SecretRegistryAddress,
    start_block: BlockNumber,
    target_block: BlockNumber,
) -> Iterable[Dict]:
    """ Read all the events of a whole deployment, starting at the network
    registry, and following the registered networks.
    """

    chain_id = ChainID(web3.eth.chainId)
    filters = [
        token_network_registry_events(token_network_registry_address, contract_manager),
        secret_registry_events(secret_registry_address, contract_manager),
    ]
    blockchain_events = BlockchainEvents(
        web3=web3,
        chain_id=chain_id,
        contract_manager=contract_manager,
        last_fetched_block=start_block,
        event_filters=filters,
        block_batch_size_config=BlockBatchSizeConfig(),
    )

    while target_block > blockchain_events.last_fetched_block:
        poll_result = blockchain_events.fetch_logs_in_batch(target_block)
        if poll_result is None:
            # No blocks could be fetched (due to timeout), retry
            continue

        for event in poll_result.events:
            yield event.event_data


class BlockchainEvents:
    def __init__(
        self,
        web3: Web3,
        chain_id: ChainID,
        contract_manager: ContractManager,
        last_fetched_block: BlockNumber,
        event_filters: List[SmartContractEvents],
        block_batch_size_config: BlockBatchSizeConfig,
    ) -> None:
        self.web3 = web3
        self.chain_id = chain_id
        self.last_fetched_block = last_fetched_block
        self.contract_manager = contract_manager
        self.block_batch_size_adjuster = BlockBatchSizeAdjuster(block_batch_size_config)

        # This lock is used to add a new smart contract to the list of polled
        # smart contracts. The crucial optimization done by this class is to
        # query all smart contracts with only one request, this requires the
        # parameters `fromBlock` and `toBlock` to be the same for all smart
        # contracts. The lock is used to hold new requests, while the logs of
        # the new smart contract are queried to catch up, and then for it to be
        # added to the list of tracked smart contracts.
        #
        # This lock also guarantees that the events will be processed only
        # once, and because of this the `target_block_number` must always be a
        # confirmed block.
        #
        # Additionally, user facing APIs, which have on-chain side-effects,
        # used force poll the blockchain to update the node's state. This force
        # poll is used to provide a consistent view to the user, e.g. a channel
        # open call waits for the transaction to be mined and force polled the
        # event to update the node's state. This pattern introduced a race with
        # the alarm task and the task which served the user request, because
        # the events are returned only once per filter. The lock below is to
        # protect against these races (introduced by the commit
        # 3686b3275ff7c0b669a6d5e2b34109c3bdf1921d)
        self._filters_lock = Semaphore()
        self._address_to_filters: Dict[Address, SmartContractEvents] = {
            event.contract_address: event for event in event_filters
        }

    def fetch_logs_in_batch(self, target_block_number: BlockNumber) -> Optional[PollResult]:
        """Poll the smart contract events for a limited number of blocks to
        avoid read timeouts (issue #3558).

        The block ``target_block_number`` will not be reached if it is more than
        ``self.block_batch_size_adjuster.batch_size`` blocks away. To ensure the
        target is reached keep calling ``fetch_logs_in_batch`` until
        ``PollResult.polled_block_number`` is the same as ``target_block_number``.

        This function will make sure that the block range for the queries is
        not too big, this is necessary because it may take a long time for an
        Ethereum node to process the request, which will result in read
        timeouts (issue #3558).

        The block batch size is adjusted dynamically based on the request
        processing duration (see ``_query_and_track()``, issue #5538).
        If the request times out the batch size is decreased and ``None``
        is returned.
        If the batch size falls below the lower threshold an exception is raised
        by the ``BlockBatchSizeAdjuster``.

        This will also group the queries as an optimization for a healthy node
        (issue #4872). This is enforced by the design of the datastructures,
        this will always fetch all the events for all the registered addresses.
        """
        # The target block has been reached already, raise an exception since
        # the caller is breaking the contract of the API
        if target_block_number <= self.last_fetched_block:
            raise ValueError(
                f"target {target_block_number} is in the past, the block has "
                f"been fetched already. Current {self.last_fetched_block}"
            )

        # As of Geth 1.9.5 there is no relational database nor an index of
        # blooms. Geth always does a linear search proportional to the number
        # of blocks in the query.
        #
        # As of Parity 2.5.8 the client has no relational database. The
        # blockchain events are indexed through a hierarchy of bloom filters
        # three levels deep, each level has it's own `.dbd` file.
        #
        # The Bottom layer is comprised of every block logs bloom, as defined
        # in the yellow paper, where each entry position matches the
        # originating block number. The top and mid layers are just an
        # optimization, in these layers each entry is composed of 16 blooms
        # filters from the layer below.
        #
        # Each pair (`address`, `topic`) of a query is used to create one bloom
        # filter, these blooms are then used find candidate blocks through the
        # bloom index, then these blocks are loaded and their logs filtered.
        #
        # Based on the `fromBlock` the index files are seeked to the correct
        # position. The search always start at the top level, if the query
        # bloom is not contained in the index then the search goes to next
        # entry at the top level and skips all the mid and lower indexes. The
        # same procedure is done for the mid level. If there is a match at the
        # lower level, then we may have a hit. Because the bloom index is the
        # same as the block number, this information is used to recover the
        # block hash.
        #
        # Each of the blocks that correspond to the hashes from the previous
        # step are then loaded, including the receipts with the logs. The
        # matching logs are then returned as results to the query.
        #
        # Additional notes for Parity :
        #
        # - Every operation to the bloom database uses an exclusive lock.
        # Therefore concurrent requests are not extremely useful.
        # - The path explained above is only used if the queries are done using
        # block numbers. Queries for block hashes will not use the index, this
        # seems necessary because there is only one index for the canonical
        # chain, and queries with block hashes seems to support uncle
        # blocks/reorgs.
        # - When an address is being queried for all the logs, it is better to
        # not specify any topics. Specially when multiple addresses are being
        # queried.
        # - The batching interface doesn't do any internal optimizations, so in
        # effect it is the same thing as sending multiple requests, one after
        # the other. The only benefit here would be to save the requests
        # round-trip time.

        with self._filters_lock:
            # Skip the last fetched block, since the ranges are inclusive the
            # same block will be fetched twice which could result in duplicate
            # events.
            from_block = BlockNumber(self.last_fetched_block + 1)

            # Limit the range of blocks fetched, this limits the size of
            # the scan done by the target node. The batch size is adjusted
            # below depending on the response time of the node.
            to_block = BlockNumber(
                min(from_block + self.block_batch_size_adjuster.batch_size, target_block_number)
            )

            # Sending a single request for all the smart contract addresses
            # is the core optimization here. Because both Geth and Parity
            # will do a linear search per request, in some shape or form,
            # sending only one request will result in only one linear
            # search.
            #
            # This optimization has a few benefits:
            #
            # - There will be only one request for all the smart contracts,
            # reducing trafic from Raiden to the Ethereum client, this is
            # important if the client is remote or a hosted service like
            # Infura.
            # - The request will be faster for large ranges (This is an
            # implementation detail that happen to be true for both
            # clients, the rationale is to reduce the number of loops that
            # go through lots of elements).

            try:
                decoded_result, request_duration = self._query_and_track(from_block, to_block)
            except EthGetLogsTimeout:
                # The request timed out - this typically means the node wasn't able to process
                # the requested batch size fast enough.
                # Decrease the batch size and let the higher layer retry.
                log.debug("Timeout while fetching blocks, decreasing batch size")
                self.block_batch_size_adjuster.decrease()
                return None

            can_use_bigger_batches = (
                target_block_number - from_block > self.block_batch_size_adjuster.batch_size
            )
            # Adjust block batch size depending on request duration.
            # To reduce oscillating the batch size is kept constant for request durations
            # between ``ETH_GET_LOGS_THRESHOLD_FAST`` and ``ETH_GET_LOGS_THRESHOLD_SLOW``.
            if request_duration < ETH_GET_LOGS_THRESHOLD_FAST:
                # The request was fast, increase batch size
                if can_use_bigger_batches:
                    # But only if we actually need bigger batches. This prevents the batch
                    # size from ballooning towards the maximum after the initial sync is done
                    # since then typically only one block is fetched at a time which is usually
                    # fast.
                    self.block_batch_size_adjuster.increase()
            elif request_duration > ETH_GET_LOGS_THRESHOLD_SLOW:
                # The request is taking longer than the 'slow' threshold - decrease
                # the batch size
                self.block_batch_size_adjuster.decrease()

            latest_confirmed_block = self.web3.eth.getBlock(to_block)

            self.last_fetched_block = to_block

            return PollResult(
                polled_block_number=to_block,
                polled_block_hash=BlockHash(bytes(latest_confirmed_block["hash"])),
                polled_block_gas_limit=BlockGasLimit(latest_confirmed_block["gasLimit"]),
                events=decoded_result,
            )

    def _query_and_track(
        self, from_block: BlockNumber, to_block: BlockNumber
    ) -> Tuple[List[DecodedEvent], float]:
        """Query the blockchain up to `to_block` and create the filters for the
        smart contracts deployed during the current batch.

        Because of how polling is optimized, filters for smart contracts
        deployed in the current batch must be created, queried, and be merged
        into the same batch. This is necessary to avoid race conditions on
        restarts that could lead to loss of events. Example:

                   last confirmed block
                   |
                   v    v end of current batch / new confirmed block
                   4    9
        Batch  ####------
        TNR    ####--*---
        TN           --*-
                     ^ ^
                     | new channel openned
                     |
                     new token network registered

        For this example, the current batch is fetching the range `[4, 9]`. In
        this range a new token is registered at block 6, at block 8 a new
        channel is openned in the new network.

        If the events of the new TN are *not* queried, block 9 will be
        confirmed after processing the batch which adds the TN, and iff the
        node crashes right after processing this batch, on the next restart
        *all* filters will start from 9, thus missing the event for the new
        channel on block 8.
        """
        filters_to_query: Iterable[SmartContractEvents]

        request_duration: float = 0
        result: List[DecodedEvent] = []
        filters_to_query = self._address_to_filters.values()

        # While there are new smart contracts to follow, this will query them
        # and add to the existing filters.
        #
        # The batch itself may have an event for a newly deployed smart
        # contract, e.g. a new token network. The new smart contract needs a
        # filter, and then the filter has to be queried before for the same
        # batch before it is dispatched. This is necessary to guarantee safety
        # of restarts.
        while filters_to_query:
            filter_params = filters_to_rpc(filters_to_query, from_block, to_block)

            log.debug(
                "StatelessFilter: querying new entries",
                from_block=filter_params["fromBlock"],
                to_block=filter_params["toBlock"],
                addresses=[to_checksum_address(address) for address in filter_params["address"]],
            )

            try:
                start = time.monotonic()
                # Using web3 because:
                # - It sets an unique request identifier, not strictly necessary.
                # - To avoid another abstraction to query the Ethereum client.
                blockchain_events: List[LogReceipt] = self.web3.manager.request_blocking(
                    RPCEndpoint("eth_getLogs"), [filter_params]
                )
                request_duration = time.monotonic() - start
            except ReadTimeout as ex:
                # The request timed out while waiting for a response (as opposed to a
                # ConnectTimeout).
                # This will usually be caused by overloading of the target eth node but can also
                # happen due to network conditions.
                raise EthGetLogsTimeout() from ex

            log.debug(
                "StatelessFilter: fetched new entries",
                from_block=filter_params["fromBlock"],
                to_block=filter_params["toBlock"],
                addresses=[to_checksum_address(address) for address in filter_params["address"]],
                blockchain_events=blockchain_events,
                request_duration=request_duration,
            )

            if blockchain_events:
                decoded_events = [
                    decode_raiden_event_to_internal(self.event_to_abi(event), self.chain_id, event)
                    for event in blockchain_events
                ]
                result.extend(decoded_events)

                # Go throught he results and create the child filters, if
                # necessary.
                #
                # The generator result is converted to a list because we need
                # to iterate over it twice
                filters_to_query = list(
                    new_filters_from_events(self.contract_manager, decoded_events)
                )

                # Register the new filters, so that they will be fetched on the next iteration
                self._address_to_filters.update(
                    (new_filter.contract_address, new_filter) for new_filter in filters_to_query
                )
            else:
                filters_to_query = []

        return result, request_duration

    def event_to_abi(self, event: LogReceipt) -> ABI:
        address = to_canonical_address(event["address"])
        return self._address_to_filters[address].abi

    def uninstall_all_event_listeners(self) -> None:
        with self._filters_lock:
            self._address_to_filters = dict()
