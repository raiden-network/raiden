import structlog
from eth_typing import ChecksumAddress
from eth_utils import decode_hex, event_abi_to_log_topic, to_checksum_address
from gevent.lock import Semaphore
from web3 import Web3
from web3.utils.abi import filter_by_type
from web3.utils.events import get_event_data
from web3.utils.filters import construct_event_filter_params

from raiden.constants import GENESIS_BLOCK_NUMBER
from raiden.utils.typing import (
    ABI,
    Any,
    BlockchainEvent,
    BlockNumber,
    BlockSpecification,
    ChannelID,
    Dict,
    List,
    Optional,
    TokenNetworkAddress,
)
from raiden_contracts.constants import CONTRACT_TOKEN_NETWORK, ChannelEvent
from raiden_contracts.contract_manager import ContractManager

log = structlog.get_logger(__name__)

# The maximum block range to query in a single filter query
# Helps against timeout errors that occur if you query a filter for
# the mainnet from Genesis to latest head as we see in:
# https://github.com/raiden-network/raiden/issues/3558
FILTER_MAX_BLOCK_RANGE = 100_000


def get_filter_args_for_specific_event_from_channel(
    token_network_address: TokenNetworkAddress,
    channel_identifier: ChannelID,
    event_name: str,
    contract_manager: ContractManager,
    from_block: BlockSpecification = GENESIS_BLOCK_NUMBER,
    to_block: BlockSpecification = "latest",
) -> Dict[str, Any]:
    """ Return the filter params for a specific event of a given channel. """
    event_abi = contract_manager.get_event_abi(CONTRACT_TOKEN_NETWORK, event_name)

    # Here the topics for a specific event are created
    # The first entry of the topics list is the event name, then the first parameter is encoded,
    # in the case of a token network, the first parameter is always the channel identifier
    _, event_filter_params = construct_event_filter_params(
        event_abi=event_abi,
        contract_address=to_checksum_address(token_network_address),
        argument_filters={"channel_identifier": channel_identifier},
        fromBlock=from_block,
        toBlock=to_block,
    )

    return event_filter_params


def get_filter_args_for_all_events_from_channel(
    token_network_address: TokenNetworkAddress,
    channel_identifier: ChannelID,
    contract_manager: ContractManager,
    from_block: BlockSpecification = GENESIS_BLOCK_NUMBER,
    to_block: BlockSpecification = "latest",
) -> Dict[str, Any]:
    """ Return the filter params for all events of a given channel. """

    event_filter_params = get_filter_args_for_specific_event_from_channel(
        token_network_address=token_network_address,
        channel_identifier=channel_identifier,
        event_name=ChannelEvent.OPENED,
        contract_manager=contract_manager,
        from_block=from_block,
        to_block=to_block,
    )

    # As we want to get all events for a certain channel we remove the event specific code here
    # and filter just for the channel identifier
    # We also have to remove the trailing topics to get all filters
    event_filter_params["topics"] = [None, event_filter_params["topics"][1]]

    return event_filter_params


def decode_event(abi: ABI, log: BlockchainEvent) -> Dict[str, Any]:
    """ Helper function to unpack event data using a provided ABI

    Args:
        abi: The ABI of the contract, not the ABI of the event
        log: The raw event data

    Returns:
        The decoded event
    """
    if isinstance(log["topics"][0], str):
        log["topics"][0] = decode_hex(log["topics"][0])
    elif isinstance(log["topics"][0], int):
        log["topics"][0] = decode_hex(hex(log["topics"][0]))
    event_id = log["topics"][0]
    events = filter_by_type("event", abi)
    topic_to_event_abi = {event_abi_to_log_topic(event_abi): event_abi for event_abi in events}
    event_abi = topic_to_event_abi[event_id]
    return get_event_data(event_abi, log)


class StatelessFilter:
    def __init__(
        self,
        web3: Web3,
        from_block: BlockNumber,
        contract_address: ChecksumAddress,
        topics: Optional[List[Optional[str]]],
    ) -> None:
        # fix off-by-one
        last_block = from_block - 1

        self.web3 = web3
        self.contract_address = contract_address
        self.topics = topics
        self.last_block = last_block
        self._lock = Semaphore()

    def from_block_number(self) -> BlockNumber:
        """Return the next block to be queried."""
        return BlockNumber(self.last_block + 1)

    def get_new_entries(self, target_block_number: BlockNumber) -> List[BlockchainEvent]:
        """Return the new log entries matching the filter, starting from the
        last run of `get_new_entries`.
        """
        with self._lock:
            result: List[BlockchainEvent] = []
            from_block_number = self.from_block_number()

            # Batch the filter queries in ranges of FILTER_MAX_BLOCK_RANGE
            # to avoid timeout problems
            while from_block_number <= target_block_number:
                to_block = BlockNumber(
                    min(from_block_number + FILTER_MAX_BLOCK_RANGE, target_block_number)
                )
                filter_params = {
                    "fromBlock": from_block_number,
                    "toBlock": to_block,
                    "address": self.contract_address,
                    "topics": self.topics,
                }

                log.debug("StatelessFilter: querying new entries", filter_params=filter_params)
                result.extend(self.web3.eth.getLogs(filter_params))

                # `getLogs` is inclusive, the next loop should start from the
                # next block.
                from_block_number = BlockNumber(to_block + 1)

                self.last_block = to_block

            return result
