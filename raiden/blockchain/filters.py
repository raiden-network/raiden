import structlog
from eth_abi.codec import ABICodec
from eth_utils import event_abi_to_log_topic
from web3._utils.abi import build_default_registry, filter_by_type
from web3._utils.events import get_event_data
from web3._utils.filters import construct_event_filter_params
from web3.types import EventData, FilterParams, LogReceipt

from raiden.constants import BLOCK_ID_LATEST, GENESIS_BLOCK_NUMBER
from raiden.utils.formatting import to_checksum_address
from raiden.utils.typing import ABI, BlockIdentifier, ChannelID, TokenNetworkAddress
from raiden_contracts.constants import CONTRACT_TOKEN_NETWORK, ChannelEvent
from raiden_contracts.contract_manager import ContractManager

log = structlog.get_logger(__name__)

ABI_CODEC = ABICodec(build_default_registry())


def get_filter_args_for_specific_event_from_channel(
    token_network_address: TokenNetworkAddress,
    channel_identifier: ChannelID,
    event_name: str,
    contract_manager: ContractManager,
    from_block: BlockIdentifier = GENESIS_BLOCK_NUMBER,
    to_block: BlockIdentifier = BLOCK_ID_LATEST,
) -> FilterParams:
    """ Return the filter params for a specific event of a given channel. """
    event_abi = contract_manager.get_event_abi(CONTRACT_TOKEN_NETWORK, event_name)

    # Here the topics for a specific event are created
    # The first entry of the topics list is the event name, then the first parameter is encoded,
    # in the case of a token network, the first parameter is always the channel identifier
    _, event_filter_params = construct_event_filter_params(
        event_abi=event_abi,
        abi_codec=ABI_CODEC,
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
    from_block: BlockIdentifier = GENESIS_BLOCK_NUMBER,
    to_block: BlockIdentifier = BLOCK_ID_LATEST,
) -> FilterParams:
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


def decode_event(abi: ABI, event_log: LogReceipt) -> EventData:
    """ Helper function to unpack event data using a provided ABI

    Args:
        abi: The ABI of the contract, not the ABI of the event
        event_log: The raw event data

    Returns:
        The decoded event
    """
    event_id = event_log["topics"][0]
    events = filter_by_type("event", abi)
    topic_to_event_abi = {
        event_abi_to_log_topic(event_abi): event_abi for event_abi in events  # type: ignore
    }
    event_abi = topic_to_event_abi[event_id]
    return get_event_data(ABI_CODEC, event_abi, event_log)
