from eth_utils import is_binary_address

from raiden.api.python import get_channel_list
from raiden.blockchain.events import ALL_EVENTS, verify_block_number
from raiden.blockchain.filters import decode_event, get_filter_args_for_all_events_from_channel
from raiden.constants import BLOCK_ID_LATEST, GENESIS_BLOCK_NUMBER
from raiden.exceptions import InvalidBinaryAddress, UnknownTokenAddress
from raiden.network.proxies.proxy_manager import ProxyManager
from raiden.transfer.views import get_confirmed_blockhash
from raiden.utils.typing import (
    ABI,
    TYPE_CHECKING,
    Address,
    BlockIdentifier,
    ChannelID,
    Dict,
    List,
    Optional,
    TokenAddress,
    TokenNetworkAddress,
    TokenNetworkRegistryAddress,
)
from raiden_contracts.constants import CONTRACT_TOKEN_NETWORK, CONTRACT_TOKEN_NETWORK_REGISTRY
from raiden_contracts.contract_manager import ContractManager

if TYPE_CHECKING:
    from raiden.raiden_service import RaidenService


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

    **Do not use with production code**, querying events over large block
    ranges is extremenly slow and will result in timeouts.
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
    """ Helper to get all events of the Registry contract at `registry_address`.

    **Do not use with production code**, querying events over large block
    ranges is extremenly slow and will result in timeouts.
    """
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
    """ Helper to get all events of the ChannelManagerContract at `token_address`.

    **Do not use with production code**, querying events over large block
    ranges is extremenly slow and will result in timeouts.
    """

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
    """ Helper to get all events of a NettingChannelContract.

    **Do not use with production code**, querying events over large block
    ranges is extremenly slow and will result in timeouts.
    """

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


def get_blockchain_events_channel(
    raiden: "RaidenService",
    token_address: TokenAddress,
    partner_address: Address = None,
    from_block: BlockIdentifier = GENESIS_BLOCK_NUMBER,
    to_block: BlockIdentifier = BLOCK_ID_LATEST,
) -> List[Dict]:
    """Returns all events of all channels the node is a participant.

    **Do not use with production code**, querying events over large block
    ranges is extremenly slow and will result in timeouts.
    """
    if not is_binary_address(token_address):
        raise InvalidBinaryAddress(
            "Expected binary address format for token in get_blockchain_events_channel"
        )
    confirmed_block_identifier = get_confirmed_blockhash(raiden)
    token_network_address = raiden.default_registry.get_token_network(
        token_address=token_address, block_identifier=confirmed_block_identifier
    )
    if token_network_address is None:
        raise UnknownTokenAddress("Token address is not known.")

    channel_list = get_channel_list(
        raiden=raiden,
        registry_address=raiden.default_registry.address,
        token_address=token_address,
        partner_address=partner_address,
    )
    returned_events = []
    for channel_state in channel_list:
        returned_events.extend(
            get_all_netting_channel_events(
                proxy_manager=raiden.proxy_manager,
                token_network_address=token_network_address,
                netting_channel_identifier=channel_state.identifier,
                contract_manager=raiden.contract_manager,
                from_block=from_block,
                to_block=to_block,
            )
        )
    returned_events.sort(key=lambda evt: evt.get("block_number"), reverse=True)
    return returned_events


def get_blockchain_events_token_network(
    raiden: "RaidenService",
    token_address: TokenAddress,
    from_block: BlockIdentifier = GENESIS_BLOCK_NUMBER,
    to_block: BlockIdentifier = BLOCK_ID_LATEST,
) -> List[Dict]:
    """Returns a list of blockchain events corresponding to the token_address.

    **Do not use with production code**, querying events over large block
    ranges is extremenly slow and will result in timeouts.
    """

    if not is_binary_address(token_address):
        raise InvalidBinaryAddress(
            "Expected binary address format for token in get_blockchain_events_token_network"
        )

    confirmed_block_identifier = get_confirmed_blockhash(raiden)
    token_network_address = raiden.default_registry.get_token_network(
        token_address=token_address, block_identifier=confirmed_block_identifier
    )

    if token_network_address is None:
        raise UnknownTokenAddress("Token address is not known.")

    returned_events = get_token_network_events(
        proxy_manager=raiden.proxy_manager,
        token_network_address=token_network_address,
        contract_manager=raiden.contract_manager,
        events=ALL_EVENTS,
        from_block=from_block,
        to_block=to_block,
    )

    for event in returned_events:
        if event.get("args"):
            event["args"] = dict(event["args"])

    returned_events.sort(key=lambda evt: evt.get("block_number"), reverse=True)
    return returned_events
