from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, cast

import structlog
from eth_abi.codec import ABICodec
from eth_typing import HexStr
from eth_utils import event_abi_to_log_topic
from web3._utils.abi import build_default_registry, filter_by_type
from web3._utils.events import get_event_data
from web3._utils.filters import construct_event_filter_params
from web3.types import BlockNumber, EventData, FilterParams, LogReceipt

from raiden.constants import BLOCK_ID_LATEST, GENESIS_BLOCK_NUMBER
from raiden.network.proxies.service_registry import ServiceRegistry
from raiden.utils.formatting import to_checksum_address
from raiden.utils.typing import (
    ABI,
    Address,
    BlockIdentifier,
    ChannelID,
    SecretRegistryAddress,
    TokenNetworkAddress,
    TokenNetworkRegistryAddress,
)
from raiden_contracts.constants import (
    CONTRACT_SECRET_REGISTRY,
    CONTRACT_SERVICE_REGISTRY,
    CONTRACT_TOKEN_NETWORK,
    CONTRACT_TOKEN_NETWORK_REGISTRY,
    EVENT_REGISTERED_SERVICE,
    EVENT_SECRET_REVEALED,
    EVENT_TOKEN_NETWORK_CREATED,
    ChannelEvent,
)
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
    """Return the filter params for a specific event of a given channel."""
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
    """Return the filter params for all events of a given channel."""

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
    """Helper function to unpack event data using a provided ABI

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


def get_topics_of_events(abi: ABI) -> Dict[str, HexStr]:
    event_abis = filter_by_type("event", abi)
    return {
        ev["name"]: "0x" + event_abi_to_log_topic(ev).hex() for ev in event_abis  # type: ignore
    }


@dataclass
class RaidenContractFilter:
    """Information to construct a filter for all relevant Raiden contract events"""

    token_network_registry_addresses: Set[TokenNetworkRegistryAddress] = field(default_factory=set)
    token_network_addresses: Set[TokenNetworkAddress] = field(default_factory=set)
    channels_of_token_network: Dict[TokenNetworkAddress, Set[ChannelID]] = field(
        default_factory=dict
    )
    secret_registry_address: Optional[SecretRegistryAddress] = None
    ignore_secret_registry_until_channel_found: bool = False
    service_registry: Optional[ServiceRegistry] = None

    def __bool__(self) -> bool:
        return bool(
            self.token_network_registry_addresses
            or self.token_network_addresses
            or any(self.channels_of_token_network.values())
            or self.secret_registry_address
        )

    def to_web3_filters(
        self,
        contract_manager: ContractManager,
        from_block: BlockNumber,
        to_block: BlockNumber,
        node_address: Address,
    ) -> List[FilterParams]:
        """Return a filter dict than can be used with web3's ``getLogs``"""
        tn_event_topics = get_topics_of_events(
            contract_manager.get_contract_abi(CONTRACT_TOKEN_NETWORK)
        )
        filters: List[dict] = []

        if self.token_network_registry_addresses:
            filters.append(
                {
                    "_name": "token_network_registry",
                    "fromBlock": from_block,
                    "toBlock": to_block,
                    "address": [
                        to_checksum_address(addr) for addr in self.token_network_registry_addresses
                    ],
                    "topics": [
                        get_topics_of_events(
                            contract_manager.get_contract_abi(CONTRACT_TOKEN_NETWORK_REGISTRY)
                        )[EVENT_TOKEN_NETWORK_CREATED]
                    ],
                }
            )

        if self.secret_registry_address and not self.ignore_secret_registry_until_channel_found:
            filters.append(
                {
                    "_name": "secret_registry",
                    "fromBlock": from_block,
                    "toBlock": to_block,
                    "address": [to_checksum_address(self.secret_registry_address)],
                    "topics": [
                        get_topics_of_events(
                            contract_manager.get_contract_abi(CONTRACT_SECRET_REGISTRY)
                        )[EVENT_SECRET_REVEALED]
                    ],
                }
            )

        if self.token_network_addresses:
            node_topic = HexStr("0x" + (bytes([0] * 12) + node_address).hex())
            filters.extend(
                [
                    {
                        "_name": "token_network",
                        "fromBlock": from_block,
                        "toBlock": to_block,
                        "address": [
                            to_checksum_address(addr) for addr in self.token_network_addresses
                        ],
                        "topics": [tn_event_topics[ChannelEvent.OPENED], None, node_topic],
                    },
                    {
                        "_name": "token_network",
                        "fromBlock": from_block,
                        "toBlock": to_block,
                        "address": [
                            to_checksum_address(addr) for addr in self.token_network_addresses
                        ],
                        "topics": [tn_event_topics[ChannelEvent.OPENED], None, None, node_topic],
                    },
                ]
            )

        if self.channels_of_token_network:
            channel_topics = [
                tn_event_topics[ev]
                for ev in [
                    ChannelEvent.CLOSED,
                    ChannelEvent.SETTLED,
                    ChannelEvent.DEPOSIT,
                    ChannelEvent.WITHDRAW,
                    ChannelEvent.UNLOCKED,
                ]
            ]
            filters.extend(
                {
                    "_name": "channel",
                    "fromBlock": from_block,
                    "toBlock": to_block,
                    "address": to_checksum_address(tn),
                    "topics": [channel_topics, [HexStr("0x{:064x}".format(c)) for c in channels]],
                }
                for tn, channels in self.channels_of_token_network.items()
            )
        if self.service_registry is not None:
            filters.append(
                {
                    "_name": "service_registered",
                    "fromBlock": from_block,
                    "toBlock": to_block,
                    "address": self.service_registry.address,
                    "topics": [
                        get_topics_of_events(self.service_registry.proxy.abi)[
                            EVENT_REGISTERED_SERVICE
                        ]
                    ],
                }
            )

        # The filters contain a ``_name`` key, which does not belong into
        # FilterParams. But that key is very helpful when debugging and it
        # gets ``pop``ed out before the filter is sent to the eth node.
        return cast(List[FilterParams], filters)

    def abi_of_contract_address(self, contract_manager: ContractManager) -> Dict[Address, ABI]:
        """This class knows which ABI is behind each filtered contract address"""
        tnr_abi = contract_manager.get_contract_abi(CONTRACT_TOKEN_NETWORK_REGISTRY)
        tn_abi = contract_manager.get_contract_abi(CONTRACT_TOKEN_NETWORK)
        secret_registry_abi = contract_manager.get_contract_abi(CONTRACT_SECRET_REGISTRY)
        service_registry_abi = contract_manager.get_contract_abi(CONTRACT_SERVICE_REGISTRY)
        abis = {
            **{Address(tnr): tnr_abi for tnr in self.token_network_registry_addresses},
            **{Address(tn): tn_abi for tn in self.token_network_addresses},
        }
        if self.secret_registry_address:
            abis[Address(self.secret_registry_address)] = secret_registry_abi
        if self.service_registry:
            abis[Address(self.service_registry.address)] = service_registry_abi
        return abis

    def union(self, other: "RaidenContractFilter") -> "RaidenContractFilter":
        """Return a new RaidenContractFilter with all elements from both input filters"""
        # We must not have two different non-None secret registries. Choose the non-None one.
        non_none_secret_registries = {
            self.secret_registry_address,
            other.secret_registry_address,
        } - {None}
        assert len(non_none_secret_registries) <= 1, "Mismatching secret_registry_address"
        secret_registry_address = (
            non_none_secret_registries.pop() if non_none_secret_registries else None
        )

        return RaidenContractFilter(
            secret_registry_address=secret_registry_address,
            token_network_registry_addresses=self.token_network_registry_addresses
            | other.token_network_registry_addresses,
            token_network_addresses=self.token_network_addresses | other.token_network_addresses,
            channels_of_token_network={
                tn: self.channels_of_token_network.get(tn, set())
                | other.channels_of_token_network.get(tn, set())
                for tn in {
                    *self.channels_of_token_network.keys(),
                    *other.channels_of_token_network.keys(),
                }
            },
            ignore_secret_registry_until_channel_found=(
                self.ignore_secret_registry_until_channel_found
                and other.ignore_secret_registry_until_channel_found
            ),
            # We must not have two different non-None service registries. Choose the non-None one.
            service_registry=(
                {self.service_registry, other.service_registry} - {None} or {None}
            ).pop(),
        )
