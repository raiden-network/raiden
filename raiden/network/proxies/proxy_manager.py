from dataclasses import dataclass

import gevent
from eth_utils import decode_hex, is_binary_address
from gevent.lock import Semaphore

from raiden.network.proxies.metadata import SmartContractMetadata
from raiden.network.proxies.payment_channel import PaymentChannel
from raiden.network.proxies.secret_registry import SecretRegistry
from raiden.network.proxies.service_registry import ServiceRegistry
from raiden.network.proxies.token import Token
from raiden.network.proxies.token_network import TokenNetwork, TokenNetworkMetadata
from raiden.network.proxies.token_network_registry import TokenNetworkRegistry
from raiden.network.proxies.user_deposit import UserDeposit
from raiden.network.rpc.client import JSONRPCClient
from raiden.transfer.identifiers import CanonicalIdentifier
from raiden.utils.typing import (
    Address,
    BlockNumber,
    ChannelID,
    Dict,
    EVMBytecode,
    Optional,
    T_ChannelID,
    TokenAddress,
    TokenNetworkAddress,
    TokenNetworkRegistryAddress,
    Tuple,
    typecheck,
)
from raiden_contracts.constants import CONTRACT_TOKEN_NETWORK, CONTRACT_TOKEN_NETWORK_REGISTRY
from raiden_contracts.contract_manager import ContractManager, gas_measurements


@dataclass
class ProxyManagerMetadata:
    # If the user deployed the smart contract the block at which it was mined
    # is unknown.
    token_network_registry_deployed_at: Optional[BlockNumber]
    filters_start_at: BlockNumber

    def __post_init__(self) -> None:
        # Having a filter installed before or after the smart contract is
        # deployed doesn't make sense. A smaller value will have a negative
        # impact on performance (see #3958), a larger value will miss logs.
        is_filter_start_valid = (
            self.token_network_registry_deployed_at is None
            or self.token_network_registry_deployed_at == self.filters_start_at
        )
        if not is_filter_start_valid:
            raise ValueError(
                "The deployed_at is known, the filters should start at that exact block"
            )


class ProxyManager:
    """ Encapsulates access and creation of contract proxies.

    This class keeps track of mapping between contract addresses and their internal
    contract proxy counterparts. It also synchronizes creation of proxies, so that
    a 1-to-1 relationship is kept.
    """

    # pylint: disable=too-many-instance-attributes

    def __init__(
        self,
        rpc_client: JSONRPCClient,
        contract_manager: ContractManager,
        metadata: ProxyManagerMetadata,
    ) -> None:
        self.address_to_secret_registry: Dict[Address, SecretRegistry] = dict()
        self.address_to_token: Dict[TokenAddress, Token] = dict()
        self.address_to_token_network: Dict[TokenNetworkAddress, TokenNetwork] = dict()
        self.address_to_token_network_registry: Dict[
            TokenNetworkRegistryAddress, TokenNetworkRegistry
        ] = dict()
        self.address_to_user_deposit: Dict[Address, UserDeposit] = dict()
        self.address_to_service_registry: Dict[Address, ServiceRegistry] = dict()
        self.identifier_to_payment_channel: Dict[
            Tuple[TokenNetworkAddress, ChannelID], PaymentChannel
        ] = dict()

        self.client = rpc_client
        self.contract_manager = contract_manager
        self.metadata = metadata

        self._token_creation_lock = Semaphore()
        self._token_network_creation_lock = Semaphore()
        self._token_network_registry_creation_lock = Semaphore()
        self._secret_registry_creation_lock = Semaphore()
        self._service_registry_creation_lock = Semaphore()
        self._payment_channel_creation_lock = Semaphore()
        self._user_deposit_creation_lock = Semaphore()

    def estimate_blocktime(self, oldest: int = 256) -> float:
        """Calculate a blocktime estimate based on some past blocks.
        Args:
            oldest: delta in block numbers to go back.
        Return:
            average block time in seconds
        """
        last_block_number = self.client.block_number()
        # around genesis block there is nothing to estimate
        if last_block_number < 1:
            return 15
        # if there are less than `oldest` blocks available, start at block 1
        if last_block_number < oldest:
            interval = (last_block_number - 1) or 1
        else:
            interval = last_block_number - oldest
        assert interval > 0
        last_timestamp = self.client.get_block(last_block_number)["timestamp"]
        first_timestamp = self.client.get_block(last_block_number - interval)["timestamp"]
        delta = last_timestamp - first_timestamp
        return delta / interval

    def wait_until_block(self, target_block_number: BlockNumber) -> BlockNumber:
        current_block = self.client.block_number()

        while current_block < target_block_number:
            current_block = self.client.block_number()
            gevent.sleep(0.5)

        return current_block

    def token(self, token_address: TokenAddress) -> Token:
        """ Return a proxy to interact with a token. """
        if not is_binary_address(token_address):
            raise ValueError("token_address must be a valid address")

        with self._token_creation_lock:
            if token_address not in self.address_to_token:
                self.address_to_token[token_address] = Token(
                    jsonrpc_client=self.client,
                    token_address=token_address,
                    contract_manager=self.contract_manager,
                )

        return self.address_to_token[token_address]

    def token_network_registry(self, address: TokenNetworkRegistryAddress) -> TokenNetworkRegistry:

        with self._token_network_registry_creation_lock:
            if address not in self.address_to_token_network_registry:

                metadata = SmartContractMetadata(
                    deployed_at=self.metadata.token_network_registry_deployed_at,
                    address=Address(address),
                    abi=self.contract_manager.get_contract_abi(CONTRACT_TOKEN_NETWORK_REGISTRY),
                    runtime_bytecode=EVMBytecode(
                        decode_hex(
                            self.contract_manager.get_runtime_hexcode(
                                CONTRACT_TOKEN_NETWORK_REGISTRY
                            )
                        )
                    ),
                    gas_measurements=gas_measurements(self.contract_manager.contracts_version),
                    filters_start_at=self.metadata.filters_start_at,
                )

                self.address_to_token_network_registry[address] = TokenNetworkRegistry(
                    rpc_client=self.client, metadata=metadata, proxy_manager=self
                )

        return self.address_to_token_network_registry[address]

    def token_network(self, address: TokenNetworkAddress) -> TokenNetwork:
        if not is_binary_address(address):
            raise ValueError("address must be a valid address")

        with self._token_network_creation_lock:
            if address not in self.address_to_token_network:
                metadata = TokenNetworkMetadata(
                    deployed_at=None,
                    abi=self.contract_manager.get_contract_abi(CONTRACT_TOKEN_NETWORK),
                    gas_measurements=gas_measurements(self.contract_manager.contracts_version),
                    runtime_bytecode=EVMBytecode(
                        decode_hex(
                            self.contract_manager.get_runtime_hexcode(CONTRACT_TOKEN_NETWORK)
                        )
                    ),
                    address=Address(address),
                    token_network_registry_address=None,
                    filters_start_at=self.metadata.filters_start_at,
                )

                self.address_to_token_network[address] = TokenNetwork(
                    jsonrpc_client=self.client,
                    contract_manager=self.contract_manager,
                    proxy_manager=self,
                    metadata=metadata,
                )

        return self.address_to_token_network[address]

    def secret_registry(self, address: Address) -> SecretRegistry:
        if not is_binary_address(address):
            raise ValueError("address must be a valid address")

        with self._secret_registry_creation_lock:
            if address not in self.address_to_secret_registry:
                self.address_to_secret_registry[address] = SecretRegistry(
                    jsonrpc_client=self.client,
                    secret_registry_address=address,
                    contract_manager=self.contract_manager,
                )

        return self.address_to_secret_registry[address]

    def service_registry(self, address: Address) -> ServiceRegistry:
        with self._service_registry_creation_lock:
            if address not in self.address_to_service_registry:
                self.address_to_service_registry[address] = ServiceRegistry(
                    jsonrpc_client=self.client,
                    service_registry_address=address,
                    contract_manager=self.contract_manager,
                )

        return self.address_to_service_registry[address]

    def payment_channel(self, canonical_identifier: CanonicalIdentifier) -> PaymentChannel:

        token_network_address = canonical_identifier.token_network_address
        channel_id = canonical_identifier.channel_identifier

        if not is_binary_address(token_network_address):
            raise ValueError("address must be a valid address")
        typecheck(channel_id, T_ChannelID)

        with self._payment_channel_creation_lock:
            dict_key = (token_network_address, channel_id)

            if dict_key not in self.identifier_to_payment_channel:
                token_network = self.token_network(token_network_address)

                self.identifier_to_payment_channel[dict_key] = PaymentChannel(
                    token_network=token_network,
                    channel_identifier=channel_id,
                    contract_manager=self.contract_manager,
                )

        return self.identifier_to_payment_channel[dict_key]

    def user_deposit(self, address: Address) -> UserDeposit:
        if not is_binary_address(address):
            raise ValueError("address must be a valid address")

        with self._user_deposit_creation_lock:
            if address not in self.address_to_user_deposit:
                self.address_to_user_deposit[address] = UserDeposit(
                    jsonrpc_client=self.client,
                    user_deposit_address=address,
                    contract_manager=self.contract_manager,
                    proxy_manager=self,
                )

        return self.address_to_user_deposit[address]
