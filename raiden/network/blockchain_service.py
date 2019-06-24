import gevent
from eth_utils import is_binary_address
from gevent.lock import Semaphore

from raiden.network.proxies.payment_channel import PaymentChannel
from raiden.network.proxies.secret_registry import SecretRegistry
from raiden.network.proxies.service_registry import ServiceRegistry
from raiden.network.proxies.token import Token
from raiden.network.proxies.token_network import TokenNetwork
from raiden.network.proxies.token_network_registry import TokenNetworkRegistry
from raiden.network.proxies.user_deposit import UserDeposit
from raiden.network.rpc.client import JSONRPCClient
from raiden.transfer.identifiers import CanonicalIdentifier
from raiden.utils.typing import (
    Address,
    BlockHash,
    BlockNumber,
    ChainID,
    ChannelID,
    Dict,
    PaymentNetworkAddress,
    T_ChannelID,
    TokenAddress,
    TokenNetworkAddress,
    Tuple,
    typecheck,
)
from raiden_contracts.contract_manager import ContractManager


class BlockChainService:
    """ Exposes the blockchain's state through JSON-RPC. """

    # pylint: disable=too-many-instance-attributes

    def __init__(self, jsonrpc_client: JSONRPCClient, contract_manager: ContractManager):
        self.address_to_secret_registry: Dict[Address, SecretRegistry] = dict()
        self.address_to_token: Dict[TokenAddress, Token] = dict()
        self.address_to_token_network: Dict[TokenNetworkAddress, TokenNetwork] = dict()
        self.address_to_token_network_registry: Dict[Address, TokenNetworkRegistry] = dict()
        self.address_to_user_deposit: Dict[Address, UserDeposit] = dict()
        self.address_to_service_registry: Dict[Address, ServiceRegistry] = dict()
        self.identifier_to_payment_channel: Dict[
            Tuple[TokenNetworkAddress, ChannelID], PaymentChannel
        ] = dict()

        self.client = jsonrpc_client
        self.contract_manager = contract_manager

        # Ask for the network id only once and store it here
        self.network_id = ChainID(int(self.client.web3.version.network))

        self._token_creation_lock = Semaphore()
        self._token_network_creation_lock = Semaphore()
        self._token_network_registry_creation_lock = Semaphore()
        self._secret_registry_creation_lock = Semaphore()
        self._service_registry_creation_lock = Semaphore()
        self._payment_channel_creation_lock = Semaphore()
        self._user_deposit_creation_lock = Semaphore()

    @property
    def node_address(self) -> Address:
        return self.client.address

    def block_number(self) -> BlockNumber:
        return self.client.block_number()

    def block_hash(self) -> BlockHash:
        return self.client.blockhash_from_blocknumber("latest")

    def get_block(self, block_identifier):
        return self.client.web3.eth.getBlock(block_identifier=block_identifier)

    def is_synced(self) -> bool:
        result = self.client.web3.eth.syncing

        # the node is synchronized
        if result is False:
            return True

        current_block = self.block_number()
        highest_block = result["highestBlock"]

        if highest_block - current_block > 2:
            return False

        return True

    def estimate_blocktime(self, oldest: int = 256) -> float:
        """Calculate a blocktime estimate based on some past blocks.
        Args:
            oldest: delta in block numbers to go back.
        Return:
            average block time in seconds
        """
        last_block_number = self.block_number()
        # around genesis block there is nothing to estimate
        if last_block_number < 1:
            return 15
        # if there are less than `oldest` blocks available, start at block 1
        if last_block_number < oldest:
            interval = (last_block_number - 1) or 1
        else:
            interval = last_block_number - oldest
        assert interval > 0
        last_timestamp = self.get_block_header(last_block_number)["timestamp"]
        first_timestamp = self.get_block_header(last_block_number - interval)["timestamp"]
        delta = last_timestamp - first_timestamp
        return delta / interval

    def get_block_header(self, block_number: int):
        return self.client.web3.eth.getBlock(block_number, False)

    def next_block(self) -> int:
        target_block_number = self.block_number() + 1
        self.wait_until_block(target_block_number=target_block_number)
        return target_block_number

    def wait_until_block(self, target_block_number):
        current_block = self.block_number()

        while current_block < target_block_number:
            current_block = self.block_number()
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

    def token_network_registry(self, address: Address) -> TokenNetworkRegistry:
        if not is_binary_address(address):
            raise ValueError("address must be a valid address")

        with self._token_network_registry_creation_lock:
            if address not in self.address_to_token_network_registry:
                self.address_to_token_network_registry[address] = TokenNetworkRegistry(
                    jsonrpc_client=self.client,
                    registry_address=PaymentNetworkAddress(address),
                    contract_manager=self.contract_manager,
                    blockchain_service=self,
                )

        return self.address_to_token_network_registry[address]

    def token_network(self, address: TokenNetworkAddress) -> TokenNetwork:
        if not is_binary_address(address):
            raise ValueError("address must be a valid address")

        with self._token_network_creation_lock:
            if address not in self.address_to_token_network:
                self.address_to_token_network[address] = TokenNetwork(
                    jsonrpc_client=self.client,
                    token_network_address=address,
                    contract_manager=self.contract_manager,
                    blockchain_service=self,
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
                    blockchain_service=self,
                )

        return self.address_to_user_deposit[address]
