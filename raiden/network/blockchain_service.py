import gevent
import structlog
from cachetools.func import ttl_cache
from eth_utils import is_binary_address
from gevent.lock import Semaphore

from raiden.network.proxies import (
    Discovery,
    PaymentChannel,
    SecretRegistry,
    Token,
    TokenNetwork,
    TokenNetworkRegistry,
)
from raiden.network.rpc.client import JSONRPCClient
from raiden.utils import privatekey_to_address
from raiden.utils.typing import Address, ChannelID, T_ChannelID

log = structlog.get_logger(__name__)  # pylint: disable=invalid-name


class BlockChainService:
    """ Exposes the blockchain's state through JSON-RPC. """
    # pylint: disable=too-many-instance-attributes

    def __init__(
            self,
            privatekey_bin: bytes,
            jsonrpc_client: JSONRPCClient,
    ):
        self.address_to_discovery = dict()
        self.address_to_secret_registry = dict()
        self.address_to_token = dict()
        self.address_to_token_network = dict()
        self.address_to_token_network_registry = dict()
        self.identifier_to_payment_channel = dict()

        self.client = jsonrpc_client
        self.private_key = privatekey_bin
        self.node_address = privatekey_to_address(privatekey_bin)

        self._token_creation_lock = Semaphore()
        self._discovery_creation_lock = Semaphore()
        self._token_network_creation_lock = Semaphore()
        self._token_network_registry_creation_lock = Semaphore()
        self._secret_registry_creation_lock = Semaphore()
        self._payment_channel_creation_lock = Semaphore()

    def block_number(self) -> int:
        return self.client.block_number()

    def get_block(self, block_identifier):
        return self.client.web3.eth.getBlock(block_identifier=block_identifier)

    def is_synced(self) -> bool:
        result = self.client.web3.eth.syncing

        # the node is synchronized
        if result is False:
            return True

        current_block = self.block_number()
        highest_block = result['highestBlock']

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
        last_timestamp = self.get_block_header(last_block_number)['timestamp']
        first_timestamp = self.get_block_header(last_block_number - interval)['timestamp']
        delta = last_timestamp - first_timestamp
        return delta / interval

    def get_block_header(self, block_number: int):
        return self.client.web3.eth.getBlock(block_number, False)

    def next_block(self) -> int:
        current_block = self.block_number()
        target_block_number = current_block + 1

        while current_block < target_block_number:
            current_block = self.block_number()
            gevent.sleep(0.5)

        return current_block

    def token(self, token_address: Address) -> Token:
        """ Return a proxy to interact with a token. """
        if not is_binary_address(token_address):
            raise ValueError('token_address must be a valid address')

        with self._token_creation_lock:
            if token_address not in self.address_to_token:
                self.address_to_token[token_address] = Token(
                    self.client,
                    token_address,
                )

        return self.address_to_token[token_address]

    def discovery(self, discovery_address: Address) -> Discovery:
        """ Return a proxy to interact with the discovery. """
        if not is_binary_address(discovery_address):
            raise ValueError('discovery_address must be a valid address')

        with self._discovery_creation_lock:
            if discovery_address not in self.address_to_discovery:
                self.address_to_discovery[discovery_address] = Discovery(
                    self.client,
                    discovery_address,
                )

        return self.address_to_discovery[discovery_address]

    def token_network_registry(self, address: Address) -> TokenNetworkRegistry:
        if not is_binary_address(address):
            raise ValueError('address must be a valid address')

        with self._token_network_registry_creation_lock:
            if address not in self.address_to_token_network_registry:
                self.address_to_token_network_registry[address] = TokenNetworkRegistry(
                    self.client,
                    address,
                )

        return self.address_to_token_network_registry[address]

    def token_network(self, address: Address) -> TokenNetwork:
        if not is_binary_address(address):
            raise ValueError('address must be a valid address')

        with self._token_network_creation_lock:
            if address not in self.address_to_token_network:
                self.address_to_token_network[address] = TokenNetwork(
                    self.client,
                    address,
                )

        return self.address_to_token_network[address]

    def secret_registry(self, address: Address) -> SecretRegistry:
        if not is_binary_address(address):
            raise ValueError('address must be a valid address')

        with self._secret_registry_creation_lock:
            if address not in self.address_to_secret_registry:
                self.address_to_secret_registry[address] = SecretRegistry(
                    self.client,
                    address,
                )

        return self.address_to_secret_registry[address]

    def payment_channel(
            self,
            token_network_address: Address,
            channel_id: ChannelID,
    ) -> PaymentChannel:

        if not is_binary_address(token_network_address):
            raise ValueError('address must be a valid address')
        if not isinstance(channel_id, T_ChannelID):
            raise ValueError('channel identifier must be of type T_ChannelID')

        with self._payment_channel_creation_lock:
            dict_key = (token_network_address, channel_id)

            if dict_key not in self.identifier_to_payment_channel:
                token_network = self.token_network(token_network_address)

                self.identifier_to_payment_channel[dict_key] = PaymentChannel(
                    token_network=token_network,
                    channel_identifier=channel_id,
                )

        return self.identifier_to_payment_channel[dict_key]

    @property
    @ttl_cache(ttl=30)
    def network_id(self) -> int:
        return int(self.client.web3.version.network)
