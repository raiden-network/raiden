import os

import gevent
from cachetools.func import ttl_cache
import structlog
from eth_utils import (
    to_int,
    is_binary_address,
    decode_hex,
)

from raiden.network.rpc.client import JSONRPCClient
from raiden.network.proxies import (
    Discovery,
    Token,
    TokenNetworkRegistry,
    TokenNetwork,
    SecretRegistry,
    PaymentChannel,
)
from raiden.utils import privatekey_to_address, ishash
from raiden.utils.solc import compile_files_cwd
from raiden.utils.typing import Address, ChannelID

log = structlog.get_logger(__name__)  # pylint: disable=invalid-name


class BlockChainService:
    """ Exposes the blockchain's state through JSON-RPC. """
    # pylint: disable=too-many-instance-attributes

    def __init__(
            self,
            privatekey_bin: bytes,
            jsonrpc_client: JSONRPCClient,
    ):
        self.address_to_token = dict()
        self.address_to_discovery = dict()
        self.address_to_nettingchannel = dict()
        self.address_to_registry = dict()
        self.address_to_manager = dict()

        self.address_to_token_network_registry = dict()
        self.address_to_token_network = dict()
        self.address_to_secret_registry = dict()

        self.identifier_to_payment_channel = dict()

        self.client = jsonrpc_client
        self.private_key = privatekey_bin
        self.node_address = privatekey_to_address(privatekey_bin)

    def block_number(self) -> int:
        return self.client.block_number()

    def is_synced(self) -> bool:
        result = self.client.web3.eth.syncing

        # the node is synchronized
        if result is False:
            return True

        current_block = self.block_number()
        highest_block = to_int(hexstr=result['highestBlock'])

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
        last_timestamp = int(self.get_block_header(last_block_number)['timestamp'], 16)
        first_timestamp = int(self.get_block_header(last_block_number - interval)['timestamp'], 16)
        delta = last_timestamp - first_timestamp
        return delta / interval

    def get_block_header(self, block_number: int):
        return self.client.web3.getBlock(block_number, False)

    def next_block(self) -> int:
        target_block_number = self.block_number() + 1
        current_block = target_block_number

        while not current_block >= target_block_number:
            current_block = self.block_number()
            gevent.sleep(0.5)

        return current_block

    def token(self, token_address: Address) -> Token:
        """ Return a proxy to interact with a token. """
        if not is_binary_address(token_address):
            raise ValueError('token_address must be a valid address')

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

        if discovery_address not in self.address_to_discovery:
            self.address_to_discovery[discovery_address] = Discovery(
                self.client,
                discovery_address,
            )

        return self.address_to_discovery[discovery_address]

    def token_network_registry(self, address: Address) -> TokenNetworkRegistry:
        if not is_binary_address(address):
            raise ValueError('address must be a valid address')

        if address not in self.address_to_token_network_registry:
            self.address_to_token_network_registry[address] = TokenNetworkRegistry(
                self.client,
                address,
            )

        return self.address_to_token_network_registry[address]

    def token_network(self, address: Address) -> TokenNetwork:
        if not is_binary_address(address):
            raise ValueError('address must be a valid address')

        if address not in self.address_to_token_network:
            self.address_to_token_network[address] = TokenNetwork(
                self.client,
                address,
            )

        return self.address_to_token_network[address]

    def secret_registry(self, address: Address) -> SecretRegistry:
        if not is_binary_address(address):
            raise ValueError('address must be a valid address')

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
        if not ishash(channel_id):
            raise ValueError('identifier must be a hash')

        dict_key = (token_network_address, channel_id)

        if dict_key not in self.identifier_to_payment_channel:
            token_network = self.token_network(token_network_address)

            self.identifier_to_payment_channel[dict_key] = PaymentChannel(
                token_network=token_network,
                channel_identifier=channel_id,
            )

        return self.identifier_to_payment_channel[dict_key]

    def deploy_contract(self, contract_name, contract_path, constructor_parameters=None):
        contracts = compile_files_cwd([contract_path])

        log.info('Deploying contract', path=os.path.basename(contract_path))

        proxy = self.client.deploy_solidity_contract(
            contract_name,
            contracts,
            list(),
            constructor_parameters,
            contract_path=contract_path,
        )

        return decode_hex(proxy.contract.address)

    def deploy_and_register_token(
            self,
            registry,
            contract_name,
            contract_path,
            constructor_parameters=None):

        token_address = self.deploy_contract(
            contract_name,
            contract_path,
            constructor_parameters,
        )
        registry.add_token(token_address)

        return token_address

    @property
    @ttl_cache(ttl=10)
    def network_id(self) -> int:
        return int(self.client.web3.version.network)
