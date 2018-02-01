# -*- coding: utf-8 -*-
import os

import gevent
from ethereum import slogging
from ethereum.tools import _solidity

from raiden.network.rpc.client import JSONRPCClient
from raiden.network.proxies import (
    Discovery,
    Token,
    NettingChannel,
    Registry,
)
from raiden.settings import DEFAULT_POLL_TIMEOUT
from raiden.utils import (
    block_tag_encoder,
    isaddress,
    privatekey_to_address,
    quantity_decoder,
)

log = slogging.getLogger(__name__)  # pylint: disable=invalid-name


class BlockChainService:
    """ Exposes the blockchain's state through JSON-RPC. """
    # pylint: disable=too-many-instance-attributes

    def __init__(
            self,
            privatekey_bin: bytes,
            jsonrpc_client: JSONRPCClient,
            poll_timeout: int = DEFAULT_POLL_TIMEOUT):

        self.address_to_token = dict()
        self.address_to_discovery = dict()
        self.address_to_nettingchannel = dict()
        self.address_to_registry = dict()

        self.client = jsonrpc_client
        self.private_key = privatekey_bin
        self.node_address = privatekey_to_address(privatekey_bin)
        self.poll_timeout = poll_timeout

    def block_number(self) -> int:
        return self.client.block_number()

    def is_synced(self) -> bool:
        result = self.client.call('eth_syncing')

        # the node is synchronized
        if result is False:
            return True

        current_block = self.block_number()
        highest_block = quantity_decoder(result['highestBlock'])

        if highest_block - current_block > 2:
            return False

        return True

    def estimate_blocktime(self, oldest: int=256) -> float:
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
        block_number = block_tag_encoder(block_number)
        return self.client.call('eth_getBlockByNumber', block_number, False)

    def next_block(self) -> int:
        target_block_number = self.block_number() + 1
        current_block = target_block_number

        while not current_block >= target_block_number:
            current_block = self.block_number()
            gevent.sleep(0.5)

        return current_block

    def token(self, token_address: bytes) -> Token:
        """ Return a proxy to interact with a token. """
        if not isaddress(token_address):
            raise ValueError('token_address must be a valid address')

        if token_address not in self.address_to_token:
            self.address_to_token[token_address] = Token(
                self.client,
                token_address,
                self.poll_timeout,
            )

        return self.address_to_token[token_address]

    def discovery(self, discovery_address: bytes) -> Discovery:
        """ Return a proxy to interact with the discovery. """
        if not isaddress(discovery_address):
            raise ValueError('discovery_address must be a valid address')

        if discovery_address not in self.address_to_discovery:
            self.address_to_discovery[discovery_address] = Discovery(
                self.client,
                discovery_address,
                self.poll_timeout,
            )

        return self.address_to_discovery[discovery_address]

    def netting_channel(self, netting_channel_address: bytes) -> NettingChannel:
        """ Return a proxy to interact with a NettingChannelContract. """
        if not isaddress(netting_channel_address):
            raise ValueError('netting_channel_address must be a valid address')

        if netting_channel_address not in self.address_to_nettingchannel:
            channel = NettingChannel(
                self.client,
                netting_channel_address,
                self.poll_timeout,
            )
            self.address_to_nettingchannel[netting_channel_address] = channel

        return self.address_to_nettingchannel[netting_channel_address]

    def registry(self, registry_address: bytes) -> Registry:
        if not isaddress(registry_address):
            raise ValueError('registry_address must be a valid address')

        if registry_address not in self.address_to_registry:
            self.address_to_registry[registry_address] = Registry(
                self.client,
                registry_address,
                self.poll_timeout,
            )

        return self.address_to_registry[registry_address]

    def uninstall_filter(self, filter_id_raw):
        self.client.call('eth_uninstallFilter', filter_id_raw)

    def deploy_contract(self, contract_name, contract_path, constructor_parameters=None):
        contracts = _solidity.compile_file(contract_path, libraries=dict())

        log.info(
            'Deploying "%s" contract',
            os.path.basename(contract_path),
        )

        proxy = self.client.deploy_solidity_contract(
            self.node_address,
            contract_name,
            contracts,
            list(),
            constructor_parameters,
            contract_path=contract_path,
            timeout=self.poll_timeout,
        )
        return proxy.contract_address

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
