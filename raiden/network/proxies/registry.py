# -*- coding: utf-8 -*-
from binascii import hexlify, unhexlify

import structlog
from eth_utils import (
    is_binary_address,
    to_checksum_address,
    to_normalized_address,
    to_canonical_address,
)
from web3.utils.filters import Filter
from web3.exceptions import BadFunctionCallOutput

from raiden.blockchain.abi import (
    CONTRACT_MANAGER,
    CONTRACT_REGISTRY,

    EVENT_TOKEN_ADDED,
)
from raiden.exceptions import (
    NoTokenManager,
    TransactionThrew,
)
from raiden.utils import (
    pex,
    privatekey_to_address,
)
from raiden.settings import (
    DEFAULT_POLL_TIMEOUT,
)
from raiden.network.proxies.channel_manager import ChannelManager
from raiden.network.rpc.client import check_address_has_code
from raiden.network.rpc.transactions import (
    check_transaction_threw,
)
from raiden.network.rpc.smartcontract_proxy import ContractProxy

log = structlog.get_logger(__name__)  # pylint: disable=invalid-name

try:
    from eth_tester.exceptions import TransactionFailed
except ModuleNotFoundError:
    TransactionFailed = Exception()


class Registry:
    def __init__(
            self,
            jsonrpc_client,
            registry_address,
            poll_timeout=DEFAULT_POLL_TIMEOUT,
    ):
        # pylint: disable=too-many-arguments
        contract = jsonrpc_client.new_contract(
            CONTRACT_MANAGER.get_contract_abi(CONTRACT_REGISTRY),
            to_normalized_address(registry_address),
        )
        self.proxy = ContractProxy(jsonrpc_client, contract)

        if not is_binary_address(registry_address):
            raise ValueError('registry_address must be a valid address')

        check_address_has_code(jsonrpc_client, registry_address, 'Registry')

        CONTRACT_MANAGER.check_contract_version(
            self.proxy.contract.functions.contract_version().call(),
            CONTRACT_REGISTRY,
        )

        self.address = registry_address
        self.client = jsonrpc_client
        self.poll_timeout = poll_timeout
        self.node_address = privatekey_to_address(self.client.privkey)

        self.address_to_channelmanager = dict()
        self.token_to_channelmanager = dict()

    def manager_address_by_token(self, token_address):
        """ Return the channel manager address for the given token or None if
        there is no correspoding address.
        """
        try:
            address = self.proxy.contract.functions.channelManagerByToken(
                to_checksum_address(token_address),
            ).call()
        except (BadFunctionCallOutput, TransactionFailed) as e:
            check_address_has_code(self.client, self.address)
            return None

        return to_canonical_address(address)

    def add_token(self, token_address):
        if not is_binary_address(token_address):
            raise ValueError('token_address must be a valid address')

        log.info(
            'add_token called',
            node=pex(self.node_address),
            token_address=pex(token_address),
            registry_address=pex(self.address),
        )

        transaction_hash = self.proxy.transact(
            'addToken',
            self.address,
            token_address,
        )

        self.client.poll(unhexlify(transaction_hash), timeout=self.poll_timeout)
        receipt_or_none = check_transaction_threw(self.client, transaction_hash)
        if receipt_or_none:
            log.info(
                'add_token failed',
                node=pex(self.node_address),
                token_address=pex(token_address),
                registry_address=pex(self.address),
            )
            raise TransactionThrew('AddToken', receipt_or_none)

        manager_address = self.manager_address_by_token(token_address)

        if manager_address is None:
            log.info(
                'add_token failed and check_transaction_threw didnt detect it',
                node=pex(self.node_address),
                token_address=pex(token_address),
                registry_address=pex(self.address),
            )

            raise RuntimeError('channelManagerByToken failed')

        log.info(
            'add_token sucessful',
            node=pex(self.node_address),
            token_address=pex(token_address),
            registry_address=pex(self.address),
            manager_address=pex(manager_address),
        )

        return manager_address

    def token_addresses(self):
        addresses = self.proxy.contract.functions.tokenAddresses().call()
        return [
            to_canonical_address(address)
            for address in addresses
        ]

    def manager_addresses(self):
        addresses = self.proxy.contract.functions.channelManagerAddresses().call()
        return [
            to_canonical_address(address)
            for address in addresses
        ]

    def tokenadded_filter(self, from_block=None, to_block=None) -> Filter:
        topics = [CONTRACT_MANAGER.get_event_id(EVENT_TOKEN_ADDED)]

        registry_address_bin = self.proxy.contract_address
        return self.client.new_filter(
            registry_address_bin,
            topics=topics,
            from_block=from_block,
            to_block=to_block,
        )

    def manager(self, manager_address):
        """ Return a proxy to interact with a ChannelManagerContract. """
        if not is_binary_address(manager_address):
            raise ValueError('manager_address must be a valid address')

        if manager_address not in self.address_to_channelmanager:
            manager = ChannelManager(
                self.client,
                manager_address,
                self.poll_timeout,
            )

            token_address = manager.token_address()

            self.token_to_channelmanager[token_address] = manager
            self.address_to_channelmanager[manager_address] = manager

        return self.address_to_channelmanager[manager_address]

    def manager_by_token(self, token_address):
        """ Find the channel manager for `token_address` and return a proxy to
        interact with it.

        If the token is not already registered it raises `EthNodeCommunicationError`,
        since we try to instantiate a Channel manager with an empty address.
        """
        if not is_binary_address(token_address):
            raise ValueError('token_address must be a valid address')

        if token_address not in self.token_to_channelmanager:
            check_address_has_code(self.client, token_address)  # check that the token exists
            manager_address = self.manager_address_by_token(token_address)

            if manager_address is None:
                raise NoTokenManager(
                    'Manager for token 0x{} does not exist'.format(hexlify(token_address)),
                )

            manager = ChannelManager(
                self.client,
                manager_address,
                self.poll_timeout,
            )

            self.token_to_channelmanager[token_address] = manager
            self.address_to_channelmanager[manager_address] = manager

        return self.token_to_channelmanager[token_address]
