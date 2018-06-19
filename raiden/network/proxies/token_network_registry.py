from binascii import hexlify, unhexlify
from typing import Optional

import structlog
from web3.utils.filters import Filter
from eth_utils import (
    is_binary_address,
    to_normalized_address,
    to_canonical_address,
    encode_hex,
    event_abi_to_log_topic,
    to_checksum_address,
    is_same_address,
)
from raiden_contracts.contract_manager import CONTRACT_MANAGER

from raiden.utils import typing
from raiden_contracts.constants import (
    CONTRACT_TOKEN_NETWORK_REGISTRY,
    EVENT_TOKEN_NETWORK_CREATED,
)
from raiden.constants import NULL_ADDRESS
from raiden.exceptions import (
    NoTokenManager,
    TransactionThrew,
    InvalidAddress,
)
from raiden.utils import (
    pex,
    privatekey_to_address,
)
from raiden.settings import (
    DEFAULT_POLL_TIMEOUT,
)
from raiden.network.proxies.token_network import TokenNetwork
from raiden.network.rpc.client import check_address_has_code
from raiden.network.rpc.transactions import (
    check_transaction_threw,
)

log = structlog.get_logger(__name__)  # pylint: disable=invalid-name


class TokenNetworkRegistry:
    def __init__(
            self,
            jsonrpc_client,
            registry_address,
            poll_timeout=DEFAULT_POLL_TIMEOUT,
    ):
        # pylint: disable=too-many-arguments

        if not is_binary_address(registry_address):
            raise InvalidAddress('Expected binary address format for token network registry')

        check_address_has_code(jsonrpc_client, registry_address, CONTRACT_TOKEN_NETWORK_REGISTRY)

        proxy = jsonrpc_client.new_contract_proxy(
            CONTRACT_MANAGER.get_contract_abi(CONTRACT_TOKEN_NETWORK_REGISTRY),
            to_normalized_address(registry_address),
        )

        # TODO: add this back
        # CONTRACT_MANAGER.check_contract_version(
        #     proxy.functions.contract_version().call(),
        #     CONTRACT_TOKEN_NETWORK_REGISTRY
        # )

        self.address = registry_address
        self.proxy = proxy
        self.client = jsonrpc_client
        self.poll_timeout = poll_timeout
        self.node_address = privatekey_to_address(self.client.privkey)

        self.address_to_tokennetwork = dict()
        self.token_to_tokennetwork = dict()

    def get_token_network(self, token_address: typing.TokenAddress) -> Optional[typing.Address]:
        """ Return the token network address for the given token or None if
        there is no correspoding address.
        """
        address = self.proxy.contract.functions.token_to_token_networks(
            to_checksum_address(token_address),
        ).call()
        address = to_canonical_address(address)

        if is_same_address(address, NULL_ADDRESS):
            return None

        return address

    def add_token(self, token_address: typing.TokenAddress):
        if not is_binary_address(token_address):
            raise InvalidAddress('Expected binary address format for token')

        log.info(
            'add_token called',
            node=pex(self.node_address),
            token_address=pex(token_address),
            registry_address=pex(self.address),
        )

        transaction_hash = self.proxy.transact(
            'createERC20TokenNetwork',
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
            raise TransactionThrew('createERC20TokenNetwork', receipt_or_none)
        token_network_address = self.get_token_network(token_address)

        if token_network_address is None:
            log.info(
                'add_token failed and check_transaction_threw didnt detect it',
                node=pex(self.node_address),
                token_address=pex(token_address),
                registry_address=pex(self.address),
            )

            raise RuntimeError('token_to_token_networks failed')
        self.token_to_tokennetwork[token_address] = TokenNetwork(
            self.client,
            token_network_address,
            self.poll_timeout,
        )

        log.info(
            'add_token sucessful',
            node=pex(self.node_address),
            token_address=pex(token_address),
            registry_address=pex(self.address),
            token_network_address=pex(token_network_address),
        )

        return token_network_address

    def tokenadded_filter(
            self,
            from_block: typing.blockSpecification = 0,
            to_block: typing.blockSpecification = 'latest',
    ) -> Filter:
        event_abi = CONTRACT_MANAGER.get_event_abi(
            CONTRACT_TOKEN_NETWORK_REGISTRY,
            EVENT_TOKEN_NETWORK_CREATED,
        )
        topics = [encode_hex(event_abi_to_log_topic(event_abi))]

        registry_address_bin = self.proxy.contract_address
        return self.client.new_filter(
            registry_address_bin,
            topics=topics,
            from_block=from_block,
            to_block=to_block,
        )

    def token_network(self, token_network_address: typing.TokenNetworkAddress):
        """ Return a proxy to interact with a TokenNetwork. """
        if not is_binary_address(token_network_address):
            raise InvalidAddress('Expected binary address format for token network')

        if token_network_address not in self.address_to_tokennetwork:
            token_network = TokenNetwork(
                self.client,
                token_network_address,
                self.poll_timeout,
            )

            token_address = token_network.token_address()

            self.token_to_tokennetwork[token_address] = token_network
            self.address_to_tokennetwork[token_network_address] = token_network

        return self.address_to_tokennetwork[token_network_address]

    def tokennetwork_by_token(self, token_address: typing.TokenAddress):
        """ Find the token network for `token_address` and return a proxy to
        interact with it.

        If the token is not already registered it raises `EthNodeCommunicationError`,
        since we try to instantiate a Token Network with an empty address.
        """
        if not is_binary_address(token_address):
            raise InvalidAddress('Expected binary address format for token')

        if token_address not in self.token_to_tokennetwork:
            check_address_has_code(self.client, token_address)  # check that the token exists
            token_network_address = self.get_token_network(token_address)

            if token_network_address is None:
                raise NoTokenManager(
                    'TokenNetwork for token 0x{} does not exist'.format(hexlify(token_address)),
                )

            token_network = TokenNetwork(
                self.client,
                token_network_address,
                self.poll_timeout,
            )

            self.token_to_tokennetwork[token_address] = token_network
            self.address_to_tokennetwork[token_network_address] = token_network

        return self.token_to_tokennetwork[token_address]
