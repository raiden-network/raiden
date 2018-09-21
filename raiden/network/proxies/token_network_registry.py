from typing import Optional

import structlog
from eth_utils import (
    encode_hex,
    event_abi_to_log_topic,
    is_binary_address,
    is_same_address,
    to_canonical_address,
    to_checksum_address,
    to_normalized_address,
)
from web3.exceptions import BadFunctionCallOutput
from web3.utils.filters import Filter

from raiden.constants import NULL_ADDRESS
from raiden.exceptions import (
    AddressWrongContract,
    ContractVersionMismatch,
    InvalidAddress,
    RaidenRecoverableError,
    TransactionThrew,
)
from raiden.network.rpc.client import check_address_has_code
from raiden.network.rpc.transactions import check_transaction_threw
from raiden.settings import EXPECTED_CONTRACTS_VERSION
from raiden.utils import compare_versions, pex, privatekey_to_address, typing
from raiden_contracts.constants import CONTRACT_TOKEN_NETWORK_REGISTRY, EVENT_TOKEN_NETWORK_CREATED
from raiden_contracts.contract_manager import CONTRACT_MANAGER


class TokenNetworkRegistry:
    def __init__(
            self,
            jsonrpc_client,
            registry_address,
    ):
        if not is_binary_address(registry_address):
            raise InvalidAddress('Expected binary address format for token network registry')

        check_address_has_code(jsonrpc_client, registry_address, CONTRACT_TOKEN_NETWORK_REGISTRY)

        proxy = jsonrpc_client.new_contract_proxy(
            CONTRACT_MANAGER.get_contract_abi(CONTRACT_TOKEN_NETWORK_REGISTRY),
            to_normalized_address(registry_address),
        )

        try:
            is_valid_version = compare_versions(
                proxy.contract.functions.contract_version().call(),
                EXPECTED_CONTRACTS_VERSION,
            )
        except BadFunctionCallOutput:
            raise AddressWrongContract('')
        if not is_valid_version:
            raise ContractVersionMismatch('Incompatible ABI for TokenNetworkRegistry')

        self.address = registry_address
        self.proxy = proxy
        self.client = jsonrpc_client
        self.node_address = privatekey_to_address(self.client.privkey)
        self.log = structlog.get_logger(__name__)

    def get_token_network(self, token_address: typing.TokenAddress) -> Optional[typing.Address]:
        """ Return the token network address for the given token or None if
        there is no correspoding address.
        """
        if not isinstance(token_address, typing.T_TargetAddress):
            raise ValueError('token_address must be an address')

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

        self.log.info(
            'add_token called',
            node=pex(self.node_address),
            token_address=pex(token_address),
            registry_address=pex(self.address),
        )

        transaction_hash = self.proxy.transact(
            'createERC20TokenNetwork',
            token_address,
        )

        self.client.poll(transaction_hash)
        receipt_or_none = check_transaction_threw(self.client, transaction_hash)
        if receipt_or_none:
            self.log.info(
                'add_token failed',
                node=pex(self.node_address),
                token_address=pex(token_address),
                registry_address=pex(self.address),
            )
            if self.get_token_network(token_address):
                raise RaidenRecoverableError('Token already registered')
            raise TransactionThrew('createERC20TokenNetwork', receipt_or_none)

        token_network_address = self.get_token_network(token_address)

        if token_network_address is None:
            self.log.info(
                'add_token failed and check_transaction_threw didnt detect it',
                node=pex(self.node_address),
                token_address=pex(token_address),
                registry_address=pex(self.address),
            )

            raise RuntimeError('token_to_token_networks failed')

        self.log.info(
            'add_token successful',
            node=pex(self.node_address),
            token_address=pex(token_address),
            registry_address=pex(self.address),
            token_network_address=pex(token_network_address),
        )

        return token_network_address

    def tokenadded_filter(
            self,
            from_block: typing.BlockSpecification = 0,
            to_block: typing.BlockSpecification = 'latest',
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

    def filter_token_added_events(self):
        filter_ = self.proxy.contract.events.TokenNetworkCreated.createFilter(fromBlock=0)
        events = filter_.get_all_entries()
        if filter_.filter_id:
            self.proxy.contract.web3.eth.uninstallFilter(filter_.filter_id)

        return events

    def settlement_timeout_min(self) -> int:
        """ Returns the minimal settlement timeout for the token network registry. """
        return self.proxy.contract.functions.settlement_timeout_min().call()

    def settlement_timeout_max(self) -> int:
        """ Returns the maximal settlement timeout for the token network registry. """
        return self.proxy.contract.functions.settlement_timeout_max().call()
