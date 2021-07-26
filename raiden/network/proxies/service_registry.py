from urllib.parse import urlparse

import structlog
import web3
from eth_utils import is_binary_address, to_canonical_address
from web3.exceptions import BadFunctionCallOutput

from raiden.exceptions import BrokenPreconditionError, RaidenUnrecoverableError
from raiden.network.rpc.client import (
    JSONRPCClient,
    check_address_has_code_handle_pruned_block,
    was_transaction_successfully_mined,
)
from raiden.utils.typing import (
    Address,
    Any,
    BlockIdentifier,
    Dict,
    Optional,
    ServiceRegistryAddress,
    TokenAddress,
    TokenAmount,
    TransactionHash,
)
from raiden_contracts.constants import CONTRACT_SERVICE_REGISTRY
from raiden_contracts.contract_manager import ContractManager

log = structlog.get_logger(__name__)


class ServiceRegistry:
    def __init__(
        self,
        jsonrpc_client: JSONRPCClient,
        service_registry_address: ServiceRegistryAddress,
        contract_manager: ContractManager,
        block_identifier: BlockIdentifier,
    ):
        if not is_binary_address(service_registry_address):
            raise ValueError("Expected binary address for service registry")

        self.contract_manager = contract_manager
        check_address_has_code_handle_pruned_block(
            client=jsonrpc_client,
            address=Address(service_registry_address),
            contract_name=CONTRACT_SERVICE_REGISTRY,
            given_block_identifier=block_identifier,
        )

        proxy = jsonrpc_client.new_contract_proxy(
            abi=self.contract_manager.get_contract_abi(CONTRACT_SERVICE_REGISTRY),
            contract_address=Address(service_registry_address),
        )

        self.address = service_registry_address
        self.proxy = proxy
        self.client = jsonrpc_client
        self.node_address = self.client.address

    def ever_made_deposits(
        self, block_identifier: BlockIdentifier, index: int
    ) -> Optional[Address]:
        """Get one of the addresses that have ever made a deposit."""
        try:
            ret = Address(
                to_canonical_address(
                    self.proxy.functions.ever_made_deposits(index).call(
                        block_identifier=block_identifier
                    )
                )
            )
            return ret
        except BadFunctionCallOutput:
            return None

    def ever_made_deposits_len(self, block_identifier: BlockIdentifier) -> int:
        """Get the number of addresses that have ever made a deposit"""
        result = self.proxy.functions.everMadeDepositsLen().call(block_identifier=block_identifier)
        return result

    def has_valid_registration(
        self, block_identifier: BlockIdentifier, service_address: Address
    ) -> Optional[bool]:
        try:
            result = self.proxy.functions.hasValidRegistration(service_address).call(
                block_identifier=block_identifier
            )
        except web3.exceptions.BadFunctionCallOutput:
            result = None
        return result

    def get_service_url(
        self, block_identifier: BlockIdentifier, service_address: Address
    ) -> Optional[str]:
        """Gets the URL of a service by address. If does not exist return None"""
        result = self.proxy.functions.urls(service_address).call(block_identifier=block_identifier)
        if result == "":
            return None
        return result

    def current_price(self, block_identifier: BlockIdentifier) -> TokenAmount:
        """Gets the currently required deposit amount."""
        return self.proxy.functions.currentPrice().call(block_identifier=block_identifier)

    def token_address(self, block_identifier: BlockIdentifier) -> TokenAddress:
        return TokenAddress(
            to_canonical_address(
                self.proxy.functions.token().call(block_identifier=block_identifier)
            )
        )

    def deposit(
        self, block_identifier: BlockIdentifier, limit_amount: TokenAmount
    ) -> TransactionHash:
        """Makes a deposit to create or extend a registration"""
        extra_log_details = {"given_block_identifier": block_identifier}
        estimated_transaction = self.client.estimate_gas(
            self.proxy, "deposit", extra_log_details, limit_amount
        )

        if estimated_transaction is None:
            msg = "ServiceRegistry.deposit transaction fails"
            raise RaidenUnrecoverableError(msg)

        transaction_sent = self.client.transact(estimated_transaction)
        transaction_mined = self.client.poll_transaction(transaction_sent)

        if not was_transaction_successfully_mined(transaction_mined):
            msg = "ServiceRegistry.deposit transaction failed"
            raise RaidenUnrecoverableError(msg)
        else:
            return transaction_mined.transaction_hash

    def set_url(self, url: str) -> TransactionHash:
        """Sets the url needed to access the service via HTTP for the caller"""
        if not url.strip():
            msg = "Invalid empty URL"
            raise BrokenPreconditionError(msg)

        parsed_url = urlparse(url)
        if parsed_url.scheme not in ("http", "https"):
            msg = "URL provided to service registry must be a valid HTTP(S) endpoint."
            raise BrokenPreconditionError(msg)

        extra_log_details: Dict[str, Any] = {}
        estimated_transaction = self.client.estimate_gas(
            self.proxy, "setURL", extra_log_details, url
        )
        if estimated_transaction is None:
            msg = f"URL {url} is invalid"
            raise RaidenUnrecoverableError(msg)

        transaction_sent = self.client.transact(estimated_transaction)
        transaction_mined = self.client.poll_transaction(transaction_sent)

        if not was_transaction_successfully_mined(transaction_mined):
            msg = f"URL {url} is invalid"
            raise RaidenUnrecoverableError(msg)
        else:
            return transaction_mined.transaction_hash
