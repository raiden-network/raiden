from urllib.parse import urlparse

import structlog
import web3
from eth_utils import is_binary_address, to_bytes, to_canonical_address, to_checksum_address
from web3.exceptions import BadFunctionCallOutput

from raiden.exceptions import BrokenPreconditionError, InvalidAddress, RaidenUnrecoverableError
from raiden.network.proxies.utils import log_transaction
from raiden.network.rpc.client import JSONRPCClient, check_address_has_code
from raiden.network.rpc.transactions import check_transaction_threw
from raiden.utils.typing import Address, AddressHex, BlockSpecification, Optional, TokenAmount
from raiden_contracts.constants import CONTRACT_SERVICE_REGISTRY
from raiden_contracts.contract_manager import ContractManager

log = structlog.get_logger(__name__)


class ServiceRegistry:
    def __init__(
        self,
        jsonrpc_client: JSONRPCClient,
        service_registry_address: Address,
        contract_manager: ContractManager,
    ):
        if not is_binary_address(service_registry_address):
            raise InvalidAddress("Expected binary address for service registry")

        self.contract_manager = contract_manager
        check_address_has_code(
            jsonrpc_client,
            service_registry_address,
            CONTRACT_SERVICE_REGISTRY,
            expected_code=to_bytes(
                hexstr=contract_manager.get_runtime_hexcode(CONTRACT_SERVICE_REGISTRY)
            ),
        )

        proxy = jsonrpc_client.new_contract_proxy(
            self.contract_manager.get_contract_abi(CONTRACT_SERVICE_REGISTRY),
            to_canonical_address(service_registry_address),
        )

        self.address = service_registry_address
        self.proxy = proxy
        self.client = jsonrpc_client
        self.node_address = self.client.address

    def ever_made_deposits(
        self, block_identifier: BlockSpecification, index: int
    ) -> Optional[Address]:
        """Get one of the addresses that have ever made a deposit."""
        try:
            ret = Address(
                to_canonical_address(
                    self.proxy.contract.functions.ever_made_deposits(index).call(
                        block_identifier=block_identifier
                    )
                )
            )
            return ret
        except BadFunctionCallOutput:
            return None

    def ever_made_deposits_len(self, block_identifier: BlockSpecification) -> int:
        """Get the number of addresses that have ever made a deposit"""
        result = self.proxy.contract.functions.everMadeDepositsLen().call(
            block_identifier=block_identifier
        )
        return result

    def has_valid_registration(
        self, block_identifier: BlockSpecification, address: Address
    ) -> Optional[bool]:
        try:
            result = self.proxy.contract.functions.hasValidRegistration(address).call(
                block_identifier=block_identifier
            )
        except web3.exceptions.BadFunctionCallOutput:
            result = None
        return result

    def get_service_url(
        self, block_identifier: BlockSpecification, service_hex_address: AddressHex
    ) -> Optional[str]:
        """Gets the URL of a service by address. If does not exist return None"""
        result = self.proxy.contract.functions.urls(service_hex_address).call(
            block_identifier=block_identifier
        )
        if result == "":
            return None
        return result

    def current_price(self, block_identifier: BlockSpecification) -> TokenAmount:
        """Gets the currently required deposit amount."""
        return self.proxy.contract.functions.currentPrice().call(block_identifier=block_identifier)

    def token_address(self, block_identifier: BlockSpecification) -> Address:
        return Address(
            to_canonical_address(
                self.proxy.contract.functions.token().call(block_identifier=block_identifier)
            )
        )

    def deposit(self, block_identifier: BlockSpecification, limit_amount: TokenAmount) -> None:
        """Makes a deposit to create or extend a registration"""
        gas_limit = self.proxy.estimate_gas(block_identifier, "deposit", limit_amount)
        if not gas_limit:
            msg = "ServiceRegistry.deposit transaction fails"
            raise RaidenUnrecoverableError(msg)
        transaction_hash = self.proxy.transact("deposit", gas_limit, limit_amount)
        self.client.poll(transaction_hash)
        receipt = check_transaction_threw(self.client, transaction_hash)
        if receipt:
            msg = "ServiceRegistry.deposit transaction failed"
            raise RaidenUnrecoverableError(msg)

    def set_url(self, url: str) -> None:
        """Sets the url needed to access the service via HTTP for the caller"""
        log_details = {
            "node": to_checksum_address(self.node_address),
            "contract": to_checksum_address(self.address),
            "url": url,
        }

        if not url.strip():
            msg = "Invalid empty URL"
            raise BrokenPreconditionError(msg)

        parsed_url = urlparse(url)
        if parsed_url.scheme not in ("http", "https"):
            msg = "URL provided to service registry must be a valid HTTP(S) endpoint."
            raise BrokenPreconditionError(msg)

        with log_transaction(log, "set_url", log_details):
            gas_limit = self.proxy.estimate_gas("latest", "setURL", url)
            if not gas_limit:
                msg = f"URL {url} is invalid"
                raise RaidenUnrecoverableError(msg)

            log_details["gas_limit"] = gas_limit
            transaction_hash = self.proxy.transact("setURL", gas_limit, url)
            self.client.poll(transaction_hash)
            receipt = check_transaction_threw(self.client, transaction_hash)
            if receipt:
                msg = f"URL {url} is invalid"
                raise RaidenUnrecoverableError(msg)
