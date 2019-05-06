import structlog
import web3
from eth_utils import is_binary_address, to_normalized_address

from raiden.exceptions import InvalidAddress
from raiden.network.proxies.utils import compare_contract_versions
from raiden.network.rpc.client import JSONRPCClient, check_address_has_code
from raiden.network.rpc.transactions import check_transaction_threw
from raiden.utils.typing import Address, AddressHex, BlockSpecification, Optional
from raiden_contracts.constants import CONTRACT_SERVICE_REGISTRY
from raiden_contracts.contract_manager import ContractManager

log = structlog.get_logger(__name__)  # pylint: disable=invalid-name


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
        check_address_has_code(jsonrpc_client, service_registry_address, CONTRACT_SERVICE_REGISTRY)

        proxy = jsonrpc_client.new_contract_proxy(
            self.contract_manager.get_contract_abi(CONTRACT_SERVICE_REGISTRY),
            to_normalized_address(service_registry_address),
        )

        compare_contract_versions(
            proxy=proxy,
            expected_version=contract_manager.contracts_version,
            contract_name=CONTRACT_SERVICE_REGISTRY,
            address=service_registry_address,
        )

        self.address = service_registry_address
        self.proxy = proxy
        self.client = jsonrpc_client
        self.node_address = self.client.address

    def service_count(self, block_identifier: BlockSpecification) -> int:
        """Get the number of registered services"""
        result = self.proxy.contract.functions.serviceCount().call(
            block_identifier=block_identifier
        )
        return result

    def get_service_address(
        self, block_identifier: BlockSpecification, index: int
    ) -> Optional[AddressHex]:
        """Gets the address of a service by index. If index is out of range return None"""
        try:
            result = self.proxy.contract.functions.service_addresses(index).call(
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

    def set_url(self, url: str):
        """Sets the url needed to access the service via HTTP for the caller"""
        gas_limit = self.proxy.estimate_gas("latest", "setURL", url)
        transaction_hash = self.proxy.transact("setURL", gas_limit, url)
        self.client.poll(transaction_hash)
        assert not check_transaction_threw(self.client, transaction_hash)
