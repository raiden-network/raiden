import structlog
from eth_utils import is_binary_address, to_normalized_address

from raiden.exceptions import InvalidAddress
from raiden.network.proxies.utils import compare_contract_versions
from raiden.network.rpc.client import check_address_has_code
from raiden.rpc.client import JSONRPCClient
from raiden.utils.typing import Address, BlockSpecification, List
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
            raise InvalidAddress('Expected binary address for service registry')

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
            block_identifier=block_identifier,
        )
        return result

    def get_services_list(self, block_identifier: BlockSpecification) -> List[Address]:
        # count = self.service_count(block_identifier)
        return self.proxy.contract.service_addresses
