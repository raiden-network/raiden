import structlog
from eth_utils import is_binary_address, to_checksum_address, to_normalized_address

from raiden.constants import NULL_ADDRESS
from raiden.exceptions import TransactionThrew, UnknownAddress
from raiden.network.proxies.utils import compare_contract_versions
from raiden.network.rpc.client import check_address_has_code
from raiden.network.rpc.smartcontract_proxy import ContractProxy
from raiden.network.rpc.transactions import check_transaction_threw
from raiden.utils import pex, privatekey_to_address, safe_gas_limit
from raiden_contracts.constants import (
    CONTRACT_ENDPOINT_REGISTRY,
    GAS_REQUIRED_FOR_ENDPOINT_REGISTER,
)
from raiden_contracts.contract_manager import ContractManager

log = structlog.get_logger(__name__)  # pylint: disable=invalid-name


class Discovery:
    """On chain smart contract raiden node discovery: allows registering
    endpoints (host, port) for your ethereum-/raiden-address and looking up
    endpoints for other ethereum-/raiden-addressess.
    """

    def __init__(
            self,
            jsonrpc_client,
            discovery_address,
            contract_manager: ContractManager,
    ):
        contract = jsonrpc_client.new_contract(
            contract_manager.get_contract_abi(CONTRACT_ENDPOINT_REGISTRY),
            to_normalized_address(discovery_address),
        )
        proxy = ContractProxy(jsonrpc_client, contract)

        if not is_binary_address(discovery_address):
            raise ValueError('discovery_address must be a valid address')

        check_address_has_code(jsonrpc_client, discovery_address, 'Discovery')

        compare_contract_versions(
            proxy=proxy,
            expected_version=contract_manager.contracts_version,
            contract_name=CONTRACT_ENDPOINT_REGISTRY,
            address=discovery_address,
        )

        self.address = discovery_address
        self.node_address = privatekey_to_address(jsonrpc_client.privkey)
        self.client = jsonrpc_client
        self.not_found_address = NULL_ADDRESS
        self.proxy = proxy

    def register_endpoint(self, node_address, endpoint):
        if node_address != self.client.address:
            raise ValueError("node_address doesnt match this node's address")

        log_details = {
            'node': pex(self.node_address),
            'node_address': pex(node_address),
            'endpoint': endpoint,
        }
        log.debug('registerEndpoint called', **log_details)

        transaction_hash = self.proxy.transact(
            'registerEndpoint',
            safe_gas_limit(GAS_REQUIRED_FOR_ENDPOINT_REGISTER),
            endpoint,
        )

        self.client.poll(transaction_hash)

        receipt_or_none = check_transaction_threw(self.client, transaction_hash)
        if receipt_or_none:
            log.critical('registerEndpoint failed', **log_details)
            raise TransactionThrew('Register Endpoint', receipt_or_none)

        log.debug('registerEndpoint successful', **log_details)

    def endpoint_by_address(self, node_address_bin):
        node_address_hex = to_checksum_address(node_address_bin)
        endpoint = self.proxy.contract.functions.findEndpointByAddress(
            node_address_hex,
        ).call()

        if endpoint == '':
            raise UnknownAddress('Unknown address {}'.format(pex(node_address_bin)))

        return endpoint

    def version(self):
        return self.proxy.contract.functions.contract_version().call()
