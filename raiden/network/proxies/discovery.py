from eth_utils import is_binary_address, to_checksum_address, to_normalized_address
from web3.exceptions import BadFunctionCallOutput

from raiden.constants import NULL_ADDRESS
from raiden.exceptions import (
    AddressWrongContract,
    ContractVersionMismatch,
    TransactionThrew,
    UnknownAddress,
)
from raiden.network.rpc.client import check_address_has_code
from raiden.network.rpc.smartcontract_proxy import ContractProxy
from raiden.network.rpc.transactions import check_transaction_threw
from raiden.settings import EXPECTED_CONTRACTS_VERSION
from raiden.utils import compare_versions, pex
from raiden_contracts.constants import CONTRACT_ENDPOINT_REGISTRY
from raiden_contracts.contract_manager import CONTRACT_MANAGER


class Discovery:
    """On chain smart contract raiden node discovery: allows registering
    endpoints (host, port) for your ethereum-/raiden-address and looking up
    endpoints for other ethereum-/raiden-addressess.
    """

    def __init__(
            self,
            jsonrpc_client,
            discovery_address,
    ):
        contract = jsonrpc_client.new_contract(
            CONTRACT_MANAGER.get_contract_abi(CONTRACT_ENDPOINT_REGISTRY),
            to_normalized_address(discovery_address),
        )
        proxy = ContractProxy(jsonrpc_client, contract)

        if not is_binary_address(discovery_address):
            raise ValueError('discovery_address must be a valid address')

        check_address_has_code(jsonrpc_client, discovery_address, 'Discovery')

        try:
            is_valid_version = compare_versions(
                proxy.contract.functions.contract_version().call(),
                EXPECTED_CONTRACTS_VERSION,
            )
            if not is_valid_version:
                raise ContractVersionMismatch('Incompatible ABI for Discovery')
        except BadFunctionCallOutput:
            raise AddressWrongContract('')

        self.address = discovery_address
        self.client = jsonrpc_client
        self.not_found_address = NULL_ADDRESS
        self.proxy = proxy

    def register_endpoint(self, node_address, endpoint):
        if node_address != self.client.sender:
            raise ValueError("node_address doesnt match this node's address")

        transaction_hash = self.proxy.transact(
            'registerEndpoint',
            endpoint,
        )

        self.client.poll(transaction_hash)

        receipt_or_none = check_transaction_threw(self.client, transaction_hash)
        if receipt_or_none:
            raise TransactionThrew('Register Endpoint', receipt_or_none)

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
