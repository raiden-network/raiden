from binascii import unhexlify

from eth_utils import (
    to_canonical_address,
    to_checksum_address,
    is_binary_address,
    to_normalized_address,
)

from raiden.blockchain.abi import (
    CONTRACT_MANAGER,
    CONTRACT_ENDPOINT_REGISTRY,
)
from raiden.exceptions import (
    TransactionThrew,
    UnknownAddress,
)
from raiden.network.rpc.client import check_address_has_code
from raiden.network.rpc.transactions import check_transaction_threw
from raiden.settings import DEFAULT_POLL_TIMEOUT
from raiden.constants import NULL_ADDRESS
from raiden.network.rpc.smartcontract_proxy import ContractProxy
from raiden.utils import pex


class Discovery:
    """On chain smart contract raiden node discovery: allows registering
    endpoints (host, port) for your ethereum-/raiden-address and looking up
    endpoints for other ethereum-/raiden-addressess.
    """

    def __init__(
            self,
            jsonrpc_client,
            discovery_address,
            poll_timeout=DEFAULT_POLL_TIMEOUT,
    ):
        contract = jsonrpc_client.new_contract(
            CONTRACT_MANAGER.get_contract_abi(CONTRACT_ENDPOINT_REGISTRY),
            to_normalized_address(discovery_address),
        )
        self.proxy = ContractProxy(jsonrpc_client, contract)

        if not is_binary_address(discovery_address):
            raise ValueError('discovery_address must be a valid address')

        check_address_has_code(jsonrpc_client, discovery_address, 'Discovery')

        CONTRACT_MANAGER.check_contract_version(
            self.version(),
            CONTRACT_ENDPOINT_REGISTRY,
        )

        self.address = discovery_address
        self.client = jsonrpc_client
        self.poll_timeout = poll_timeout
        self.not_found_address = NULL_ADDRESS

    def register_endpoint(self, node_address, endpoint):
        if node_address != self.client.sender:
            raise ValueError("node_address doesnt match this node's address")

        transaction_hash = self.proxy.transact(
            'registerEndpoint',
            endpoint,
        )

        self.client.poll(
            unhexlify(transaction_hash),
            timeout=self.poll_timeout,
        )

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

    def address_by_endpoint(self, endpoint):
        address = self.proxy.contract.functions.findAddressByEndpoint(endpoint).call()

        if address == self.not_found_address:  # the 0 address means nothing found
            return None

        return to_canonical_address(address)

    def version(self):
        return self.proxy.contract.functions.contract_version().call()
