# -*- coding: utf-8 -*-
from binascii import hexlify, unhexlify

from ethereum.utils import normalize_address

from raiden.blockchain.abi import (
    CONTRACT_MANAGER,
    CONTRACT_ENDPOINT_REGISTRY,
)
from raiden.exceptions import (
    TransactionThrew,
    UnknownAddress,
)
from raiden.network.rpc.client import check_address_has_code
from raiden.network.rpc.transactions import (
    check_transaction_threw,
)
from raiden.settings import (
    DEFAULT_POLL_TIMEOUT,
)
from raiden.utils import (
    address_encoder,
    isaddress,
    pex,
)


class Discovery:
    """On chain smart contract raiden node discovery: allows registering
    endpoints (host, port) for your ethereum-/raiden-address and looking up
    endpoints for other ethereum-/raiden-addressess.
    """

    def __init__(
            self,
            jsonrpc_client,
            discovery_address,
            poll_timeout=DEFAULT_POLL_TIMEOUT):

        if not isaddress(discovery_address):
            raise ValueError('discovery_address must be a valid address')

        check_address_has_code(jsonrpc_client, discovery_address, 'Discovery')

        proxy = jsonrpc_client.new_contract_proxy(
            CONTRACT_MANAGER.get_abi(CONTRACT_ENDPOINT_REGISTRY),
            address_encoder(discovery_address),
        )

        self.address = discovery_address
        self.proxy = proxy
        self.client = jsonrpc_client
        self.poll_timeout = poll_timeout
        self.not_found_address = '0x' + '0' * 40

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
        node_address_hex = hexlify(node_address_bin)
        endpoint = self.proxy.call('findEndpointByAddress', node_address_hex)

        if endpoint == b'':
            raise UnknownAddress('Unknown address {}'.format(pex(node_address_bin)))

        return endpoint

    def address_by_endpoint(self, endpoint):
        address = self.proxy.call('findAddressByEndpoint', endpoint)

        if address == self.not_found_address:  # the 0 address means nothing found
            return None

        return normalize_address(address)

    def version(self):
        return self.proxy.call('contract_version')
