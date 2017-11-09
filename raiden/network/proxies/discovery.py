# -*- coding: utf-8 -*-

from raiden.blockchain.abi import (
    CONTRACT_MANAGER,
    CONTRACT_ENDPOINT_REGISTRY,
)
from raiden.constants import (
    DISCOVERY_REGISTRATION_GAS,
)
from raiden.exceptions import (
    AddressWithoutCode,
    TransactionThrew,
    UnknownAddress,
)
from raiden.network.rpc.transactions import (
    check_transaction_threw,
)
from raiden.settings import (
    DEFAULT_POLL_TIMEOUT,
    GAS_LIMIT,
    GAS_PRICE,
)
from raiden.utils import (
    address_encoder,
    isaddress,
    pex,
)


class Discovery(object):
    """On chain smart contract raiden node discovery: allows registering
    endpoints (host, port) for your ethereum-/raiden-address and looking up
    endpoints for other ethereum-/raiden-addressess.
    """

    def __init__(
            self,
            jsonrpc_client,
            discovery_address,
            startgas,
            gasprice,
            poll_timeout=DEFAULT_POLL_TIMEOUT):

        if not isaddress(discovery_address):
            raise ValueError('discovery_address must be a valid address')

        result = jsonrpc_client.call(
            'eth_getCode',
            address_encoder(discovery_address),
            'latest',
        )

        if result == '0x':
            raise AddressWithoutCode('Discovery address {} does not contain code'.format(
                address_encoder(discovery_address),
            ))

        proxy = jsonrpc_client.new_contract_proxy(
            CONTRACT_MANAGER.get_abi(CONTRACT_ENDPOINT_REGISTRY),
            address_encoder(discovery_address),
        )

        self.address = discovery_address
        self.proxy = proxy
        self.client = jsonrpc_client
        self.startgas = startgas
        self.gasprice = gasprice
        self.poll_timeout = poll_timeout

    def register_endpoint(self, node_address, endpoint):
        if node_address != self.client.sender:
            raise ValueError("node_address doesnt match this node's address")

        transaction_hash = self.proxy.registerEndpoint.transact(
            endpoint,
            gasprice=self.gasprice,
            startgas=DISCOVERY_REGISTRATION_GAS,
        )

        self.client.poll(
            transaction_hash.decode('hex'),
            timeout=self.poll_timeout,
        )

        receipt_or_none = check_transaction_threw(self.client, transaction_hash)
        if receipt_or_none:
            raise TransactionThrew('Register Endpoint', receipt_or_none)

    def endpoint_by_address(self, node_address_bin):
        node_address_hex = node_address_bin.encode('hex')
        endpoint = self.proxy.findEndpointByAddress.call(node_address_hex)

        if endpoint == '':
            raise UnknownAddress('Unknown address {}'.format(pex(node_address_bin)))

        return endpoint

    def address_by_endpoint(self, endpoint):
        address = self.proxy.findAddressByEndpoint.call(endpoint)

        if set(address) == {'0'}:  # the 0 address means nothing found
            return None

        return address.decode('hex')

    def version(self):
        return self.proxy.contract_version.call()
