# -*- coding: utf-8 -*-
from raiden.blockchain.abi import (
    CONTRACT_MANAGER,
    CONTRACT_HUMAN_STANDARD_TOKEN,
)
from raiden.exceptions import (
    AddressWithoutCode,
    TransactionThrew,
)
from raiden.network.rpc.transactions import (
    check_transaction_threw,
    estimate_and_transact,
)
from raiden.settings import (
    DEFAULT_POLL_TIMEOUT,
)
from raiden.utils import (
    address_encoder,
    isaddress,
)


class Token(object):
    def __init__(
            self,
            jsonrpc_client,
            token_address,
            startgas,
            gasprice,
            poll_timeout=DEFAULT_POLL_TIMEOUT):

        if not isaddress(token_address):
            raise ValueError('token_address must be a valid address')

        result = jsonrpc_client.call(
            'eth_getCode',
            address_encoder(token_address),
            'latest',
        )

        if result == '0x':
            raise AddressWithoutCode('Token address {} does not contain code'.format(
                address_encoder(token_address),
            ))

        proxy = jsonrpc_client.new_contract_proxy(
            CONTRACT_MANAGER.get_abi(CONTRACT_HUMAN_STANDARD_TOKEN),
            address_encoder(token_address),
        )

        self.address = token_address
        self.proxy = proxy
        self.client = jsonrpc_client
        self.startgas = startgas
        self.gasprice = gasprice
        self.poll_timeout = poll_timeout

    def approve(self, contract_address, allowance):
        """ Aprove `contract_address` to transfer up to `deposit` amount of token. """
        # TODO: check that `contract_address` is a netting channel and that
        # `self.address` is one of the participants (maybe add this logic into
        # `NettingChannel` and keep this straight forward)

        transaction_hash = estimate_and_transact(
            self.proxy.approve,
            self.startgas,
            self.gasprice,
            contract_address,
            allowance,
        )

        self.client.poll(transaction_hash.decode('hex'), timeout=self.poll_timeout)
        receipt_or_none = check_transaction_threw(self.client, transaction_hash)
        if receipt_or_none:
            raise TransactionThrew('Approve', receipt_or_none)

    def balance_of(self, address):
        """ Return the balance of `address`. """
        return self.proxy.balanceOf.call(address)

    def transfer(self, to_address, amount):
        transaction_hash = estimate_and_transact(
            self.proxy.transfer,  # pylint: disable=no-member
            self.startgas,
            self.gasprice,
            to_address,
            amount,
        )

        self.client.poll(transaction_hash.decode('hex'))
        receipt_or_none = check_transaction_threw(self.client, transaction_hash)
        if receipt_or_none:
            raise TransactionThrew('Transfer', receipt_or_none)

        # TODO: check Transfer event
