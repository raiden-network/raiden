from eth_utils import (
    is_binary_address,
    to_checksum_address,
    to_normalized_address,
)
from raiden_contracts.constants import CONTRACT_HUMAN_STANDARD_TOKEN
from raiden_contracts.contract_manager import CONTRACT_MANAGER

from raiden.exceptions import TransactionThrew
from raiden.network.rpc.client import check_address_has_code
from raiden.network.rpc.transactions import (
    check_transaction_threw,
)
from raiden.network.rpc.smartcontract_proxy import ContractProxy


class Token:
    def __init__(
            self,
            jsonrpc_client,
            token_address,
    ):
        contract = jsonrpc_client.new_contract(
            CONTRACT_MANAGER.get_contract_abi(CONTRACT_HUMAN_STANDARD_TOKEN),
            to_normalized_address(token_address),
        )
        proxy = ContractProxy(jsonrpc_client, contract)

        if not is_binary_address(token_address):
            raise ValueError('token_address must be a valid address')

        check_address_has_code(jsonrpc_client, token_address, 'Token')

        self.address = token_address
        self.client = jsonrpc_client
        self.proxy = proxy

    def allowance(self, owner, spender):
        return self.proxy.contract.functions.allowance(
            to_checksum_address(owner),
            to_checksum_address(spender),
        ).call()

    def approve(self, contract_address, allowance):
        """ Aprove `contract_address` to transfer up to `deposit` amount of token. """
        # TODO: check that `contract_address` is a netting channel and that
        # `self.address` is one of the participants (maybe add this logic into
        # `NettingChannel` and keep this straight forward)
        transaction_hash = self.proxy.transact(
            'approve',
            to_checksum_address(contract_address),
            allowance,
        )

        self.client.poll(transaction_hash)
        receipt_or_none = check_transaction_threw(self.client, transaction_hash)

        if receipt_or_none:
            user_balance = self.balance_of(self.client.sender)

            # If the balance is zero, either the smart contract doesnt have a
            # balanceOf function or the actual balance is zero
            if user_balance == 0:
                msg = (
                    "Approve failed. \n"
                    "Your account balance is 0 (zero), either the smart "
                    "contract is not a valid ERC20 token or you don't have funds "
                    "to use for openning a channel. "
                )
                raise TransactionThrew(msg, receipt_or_none)

            # The approve call failed, check the user has enough balance
            # (assuming the token smart contract may check for the maximum
            # allowance, which is not necessarily the case)
            elif user_balance < allowance:
                msg = (
                    'Approve failed. \n'
                    'Your account balance is {}, nevertheless the call to '
                    'approve failed. Please make sure the corresponding smart '
                    'contract is a valid ERC20 token.'
                ).format(user_balance)
                raise TransactionThrew(msg, receipt_or_none)

            # If the user has enough balance, warn the user the smart contract
            # may not have the approve function.
            else:
                msg = (
                    'Approve failed. \n'
                    'Your account balance is {}, the request allowance is {}. '
                    'The smart contract may be rejecting your request for the '
                    'lack of balance.'
                ).format(user_balance, allowance)
                raise TransactionThrew(msg, receipt_or_none)

    def balance_of(self, address):
        """ Return the balance of `address`. """
        return self.proxy.contract.functions.balanceOf(
            to_checksum_address(address),
        ).call()

    def transfer(self, to_address, amount):
        transaction_hash = self.proxy.transact(
            'transfer',
            to_checksum_address(to_address),
            amount,
        )

        self.client.poll(transaction_hash)
        receipt_or_none = check_transaction_threw(self.client, transaction_hash)
        if receipt_or_none:
            raise TransactionThrew('Transfer', receipt_or_none)

        # TODO: check Transfer event
