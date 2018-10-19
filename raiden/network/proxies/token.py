import structlog
from eth_utils import is_binary_address, to_checksum_address, to_normalized_address

from raiden.exceptions import TransactionThrew
from raiden.network.rpc.client import check_address_has_code
from raiden.network.rpc.smartcontract_proxy import ContractProxy
from raiden.network.rpc.transactions import check_transaction_threw
from raiden.utils import pex, privatekey_to_address
from raiden_contracts.constants import CONTRACT_HUMAN_STANDARD_TOKEN
from raiden_contracts.contract_manager import ContractManager

log = structlog.get_logger(__name__)  # pylint: disable=invalid-name


class Token:
    def __init__(
            self,
            jsonrpc_client,
            token_address,
            contract_manager: ContractManager,
    ):
        contract = jsonrpc_client.new_contract(
            contract_manager.get_contract_abi(CONTRACT_HUMAN_STANDARD_TOKEN),
            to_normalized_address(token_address),
        )
        proxy = ContractProxy(jsonrpc_client, contract)

        if not is_binary_address(token_address):
            raise ValueError('token_address must be a valid address')

        check_address_has_code(jsonrpc_client, token_address, 'Token')

        self.address = token_address
        self.client = jsonrpc_client
        self.node_address = privatekey_to_address(jsonrpc_client.privkey)
        self.proxy = proxy

    def allowance(self, owner, spender):
        return self.proxy.contract.functions.allowance(
            to_checksum_address(owner),
            to_checksum_address(spender),
        ).call()

    def approve(self, allowed_address, allowance):
        """ Aprove `allowed_address` to transfer up to `deposit` amount of token.

        Note:

            For channel deposit please use the channel proxy, since it does
            additional validations.
        """

        log_details = {
            'node': pex(self.node_address),
            'contract': pex(self.address),
            'allowed_address': pex(allowed_address),
            'allowance': allowance,
        }
        log.debug('approve called', **log_details)

        transaction_hash = self.proxy.transact(
            'approve',
            to_checksum_address(allowed_address),
            allowance,
        )

        self.client.poll(transaction_hash)
        receipt_or_none = check_transaction_threw(self.client, transaction_hash)

        if receipt_or_none:
            user_balance = self.balance_of(self.client.address)

            # If the balance is zero, either the smart contract doesnt have a
            # balanceOf function or the actual balance is zero
            if user_balance == 0:
                msg = (
                    "Approve failed. \n"
                    "Your account balance is 0 (zero), either the smart "
                    "contract is not a valid ERC20 token or you don't have funds "
                    "to use for openning a channel. "
                )

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

            # If the user has enough balance, warn the user the smart contract
            # may not have the approve function.
            else:
                msg = (
                    f'Approve failed. \n'
                    f'Your account balance is {user_balance}, '
                    f'the request allowance is {allowance}. '
                    f'The smart contract may be rejecting your request for the '
                    f'lack of balance.'
                )

            log.critical(f'approve failed, {msg}', **log_details)
            raise TransactionThrew(msg, receipt_or_none)

        log.info('approve successful', **log_details)

    def balance_of(self, address):
        """ Return the balance of `address`. """
        return self.proxy.contract.functions.balanceOf(
            to_checksum_address(address),
        ).call()

    def transfer(self, to_address, amount):
        log_details = {
            'node': pex(self.node_address),
            'contract': pex(self.address),
            'to_address': pex(to_address),
            'amount': amount,
        }
        log.debug('transfer called', **log_details)

        transaction_hash = self.proxy.transact(
            'transfer',
            to_checksum_address(to_address),
            amount,
        )

        self.client.poll(transaction_hash)
        receipt_or_none = check_transaction_threw(self.client, transaction_hash)
        if receipt_or_none:
            log.critical('transfer failed', **log_details)
            raise TransactionThrew('Transfer', receipt_or_none)

        # TODO: check Transfer event (issue: #2598)
        log.info('transfer successful', **log_details)
