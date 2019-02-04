import structlog
from eth_utils import is_binary_address, to_checksum_address, to_normalized_address

from raiden.constants import GAS_LIMIT_FOR_TOKEN_CONTRACT_CALL
from raiden.exceptions import RaidenUnrecoverableError, TransactionThrew
from raiden.network.rpc.client import check_address_has_code
from raiden.network.rpc.smartcontract_proxy import ContractProxy
from raiden.network.rpc.transactions import check_transaction_threw
from raiden.utils import pex, safe_gas_limit
from raiden.utils.typing import Address, BlockSpecification, TokenAmount
from raiden_contracts.constants import CONTRACT_HUMAN_STANDARD_TOKEN
from raiden_contracts.contract_manager import ContractManager

log = structlog.get_logger(__name__)  # pylint: disable=invalid-name

# Determined by safe_gas_limit(estimateGas(approve)) on 17/01/19 with geth 1.8.20
GAS_REQUIRED_FOR_APPROVE = 58792


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
        self.node_address = jsonrpc_client.address
        self.proxy = proxy

    def allowance(self, owner: Address, spender: Address, block_identifier: BlockSpecification):
        return self.proxy.contract.functions.allowance(
            to_checksum_address(owner),
            to_checksum_address(spender),
        ).call(block_identifier=block_identifier)

    def approve(
            self,
            allowed_address: Address,
            allowance: TokenAmount,
            given_block_identifier: BlockSpecification,
    ):
        """ Aprove `allowed_address` to transfer up to `deposit` amount of token.

        Note:

            For channel deposit please use the channel proxy, since it does
            additional validations.
        """
        # Note that given_block_identifier is not used here as there
        # are no preconditions to check before sending the transaction

        log_details = {
            'node': pex(self.node_address),
            'contract': pex(self.address),
            'allowed_address': pex(allowed_address),
            'allowance': allowance,
        }

        checking_block = self.client.get_checking_block()
        error_prefix = 'Call to approve will fail'
        gas_limit = self.proxy.estimate_gas(
            checking_block,
            'approve',
            to_checksum_address(allowed_address),
            allowance,
        )

        if gas_limit:
            error_prefix = 'Call to approve failed'
            log.debug('approve called', **log_details)
            transaction_hash = self.proxy.transact(
                'approve',
                safe_gas_limit(gas_limit),
                to_checksum_address(allowed_address),
                allowance,
            )

            self.client.poll(transaction_hash)
            receipt_or_none = check_transaction_threw(self.client, transaction_hash)

        transaction_executed = gas_limit is not None
        if not transaction_executed or receipt_or_none:
            if transaction_executed:
                block = receipt_or_none['blockNumber']
            else:
                block = checking_block

            self.proxy.jsonrpc_client.check_for_insufficient_eth(
                transaction_name='approve',
                transaction_executed=transaction_executed,
                required_gas=GAS_REQUIRED_FOR_APPROVE,
                block_identifier=block,
            )

            msg = self._check_why_approved_failed(allowance, block)
            error_msg = f'{error_prefix}. {msg}'
            log.critical(error_msg, **log_details)
            raise RaidenUnrecoverableError(error_msg)

        log.info('approve successful', **log_details)

    def _check_why_approved_failed(
            self,
            allowance: TokenAmount,
            block_identifier: BlockSpecification,
    ) -> str:
        user_balance = self.balance_of(
            address=self.client.address,
            block_identifier=block_identifier,
        )

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
                f'Approve failed. \n'
                f'Your account balance is {user_balance}. '
                f'The requested allowance is {allowance}. '
                f'The smart contract may be rejecting your request due to the '
                f'lack of balance.'
            )

        # If the user has enough balance, warn the user the smart contract
        # may not have the approve function.
        else:
            msg = (
                f'Approve failed. \n'
                f'Your account balance is {user_balance}. Nevertheless the call to'
                f'approve failed. Please make sure the corresponding smart '
                f'contract is a valid ERC20 token.'
            ).format(user_balance)

        return msg

    def balance_of(self, address, block_identifier='latest'):
        """ Return the balance of `address`. """
        return self.proxy.contract.functions.balanceOf(
            to_checksum_address(address),
        ).call(block_identifier=block_identifier)

    def transfer(
            self,
            to_address: Address,
            amount: TokenAmount,
            given_block_identifier: BlockSpecification,
    ):
        # Note that given_block_identifier is not used here as there
        # are no preconditions to check before sending the transaction
        log_details = {
            'node': pex(self.node_address),
            'contract': pex(self.address),
            'to_address': pex(to_address),
            'amount': amount,
        }
        log.debug('transfer called', **log_details)

        startgas = GAS_LIMIT_FOR_TOKEN_CONTRACT_CALL
        transaction_hash = self.proxy.transact(
            'transfer',
            safe_gas_limit(startgas),
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
