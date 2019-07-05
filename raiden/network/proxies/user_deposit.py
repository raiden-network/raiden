import structlog
from eth_utils import (
    is_binary_address,
    to_bytes,
    to_canonical_address,
    to_checksum_address,
    to_normalized_address,
)
from gevent.lock import RLock
from web3.exceptions import BadFunctionCallOutput

from raiden.constants import UINT256_MAX
from raiden.exceptions import BrokenPreconditionError, InvalidAddress, RaidenRecoverableError
from raiden.network.proxies.token import Token
from raiden.network.proxies.utils import log_transaction, raise_on_call_returned_empty
from raiden.network.rpc.client import JSONRPCClient, check_address_has_code
from raiden.network.rpc.transactions import check_transaction_threw
from raiden.utils import safe_gas_limit
from raiden.utils.typing import (
    TYPE_CHECKING,
    Address,
    Any,
    Balance,
    BlockSpecification,
    Dict,
    TokenAddress,
    TokenAmount,
)
from raiden_contracts.constants import CONTRACT_USER_DEPOSIT
from raiden_contracts.contract_manager import ContractManager, gas_measurements

if TYPE_CHECKING:
    # pylint: disable=unused-import
    from raiden.network.blockchain_service import BlockChainService


log = structlog.get_logger(__name__)


class UserDeposit:
    def __init__(
        self,
        jsonrpc_client: JSONRPCClient,
        user_deposit_address: Address,
        contract_manager: ContractManager,
        blockchain_service: "BlockChainService",
    ):
        if not is_binary_address(user_deposit_address):
            raise InvalidAddress("Expected binary address format for token nework")

        check_address_has_code(
            jsonrpc_client,
            Address(user_deposit_address),
            CONTRACT_USER_DEPOSIT,
            expected_code=to_bytes(
                hexstr=contract_manager.get_runtime_hexcode(CONTRACT_USER_DEPOSIT)
            ),
        )

        self.client = jsonrpc_client

        self.address = user_deposit_address
        self.node_address = self.client.address
        self.contract_manager = contract_manager
        self.gas_measurements = gas_measurements(self.contract_manager.contracts_version)

        self.blockchain_service = blockchain_service

        self.proxy = jsonrpc_client.new_contract_proxy(
            self.contract_manager.get_contract_abi(CONTRACT_USER_DEPOSIT),
            to_normalized_address(user_deposit_address),
        )

        self.deposit_lock = RLock()

    def token_address(self, block_identifier: BlockSpecification) -> TokenAddress:
        return to_canonical_address(
            self.proxy.contract.functions.token().call(block_identifier=block_identifier)
        )

    def get_total_deposit(
        self, address: Address, block_identifier: BlockSpecification
    ) -> TokenAmount:
        return self.proxy.contract.functions.balances(address).call(
            block_identifier=block_identifier
        )

    def whole_balance(self, block_identifier: BlockSpecification) -> TokenAmount:
        return TokenAmount(
            self.proxy.contract.functions.whole_balance().call(block_identifier=block_identifier)
        )

    def whole_balance_limit(self, block_identifier: BlockSpecification) -> TokenAmount:
        return TokenAmount(
            self.proxy.contract.functions.whole_balance_limit().call(
                block_identifier=block_identifier
            )
        )

    def deposit(
        self,
        beneficiary: Address,
        total_deposit: TokenAmount,
        given_block_identifier: BlockSpecification,
    ) -> None:
        """ Deposit provided amount into the user-deposit contract
        to the beneficiary's account. """

        token_address = self.token_address(given_block_identifier)
        token = self.blockchain_service.token(token_address=token_address)

        log_details = {
            "beneficiary": to_checksum_address(beneficiary),
            "contract": to_checksum_address(self.address),
            "node": to_checksum_address(self.node_address),
            "total_deposit": total_deposit,
        }

        # To prevent concurrent transactions for token transfers where it is unknown if
        # we have enough capacity for both, we acquire the lock
        # for the token proxy. Example: A user deposit and a channel deposit
        # for the same token.
        with self.deposit_lock, token.token_lock:
            # check preconditions
            try:
                previous_total_deposit = self.get_total_deposit(
                    address=beneficiary, block_identifier=given_block_identifier
                )
                current_balance = token.balance_of(
                    address=self.node_address, block_identifier=given_block_identifier
                )
                whole_balance = self.whole_balance(block_identifier=given_block_identifier)
                whole_balance_limit = self.whole_balance_limit(
                    block_identifier=given_block_identifier
                )
            except ValueError:
                # If 'given_block_identifier' has been pruned, we cannot perform the
                # precondition checks but must still set the amount_to_deposit to a
                # reasonable value.
                previous_total_deposit = self.get_total_deposit(
                    address=beneficiary, block_identifier=self.client.get_checking_block()
                )
                amount_to_deposit = TokenAmount(total_deposit - previous_total_deposit)
            except BadFunctionCallOutput:
                raise_on_call_returned_empty(given_block_identifier)
            else:
                log_details["previous_total_deposit"] = previous_total_deposit
                amount_to_deposit = TokenAmount(total_deposit - previous_total_deposit)

                if whole_balance + amount_to_deposit > UINT256_MAX:
                    msg = (
                        f"Current whole balance is {whole_balance}. "
                        f"The new deposit of {amount_to_deposit} would lead to an overflow."
                    )
                    raise BrokenPreconditionError(msg)

                if whole_balance + amount_to_deposit > whole_balance_limit:
                    msg = (
                        f"Current whole balance is {whole_balance}. "
                        f"With the new deposit of {amount_to_deposit}, the deposit "
                        f"limit of {whole_balance_limit} would be exceeded."
                    )
                    raise BrokenPreconditionError(msg)

                if total_deposit <= previous_total_deposit:
                    msg = (
                        f"Current total deposit {previous_total_deposit} is already larger "
                        f"than the requested total deposit amount {total_deposit}"
                    )
                    raise BrokenPreconditionError(msg)

                if current_balance < amount_to_deposit:
                    msg = (
                        f"new_total_deposit - previous_total_deposit = {amount_to_deposit} "
                        f"can not be larger than the available balance {current_balance}, "
                        f"for token at address {to_checksum_address(token.address)}"
                    )
                    raise BrokenPreconditionError(msg)

            with log_transaction(log, "deposit", log_details):
                self._deposit(
                    beneficiary=beneficiary,
                    token=token,
                    total_deposit=total_deposit,
                    amount_to_deposit=amount_to_deposit,
                    log_details=log_details,
                )

    def effective_balance(self, address: Address, block_identifier: BlockSpecification) -> Balance:
        """ The user's balance with planned withdrawals deducted. """
        balance = self.proxy.contract.functions.effectiveBalance(address).call(
            block_identifier=block_identifier
        )

        if balance == b"":
            raise RuntimeError(f"Call to 'effectiveBalance' returned nothing")

        return balance

    def _deposit(
        self,
        beneficiary: Address,
        token: Token,
        total_deposit: TokenAmount,
        amount_to_deposit: TokenAmount,
        log_details: Dict[str, Any],
    ):
        token.approve(allowed_address=Address(self.address), allowance=amount_to_deposit)

        checking_block = self.client.get_checking_block()
        gas_limit = self.proxy.estimate_gas(
            checking_block, "deposit", to_checksum_address(beneficiary), total_deposit
        )

        if not gas_limit:
            failed_at = self.proxy.jsonrpc_client.get_block("latest")
            failed_at_blocknumber = failed_at["number"]

            self.proxy.jsonrpc_client.check_for_insufficient_eth(
                transaction_name="deposit",
                transaction_executed=False,
                required_gas=self.gas_measurements["UserDeposit.deposit"],
                block_identifier=failed_at_blocknumber,
            )

            latest_deposit = self.get_total_deposit(
                address=self.node_address, block_identifier=failed_at_blocknumber
            )
            amount_to_deposit = TokenAmount(total_deposit - latest_deposit)

            allowance = token.allowance(
                owner=self.node_address,
                spender=Address(self.address),
                block_identifier=failed_at_blocknumber,
            )
            whole_balance = self.whole_balance(block_identifier=failed_at_blocknumber)
            whole_balance_limit = self.whole_balance_limit(block_identifier=failed_at_blocknumber)

            if allowance < amount_to_deposit:
                msg = (
                    "The allowance is insufficient. Check concurrent deposits "
                    "for the same user deposit but different proxies."
                )
                raise RaidenRecoverableError(msg)

            if token.balance_of(self.node_address, failed_at_blocknumber) < amount_to_deposit:
                msg = "The address doesnt have enough tokens"
                raise RaidenRecoverableError(msg)

            if latest_deposit < total_deposit:
                msg = "Deposit amount did not increase after deposit transaction"
                raise RaidenRecoverableError(msg)

            if whole_balance + amount_to_deposit > UINT256_MAX:
                msg = (
                    f"Current whole balance is {whole_balance}. "
                    f"The new deposit of {amount_to_deposit} would lead to an overflow."
                )
                raise RaidenRecoverableError(msg)

            if whole_balance + amount_to_deposit > whole_balance_limit:
                msg = (
                    f"Current whole balance is {whole_balance}. "
                    f"With the new deposit of {amount_to_deposit}, the deposit "
                    f"limit of {whole_balance_limit} would be exceeded."
                )
                raise RaidenRecoverableError(msg)

            raise RaidenRecoverableError("Deposit failed of unknown reason")

        else:
            gas_limit = safe_gas_limit(gas_limit)
            log_details["gas_limit"] = gas_limit

            transaction_hash = self.proxy.transact(
                "deposit", gas_limit, to_checksum_address(beneficiary), total_deposit
            )

            self.client.poll(transaction_hash)
            failed_receipt = check_transaction_threw(self.client, transaction_hash)

            if failed_receipt:
                failed_at_blocknumber = failed_receipt["blockNumber"]

                latest_deposit = self.get_total_deposit(
                    address=self.node_address, block_identifier=failed_at_blocknumber
                )
                amount_to_deposit = TokenAmount(total_deposit - latest_deposit)

                allowance = token.allowance(
                    owner=self.node_address,
                    spender=Address(self.address),
                    block_identifier=failed_at_blocknumber,
                )

                whole_balance = self.whole_balance(block_identifier=failed_at_blocknumber)
                whole_balance_limit = self.whole_balance_limit(
                    block_identifier=failed_at_blocknumber
                )

                if latest_deposit >= total_deposit:
                    msg = "Deposit amount already increased after another transaction"
                    raise RaidenRecoverableError(msg)

                if allowance < amount_to_deposit:
                    msg = (
                        "The allowance is insufficient. Check concurrent deposits "
                        "for the same token network but different proxies."
                    )
                    raise RaidenRecoverableError(msg)

                # Because we acquired the lock for the token, and the gas estimation succeeded,
                # We know that the account had enough balance for the deposit transaction.
                if token.balance_of(self.node_address, failed_at_blocknumber) < amount_to_deposit:
                    msg = (
                        f"Transaction failed and balance decreased unexpectedly. "
                        f"This could be a bug in Raiden or a mallicious "
                        f"ERC20 Token."
                    )
                    raise RaidenRecoverableError(msg)

                if whole_balance + amount_to_deposit > UINT256_MAX:
                    msg = (
                        f"Current whole balance is {whole_balance}. "
                        f"The new deposit of {amount_to_deposit} caused an overflow."
                    )
                    raise RaidenRecoverableError(msg)

                if whole_balance + amount_to_deposit > whole_balance_limit:
                    msg = (
                        f"Current whole balance is {whole_balance}. "
                        f"With the new deposit of {amount_to_deposit}, the deposit "
                        f"limit of {whole_balance_limit} was exceeded."
                    )
                    raise RaidenRecoverableError(msg)

                if latest_deposit < total_deposit:
                    msg = "Deposit amount did not increase after deposit transaction"
                    raise RaidenRecoverableError(msg)

                raise RaidenRecoverableError("Deposit failed of unknown reason")
