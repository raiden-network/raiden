import structlog
from eth_utils import (
    is_binary_address,
    to_canonical_address,
    to_checksum_address,
    to_normalized_address,
)
from gevent.lock import RLock

from raiden.exceptions import BrokenPreconditionError, InvalidAddress, RaidenUnrecoverableError
from raiden.network.proxies.token import Token
from raiden.network.proxies.utils import log_transaction
from raiden.network.rpc.client import JSONRPCClient, check_address_has_code
from raiden.network.rpc.transactions import check_transaction_threw
from raiden.utils import safe_gas_limit
from raiden.utils.typing import (
    TYPE_CHECKING,
    Address,
    Balance,
    BlockSpecification,
    Dict,
    TokenAddress,
    TokenAmount,
    Tuple,
    typecheck,
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
            expected_code=contract_manager.get_runtime_hexcode(CONTRACT_USER_DEPOSIT),
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

    def deposit(
        self,
        beneficiary: Address,
        total_deposit: TokenAmount,
        block_identifier: BlockSpecification,
    ) -> None:
        """ Deposit provided amount into the user-deposit contract
        to the beneficiary's account. """

        token_address = self.token_address(block_identifier)
        token = self.blockchain_service.token(token_address=token_address)

        log_details = {
            "beneficiary": to_checksum_address(beneficiary),
            "contract": to_checksum_address(self.address),
            "node": to_checksum_address(self.node_address),
            "total_deposit": total_deposit,
        }

        checking_block = self.client.get_checking_block()
        error_prefix = "Call to deposit will fail"

        with self.deposit_lock:
            amount_to_deposit, log_details = self._deposit_preconditions(
                total_deposit=total_deposit,
                beneficiary=beneficiary,
                token=token,
                block_identifier=block_identifier,
            )

            with log_transaction(log, "deposit", log_details):
                gas_limit = self.proxy.estimate_gas(
                    checking_block, "deposit", to_checksum_address(beneficiary), total_deposit
                )

                if gas_limit:
                    error_prefix = "Call to deposit failed"
                    gas_limit = safe_gas_limit(gas_limit)
                    log_details["gas_limit"] = gas_limit

                    transaction_hash = self.proxy.transact(
                        "deposit", gas_limit, to_checksum_address(beneficiary), total_deposit
                    )

                    self.client.poll(transaction_hash)
                    receipt_or_none = check_transaction_threw(self.client, transaction_hash)

                transaction_executed = gas_limit is not None
                if not transaction_executed or receipt_or_none:
                    if transaction_executed:
                        block = receipt_or_none["blockNumber"]
                    else:
                        block = checking_block

                    self.proxy.jsonrpc_client.check_for_insufficient_eth(
                        transaction_name="deposit",
                        transaction_executed=transaction_executed,
                        required_gas=self.gas_measurements["UserDeposit.deposit"],
                        block_identifier=block,
                    )

                    msg = self._check_why_deposit_failed(
                        token=token,
                        amount_to_deposit=amount_to_deposit,
                        total_deposit=total_deposit,
                        block_identifier=block,
                    )
                    raise RaidenUnrecoverableError(f"{error_prefix}. {msg}")

    def effective_balance(self, address: Address, block_identifier: BlockSpecification) -> Balance:
        """ The user's balance with planned withdrawals deducted. """
        balance = self.proxy.contract.functions.effectiveBalance(address).call(
            block_identifier=block_identifier
        )

        if balance == b"":
            raise RuntimeError(f"Call to 'effectiveBalance' returned nothing")

        return balance

    def _deposit_preconditions(
        self,
        total_deposit: TokenAmount,
        beneficiary: Address,
        token: Token,
        block_identifier: BlockSpecification,
    ) -> Tuple[TokenAmount, Dict]:
        typecheck(total_deposit, int)

        previous_total_deposit = self.get_total_deposit(
            address=beneficiary, block_identifier=block_identifier
        )
        amount_to_deposit = TokenAmount(total_deposit - previous_total_deposit)

        log_details = {
            "user_deposit_address": to_checksum_address(self.address),
            "node": to_checksum_address(self.node_address),
            "beneficiary": to_checksum_address(beneficiary),
            "new_total_deposit": total_deposit,
            "previous_total_deposit": previous_total_deposit,
        }

        if total_deposit <= previous_total_deposit:
            msg = (
                f"Current total deposit {previous_total_deposit} is already larger "
                f"than the requested total deposit amount {total_deposit}"
            )
            log.info("deposit failed", reason=msg, **log_details)
            raise BrokenPreconditionError(msg)

        current_balance = token.balance_of(
            address=self.node_address, block_identifier=block_identifier
        )
        if current_balance < amount_to_deposit:
            msg = (
                f"new_total_deposit - previous_total_deposit =  {amount_to_deposit} can not "
                f"be larger than the available balance {current_balance}, "
                f"for token at address {to_checksum_address(token.address)}"
            )
            log.info("deposit failed", reason=msg, **log_details)
            raise BrokenPreconditionError(msg)

        token.approve(allowed_address=Address(self.address), allowance=amount_to_deposit)

        return amount_to_deposit, log_details

    def _check_why_deposit_failed(
        self,
        token: Token,
        amount_to_deposit: TokenAmount,
        total_deposit: TokenAmount,
        block_identifier: BlockSpecification,
    ) -> str:
        msg = ""
        latest_deposit = self.get_total_deposit(
            address=self.node_address, block_identifier=block_identifier
        )

        allowance = token.allowance(
            owner=self.node_address,
            spender=Address(self.address),
            block_identifier=block_identifier,
        )
        if allowance < amount_to_deposit:
            msg = (
                "The allowance is insufficient. Check concurrent deposits "
                "for the same token network but different proxies."
            )
        elif token.balance_of(self.node_address, block_identifier) < amount_to_deposit:
            msg = "The address doesnt have enough tokens"
        elif latest_deposit < total_deposit:
            msg = "Deposit amount did not increase after deposit transaction"
        else:
            msg = "Deposit failed of unknown reason"

        return msg
