import structlog
from eth_utils import (
    encode_hex,
    is_binary_address,
    to_bytes,
    to_canonical_address,
    to_checksum_address,
    to_normalized_address,
)
from gevent.lock import RLock
from web3.exceptions import BadFunctionCallOutput

from raiden.exceptions import BrokenPreconditionError, InvalidAddress, RaidenRecoverableError
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
            amount_to_deposit = self._check_deposit_preconditions(
                total_deposit=total_deposit,
                beneficiary=beneficiary,
                token=token,
                given_block_identifier=block_identifier,
                log_details=log_details,
            )

            token.approve(allowed_address=Address(self.address), allowance=amount_to_deposit)

            with log_transaction(log, "deposit", log_details):
                gas_limit = self.proxy.estimate_gas(
                    checking_block, "deposit", to_checksum_address(beneficiary), total_deposit
                )

                if not gas_limit:
                    failed_at = self.proxy.jsonrpc_client.get_block("latest")
                    failed_at_blocknumber = failed_at["number"]
                    failed_at_blockhash = encode_hex(failed_at["hash"])

                    self.proxy.jsonrpc_client.check_for_insufficient_eth(
                        transaction_name="deposit",
                        transaction_executed=False,
                        required_gas=self.gas_measurements["UserDeposit.deposit"],
                        block_identifier=failed_at_blocknumber,
                    )

                    msg = self._check_why_deposit_failed(
                        token=token,
                        total_deposit=total_deposit,
                        block_identifier=failed_at_blockhash,
                    )
                    raise RaidenRecoverableError(f"{error_prefix}. {msg}")

                else:
                    error_prefix = "Call to deposit failed"
                    gas_limit = safe_gas_limit(gas_limit)
                    log_details["gas_limit"] = gas_limit

                    transaction_hash = self.proxy.transact(
                        "deposit", gas_limit, to_checksum_address(beneficiary), total_deposit
                    )

                    self.client.poll(transaction_hash)
                    failed_receipt = check_transaction_threw(self.client, transaction_hash)

                    if failed_receipt:
                        failed_at_blockhash = encode_hex(failed_receipt["blockHash"])

                        msg = self._check_why_deposit_failed(
                            token=token,
                            total_deposit=total_deposit,
                            block_identifier=failed_at_blockhash,
                        )
                        raise RaidenRecoverableError(f"{error_prefix}. {msg}")

                
    def effective_balance(self, address: Address, block_identifier: BlockSpecification) -> Balance:
        """ The user's balance with planned withdrawals deducted. """
        balance = self.proxy.contract.functions.effectiveBalance(address).call(
            block_identifier=block_identifier
        )

        if balance == b"":
            raise RuntimeError(f"Call to 'effectiveBalance' returned nothing")

        return balance

    def _check_deposit_preconditions(
        self,
        total_deposit: TokenAmount,
        beneficiary: Address,
        token: Token,
        given_block_identifier: BlockSpecification,
        log_details: Dict,
    ) -> TokenAmount:
        typecheck(total_deposit, int)

        try:
            previous_total_deposit = self.get_total_deposit(
                address=beneficiary, block_identifier=given_block_identifier
            )
            current_balance = token.balance_of(
                address=self.node_address, block_identifier=given_block_identifier
            )
        except (BadFunctionCallOutput, ValueError):
            pass
        else:
            log_details["previous_total_deposit"] = previous_total_deposit
            amount_to_deposit = TokenAmount(total_deposit - previous_total_deposit)

            if total_deposit <= previous_total_deposit:
                msg = (
                    f"Current total deposit {previous_total_deposit} is already larger "
                    f"than the requested total deposit amount {total_deposit}"
                )
                log.info("deposit failed", reason=msg, **log_details)
                raise BrokenPreconditionError(msg)

            if current_balance < amount_to_deposit:
                msg = (
                    f"new_total_deposit - previous_total_deposit =  {amount_to_deposit} can not "
                    f"be larger than the available balance {current_balance}, "
                    f"for token at address {to_checksum_address(token.address)}"
                )
                log.info("deposit failed", reason=msg, **log_details)
                raise BrokenPreconditionError(msg)

            return amount_to_deposit

    def _check_why_deposit_failed(
        self, token: Token, total_deposit: TokenAmount, block_identifier: BlockSpecification
    ) -> str:
        latest_deposit = self.get_total_deposit(
            address=self.node_address, block_identifier=block_identifier
        )
        amount_to_deposit = TokenAmount(total_deposit - latest_deposit)

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
