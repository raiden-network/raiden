from contextlib import contextmanager
from dataclasses import dataclass, field

import structlog
from eth_utils import decode_hex, is_binary_address, to_canonical_address
from gevent.event import AsyncResult
from web3.exceptions import BadFunctionCallOutput

from raiden.constants import BLOCK_ID_LATEST, EMPTY_ADDRESS, UINT256_MAX
from raiden.exceptions import BrokenPreconditionError, RaidenRecoverableError
from raiden.network.proxies.token import Token
from raiden.network.proxies.utils import raise_on_call_returned_empty
from raiden.network.rpc.client import (
    JSONRPCClient,
    TransactionSent,
    check_address_has_code,
    was_transaction_successfully_mined,
)
from raiden.utils.formatting import format_block_id, to_checksum_address
from raiden.utils.typing import (
    TYPE_CHECKING,
    Address,
    Any,
    Balance,
    BlockIdentifier,
    BlockNumber,
    Dict,
    Iterator,
    MonitoringServiceAddress,
    OneToNAddress,
    Optional,
    TokenAddress,
    TokenAmount,
    Tuple,
    UserDepositAddress,
)
from raiden_contracts.constants import (
    CONTRACT_MONITORING_SERVICE,
    CONTRACT_ONE_TO_N,
    CONTRACT_USER_DEPOSIT,
)
from raiden_contracts.contract_manager import ContractManager, gas_measurements

if TYPE_CHECKING:
    # pylint: disable=unused-import
    from raiden.network.proxies.proxy_manager import ProxyManager


log = structlog.get_logger(__name__)


@dataclass
class InflightDeposit:
    total_deposit: TokenAmount = field(default_factory=lambda: TokenAmount(0))
    async_result: AsyncResult = field(default_factory=AsyncResult)


class UserDeposit:
    def __init__(
        self,
        jsonrpc_client: JSONRPCClient,
        user_deposit_address: UserDepositAddress,
        contract_manager: ContractManager,
        proxy_manager: "ProxyManager",
        block_identifier: BlockIdentifier,
    ) -> None:
        if not is_binary_address(user_deposit_address):
            raise ValueError("Expected binary address format for token nework")

        check_address_has_code(
            client=jsonrpc_client,
            address=Address(user_deposit_address),
            contract_name=CONTRACT_USER_DEPOSIT,
            expected_code=decode_hex(contract_manager.get_runtime_hexcode(CONTRACT_USER_DEPOSIT)),
            given_block_identifier=block_identifier,
        )

        self.client = jsonrpc_client

        self.address = user_deposit_address
        self.node_address = self.client.address
        self.contract_manager = contract_manager
        self.gas_measurements = gas_measurements(self.contract_manager.contracts_version)

        self.proxy_manager = proxy_manager

        self.proxy = jsonrpc_client.new_contract_proxy(
            abi=self.contract_manager.get_contract_abi(CONTRACT_USER_DEPOSIT),
            contract_address=Address(user_deposit_address),
        )

        # Keeps track of the current in-flight deposits, to avoid sending
        # unecessary transactions.
        self._inflight_deposits: Dict[Address, InflightDeposit] = dict()

    def token_address(self, block_identifier: BlockIdentifier) -> TokenAddress:
        return TokenAddress(
            to_canonical_address(
                self.proxy.functions.token().call(block_identifier=block_identifier)
            )
        )

    def monitoring_service_address(
        self, block_identifier: BlockIdentifier
    ) -> MonitoringServiceAddress:
        return MonitoringServiceAddress(
            to_canonical_address(
                self.proxy.functions.msc_address().call(block_identifier=block_identifier)
            )
        )

    def one_to_n_address(self, block_identifier: BlockIdentifier) -> OneToNAddress:
        return OneToNAddress(
            to_canonical_address(
                self.proxy.functions.one_to_n_address().call(block_identifier=block_identifier)
            )
        )

    def get_total_deposit(
        self, address: Address, block_identifier: BlockIdentifier
    ) -> TokenAmount:
        return self.proxy.functions.balances(address).call(block_identifier=block_identifier)

    def whole_balance(self, block_identifier: BlockIdentifier) -> TokenAmount:
        return TokenAmount(
            self.proxy.functions.whole_balance().call(block_identifier=block_identifier)
        )

    def whole_balance_limit(self, block_identifier: BlockIdentifier) -> TokenAmount:
        return TokenAmount(
            self.proxy.functions.whole_balance_limit().call(block_identifier=block_identifier)
        )

    def init(
        self,
        monitoring_service_address: MonitoringServiceAddress,
        one_to_n_address: OneToNAddress,
        given_block_identifier: BlockIdentifier,
    ) -> None:
        """ Initialize the UserDeposit contract with MS and OneToN addresses """
        check_address_has_code(
            client=self.client,
            address=Address(monitoring_service_address),
            contract_name=CONTRACT_MONITORING_SERVICE,
            expected_code=decode_hex(
                self.contract_manager.get_runtime_hexcode(CONTRACT_MONITORING_SERVICE)
            ),
            given_block_identifier=given_block_identifier,
        )
        check_address_has_code(
            client=self.client,
            address=Address(one_to_n_address),
            contract_name=CONTRACT_ONE_TO_N,
            expected_code=decode_hex(self.contract_manager.get_runtime_hexcode(CONTRACT_ONE_TO_N)),
            given_block_identifier=given_block_identifier,
        )
        try:
            existing_monitoring_service_address = self.monitoring_service_address(
                block_identifier=given_block_identifier
            )
            existing_one_to_n_address = self.one_to_n_address(
                block_identifier=given_block_identifier
            )
        except ValueError:
            pass
        except BadFunctionCallOutput:
            raise_on_call_returned_empty(given_block_identifier)
        else:
            if existing_monitoring_service_address != EMPTY_ADDRESS:
                msg = (
                    f"MonitoringService contract address is already set to "
                    f"{to_checksum_address(existing_monitoring_service_address)}"
                )
                raise BrokenPreconditionError(msg)

            if existing_one_to_n_address != EMPTY_ADDRESS:
                msg = (
                    f"OneToN contract address is already set to "
                    f"{to_checksum_address(existing_one_to_n_address)}"
                )
                raise BrokenPreconditionError(msg)

        self._init(
            monitoring_service_address=monitoring_service_address,
            one_to_n_address=one_to_n_address,
        )

    def _init(
        self, monitoring_service_address: MonitoringServiceAddress, one_to_n_address: OneToNAddress
    ) -> None:
        log_details: Dict[str, Any] = {}
        estimated_transaction = self.client.estimate_gas(
            self.proxy, "init", log_details, monitoring_service_address, one_to_n_address
        )

        if estimated_transaction is None:
            failed_at = self.client.get_block(BLOCK_ID_LATEST)
            failed_at_blocknumber = failed_at["number"]

            self.client.check_for_insufficient_eth(
                transaction_name="init",
                transaction_executed=False,
                required_gas=self.gas_measurements["UserDeposit.init"],
                block_identifier=failed_at_blocknumber,
            )

            existing_monitoring_service_address = self.monitoring_service_address(
                block_identifier=failed_at_blocknumber
            )
            existing_one_to_n_address = self.one_to_n_address(
                block_identifier=failed_at_blocknumber
            )
            if existing_monitoring_service_address != EMPTY_ADDRESS:
                msg = (
                    f"MonitoringService contract address was set to "
                    f"{to_checksum_address(existing_monitoring_service_address)}"
                )
                raise RaidenRecoverableError(msg)

            if existing_one_to_n_address != EMPTY_ADDRESS:
                msg = (
                    f"OneToN contract address was set to "
                    f"{to_checksum_address(existing_one_to_n_address)}"
                )
                raise RaidenRecoverableError(msg)

            raise RaidenRecoverableError("Deposit failed of unknown reason")

        else:
            transaction_sent = self.client.transact(estimated_transaction)
            transaction_mined = self.client.poll_transaction(transaction_sent)

            if not was_transaction_successfully_mined(transaction_mined):
                failed_at_blocknumber = BlockNumber(transaction_mined.receipt["blockNumber"])

                existing_monitoring_service_address = self.monitoring_service_address(
                    block_identifier=failed_at_blocknumber
                )
                existing_one_to_n_address = self.one_to_n_address(
                    block_identifier=failed_at_blocknumber
                )
                if existing_monitoring_service_address != EMPTY_ADDRESS:
                    msg = (
                        f"MonitoringService contract address was set to "
                        f"{to_checksum_address(existing_monitoring_service_address)}"
                    )
                    raise RaidenRecoverableError(msg)

                if existing_one_to_n_address != EMPTY_ADDRESS:
                    msg = (
                        f"OneToN contract address was set to "
                        f"{to_checksum_address(existing_one_to_n_address)}"
                    )
                    raise RaidenRecoverableError(msg)

                raise RaidenRecoverableError("Deposit failed of unknown reason")

    def effective_balance(self, address: Address, block_identifier: BlockIdentifier) -> Balance:
        """ The user's balance with planned withdrawals deducted. """
        balance = self.proxy.functions.effectiveBalance(address).call(
            block_identifier=block_identifier
        )

        if balance == b"":
            raise RuntimeError(f"Call to 'effectiveBalance' returned nothing")

        return balance

    def deposit(
        self,
        beneficiary: Address,
        total_deposit: TokenAmount,
        given_block_identifier: BlockIdentifier,
    ) -> None:
        """ Increase the total deposit of the beneficiary's account to `total_deposit`. """

        token_address = self.token_address(given_block_identifier)
        token = self.proxy_manager.token(
            token_address=token_address, block_identifier=given_block_identifier
        )

        previous_total_deposit, amount_to_deposit = self._deposit_preconditions(
            beneficiary, total_deposit, given_block_identifier, token
        )

        # The call to `_deposit_preconditions` makes sure the deposit was valid
        # at block `given_block_identifier`, the check below is for another
        # concurrent deposits, with a higher value. Since concurrent calls is
        # not an error, just a race condition, just wait for the result of the
        # other operation.
        current_inflight = self._inflight_deposits.get(beneficiary)
        if current_inflight is not None and current_inflight.total_deposit >= total_deposit:
            current_inflight.async_result.get()
            return

        with self._deposit_inflight(beneficiary, total_deposit):
            log_details = {
                "given_block_identifier": format_block_id(given_block_identifier),
                "previous_total_deposit": previous_total_deposit,
            }
            estimated_transaction = self.client.estimate_gas(
                self.proxy, "deposit", log_details, beneficiary, total_deposit
            )

            transaction_hash = None
            if estimated_transaction is not None:
                transaction_hash = self.client.transact(estimated_transaction)

            self._deposit_check_result(transaction_hash, token, total_deposit, amount_to_deposit)

    def approve_and_deposit(
        self,
        beneficiary: Address,
        total_deposit: TokenAmount,
        given_block_identifier: BlockIdentifier,
    ) -> None:
        """ Deposit provided amount into the user-deposit contract
        to the beneficiary's account.

        This function will also call approve with the *same* amount of tokens
        for the deposit. Note that this will overwrite the existing value, so
        large allowances are not useful when this method is used.
        """

        token_address = self.token_address(given_block_identifier)
        token = self.proxy_manager.token(
            token_address=token_address, block_identifier=given_block_identifier
        )

        previous_total_deposit, amount_to_deposit = self._deposit_preconditions(
            beneficiary, total_deposit, given_block_identifier, token
        )

        log_details = {
            "given_block_identifier": format_block_id(given_block_identifier),
            "previous_total_deposit": previous_total_deposit,
        }

        current_inflight = self._inflight_deposits.get(beneficiary)
        if current_inflight is not None and current_inflight.total_deposit >= total_deposit:
            current_inflight.async_result.get()
            return

        with self._deposit_inflight(beneficiary, total_deposit):
            # Make sure another `approve` transactions is not sent before the
            # deposit, otherwise the value would be overwritten.
            transaction_sent = None
            with token.token_lock:
                # HACK: Prevents gas estimation failures because of race
                # conditions, for more details check `TokenNetwork.approve_and_set_total_deposit.
                allowance = TokenAmount(amount_to_deposit + 1)
                token.approve(allowed_address=Address(self.address), allowance=allowance)

                estimated_transaction = self.client.estimate_gas(
                    self.proxy, "deposit", log_details, beneficiary, total_deposit
                )

                if estimated_transaction is not None:
                    transaction_sent = self.client.transact(estimated_transaction)

            self._deposit_check_result(transaction_sent, token, total_deposit, amount_to_deposit)

    def _deposit_preconditions(
        self,
        beneficiary: Address,
        total_deposit: TokenAmount,
        given_block_identifier: BlockIdentifier,
        token: Token,
    ) -> Tuple[TokenAmount, TokenAmount]:
        try:
            previous_total_deposit = self.get_total_deposit(
                address=beneficiary, block_identifier=given_block_identifier
            )
            current_balance = token.balance_of(
                address=self.node_address, block_identifier=given_block_identifier
            )
            whole_balance = self.whole_balance(block_identifier=given_block_identifier)
            whole_balance_limit = self.whole_balance_limit(block_identifier=given_block_identifier)
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

        return previous_total_deposit, amount_to_deposit

    @contextmanager
    def _deposit_inflight(
        self, beneficiary: Address, total_deposit: TokenAmount
    ) -> Iterator[None]:
        """ Updates the `_inflight_deposits` dictionary to handle concurrent deposits.

        Note: This must be called after `_deposit_preconditions`.
        """
        async_result = AsyncResult()
        current_inflight = InflightDeposit(total_deposit, async_result)
        self._inflight_deposits[beneficiary] = current_inflight

        try:
            yield
        except Exception as e:
            async_result.set_exception(e)
            raise
        else:
            async_result.set_result(None)
        finally:
            # Clearing the dictionary is not strictly necessary since the
            # deposit is always increasing. But it is just nice to clear up the
            # container.
            #
            # When two transactions are in the flight, only the one for the
            # highest `total_deposit` should clear the container.
            stored_inflight = self._inflight_deposits.get(beneficiary)
            if stored_inflight == current_inflight:
                del self._inflight_deposits[beneficiary]

    def _deposit_check_result(
        self,
        transaction_sent: Optional[TransactionSent],
        token: Token,
        total_deposit: TokenAmount,
        amount_to_deposit: TokenAmount,
    ) -> None:
        if transaction_sent is None:
            failed_at = self.client.get_block(BLOCK_ID_LATEST)
            failed_at_blocknumber = failed_at["number"]

            self.client.check_for_insufficient_eth(
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
            transaction_mined = self.client.poll_transaction(transaction_sent)

            if not was_transaction_successfully_mined(transaction_mined):
                failed_at_blocknumber = BlockNumber(transaction_mined.receipt["blockNumber"])

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
