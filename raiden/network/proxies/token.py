import structlog
from eth_utils import encode_hex, is_binary_address
from gevent.lock import RLock

from raiden.constants import BLOCK_ID_LATEST, GAS_LIMIT_FOR_TOKEN_CONTRACT_CALL
from raiden.exceptions import RaidenRecoverableError
from raiden.network.rpc.client import (
    JSONRPCClient,
    check_address_has_code_handle_pruned_block,
    check_transaction_failure,
    was_transaction_successfully_mined,
)
from raiden.utils.typing import (
    ABI,
    Address,
    Any,
    Balance,
    BlockIdentifier,
    BlockNumber,
    Dict,
    Optional,
    TokenAddress,
    TokenAmount,
)
from raiden_contracts.constants import CONTRACT_HUMAN_STANDARD_TOKEN
from raiden_contracts.contract_manager import ContractManager

log = structlog.get_logger(__name__)

# Determined by safe_gas_limit(estimateGas(approve)) on 17/01/19 with geth 1.8.20
GAS_REQUIRED_FOR_APPROVE = 58792


class Token:
    def __init__(
        self,
        jsonrpc_client: JSONRPCClient,
        token_address: TokenAddress,
        contract_manager: ContractManager,
        block_identifier: BlockIdentifier,
    ) -> None:
        proxy = jsonrpc_client.new_contract_proxy(
            self.abi(contract_manager), Address(token_address)
        )

        if not is_binary_address(token_address):
            raise ValueError("token_address must be a valid address")

        check_address_has_code_handle_pruned_block(
            jsonrpc_client,
            Address(token_address),
            "Token",
            expected_code=None,
            given_block_identifier=block_identifier,
        )

        self.address = token_address
        self.client = jsonrpc_client
        self.node_address = jsonrpc_client.address
        self.proxy = proxy

        self.token_lock: RLock = RLock()

    @staticmethod
    def abi(contract_manager: ContractManager) -> ABI:
        """Overwrittable by subclasses to change the proxies ABI."""
        return contract_manager.get_contract_abi(CONTRACT_HUMAN_STANDARD_TOKEN)

    def allowance(
        self, owner: Address, spender: Address, block_identifier: BlockIdentifier
    ) -> TokenAmount:
        return TokenAmount(
            self.proxy.functions.allowance(owner, spender).call(block_identifier=block_identifier)
        )

    def approve(self, allowed_address: Address, allowance: TokenAmount) -> None:
        """ Approve `allowed_address` to transfer up to `deposit` amount of token.

        Note:

            For channel deposit please use the channel proxy, since it does
            additional validations.
            We assume there to be sufficient balance as a precondition if this
            is called, so it is not checked as a precondition here.
        """
        # Note that given_block_identifier is not used here as there
        # are no preconditions to check before sending the transaction
        # There are no direct calls to this method in any event handler,
        # so a precondition check would make no sense.
        with self.token_lock:
            log_details: Dict[str, Any] = {}

            error_prefix = "Call to approve will fail"
            estimated_transaction = self.client.estimate_gas(
                self.proxy, "approve", log_details, allowed_address, allowance
            )

            if estimated_transaction is not None:
                error_prefix = "Call to approve failed"
                transaction_sent = self.client.transact(estimated_transaction)
                transaction_mined = self.client.poll_transaction(transaction_sent)

                if not was_transaction_successfully_mined(transaction_mined):
                    failed_receipt = transaction_mined.receipt
                    failed_at_blockhash = encode_hex(failed_receipt["blockHash"])

                    check_transaction_failure(transaction_mined, self.client)

                    balance = self.balance_of(self.client.address, failed_at_blockhash)
                    if balance < allowance:
                        msg = (
                            f"{error_prefix} Your balance of {balance} is "
                            "below the required amount of {allowance}."
                        )
                        if balance == 0:
                            msg += (
                                " Note: The balance was 0, which may also happen "
                                "if the contract is not a valid ERC20 token "
                                "(balanceOf method missing)."
                            )
                        raise RaidenRecoverableError(msg)

                    raise RaidenRecoverableError(
                        f"{error_prefix}. The reason is unknown, you have enough tokens for "
                        f"the requested allowance and enough eth to pay the gas. There may "
                        f"be a problem with the token contract."
                    )

            else:
                failed_at = self.client.get_block(BLOCK_ID_LATEST)
                failed_at_blockhash = encode_hex(failed_at["hash"])
                failed_at_blocknumber = failed_at["number"]

                self.client.check_for_insufficient_eth(
                    transaction_name="approve",
                    transaction_executed=False,
                    required_gas=GAS_REQUIRED_FOR_APPROVE,
                    block_identifier=failed_at_blocknumber,
                )

                balance = self.balance_of(self.client.address, failed_at_blockhash)
                if balance < allowance:
                    msg = (
                        f"{error_prefix} Your balance of {balance} is "
                        "below the required amount of {allowance}."
                    )
                    if balance == 0:
                        msg += (
                            " Note: The balance was 0, which may also happen if the contract "
                            "is not a valid ERC20 token (balanceOf method missing)."
                        )
                    raise RaidenRecoverableError(msg)

                raise RaidenRecoverableError(
                    f"{error_prefix} Gas estimation failed for unknown reason. "
                    f"Please make sure the contract is a valid ERC20 token."
                )

    def balance_of(
        self, address: Address, block_identifier: BlockIdentifier = BLOCK_ID_LATEST
    ) -> Balance:
        """ Return the balance of `address`. """
        return self.proxy.functions.balanceOf(address).call(block_identifier=block_identifier)

    def total_supply(
        self, block_identifier: BlockIdentifier = BLOCK_ID_LATEST
    ) -> Optional[TokenAmount]:
        """ Return the total supply of the token at the given block identifier.

        Because Token is just an interface, it is not possible to check the
        bytecode during the proxy instantiation. This means it is possible for
        the proxy to be instantiated with a a smart contrat address of the
        wrong type (a non ERC20 contract), or a partial implementation of the
        ERC20 standard (the function totalSupply is missing). If that happens
        this method will return `None`.
        """
        total_supply = self.proxy.functions.totalSupply().call(block_identifier=block_identifier)

        if isinstance(total_supply, int):
            return TokenAmount(total_supply)

        return None

    def transfer(self, to_address: Address, amount: TokenAmount) -> None:
        """ Transfer `amount` tokens to `to_address`.

        Note:

            We assume there to be sufficient balance as a precondition if
            this is called, so that is not checked as a precondition here.
        """

        def check_for_insufficient_token_balance(block_number: BlockNumber) -> None:

            failed_at_hash = encode_hex(self.client.blockhash_from_blocknumber(block_number))
            self.client.check_for_insufficient_eth(
                transaction_name="transfer",
                transaction_executed=False,
                required_gas=GAS_LIMIT_FOR_TOKEN_CONTRACT_CALL,
                block_identifier=block_number,
            )

            balance = self.balance_of(self.client.address, failed_at_hash)
            if balance < amount:
                msg = (
                    f"Call to transfer will fail. Your balance of {balance} is "
                    f"below the required amount of {amount}."
                )
                if balance == 0:
                    msg += (
                        " Note: The balance was 0, which may also happen if the contract "
                        "is not a valid ERC20 token (balanceOf method missing)."
                    )
                raise RaidenRecoverableError(msg)

        # Note that given_block_identifier is not used here as there
        # are no preconditions to check before sending the transaction
        # There are no direct calls to this method in any event handler,
        # so a precondition check would make no sense.
        with self.token_lock:
            log_details: Dict[str, Any] = {}

            estimated_transaction = self.client.estimate_gas(
                self.proxy, "transfer", log_details, to_address, amount
            )

            if estimated_transaction is not None:
                # TODO: check Transfer event (issue: #2598)
                transaction_sent = self.client.transact(estimated_transaction)
                transaction_mined = self.client.poll_transaction(transaction_sent)

                if was_transaction_successfully_mined(transaction_mined):
                    return

                failed_at_block_number = BlockNumber(transaction_mined.receipt["blockNumber"])
                check_for_insufficient_token_balance(failed_at_block_number)
                raise RaidenRecoverableError(
                    "Call to transfer failed for unknown reason. Please make sure the "
                    "contract is a valid ERC20 token."
                )
            else:
                failed_at_block_number = self.client.get_block(BLOCK_ID_LATEST)["number"]
                check_for_insufficient_token_balance(failed_at_block_number)
                raise RaidenRecoverableError(
                    "Call to transfer will fail. Gas estimation failed for unknown "
                    "reason. Please make sure the contract is a valid ERC20 token."
                )
