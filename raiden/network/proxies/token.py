import structlog
from eth_utils import encode_hex, is_binary_address, to_checksum_address
from gevent.lock import RLock

from raiden.constants import GAS_LIMIT_FOR_TOKEN_CONTRACT_CALL
from raiden.exceptions import RaidenRecoverableError
from raiden.network.proxies.utils import log_transaction
from raiden.network.rpc.client import JSONRPCClient, check_address_has_code
from raiden.network.rpc.smartcontract_proxy import ContractProxy
from raiden.network.rpc.transactions import check_transaction_threw
from raiden.utils import safe_gas_limit
from raiden.utils.typing import Address, Balance, BlockSpecification, TokenAddress, TokenAmount
from raiden_contracts.constants import CONTRACT_CUSTOM_TOKEN
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
    ) -> None:
        contract = jsonrpc_client.new_contract(
            contract_manager.get_contract_abi(CONTRACT_CUSTOM_TOKEN), Address(token_address)
        )
        proxy = ContractProxy(jsonrpc_client, contract)

        if not is_binary_address(token_address):
            raise ValueError("token_address must be a valid address")

        check_address_has_code(jsonrpc_client, Address(token_address), "Token", expected_code=None)

        self.address = token_address
        self.client = jsonrpc_client
        self.node_address = jsonrpc_client.address
        self.proxy = proxy

        self.token_lock: RLock = RLock()

    def allowance(
        self, owner: Address, spender: Address, block_identifier: BlockSpecification
    ) -> TokenAmount:
        return TokenAmount(
            self.proxy.contract.functions.allowance(
                to_checksum_address(owner), to_checksum_address(spender)
            ).call(block_identifier=block_identifier)
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
            log_details = {
                "node": to_checksum_address(self.node_address),
                "contract": to_checksum_address(self.address),
                "allowed_address": to_checksum_address(allowed_address),
                "allowance": allowance,
            }

            with log_transaction(log, "approve", log_details):
                checking_block = self.client.get_checking_block()
                error_prefix = "Call to approve will fail"
                gas_limit = self.proxy.estimate_gas(
                    checking_block, "approve", to_checksum_address(allowed_address), allowance
                )

                if gas_limit:
                    error_prefix = "Call to approve failed"
                    gas_limit = safe_gas_limit(gas_limit)
                    log_details["gas_limit"] = gas_limit
                    transaction_hash = self.proxy.transact(
                        "approve", gas_limit, to_checksum_address(allowed_address), allowance
                    )

                    receipt = self.client.poll(transaction_hash)
                    failed_receipt = check_transaction_threw(receipt=receipt)

                    if failed_receipt:
                        failed_at_blockhash = encode_hex(failed_receipt["blockHash"])

                        if failed_receipt["cumulativeGasUsed"] == gas_limit:
                            msg = (
                                f"approve failed and all gas was used ({gas_limit}). "
                                f"Estimate gas may have underestimated approve, or "
                                f"succeeded even though an assert is triggered, or "
                                f"the smart contract code has a conditional assert."
                            )
                            raise RaidenRecoverableError(msg)

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
                    failed_at = self.proxy.rpc_client.get_block("latest")
                    failed_at_blockhash = encode_hex(failed_at["hash"])
                    failed_at_blocknumber = failed_at["number"]

                    self.proxy.rpc_client.check_for_insufficient_eth(
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
        self, address: Address, block_identifier: BlockSpecification = "latest"
    ) -> Balance:
        """ Return the balance of `address`. """
        return self.proxy.contract.functions.balanceOf(to_checksum_address(address)).call(
            block_identifier=block_identifier
        )

    def total_supply(self, block_identifier: BlockSpecification = "latest") -> TokenAmount:
        """ Return the total supply of the token at the given block identifier. """
        return TokenAmount(
            self.proxy.contract.functions.totalSupply().call(block_identifier=block_identifier)
        )

    def transfer(self, to_address: Address, amount: TokenAmount) -> None:
        """ Transfer `amount` tokens to `to_address`.

        Note:

            We assume there to be sufficient balance as a precondition if
            this is called, so that is not checked as a precondition here.
        """
        # Note that given_block_identifier is not used here as there
        # are no preconditions to check before sending the transaction
        # There are no direct calls to this method in any event handler,
        # so a precondition check would make no sense.
        with self.token_lock:
            log_details = {
                "node": to_checksum_address(self.node_address),
                "contract": to_checksum_address(self.address),
                "to_address": to_checksum_address(to_address),
                "amount": amount,
            }

            with log_transaction(log, "transfer", log_details):
                checking_block = self.client.get_checking_block()
                gas_limit = self.proxy.estimate_gas(
                    checking_block, "transfer", to_checksum_address(to_address), amount
                )
                failed_receipt = None

                if gas_limit is not None:
                    gas_limit = safe_gas_limit(gas_limit)
                    log_details["gas_limit"] = gas_limit

                    transaction_hash = self.proxy.transact(
                        "transfer", gas_limit, to_checksum_address(to_address), amount
                    )

                    receipt = self.client.poll(transaction_hash)
                    # TODO: check Transfer event (issue: #2598)
                    failed_receipt = check_transaction_threw(receipt=receipt)

                if gas_limit is None or failed_receipt is not None:
                    if failed_receipt:
                        failed_at_number = failed_receipt["blockNumber"]
                    else:
                        failed_at_number = checking_block
                    failed_at_hash = encode_hex(
                        self.client.blockhash_from_blocknumber(failed_at_number)
                    )

                    self.proxy.rpc_client.check_for_insufficient_eth(
                        transaction_name="transfer",
                        transaction_executed=False,
                        required_gas=GAS_LIMIT_FOR_TOKEN_CONTRACT_CALL,
                        block_identifier=failed_at_number,
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

                    if gas_limit is None:
                        raise RaidenRecoverableError(
                            "Call to transfer will fail. Gas estimation failed for unknown "
                            "reason. Please make sure the contract is a valid ERC20 token."
                        )
                    else:
                        raise RaidenRecoverableError(
                            "Call to transfer failed for unknown reason. Please make sure the "
                            "contract is a valid ERC20 token."
                        )
