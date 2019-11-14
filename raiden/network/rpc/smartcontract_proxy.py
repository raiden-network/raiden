import json
from enum import Enum
from typing import Any, Dict, List, Optional

from eth_utils import decode_hex, to_canonical_address, to_checksum_address
from web3.contract import Contract
from web3.utils.contracts import encode_transaction_data, find_matching_fn_abi

from raiden import constants
from raiden.blockchain.filters import decode_event
from raiden.constants import EthClient
from raiden.exceptions import (
    EthereumNonceTooLow,
    InsufficientEth,
    RaidenUnrecoverableError,
    ReplacementTransactionUnderpriced,
)
from raiden.utils.typing import TYPE_CHECKING, Address, BlockSpecification, TransactionHash

if TYPE_CHECKING:
    from raiden.network.rpc.client import JSONRPCClient


class ClientErrorInspectResult(Enum):
    """Represents the action to follow after inspecting a client exception"""

    PROPAGATE_ERROR = 1
    INSUFFICIENT_FUNDS = 2
    TRANSACTION_UNDERPRICED = 3
    TRANSACTION_PENDING = 4
    ALWAYS_FAIL = 5
    TRANSACTION_ALREADY_IMPORTED = 7
    TRANSACTION_PENDING_OR_ALREADY_IMPORTED = 8


# Geth has one error message for resending a transaction from the transaction
# pool, and another for reusing a nonce of a mined transaction. Parity on the
# other hand has just a single error message, so these errors have to be
# grouped. (Tested with Geth 1.9.6 and Parity 2.5.9).
THE_NONCE_WAS_REUSED = (
    ClientErrorInspectResult.TRANSACTION_PENDING,
    ClientErrorInspectResult.TRANSACTION_ALREADY_IMPORTED,
    ClientErrorInspectResult.TRANSACTION_PENDING_OR_ALREADY_IMPORTED,
)


def inspect_client_error(
    val_err: ValueError, eth_node: Optional[EthClient]
) -> ClientErrorInspectResult:
    # both clients return invalid json. They use single quotes while json needs double ones.
    # Also parity may return something like: 'data': 'Internal("Error message")' which needs
    # special processing
    json_response = str(val_err).replace("'", '"').replace('("', "(").replace('")', ")")
    try:
        error = json.loads(json_response)
    except json.JSONDecodeError:
        return ClientErrorInspectResult.PROPAGATE_ERROR

    if eth_node is EthClient.GETH:
        if error["code"] == -32000:
            if "insufficient funds" in error["message"]:
                return ClientErrorInspectResult.INSUFFICIENT_FUNDS

            if "always failing transaction" in error["message"]:
                return ClientErrorInspectResult.ALWAYS_FAIL

            if "replacement transaction underpriced" in error["message"]:
                return ClientErrorInspectResult.TRANSACTION_UNDERPRICED

            if "known transaction:" in error["message"]:
                return ClientErrorInspectResult.TRANSACTION_PENDING

            if "nonce too low" in error["message"]:
                return ClientErrorInspectResult.TRANSACTION_ALREADY_IMPORTED

    elif eth_node is EthClient.PARITY:
        if error["code"] == -32010:
            if "Insufficient funds" in error["message"]:
                return ClientErrorInspectResult.INSUFFICIENT_FUNDS

            if "another transaction with same nonce in the queue" in error["message"]:
                return ClientErrorInspectResult.TRANSACTION_UNDERPRICED

            # This error code is known to be used for pending transactions, it
            # may also be used for reusing the nonce of mined transactions.
            if "Transaction nonce is too low. Try incrementing the nonce." in error["message"]:
                return ClientErrorInspectResult.TRANSACTION_PENDING_OR_ALREADY_IMPORTED

            # This error code is used for both resending pending transactions
            # and reusing nonce of mined transactions.
            if "Transaction with the same hash was already imported" in error["message"]:
                return ClientErrorInspectResult.TRANSACTION_PENDING_OR_ALREADY_IMPORTED

        elif error["code"] == -32015 and "Transaction execution error" in error["message"]:
            return ClientErrorInspectResult.ALWAYS_FAIL

    return ClientErrorInspectResult.PROPAGATE_ERROR


class ContractProxy:
    def __init__(self, rpc_client: "JSONRPCClient", contract: Contract) -> None:
        if contract is None:
            raise ValueError("Contract must not be None")
        if rpc_client is None:
            raise ValueError("JSONRPCClient must not be None")
        self.rpc_client = rpc_client
        self.contract = contract

    def transact(
        self, function_name: str, startgas: int, *args: Any, **kwargs: Any
    ) -> TransactionHash:
        data = ContractProxy.get_transaction_data(
            abi=self.contract.abi, function_name=function_name, args=args, kwargs=kwargs
        )

        slot = self.rpc_client.get_next_transaction()
        try:
            tx_hash = slot.send_transaction(
                to=self.contract.address,
                startgas=startgas,
                value=kwargs.pop("value", 0),
                data=decode_hex(data),
            )
        except ValueError as e:
            action = inspect_client_error(e, self.rpc_client.eth_node)
            if action == ClientErrorInspectResult.INSUFFICIENT_FUNDS:
                raise InsufficientEth(
                    "Transaction failed due to insufficient ETH balance. "
                    "Please top up your ETH account."
                )
            elif action == ClientErrorInspectResult.TRANSACTION_UNDERPRICED:
                raise ReplacementTransactionUnderpriced(
                    "Transaction was rejected. This is potentially "
                    "caused by the reuse of the previous transaction "
                    "nonce as well as paying an amount of gas less than or "
                    "equal to the previous transaction's gas amount"
                )
            elif action in THE_NONCE_WAS_REUSED:
                # XXX: Add logic to check that it is the same transaction
                # (instead of relying on the error message), and instead of
                # raising an unrecoverable error proceed as normal with the
                # polling.
                #
                # This was previously done, but removed by #4909, and for it to
                # be finished #2088 has to be implemented.
                raise EthereumNonceTooLow(
                    "Transaction rejected because the nonce has been already mined."
                )

            raise RaidenUnrecoverableError(
                f"Unexpected error in underlying Ethereum node: {str(e)}"
            )

        return tx_hash

    @staticmethod
    def get_transaction_data(
        abi: Dict, function_name: str, args: Any = None, kwargs: Any = None
    ) -> str:
        """Get encoded transaction data"""
        args = args or list()
        fn_abi = find_matching_fn_abi(abi, function_name, args=args, kwargs=kwargs)
        return encode_transaction_data(
            web3=None,
            fn_identifier=function_name,
            contract_abi=abi,
            fn_abi=fn_abi,
            args=args,
            kwargs=kwargs,
        )

    def decode_event(self, log: Dict[str, Any]) -> Dict[str, Any]:
        return decode_event(self.contract.abi, log)

    def encode_function_call(self, function: str, args: List = None) -> str:
        return self.get_transaction_data(self.contract.abi, function, args)

    def estimate_gas(
        self,
        block_identifier: Optional[BlockSpecification],
        function: str,
        *args: Any,
        **kwargs: Any,
    ) -> Optional[int]:
        """Estimate the gas necessary to run the transaction.

        Returns `None` transaction would fail because it hit an assert/require,
        or if the amount of gas required is larger than the block gas limit.
        """

        fn = getattr(self.contract.functions, function)
        address = to_checksum_address(self.rpc_client.address)
        if self.rpc_client.eth_node is constants.EthClient.GETH:
            # Unfortunately geth does not follow the ethereum JSON-RPC spec and
            # does not accept a block identifier argument for eth_estimateGas
            # parity and py-evm (trinity) do.
            #
            # Geth only runs estimateGas on the pending block and that's why we
            # should also enforce parity, py-evm and others to do the same since
            # we can't customize geth.
            #
            # Spec: https://github.com/ethereum/wiki/wiki/JSON-RPC#eth_estimategas
            # Geth Issue: https://github.com/ethereum/go-ethereum/issues/2586
            # Relevant web3 PR: https://github.com/ethereum/web3.py/pull/1046
            block_identifier = None
        try:
            return fn(*args, **kwargs).estimateGas(
                transaction={"from": address}, block_identifier=block_identifier
            )
        except ValueError as err:
            action = inspect_client_error(err, self.rpc_client.eth_node)
            will_fail = action in (
                ClientErrorInspectResult.INSUFFICIENT_FUNDS,
                ClientErrorInspectResult.ALWAYS_FAIL,
            )
            if will_fail:
                return None

            raise err

    @property
    def contract_address(self) -> Address:
        return to_canonical_address(self.contract.address)
