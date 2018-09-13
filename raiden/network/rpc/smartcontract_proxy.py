import json
from enum import Enum
from typing import Dict, List

from eth_utils import decode_hex, to_canonical_address, to_checksum_address
from pkg_resources import DistributionNotFound
from web3.contract import Contract
from web3.utils.abi import get_abi_input_types
from web3.utils.contracts import encode_transaction_data, find_matching_fn_abi

from raiden.constants import EthClient
from raiden.exceptions import (
    InsufficientFunds,
    ReplacementTransactionUnderpriced,
    TransactionAlreadyPending,
)
from raiden.utils.filters import decode_event

try:
    from eth_tester.exceptions import TransactionFailed
except (ModuleNotFoundError, DistributionNotFound):
    class TransactionFailed(Exception):
        pass


class ClientErrorInspectResult(Enum):
    """Represents the action to follow after inspecting a client exception"""
    PROPAGATE_ERROR = 1
    INSUFFICIENT_FUNDS = 2
    TRANSACTION_UNDERPRICED = 3
    TRANSACTION_PENDING = 4
    ALWAYS_FAIL = 5


def inspect_client_error(val_err: ValueError, eth_node: str) -> ClientErrorInspectResult:
    # both clients return invalid json. They use single quotes while json needs double ones.
    json_response = str(val_err).replace("'", '"')
    try:
        error = json.loads(json_response)
    except json.JSONDecodeError:
        return ClientErrorInspectResult.PROPAGATE_ERROR

    if eth_node == EthClient.GETH:
        if error['code'] == -32000:
            if 'insufficient funds' in error['message']:
                return ClientErrorInspectResult.INSUFFICIENT_FUNDS
            elif 'always failing transaction' in error['message']:
                return ClientErrorInspectResult.ALWAYS_FAIL
            elif error['message'] == 'replacement transaction underpriced':
                return ClientErrorInspectResult.TRANSACTION_UNDERPRICED
            elif error['message'].startswith('known transaction:'):
                return ClientErrorInspectResult.TRANSACTION_PENDING

    elif eth_node == EthClient.PARITY:
        if error['code'] == -32010 and 'insufficient funds' in error['message']:
            return ClientErrorInspectResult.INSUFFICIENT_FUNDS
        elif error['code'] == -32010 and 'another transaction with same nonce in the queue':
            return ClientErrorInspectResult.TRANSACTION_UNDERPRICED

    return ClientErrorInspectResult.PROPAGATE_ERROR


class ContractProxy:
    def __init__(
            self,
            jsonrpc_client,
            contract: Contract,
    ):
        if contract is None:
            raise ValueError('Contract must not be None')
        if jsonrpc_client is None:
            raise ValueError('JSONRPCClient must not be None')
        self.jsonrpc_client = jsonrpc_client
        self.contract = contract

    def transact(self, function_name: str, *args, **kargs):
        data = ContractProxy.get_transaction_data(self.contract.abi, function_name, args)

        try:
            txhash = self.jsonrpc_client.send_transaction(
                to=self.contract.address,
                value=kargs.pop('value', 0),
                data=decode_hex(data),
                **kargs,
            )
        except ValueError as e:
            action = inspect_client_error(e, self.jsonrpc_client.eth_node)
            if action == ClientErrorInspectResult.INSUFFICIENT_FUNDS:
                raise InsufficientFunds('Insufficient ETH for transaction')
            elif action == ClientErrorInspectResult.TRANSACTION_UNDERPRICED:
                raise ReplacementTransactionUnderpriced(
                    'Transaction was rejected. This is potentially '
                    'caused by the reuse of the previous transaction '
                    'nonce as well as paying an amount of gas less than or '
                    'equal to the previous transaction\'s gas amount',
                )
            elif action == ClientErrorInspectResult.TRANSACTION_PENDING:
                raise TransactionAlreadyPending(
                    'The transaction has already been submitted. Please '
                    'wait until is has been mined or increase the gas price.',
                )

            raise e

        return txhash

    @staticmethod
    def sanitize_args(abi: Dict, args: List):
        """Prepare inputs to match the ABI"""
        inputs = get_abi_input_types(abi)
        output = []
        assert len(inputs) == len(args)
        for input_type, arg in zip(inputs, args):
            if input_type == 'address':
                output.append(to_checksum_address(arg))
            elif input_type == 'bytes' and isinstance(arg, str):
                output.append(arg.encode())
            else:
                output.append(arg)
        return output

    @staticmethod
    def get_transaction_data(abi: Dict, function_name: str, args: List = None):
        """Get encoded transaction data"""
        args = args or list()
        fn_abi = find_matching_fn_abi(
            abi,
            function_name,
            args,
        )
        args = ContractProxy.sanitize_args(fn_abi, args)
        return encode_transaction_data(
            None,
            function_name,
            contract_abi=abi,
            fn_abi=fn_abi,
            args=args,
        )

    def decode_transaction_input(self, transaction_hash: bytes) -> Dict:
        """Return inputs of a method call"""
        transaction = self.contract.web3.eth.getTransaction(
            transaction_hash,
        )

        return self.contract.decode_function_input(
            transaction['input'],
        )

    def decode_event(self, log: Dict):
        return decode_event(self.contract.abi, log)

    def encode_function_call(self, function: str, args: List = None):
        return self.get_transaction_data(self.contract.abi, function, args)

    def estimate_gas(self, function: str, *args):
        fn = getattr(self.contract.functions, function)
        try:
            return fn(*args).estimateGas({'from': to_checksum_address(self.jsonrpc_client.sender)})
        except ValueError as err:
            action = inspect_client_error(err, self.jsonrpc_client.eth_node)
            will_fail = action in (
                ClientErrorInspectResult.INSUFFICIENT_FUNDS,
                ClientErrorInspectResult.ALWAYS_FAIL,
            )
            if will_fail:
                return None

            raise err
        except TransactionFailed:
            return None

    @property
    def contract_address(self):
        return to_canonical_address(self.contract.address)
