from typing import Dict, List

from eth_utils import (
    to_canonical_address,
    decode_hex,
    to_checksum_address,
)
from web3.utils.contracts import encode_transaction_data, find_matching_fn_abi
from web3.utils.abi import get_abi_input_types
from web3.contract import Contract
from raiden.utils.filters import decode_event
try:
    from eth_tester.exceptions import TransactionFailed
except ModuleNotFoundError:
    TransactionFailed = Exception()


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

        txhash = self.jsonrpc_client.send_transaction(
            to=self.contract.address,
            value=kargs.pop('value', 0),
            data=decode_hex(data),
            **kargs,
        )

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

    def decode_event(self, log: Dict):
        return decode_event(self.contract.abi, log)

    def encode_function_call(self, function: str, args: List = None):
        return self.get_transaction_data(self.contract.abi, function, args)

    def estimate_gas(self, function: str, *args):
        fn = getattr(self.contract.functions, function)
        try:
            return fn(*args).estimateGas({'from': to_checksum_address(self.jsonrpc_client.sender)})
        except ValueError as err:
            tx_would_fail = (
                '-32015' in str(err) or
                '-32000' in str(err)
            )
            if tx_would_fail:  # -32015 is parity and -32000 is geth
                return None
            else:
                raise err
        except TransactionFailed:
            return None

    @property
    def contract_address(self):
        return to_canonical_address(self.contract.address)
