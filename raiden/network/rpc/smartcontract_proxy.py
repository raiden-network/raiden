# -*- coding: utf-8 -*-
from typing import Callable, Optional, Dict, List

from eth_utils import (
    to_canonical_address,
    decode_hex,
    to_checksum_address,
    event_abi_to_log_topic
)
from eth_abi import decode_abi, encode_abi
from web3.utils.contracts import encode_transaction_data, find_matching_fn_abi
from web3.utils.abi import get_abi_input_types, get_abi_output_types, filter_by_type
from web3.utils.events import get_event_data

from raiden.exceptions import InvalidFunctionName
from raiden.utils.typing import Address


def decode_event(abi: Dict, log: Dict):
    """Helper function to unpack event data using a provided ABI"""
    if isinstance(log['topics'][0], str):
        log['topics'][0] = decode_hex(log['topics'][0])
    elif isinstance(log['topics'][0], int):
        log['topics'][0] = decode_hex(hex(log['topics'][0]))
    event_id = log['topics'][0]
    events = filter_by_type('event', abi)
    topic_to_event_abi = {
        event_abi_to_log_topic(event_abi): event_abi
        for event_abi in events
    }
    event_abi = topic_to_event_abi[event_id]
    return get_event_data(event_abi, log)


def encode_function_call(abi: Dict, function: str, args: List=list()):
    fn_abi = find_matching_fn_abi(abi, function, args)
    fn_types = get_abi_input_types(fn_abi)
    return encode_abi(fn_types, args)


class ContractProxy:
    """ Proxy to interact with a smart contract through the rpc interface. """

    def __init__(
            self,
            sender: Address,
            abi: Dict,
            contract_address: Address,
            call_function: Callable,
            transact_function: Callable,
            estimate_function: Optional[Callable] = None):

        sender = to_canonical_address(sender)
        contract_address = to_canonical_address(contract_address)

        self.abi = abi
        self.call_function = call_function
        self.contract_address = contract_address
        self.estimate_function = estimate_function
        self.sender = sender
        self.transaction_function = transact_function
        self.valid_kargs = {'gasprice', 'startgas', 'value'}

    def _check_function_name_and_kargs(self, function_name: str, kargs):
        functions = [x['name'] for x in self.abi if x['type'] == 'function']
        if function_name not in functions:
            raise InvalidFunctionName('Unknown function {}'.format(function_name))

        invalid_args = set(kargs.keys()).difference(self.valid_kargs)
        if invalid_args:
            raise TypeError('got an unexpected keyword argument: {}'.format(
                ', '.join(invalid_args),
            ))

    def transact(self, function_name: str, *args, **kargs):
        self._check_function_name_and_kargs(function_name, kargs)
        data = self.get_transaction_data(self.abi, function_name, args)

        txhash = self.transaction_function(
            to=self.contract_address,
            value=kargs.pop('value', 0),
            data=decode_hex(data),
            **kargs
        )

        return txhash

    def call(self, function_name: str, *args, **kargs):
        self._check_function_name_and_kargs(function_name, kargs)
        data = self.get_transaction_data(self.abi, function_name, args)

        res = self.call_function(
            sender=self.sender,
            to=self.contract_address,
            value=kargs.pop('value', 0),
            data=decode_hex(data),
            **kargs
        )

        if res:
            fn_abi = find_matching_fn_abi(self.abi, function_name, args)
            output_types = get_abi_output_types(fn_abi)
            res = decode_abi(output_types, res)
            if len(res) == 1:
                res = res[0]

        return res

    def estimate_gas(self, function_name: str, *args, **kargs):
        """ Returns the estimated gas for the function or None if the function
        will throw.

        Raises:
            EthNodeCommunicationError: If the ethereum node's reply can't be parsed.
        """
        if not self.estimate_function:
            raise RuntimeError('estimate_function was not supplied.')

        self._check_function_name_and_kargs(function_name, kargs)
        data = self.get_transaction_data(self.abi, function_name, args)

        res = self.estimate_function(
            sender=self.sender,
            to=self.contract_address,
            value=kargs.pop('value', 0),
            data=decode_hex(data),
            **kargs
        )

        return res

    def decode_event(self, log):
        return decode_event(self.abi, log)

    def encode_function_call(self, function: str, args: List=list()):
        return self.get_transaction_data(self.abi, function, args)

    @staticmethod
    def sanitize_args(abi: dict, args: List):
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
    def get_transaction_data(abi: Dict, function_name: str, args: List=list()):
        """Get encoded transaction data"""
        fn_abi = find_matching_fn_abi(
            abi,
            function_name,
            args
        )
        args = ContractProxy.sanitize_args(fn_abi, args)
        return encode_transaction_data(
            abi,
            None,
            function_name,
            args
        )
