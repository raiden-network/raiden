# -*- coding: utf-8 -*-
from typing import Callable, Optional, Dict

from ethereum.abi import ContractTranslator
from ethereum.utils import normalize_address

from raiden.exceptions import InvalidFunctionName
from raiden.utils.typing import address


class ContractProxy:
    """ Proxy to interact with a smart contract through the rpc interface. """

    def __init__(
            self,
            sender: address,
            abi: Dict,
            contract_address: address,
            call_function: Callable,
            transact_function: Callable,
            estimate_function: Optional[Callable] = None):

        sender = normalize_address(sender)
        contract_address = normalize_address(contract_address)
        translator = ContractTranslator(abi)

        self.abi = abi
        self.call_function = call_function
        self.contract_address = contract_address
        self.estimate_function = estimate_function
        self.sender = sender
        self.transaction_function = transact_function
        self.translator = translator
        self.valid_kargs = {'gasprice', 'startgas', 'value'}

    def _check_function_name_and_kargs(self, function_name: str, kargs):
        if function_name not in self.translator.function_data:
            raise InvalidFunctionName('Unknown function {}'.format(function_name))

        invalid_args = set(kargs.keys()).difference(self.valid_kargs)
        if invalid_args:
            raise TypeError('got an unexpected keyword argument: {}'.format(
                ', '.join(invalid_args),
            ))

    def transact(self, function_name: str, *args, **kargs):
        self._check_function_name_and_kargs(function_name, kargs)

        data = self.translator.encode_function_call(function_name, args)
        txhash = self.transaction_function(
            sender=self.sender,
            to=self.contract_address,
            value=kargs.pop('value', 0),
            data=data,
            **kargs
        )

        return txhash

    def call(self, function_name: str, *args, **kargs):
        self._check_function_name_and_kargs(function_name, kargs)

        data = self.translator.encode_function_call(function_name, args)
        res = self.call_function(
            sender=self.sender,
            to=self.contract_address,
            value=kargs.pop('value', 0),
            data=data,
            **kargs
        )

        if res:
            res = self.translator.decode_function_result(function_name, res)
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

        data = self.translator.encode_function_call(function_name, args)

        res = self.estimate_function(
            sender=self.sender,
            to=self.contract_address,
            value=kargs.pop('value', 0),
            data=data,
            **kargs
        )

        return res
