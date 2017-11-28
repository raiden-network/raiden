# -*- coding: utf-8 -*-
from ethereum.abi import ContractTranslator
from ethereum.utils import normalize_address

from raiden.exceptions import InvalidFunctionName


VALID_KARGS = {'gasprice', 'startgas', 'value'}


class ContractProxy(object):
    """ Proxy to interact with a smart contract through the rpc interface. """

    def __init__(
            self,
            sender,
            abi,
            contract_address,
            call_function,
            transact_function,
            estimate_function=None):

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

    def transact(self, function_name, *args, **kargs):
        if function_name not in self.translator.function_data:
            raise InvalidFunctionName('Unknown function {}'.format(function_name))

        invalid_args = set(kargs.keys()).difference(VALID_KARGS)
        if invalid_args:
            raise TypeError('got an unexpected keyword argument: {}'.format(
                ', '.join(invalid_args),
            ))

        data = self.translator.encode(function_name, args)
        txhash = self.transaction_function(
            sender=self.sender,
            to=self.contract_address,
            value=kargs.pop('value', 0),
            data=data,
            **kargs
        )

        return txhash

    def call(self, function_name, *args, **kargs):
        if function_name not in self.translator.function_data:
            raise InvalidFunctionName('Unknown function {}'.format(function_name))

        invalid_args = set(kargs.keys()).difference(VALID_KARGS)
        if invalid_args:
            raise TypeError('got an unexpected keyword argument: {}'.format(
                ', '.join(invalid_args),
            ))

        data = self.translator.encode(function_name, args)
        res = self.call_function(
            sender=self.sender,
            to=self.contract_address,
            value=kargs.pop('value', 0),
            data=data,
            **kargs
        )

        if res:
            res = self.translator.decode(function_name, res)
            if len(res) == 1:
                res = res[0]

        return res

    def estimate_gas(self, function_name, *args, **kargs):
        if not self.estimate_function:
            raise RuntimeError('estimate_function was not supplied.')

        if function_name not in self.translator.function_data:
            raise InvalidFunctionName('Unknown function {}'.format(function_name))

        invalid_args = set(kargs.keys()).difference(VALID_KARGS)
        if invalid_args:
            raise TypeError('got an unexpected keyword argument: {}'.format(
                ', '.join(invalid_args),
            ))

        data = self.translator.encode(function_name, args)

        res = self.estimate_function(
            sender=self.sender,
            to=self.contract_address,
            value=kargs.pop('value', 0),
            data=data,
            **kargs
        )

        return res
