# -*- coding: utf-8 -*-
from ethereum.abi import ContractTranslator
from ethereum.utils import normalize_address


class ContractProxy(object):
    """ Exposes a smart contract as a python object.

    Contract calls can be made directly in this object, all the functions will
    be exposed with the equivalent api and will perform the argument
    translation.
    """

    def __init__(self, sender, abi, address, call_func, transact_func, estimate_function=None):
        sender = normalize_address(sender)

        self.abi = abi
        self.address = address = normalize_address(address)
        self.translator = ContractTranslator(abi)

        for function_name in self.translator.function_data:
            function_proxy = MethodProxy(
                sender,
                address,
                function_name,
                self.translator,
                call_func,
                transact_func,
                estimate_function,
            )

            type_argument = self.translator.function_data[function_name]['signature']

            arguments = [
                '{type} {argument}'.format(type=type_, argument=argument)
                for type_, argument in type_argument
            ]
            function_signature = ', '.join(arguments)

            function_proxy.__doc__ = '{function_name}({function_signature})'.format(
                function_name=function_name,
                function_signature=function_signature,
            )

            setattr(self, function_name, function_proxy)


class MethodProxy(object):
    """ A callable interface that exposes a contract function. """
    valid_kargs = set(('gasprice', 'startgas', 'value'))

    def __init__(
            self,
            sender,
            contract_address,
            function_name,
            translator,
            call_function,
            transaction_function,
            estimate_function=None):

        self.sender = sender
        self.contract_address = contract_address
        self.function_name = function_name
        self.translator = translator
        self.call_function = call_function
        self.transaction_function = transaction_function
        self.estimate_function = estimate_function

    def transact(self, *args, **kargs):
        assert set(kargs.keys()).issubset(self.valid_kargs)
        data = self.translator.encode(self.function_name, args)

        txhash = self.transaction_function(
            sender=self.sender,
            to=self.contract_address,
            value=kargs.pop('value', 0),
            data=data,
            **kargs
        )

        return txhash

    def call(self, *args, **kargs):
        assert set(kargs.keys()).issubset(self.valid_kargs)
        data = self.translator.encode(self.function_name, args)

        res = self.call_function(
            sender=self.sender,
            to=self.contract_address,
            value=kargs.pop('value', 0),
            data=data,
            **kargs
        )

        if res:
            res = self.translator.decode(self.function_name, res)
            res = res[0] if len(res) == 1 else res
        return res

    def estimate_gas(self, *args, **kargs):
        if not self.estimate_function:
            raise RuntimeError('estimate_function was not supplied.')

        assert set(kargs.keys()).issubset(self.valid_kargs)
        data = self.translator.encode(self.function_name, args)

        res = self.estimate_function(
            sender=self.sender,
            to=self.contract_address,
            value=kargs.pop('value', 0),
            data=data,
            **kargs
        )

        return res

    def __call__(self, *args, **kargs):
        if self.translator.function_data[self.function_name]['is_constant']:
            result = self.call(*args, **kargs)
        else:
            result = self.transact(*args, **kargs)

        return result
