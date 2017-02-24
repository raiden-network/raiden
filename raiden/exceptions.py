# -*- coding: utf-8 -*-
from raiden.utils import pex


class UnknownAddress(Exception):
    pass


class TransferWhenClosed(Exception):
    pass


class UnknownTokenAddress(Exception):
    def __init__(self, address):
        self.address = address
        Exception.__init__(
            self,
            'Message with unknown token address {} received'.format(pex(address))
        )


class RaidenError(Exception):
    pass


class NoPathError(RaidenError):
    pass


class InvalidAddress(RaidenError):
    pass


class InvalidAmount(RaidenError):
    pass


class InvalidState(RaidenError):
    pass


class InsufficientFunds(RaidenError):
    pass
