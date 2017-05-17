# -*- coding: utf-8 -*-
from raiden.utils import pex


class RaidenError(Exception):
    pass


class HashLengthNot32(Exception):
    """The length of a 32 bytes hash is not as expected"""
    pass


class InsufficientBalance(Exception):
    pass


class InsufficientFunds(RaidenError):
    pass


class InvalidAddress(RaidenError):
    pass


class InvalidAmount(RaidenError):
    pass


class InvalidLocksRoot(Exception):
    def __init__(self, expected_locksroot, got_locksroot):
        Exception.__init__(
            self,
            'Locksroot mismatch. Expected {} but got {}'.format(
                pex(expected_locksroot),
                pex(got_locksroot)
            ))


class InvalidNonce(Exception):
    pass


class InvalidState(RaidenError):
    pass


class NoPathError(RaidenError):
    pass


class TransferWhenClosed(Exception):
    pass


class UnknownAddress(Exception):
    pass


class UnknownTokenAddress(Exception):
    def __init__(self, address):
        super(UnknownTokenAddress, self).__init__(
            'Message with unknown token address {} received'.format(pex(address))
        )

        self.address = address


class STUNUnavailableException(Exception):
    pass
