# -*- coding: utf-8 -*-
from raiden.utils import pex


class RaidenError(Exception):
    """ Base exception, used to catch all raiden related exceptions. """
    pass


# Exceptions raised due to programming errors

class HashLengthNot32(RaidenError):
    """ Raised if the length of the provided element is not 32 bytes in length,
    a keccak hash is required to include the element in the merkle tree.
    """
    pass


class InvalidFunctionName(RaidenError):
    """ Raised by the rpc proxy when a call to an unknown function is made. """


# Exceptions raised due to user interaction (the user may be another software)

class ChannelNotFound(RaidenError):
    """ Raised when a provided channel via the REST api is not found in the
    internal data structures"""
    pass


class InsufficientFunds(RaidenError):
    """ Raised when provided account doesn't have token funds to complete the
    requested deposit.

    Used when a *user* tries to deposit a given amount of token in a channel,
    but his account doesn't have enough funds to pay for the deposit.
    """
    pass


class InvalidAddress(RaidenError):
    """ Raised when the user provided value is not a valid address. """
    pass


class InvalidAmount(RaidenError):
    """ Raised when the user provided value is not an integer and cannot be
    used to defined a transfer value.
    """
    pass


class InvalidSettleTimeout(RaidenError):
    """ Raised when the user provided timeout value is less than the minimum
    settle timeout"""
    pass


class NoPathError(RaidenError):
    """ Raised when there is no path to the requested target address in the
    payment network.

    This exception is raised if there is not a single path in the network to
    reach the target, it's not used if there is a path but the transfre failed
    because of the lack of capacity or network problems.
    """
    pass


class SamePeerAddress(RaidenError):
    """ Raised when a user tries to create a channel where the address of both
    peers is the same.
    """


# TODO: Use more descriptive exceptions than this
class InvalidState(RaidenError):
    """ Raised when the user requested action cannot be done due to the current
    state of the channel.
    """
    pass


class TransferWhenClosed(RaidenError):
    """ Raised when a user tries to request a transfer in a closed channel. """
    pass


class UnknownAddress(RaidenError):
    """ Raised when the user provided address is valid but is not from a known
    node. """
    pass


# Exceptions raised due to protocol errors (this includes messages received
# from a byzantine node)


class InsufficientBalance(RaidenError):
    """ Raised when the netting channel doesn't have enough available capacity
    to pay for the transfer.

    Used for the validation of *incoming* messages.
    """
    pass


class InvalidLocksRoot(RaidenError):
    """ Raised when the received message has an invalid locksroot.

    Used to reject a message when a pending lock is missing from the locksroot,
    otherwise if the message is accepted there is a potential loss of token.
    """
    def __init__(self, expected_locksroot, got_locksroot):
        msg = 'Locksroot mismatch. Expected {} but got {}'.format(
            pex(expected_locksroot),
            pex(got_locksroot),
        )

        super().__init__(msg)


class InvalidNonce(RaidenError):
    """ Raised when the received messages has an invalid value for the nonce.

    The nonce field must change incrementally.
    """
    pass


class TransferUnwanted(RaidenError):
    """ Raised when the node is not receiving new transfers. """
    pass


class UnknownTokenAddress(RaidenError):
    """ Raised when the token address in unknown. """
    pass


class STUNUnavailableException(RaidenError):
    pass


class RaidenShuttingDown(RaidenError):
    """ Raised when Raiden is in the process of shutting down to help with a
    clean shutdown and not have exceptions thrown in all greenlets when there
    is a connection timeout with the rpc client before shutting down."""
    pass


class EthNodeCommunicationError(RaidenError):
    """ Raised when something unexpected has happened during
    communication with the underlying ethereum node"""
    def __init__(self, error_msg, error_code=None):
        super().__init__(error_msg)
        self.error_code = error_code


class AddressWithoutCode(RaidenError):
    """Raised on attempt to execute contract on address without a code."""
    pass


class NoTokenManager(RaidenError):
    """Manager for a given token does not exist."""


class DuplicatedChannelError(RaidenError):
    """Raised if someone tries to create a channel that already exists."""


class TransactionThrew(RaidenError):
    """Raised when, after waiting for a transaction to be mined,
    the receipt has a 0x0 status field"""
    def __init__(self, txname, receipt):
        super().__init__(
            '{} transaction threw. Receipt={}'.format(txname, receipt)
        )


class InvalidProtocolMessage(RaidenError):
    """Raised on an invalid or an unknown Raiden protocol message"""
