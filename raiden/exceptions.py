

class RaidenError(Exception):
    """ Base exception, used to catch all raiden related exceptions. """
    pass


class RaidenRecoverableError(RaidenError):
    pass


class RaidenUnrecoverableError(RaidenError):
    pass


# Exceptions raised due to programming errors

class HashLengthNot32(RaidenError):
    """ Raised if the length of the provided element is not 32 bytes in length,
    a keccak hash is required to include the element in the merkle tree.
    """
    pass


class UnknownEventType(RaidenError):
    """Raised if decoding of an event failed."""
    pass


# Exceptions raised due to user interaction (the user may be another software)

class ChannelNotFound(RaidenError):
    """ Raised when a provided channel via the REST api is not found in the
    internal data structures"""
    pass


class PaymentConflict(RaidenRecoverableError):
    """ Raised when there is another payment with the same identifier but the
    attributes of the payment don't match.
    """
    pass


class InsufficientFunds(RaidenError):
    """ Raised when provided account doesn't have token funds to complete the
    requested deposit.

    Used when a *user* tries to deposit a given amount of token in a channel,
    but his account doesn't have enough funds to pay for the deposit.
    """
    pass


class DepositOverLimit(RaidenError):
    """ Raised when the requested deposit is over the limit

    Used when a *user* tries to deposit a given amount of token in a channel,
    but the amount is over the testing limit.
    """
    pass


class DepositMismatch(RaidenRecoverableError):
    """ Raised when the requested deposit is lower than actual channel deposit

    Used when a *user* tries to deposit a given amount of token in a channel,
    but the on-chain amount is already higher.
    """
    pass


class InvalidAddress(RaidenError):
    """ Raised when the user provided value is not a valid address. """
    pass


class InvalidSecretOrSecretHash(RaidenError):
    """ Raised when the user provided value is not a valid secret. """
    pass


class InvalidAmount(RaidenError):
    """ Raised when the user provided value is not a positive integer and
    cannot be used to define a transfer value.
    """
    pass


class InvalidSettleTimeout(RaidenError):
    """ Raised when the user provided timeout value is less than the minimum
    settle timeout"""
    pass


class InvalidSignature(RaidenError):
    """Raised on invalid signature recover/verify"""
    pass


class SamePeerAddress(RaidenError):
    """ Raised when a user tries to create a channel where the address of both
    peers is the same.
    """


class UnknownAddress(RaidenError):
    """ Raised when the user provided address is valid but is not from a known
    node. """
    pass


class UnknownTokenAddress(RaidenError):
    """ Raised when the token address in unknown. """
    pass


class TokenNotRegistered(RaidenError):
    """ Raised if there is no token network for token used when opening a channel  """
    pass


class AlreadyRegisteredTokenAddress(RaidenError):
    """ Raised when the token address in already registered with the given network. """
    pass


# Exceptions raised due to protocol errors (this includes messages received
# from a byzantine node)


class STUNUnavailableException(RaidenError):
    pass


class EthNodeCommunicationError(RaidenError):
    """ Raised when something unexpected has happened during
    communication with the underlying ethereum node"""

    def __init__(self, error_msg, error_code=None):
        super().__init__(error_msg)
        self.error_code = error_code


class EthNodeInterfaceError(RaidenError):
    """ Raised when the underlying ETH node does not support an rpc interface"""
    pass


class AddressWithoutCode(RaidenError):
    """Raised on attempt to execute contract on address without a code."""
    pass


class AddressWrongContract(RaidenError):
    """Raised on attempt to execute contract on address that has code but
    is probably not the contract we wanted."""
    pass


class DuplicatedChannelError(RaidenRecoverableError):
    """Raised if someone tries to create a channel that already exists."""


class ContractVersionMismatch(RaidenError):
    """Raised if deployed version of the contract differs."""


class TransactionThrew(RaidenError):
    """Raised when, after waiting for a transaction to be mined,
    the receipt has a 0x0 status field"""

    def __init__(self, txname, receipt):
        super().__init__(
            '{} transaction threw. Receipt={}'.format(txname, receipt),
        )


class InvalidProtocolMessage(RaidenError):
    """Raised on an invalid or an unknown Raiden protocol message"""


class APIServerPortInUseError(RaidenError):
    """Raised when API server port is already in use"""


class RaidenServicePortInUseError(RaidenError):
    """Raised when Raiden service port is already in use"""


class InvalidDBData(RaidenUnrecoverableError):
    """Raised when the data of the WAL are in an unexpected format"""


class InvalidBlockNumberInput(RaidenError):
    """Raised when the user provided a block number that is  < 0 or > UINT64_MAX"""


class InvalidNumberInput(RaidenError):
    """Raised when the user provided an invalid number"""


class TransportError(RaidenError):
    """ Raised when a transport encounters an unexpected error """


class ReplacementTransactionUnderpriced(RaidenError):
    """Raised when a replacement transaction is rejected by the blockchain"""


class TransactionAlreadyPending(RaidenUnrecoverableError):
    """Raised when a transaction is already pending"""


class ChannelOutdatedError(RaidenError):
    """ Raised when an action is invoked on a channel whose
    identifier has been replaced with a new channel identifier
    due to a close/re-open of current channel.
    """


class InsufficientGasReserve(RaidenError):
    """ Raised when an action cannot be done because the available balance
    is not sufficient for the lifecycles of all active channels. """
