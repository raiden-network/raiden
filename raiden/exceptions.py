from typing import Any, Dict, Optional


class RaidenError(Exception):
    """Raiden base exception.

    This exception exists for user code to catch all Raiden related exceptions.

    This should be used with care, because `RaidenUnrecoverableError` is a
    `RaidenError`, and when one of such exceptions is raised the state of the
    client node is undetermined.
    """


class RaidenRecoverableError(RaidenError):
    """Exception for recoverable errors.

    This base exception exists for code written in a EAFP style. It should be
    inherited when exceptions are expected to happen and handling them will not
    leave the node is a undefined state.

    Usage examples:

    - Operations that failed because of race conditions, e.g. openning a
      channel fails because both participants try at the same time.
    - Transient connectivety problems.
    - Timeouts.

    Note:

    Some errors are undesirable, but they are still possible and should be
    expected. Example a secret registration that finishes after the timeout
    window.
    """


class RaidenUnrecoverableError(RaidenError):
    """Base exception for unexpected errors that should crash the client.

    This exception is used when something unrecoverable happened:

    - Corrupted database.
    - Running out of disk space.
    """


class ChannelNotFound(RaidenError):
    """ Raised when a provided channel via the REST api is not found in the
    internal data structures"""


class PaymentConflict(RaidenRecoverableError):
    """ Raised when there is another payment with the same identifier but the
    attributes of the payment don't match.
    """


class InsufficientFunds(RaidenError):
    """ Raised when provided account doesn't have token funds to complete the
    requested deposit.

    Used when a *user* tries to deposit a given amount of token in a channel,
    but his account doesn't have enough funds to pay for the deposit.
    """


class DepositOverLimit(RaidenError):
    """ Raised when the requested deposit is over the limit

    Used when a *user* tries to deposit a given amount of token in a channel,
    but the amount is over the testing limit.
    """


class DepositMismatch(RaidenRecoverableError):
    """ Raised when the requested deposit is lower than actual channel deposit

    Used when a *user* tries to deposit a given amount of tokens in a channel,
    but the on-chain amount is already higher.
    """


class InvalidChannelID(RaidenError):
    """ Raised when the user provided value is not a channel id. """


class WithdrawMismatch(RaidenRecoverableError):
    """ Raised when the requested withdraw is larger than actual channel balance. """


class InvalidAddress(RaidenError):
    """ Raised when the user provided value is not a valid address. """


class InvalidSecret(RaidenError):
    """ Raised when the user provided value is not a valid secret. """


class InvalidSecretHash(RaidenError):
    """ Raised when the user provided value is not a valid secrethash. """


class InvalidAmount(RaidenError):
    """ Raised when the user provided value is not a positive integer and
    cannot be used to define a transfer value.
    """


class InvalidSettleTimeout(RaidenError):
    """ Raised when the user provided timeout value is less than the minimum
    settle timeout"""


class InvalidSignature(RaidenError):
    """Raised on invalid signature recover/verify"""


class SamePeerAddress(RaidenError):
    """ Raised when a user tries to create a channel where the address of both
    peers is the same.
    """


class UnknownAddress(RaidenError):
    """ Raised when the user provided address is valid but is not from a known
    node. """


class UnknownTokenAddress(RaidenError):
    """ Raised when the token address in unknown. """


class TokenNotRegistered(RaidenError):
    """ Raised if there is no token network for token used when opening a channel  """


class AlreadyRegisteredTokenAddress(RaidenError):
    """ Raised when the token address in already registered with the given network. """


class InvalidToken(RaidenError):
    """ Raised if the token does not follow the ERC20 standard """


class STUNUnavailableException(RaidenError):
    pass


class EthNodeCommunicationError(RaidenError):
    """ Raised when something unexpected has happened during
    communication with the underlying ethereum node"""

    def __init__(self, error_msg: str) -> None:
        super().__init__(error_msg)


class EthNodeInterfaceError(RaidenError):
    """ Raised when the underlying ETH node does not support an rpc interface"""


class AddressWithoutCode(RaidenError):
    """Raised on attempt to execute contract on address without a code."""


class AddressWrongContract(RaidenError):
    """Raised on attempt to execute contract on address that has code but
    is probably not the contract we wanted."""


class DuplicatedChannelError(RaidenRecoverableError):
    """Raised if someone tries to create a channel that already exists."""


class ContractCodeMismatch(RaidenError):
    """Raised if the onchain code of the contract differs."""


class TransactionThrew(RaidenError):
    """Raised when, after waiting for a transaction to be mined,
    the receipt has a 0x0 status field"""

    def __init__(self, txname: str, receipt: Optional[Dict[str, Any]]) -> None:
        super().__init__(f"{txname} transaction threw. Receipt={receipt}")


class APIServerPortInUseError(RaidenError):
    """Raised when API server port is already in use"""


class RaidenServicePortInUseError(RaidenError):
    """Raised when Raiden service port is already in use"""


class InvalidDBData(RaidenUnrecoverableError):
    """Raised when the data of the WAL are in an unexpected format"""


class InvalidBlockNumberInput(RaidenError):
    """Raised when the user provided a block number that is  < 0 or > UINT64_MAX"""


class NoStateForBlockIdentifier(RaidenError):
    """
    Raised when we attempt to provide a block identifier older
    than STATE_PRUNING_AFTER_BLOCKS blocks
    """


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
    is not sufficient for the lifecycles of all active channels.
    """


class BrokenPreconditionError(RaidenError):
    """ Raised while checking transaction preconditions
    which should be satisfied before sending the transaction.
    This exception when:
    1. An assert or a revert in the smart contract would be hit for
    triggering block.

    2. If provided values are invalid (i.e ValueError)
    """


class ServiceRequestFailed(RaidenError):
    """ Raised when a request to one of the raiden services fails. """


class ServiceRequestIOURejected(ServiceRequestFailed):
    """ Raised when a service request fails due to a problem with the iou. """

    def __init__(self, message: str, error_code: int) -> None:
        super().__init__(f"{message} ({error_code})")
        self.error_code = error_code


class UndefinedMediationFee(RaidenError):
    """The fee schedule is not applicable resulting in undefined fees

    Either the raiden node is not capable of mediating this payment, or the
    FeeSchedule is outdated/inconsistent."""


class TokenNetworkDeprecated(RaidenError):
    """ Raised when the token network proxy safety switch
    is turned on (i.e deprecated).
    """


class MintFailed(RaidenError):
    """ Raised when an attempt to mint a testnet token failed. """


class SerializationError(RaidenError):
    """ Invalid data are to be (de-)serialized. """
