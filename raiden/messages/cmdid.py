import enum


@enum.unique
class CmdId(enum.Enum):
    """Identifier for off-chain messages.

    These magic numbers are used to identify the type of a message.
    """

    PROCESSED = 0
    PING = 1
    PONG = 2
    SECRETREQUEST = 3
    UNLOCK = 4
    LOCKEDTRANSFER = 7
    REFUNDTRANSFER = 8
    REVEALSECRET = 11
    DELIVERED = 12
    LOCKEXPIRED = 13
    WITHDRAW_REQUEST = 15
    WITHDRAW_CONFIRMATION = 16
    WITHDRAW_EXPIRED = 17
