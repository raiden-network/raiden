from raiden.exceptions import RaidenRecoverableError, RaidenUnrecoverableError


class UnknownRaidenEventType(RaidenUnrecoverableError):
    """Raised if decoding an event from a Raiden smart contract failed.

    Deserializing an event from one of the Raiden smart contracts fails may
    happen for a few reasons:

    - The address is not a Raiden smart contract.
    - The address is for a newer version of the Raiden's smart contracts with
      an unknown event.

    Either case, it means the node will not be properly synchronized with the
    on-chain state, and this cannot be recovered from.
    """


class UnknownExternalEventType(RaidenRecoverableError):
    """Raised if decoding an event from a third-party smart contract failed.

    This cannot be an unrecoverable error, because third party contracts are
    not controlled. If this was an unrecoverable it would open a surface for
    attacks.
    """
