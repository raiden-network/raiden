# pylint: disable=too-few-public-methods,too-many-arguments,too-many-instance-attributes
from dataclasses import dataclass, field
from hashlib import sha256

from raiden.constants import EMPTY_SECRETHASH
from raiden.transfer.architecture import AuthenticatedSenderStateChange, StateChange
from raiden.transfer.mediated_transfer.events import SendSecretReveal
from raiden.transfer.mediated_transfer.state import (
    LockedTransferSignedState,
    TransferDescriptionWithSecretState,
)
from raiden.transfer.state import HopState, RouteState
from raiden.transfer.state_change import BalanceProofStateChange
from raiden.utils.typing import (
    BlockExpiration,
    List,
    MessageID,
    Optional,
    PaymentAmount,
    PaymentID,
    Secret,
    SecretHash,
)


# Note: The init states must contain all the required data for trying doing
# useful work, ie. there must /not/ be an event for requesting new data.
@dataclass
class ActionInitInitiator(StateChange):
    """ Initial state of a new mediated transfer. """

    transfer: TransferDescriptionWithSecretState
    routes: List[RouteState]

    def __post_init__(self) -> None:
        if not isinstance(self.transfer, TransferDescriptionWithSecretState):
            raise ValueError("transfer must be an TransferDescriptionWithSecretState instance.")


@dataclass
class ActionInitMediator(BalanceProofStateChange):
    """ Initial state for a new mediator.

    Args:
        from_hop: The payee route.
        route_state: The forward route state.
        from_transfer: The payee transfer.
    """

    from_hop: HopState
    route_state: RouteState = field(repr=False)
    from_transfer: LockedTransferSignedState

    def __post_init__(self) -> None:
        super().__post_init__()
        if not isinstance(self.from_hop, HopState):
            raise ValueError("from_route must be a HopState instance")

        if not isinstance(self.from_transfer, LockedTransferSignedState):
            raise ValueError("from_transfer must be a LockedTransferSignedState instance")


@dataclass
class ActionInitTarget(BalanceProofStateChange):
    """ Initial state for a new target.

    Args:
        from_hop: The payee route.
        transfer: The payee transfer.
    """

    from_hop: HopState
    transfer: LockedTransferSignedState

    def __post_init__(self) -> None:
        super().__post_init__()

        if not isinstance(self.from_hop, HopState):
            raise ValueError("route must be a RouteState instance")

        if not isinstance(self.transfer, LockedTransferSignedState):
            raise ValueError("transfer must be a LockedTransferSignedState instance")


@dataclass
class ReceiveLockExpired(BalanceProofStateChange):
    """ A LockExpired message received. """

    secrethash: SecretHash
    message_identifier: MessageID


@dataclass
class ReceiveSecretRequest(AuthenticatedSenderStateChange):
    """ A SecretRequest message received. """

    payment_identifier: PaymentID
    amount: PaymentAmount
    expiration: BlockExpiration = field(repr=False)
    secrethash: SecretHash
    revealsecret: Optional[SendSecretReveal] = field(default=None)


@dataclass
class ReceiveSecretReveal(AuthenticatedSenderStateChange):
    """ A SecretReveal message received. """

    secret: Secret = field(repr=False)
    secrethash: SecretHash = field(default=EMPTY_SECRETHASH)

    def __post_init__(self) -> None:
        self.secrethash = SecretHash(sha256(self.secret).digest())


@dataclass
class ReceiveTransferRefundCancelRoute(BalanceProofStateChange):
    """ A RefundTransfer message received by the initiator will cancel the current
    route.
    """

    routes: List[RouteState] = field(repr=False)
    transfer: LockedTransferSignedState
    secret: Secret = field(repr=False)
    secrethash: SecretHash = field(default=EMPTY_SECRETHASH)

    def __post_init__(self) -> None:
        super().__post_init__()
        if not isinstance(self.transfer, LockedTransferSignedState):
            raise ValueError("transfer must be an instance of LockedTransferSignedState")

        self.secrethash = SecretHash(sha256(self.secret).digest())


@dataclass
class ReceiveTransferRefund(BalanceProofStateChange):
    """ A RefundTransfer message received. """

    transfer: LockedTransferSignedState
    routes: List[RouteState] = field(repr=False)

    def __post_init__(self) -> None:
        super().__post_init__()
        if not isinstance(self.transfer, LockedTransferSignedState):
            raise ValueError("transfer must be an instance of LockedTransferSignedState")
