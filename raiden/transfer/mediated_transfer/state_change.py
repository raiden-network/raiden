# pylint: disable=too-few-public-methods,too-many-arguments,too-many-instance-attributes
from dataclasses import dataclass, field

from raiden.transfer.architecture import AuthenticatedSenderStateChange, StateChange
from raiden.transfer.mediated_transfer.state import (
    LockedTransferSignedState,
    TransferDescriptionWithSecretState,
)
from raiden.transfer.state import RouteState
from raiden.transfer.state_change import BalanceProofStateChange
from raiden.utils import sha3
from raiden.utils.typing import (
    TYPE_CHECKING,
    BlockExpiration,
    List,
    MessageID,
    Optional,
    PaymentAmount,
    PaymentID,
    Secret,
    SecretHash,
)

if TYPE_CHECKING:
    # pylint: disable=unused-import
    from raiden.transfer.mediated_transfer.events import SendSecretReveal  # noqa


# Note: The init states must contain all the required data for trying doing
# useful work, ie. there must /not/ be an event for requesting new data.
@dataclass
class ActionInitInitiator(StateChange):
    """ Initial state of a new mediated transfer.

    Args:
        transfer_description: A state object containing the transfer details.
        routes: A list of possible routes provided by a routing service.
    """

    transfer: TransferDescriptionWithSecretState
    routes: List[RouteState]

    def __post_init__(self) -> None:
        if not isinstance(self.transfer, TransferDescriptionWithSecretState):
            raise ValueError("transfer must be an TransferDescriptionWithSecretState instance.")


@dataclass
class ActionInitMediator(BalanceProofStateChange):
    """ Initial state for a new mediator.

    Args:
        routes: A list of possible routes provided by a routing service.
        from_route: The payee route.
        from_transfer: The payee transfer.
    """

    routes: List[RouteState] = field(repr=False)
    from_route: RouteState
    from_transfer: LockedTransferSignedState

    def __post_init__(self) -> None:
        super().__post_init__()
        if not isinstance(self.from_route, RouteState):
            raise ValueError("from_route must be a RouteState instance")

        if not isinstance(self.from_transfer, LockedTransferSignedState):
            raise ValueError("from_transfer must be a LockedTransferSignedState instance")


@dataclass
class ActionInitTarget(BalanceProofStateChange):
    """ Initial state for a new target.

    Args:
        route: The payee route.
        transfer: The payee transfer.
    """

    route: RouteState
    transfer: LockedTransferSignedState

    def __post_init__(self) -> None:
        super().__post_init__()

        if not isinstance(self.route, RouteState):
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
    revealsecret: Optional["SendSecretReveal"] = field(default=None)


@dataclass
class ReceiveSecretReveal(AuthenticatedSenderStateChange):
    """ A SecretReveal message received. """

    secret: Secret = field(repr=False)
    secrethash: SecretHash = field(init=False)

    def __post_init__(self) -> None:
        self.secrethash = sha3(self.secret)


@dataclass
class ReceiveTransferRefundCancelRoute(BalanceProofStateChange):
    """ A RefundTransfer message received by the initiator will cancel the current
    route.
    """

    routes: List[RouteState] = field(repr=False)
    transfer: LockedTransferSignedState
    secret: Secret = field(repr=False)
    secrethash: SecretHash = field(init=False, repr=False)

    def __post_init__(self) -> None:
        super().__post_init__()
        if not isinstance(self.transfer, LockedTransferSignedState):
            raise ValueError("transfer must be an instance of LockedTransferSignedState")

        self.secrethash = sha3(self.secret)


@dataclass
class ReceiveTransferRefund(BalanceProofStateChange):
    """ A RefundTransfer message received. """

    transfer: LockedTransferSignedState
    routes: List[RouteState] = field(repr=False)

    def __post_init__(self) -> None:
        super().__post_init__()
        if not isinstance(self.transfer, LockedTransferSignedState):
            raise ValueError("transfer must be an instance of LockedTransferSignedState")
