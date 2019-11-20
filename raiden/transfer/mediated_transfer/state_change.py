# pylint: disable=too-few-public-methods,too-many-arguments,too-many-instance-attributes
from dataclasses import dataclass, field

from raiden.constants import EMPTY_SECRETHASH
from raiden.transfer.architecture import AuthenticatedSenderStateChange, StateChange
from raiden.transfer.mediated_transfer.events import SendSecretReveal
from raiden.transfer.mediated_transfer.state import (
    LockedTransferSignedState,
    TransferDescriptionWithSecretState,
)
from raiden.transfer.state import HopState, RouteState
from raiden.transfer.state_change import BalanceProofStateChange
from raiden.utils.secrethash import sha256_secrethash
from raiden.utils.typing import (
    BlockExpiration,
    List,
    MessageID,
    Optional,
    PaymentAmount,
    PaymentID,
    Secret,
    SecretHash,
    typecheck,
)


# Note: The init states must contain all the required data for trying doing
# useful work, ie. there must /not/ be an event for requesting new data.
@dataclass(frozen=True)
class ActionInitInitiator(StateChange):
    """ Initial state of a new mediated transfer. """

    transfer: TransferDescriptionWithSecretState
    routes: List[RouteState]

    def __post_init__(self) -> None:
        typecheck(self.transfer, TransferDescriptionWithSecretState)


@dataclass(frozen=True)
class ActionInitMediator(BalanceProofStateChange):
    """ Initial state for a new mediator.

    Args:
        from_hop: The payee route.
        route_states: list of forward route states.
        from_transfer: The payee transfer.
    """

    from_hop: HopState
    route_states: List[RouteState]
    from_transfer: LockedTransferSignedState

    def __post_init__(self) -> None:
        super().__post_init__()
        typecheck(self.from_hop, HopState)
        typecheck(self.from_transfer, LockedTransferSignedState)


@dataclass(frozen=True)
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
        typecheck(self.from_hop, HopState)
        typecheck(self.transfer, LockedTransferSignedState)


@dataclass(frozen=True)
class ActionTransferReroute(BalanceProofStateChange):
    """ A transfer will be rerouted

    Args:
        transfer: the transfer being re-routed
        secret: the new secret
        secrethash: the new secrethash
    """

    transfer: LockedTransferSignedState
    secret: Secret = field(repr=False)
    secrethash: SecretHash = field(default=EMPTY_SECRETHASH)

    def __post_init__(self) -> None:
        super().__post_init__()
        typecheck(self.transfer, LockedTransferSignedState)

        object.__setattr__(self, "secrethash", sha256_secrethash(self.secret))


@dataclass(frozen=True)
class ReceiveTransferCancelRoute(BalanceProofStateChange):
    """ A mediator sends us a refund due to a failed route """

    transfer: LockedTransferSignedState


@dataclass(frozen=True)
class ReceiveLockExpired(BalanceProofStateChange):
    """ A LockExpired message received. """

    secrethash: SecretHash
    message_identifier: MessageID


@dataclass(frozen=True)
class ReceiveSecretRequest(AuthenticatedSenderStateChange):
    """ A SecretRequest message received. """

    payment_identifier: PaymentID
    amount: PaymentAmount
    expiration: BlockExpiration = field(repr=False)
    secrethash: SecretHash
    revealsecret: Optional[SendSecretReveal] = field(default=None)


@dataclass(frozen=True)
class ReceiveSecretReveal(AuthenticatedSenderStateChange):
    """ A SecretReveal message received. """

    secret: Secret = field(repr=False)
    secrethash: SecretHash = field(default=EMPTY_SECRETHASH)

    def __post_init__(self) -> None:
        object.__setattr__(self, "secrethash", sha256_secrethash(self.secret))


@dataclass(frozen=True)
class ReceiveTransferRefund(BalanceProofStateChange):
    """ A RefundTransfer message received. """

    transfer: LockedTransferSignedState

    def __post_init__(self) -> None:
        super().__post_init__()

        typecheck(self.transfer, LockedTransferSignedState)
