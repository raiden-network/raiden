# pylint: disable=too-few-public-methods,too-many-arguments,too-many-instance-attributes

from raiden.storage.serialization import dataclass, field
from raiden.transfer.architecture import (
    AuthenticatedSenderStateChange,
    BalanceProofStateChange,
    StateChange,
)
from raiden.transfer.mediated_transfer.state import (
    LockedTransferSignedState,
    TransferDescriptionWithSecretState,
)
from raiden.transfer.state import BalanceProofSignedState, RouteState
from raiden.utils import sha3
from raiden.utils.typing import (
    Address,
    BlockExpiration,
    List,
    MessageID,
    PaymentAmount,
    PaymentID,
    Secret,
    SecretHash,
)

# Note: The init states must contain all the required data for trying doing
# useful work, ie. there must /not/ be an event for requesting new data.


@dataclass
class ActionInitInitiator(StateChange):
    """ Initial state of a new mediated transfer.

    Args:
        transfer_description: A state object containing the transfer details.
        routes: A list of possible routes provided by a routing service.
    """
    transfer_description: TransferDescriptionWithSecretState
    routes: List[RouteState]

    def __post_init__(self) -> None:
        if not isinstance(self.transfer_description, TransferDescriptionWithSecretState):
            raise ValueError('transfer must be an TransferDescriptionWithSecretState instance.')


@dataclass(init=False)
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

    def __init__(
        self,
        routes: List[RouteState],
        from_route: RouteState,
        from_transfer: LockedTransferSignedState,
    ) -> None:

        if not isinstance(from_route, RouteState):
            raise ValueError("from_route must be a RouteState instance")

        if not isinstance(from_transfer, LockedTransferSignedState):
            raise ValueError("from_transfer must be a LockedTransferSignedState instance")

        super().__init__(from_transfer.balance_proof)
        self.routes = routes
        self.from_route = from_route
        self.from_transfer = from_transfer


@dataclass(init=False)
class ActionInitTarget(BalanceProofStateChange):
    """ Initial state for a new target.

    Args:
        route: The payee route.
        transfer: The payee transfer.
    """
    route: RouteState
    transfer: LockedTransferSignedState

    def __init__(self, route: RouteState, transfer: LockedTransferSignedState) -> None:
        if not isinstance(route, RouteState):
            raise ValueError("route must be a RouteState instance")

        if not isinstance(transfer, LockedTransferSignedState):
            raise ValueError("transfer must be a LockedTransferSignedState instance")

        super().__init__(transfer.balance_proof)
        self.route = route
        self.transfer = transfer


@dataclass(init=False)
class ReceiveLockExpired(BalanceProofStateChange):
    """ A LockExpired message received. """
    secrethash: SecretHash
    message_identifier: MessageID

    def __init__(
        self,
        balance_proof: BalanceProofSignedState,
        secrethash: SecretHash,
        message_identifier: MessageID,
    ) -> None:
        super().__init__(balance_proof)
        self.secrethash = secrethash
        self.message_identifier = message_identifier


@dataclass(init=False)
class ReceiveSecretRequest(AuthenticatedSenderStateChange):
    """ A SecretRequest message received. """
    payment_identifier: PaymentID
    amount: PaymentAmount
    expiration: BlockExpiration = field(repr=False)
    secrethash: SecretHash

    def __init__(
        self,
        payment_identifier: PaymentID,
        amount: PaymentAmount,
        expiration: BlockExpiration,
        secrethash: SecretHash,
        sender: Address,
    ) -> None:
        super().__init__(sender)
        self.payment_identifier = payment_identifier
        self.amount = amount
        self.expiration = expiration
        self.secrethash = secrethash
        self.revealsecret = None


@dataclass(init=False)
class ReceiveSecretReveal(AuthenticatedSenderStateChange):
    """ A SecretReveal message received. """
    secret: Secret = field(repr=False)
    secrethash: SecretHash = field(init=False)

    def __init__(self, secret: Secret, sender: Address) -> None:
        super().__init__(sender)
        secrethash = sha3(secret)

        self.secret = secret
        self.secrethash = secrethash


@dataclass(init=False)
class ReceiveTransferRefundCancelRoute(BalanceProofStateChange):
    """ A RefundTransfer message received by the initiator will cancel the current
    route.
    """
    routes: List[RouteState] = field(repr=False)
    transfer: LockedTransferSignedState
    secret: Secret = field(repr=False)
    secrethash: SecretHash = field(init=False, repr=False)

    def __init__(
        self, routes: List[RouteState], transfer: LockedTransferSignedState, secret: Secret
    ) -> None:
        if not isinstance(transfer, LockedTransferSignedState):
            raise ValueError("transfer must be an instance of LockedTransferSignedState")

        super().__init__(transfer.balance_proof)

        self.transfer = transfer
        self.routes = routes
        self.secrethash = sha3(secret)
        self.secret = secret


@dataclass(init=False)
class ReceiveTransferRefund(BalanceProofStateChange):
    """ A RefundTransfer message received. """
    transfer: LockedTransferSignedState
    routes: List[RouteState] = field(repr=False)

    def __init__(self, transfer: LockedTransferSignedState, routes: List[RouteState]) -> None:
        if not isinstance(transfer, LockedTransferSignedState):
            raise ValueError("transfer must be an instance of LockedTransferSignedState")

        super().__init__(transfer.balance_proof)
        self.transfer = transfer
        self.routes = routes
