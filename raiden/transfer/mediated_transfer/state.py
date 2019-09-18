# pylint: disable=too-few-public-methods,too-many-arguments,too-many-instance-attributes
from dataclasses import dataclass, field

from raiden.constants import EMPTY_SECRETHASH, LOCKSROOT_OF_NO_LOCKS
from raiden.transfer.architecture import State
from raiden.transfer.state import (
    BalanceProofSignedState,
    BalanceProofUnsignedState,
    HashTimeLockState,
    HopState,
    RouteState,
)
from raiden.utils.secrethash import sha256_secrethash
from raiden.utils.typing import (
    TYPE_CHECKING,
    Address,
    BlockTimeout,
    ChannelID,
    Dict,
    InitiatorAddress,
    List,
    MessageID,
    Optional,
    PaymentAmount,
    PaymentID,
    Secret,
    SecretHash,
    T_Address,
    TargetAddress,
    TokenAddress,
    TokenNetworkAddress,
    TokenNetworkRegistryAddress,
    typecheck,
)

if TYPE_CHECKING:
    # pylint: disable=unused-import
    from raiden.transfer.mediated_transfer.events import SendSecretReveal  # noqa


@dataclass
class LockedTransferState(State):

    payment_identifier: PaymentID
    token: TokenAddress
    lock: HashTimeLockState
    initiator: InitiatorAddress
    target: TargetAddress

    def __post_init__(self) -> None:
        if not isinstance(self.lock, HashTimeLockState):
            raise ValueError("lock must be a HashTimeLockState instance")


@dataclass
class LockedTransferUnsignedState(LockedTransferState):
    """ State for a transfer created by the local node which contains a hash
    time lock and may be sent.
    """

    balance_proof: BalanceProofUnsignedState
    route_states: List[RouteState] = field(default_factory=list)

    def __post_init__(self) -> None:
        super().__post_init__()

        typecheck(self.lock, HashTimeLockState)
        typecheck(self.balance_proof, BalanceProofUnsignedState)

        # At least the lock for this transfer must be in the locksroot, so it
        # must not be empty
        if self.balance_proof.locksroot == LOCKSROOT_OF_NO_LOCKS:
            raise ValueError("balance_proof must not be empty")


@dataclass
class LockedTransferSignedState(LockedTransferState):
    """ State for a received transfer which contains a hash time lock and a
    signed balance proof.
    """

    message_identifier: MessageID
    balance_proof: BalanceProofSignedState = field(repr=False)
    routes: List[List[Address]]

    def __post_init__(self) -> None:
        typecheck(self.lock, HashTimeLockState)
        typecheck(self.balance_proof, BalanceProofSignedState)

        # At least the lock for this transfer must be in the locksroot, so it
        # must not be empty
        # pylint: disable=E1101
        if self.balance_proof.locksroot == LOCKSROOT_OF_NO_LOCKS:
            raise ValueError("balance_proof must not be empty")

    @property
    def payer_address(self) -> Address:
        # pylint: disable=E1101
        return self.balance_proof.sender


@dataclass
class TransferDescriptionWithSecretState(State):
    """ Describes a transfer (target, amount, and token) and contains an
    additional secret that can be used with a hash-time-lock.
    """

    token_network_registry_address: TokenNetworkRegistryAddress = field(repr=False)
    payment_identifier: PaymentID = field(repr=False)
    amount: PaymentAmount
    token_network_address: TokenNetworkAddress
    initiator: InitiatorAddress = field(repr=False)
    target: TargetAddress
    secret: Secret = field(repr=False)
    secrethash: SecretHash = field(default=EMPTY_SECRETHASH)
    lock_timeout: Optional[BlockTimeout] = field(default=None)

    def __post_init__(self) -> None:
        if self.secrethash == EMPTY_SECRETHASH and self.secret:
            self.secrethash = sha256_secrethash(self.secret)


@dataclass
class WaitingTransferState(State):
    transfer: LockedTransferSignedState
    state: str = field(default="waiting")


@dataclass
class InitiatorTransferState(State):
    """ State of a transfer for the initiator node. """

    route: RouteState
    transfer_description: TransferDescriptionWithSecretState = field(repr=False)
    channel_identifier: ChannelID
    transfer: LockedTransferUnsignedState
    received_secret_request: bool = field(default=False, repr=False)
    transfer_state: str = field(default="transfer_pending")


@dataclass
class InitiatorPaymentState(State):
    """ State of a payment for the initiator node.
    A single payment may have multiple transfers. E.g. because if one of the
    transfers fails or timeouts another transfer will be started with a
    different secrethash.
    """

    routes: List[RouteState]
    initiator_transfers: Dict[SecretHash, InitiatorTransferState]
    cancelled_channels: List[ChannelID] = field(repr=False, default_factory=list)


@dataclass
class MediationPairState(State):
    """ State for a mediated transfer.
    A mediator will pay payee node knowing that there is a payer node to cover
    the token expenses. This state keeps track of transfers for
    the payer and payee, and the current state of the payment.
    """

    payer_transfer: LockedTransferSignedState
    payee_address: Address
    payee_transfer: LockedTransferUnsignedState
    payer_state: str = field(default="payer_pending")
    payee_state: str = field(default="payee_pending")
    # payee_pending:
    #   Initial state.
    #
    # payee_secret_revealed:
    #   The payee is following the raiden protocol and has sent a SecretReveal.
    #
    # payee_contract_unlock:
    #   The payee received the token on-chain. A transition to this state is
    #   valid from all but the `payee_expired` state.
    #
    # payee_balance_proof:
    #   This node has sent a SendBalanceProof to the payee with the balance
    #   updated.
    #
    # payee_expired:
    #   The lock has expired.
    valid_payee_states = (
        "payee_pending",
        "payee_secret_revealed",
        "payee_contract_unlock",
        "payee_balance_proof",
        "payee_expired",
    )

    valid_payer_states = (
        "payer_pending",
        "payer_secret_revealed",  # SendSecretReveal was sent
        "payer_waiting_unlock",  # ContractSendChannelBatchUnlock was sent
        "payer_waiting_secret_reveal",  # ContractSendSecretReveal was sent
        "payer_balance_proof",  # ReceiveUnlock was received
        "payer_expired",  # None of the above happened and the lock expired
    )

    def __post_init__(self) -> None:
        typecheck(self.payer_transfer, LockedTransferSignedState)
        typecheck(self.payee_address, T_Address)
        typecheck(self.payee_transfer, LockedTransferUnsignedState)

    @property
    def payer_address(self) -> Address:
        return self.payer_transfer.payer_address


@dataclass
class MediatorTransferState(State):
    """ State of a transfer for the mediator node.
    A mediator may manage multiple channels because of refunds, but all these
    channels will be used for the same transfer (not for different payments).
    Args:
        secrethash: The secrethash used for this transfer.
        routes: list of all routes given for this transfer
        refunded_channels: list of channel identifiers that sent refunds
    """

    secrethash: SecretHash
    routes: List[RouteState]
    refunded_channels: List[ChannelID] = field(repr=False, default_factory=list)
    secret: Optional[Secret] = field(default=None)
    transfers_pair: List[MediationPairState] = field(default_factory=list)
    waiting_transfer: Optional[WaitingTransferState] = field(default=None)


@dataclass
class TargetTransferState(State):
    """ State of a transfer for the target node. """

    EXPIRED = "expired"
    OFFCHAIN_SECRET_REVEAL = "reveal_secret"
    ONCHAIN_SECRET_REVEAL = "onchain_secret_reveal"
    ONCHAIN_UNLOCK = "onchain_unlock"
    SECRET_REQUEST = "secret_request"

    from_hop: HopState = field(repr=False)
    transfer: LockedTransferSignedState
    secret: Optional[Secret] = field(repr=False, default=None)
    state: str = field(default="secret_request")
