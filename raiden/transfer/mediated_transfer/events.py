# pylint: disable=too-many-arguments,too-few-public-methods
from dataclasses import dataclass, field

from raiden.transfer.architecture import Event, SendMessageEvent
from raiden.transfer.mediated_transfer.state import LockedTransferUnsignedState
from raiden.transfer.state import BalanceProofUnsignedState
from raiden.utils import sha3
from raiden.utils.typing import (
    Address,
    BlockExpiration,
    ChannelID,
    MessageID,
    PaymentID,
    PaymentWithFeeAmount,
    Secret,
    SecretHash,
    TokenAddress,
)

# According to the smart contracts as of 07/08:
# https://github.com/raiden-network/raiden-contracts/blob/fff8646ebcf2c812f40891c2825e12ed03cc7628/raiden_contracts/contracts/TokenNetwork.sol#L213
# channel_identifier can never be 0. We make this a requirement in the client and use this fact
# to signify that a channel_identifier of `0` passed to the messages adds them to the
# global queue
CHANNEL_IDENTIFIER_GLOBAL_QUEUE = ChannelID(0)


def refund_from_sendmediated(
    send_lockedtransfer_event: "SendLockedTransfer",
) -> "SendRefundTransfer":
    return SendRefundTransfer(
        recipient=send_lockedtransfer_event.recipient,
        channel_identifier=send_lockedtransfer_event.queue_identifier.channel_identifier,
        message_identifier=send_lockedtransfer_event.message_identifier,
        transfer=send_lockedtransfer_event.transfer,
    )


@dataclass(init=False)
class SendLockExpired(SendMessageEvent):
    balance_proof: BalanceProofUnsignedState
    secrethash: SecretHash

    def __init__(
        self,
        recipient: Address,
        message_identifier: MessageID,
        balance_proof: BalanceProofUnsignedState,
        secrethash: SecretHash,
    ) -> None:
        super().__init__(recipient, balance_proof.channel_identifier, message_identifier)

        self.balance_proof = balance_proof
        self.secrethash = secrethash


@dataclass(init=False)
class SendLockedTransfer(SendMessageEvent):
    """ A locked transfer that must be sent to `recipient`. """

    transfer: LockedTransferUnsignedState

    def __init__(
        self,
        recipient: Address,
        channel_identifier: ChannelID,
        message_identifier: MessageID,
        transfer: LockedTransferUnsignedState,
    ) -> None:
        if not isinstance(transfer, LockedTransferUnsignedState):
            raise ValueError("transfer must be a LockedTransferUnsignedState instance")

        super().__init__(recipient, channel_identifier, message_identifier)

        self.transfer = transfer

    @property
    def balance_proof(self) -> BalanceProofUnsignedState:
        return self.transfer.balance_proof


@dataclass(init=False)
class SendSecretReveal(SendMessageEvent):
    """ Sends a SecretReveal to another node.

    This event is used once the secret is known locally and an action must be
    performed on the recipient:

        - For receivers in the payee role, it informs the node that the lock has
            been released and the token can be claimed, either on-chain or
            off-chain.
        - For receivers in the payer role, it tells the payer that the payee
            knows the secret and wants to claim the lock off-chain, so the payer
            may unlock the lock and send an up-to-date balance proof to the payee,
            avoiding on-chain payments which would require the channel to be
            closed.

    For any mediated transfer:
        - The initiator will only perform the payer role.
        - The target will only perform the payee role.
        - The mediators will have `n` channels at the payee role and `n` at the
          payer role, where `n` is equal to `1 + number_of_refunds`.

    Note:
        The payee must only update its local balance once the payer sends an
        up-to-date balance-proof message. This is a requirement for keeping the
        nodes synchronized. The reveal secret message flows from the recipient
        to the sender, so when the secret is learned it is not yet time to
        update the balance.
    """

    secret: Secret = field(repr=False)
    secrethash: SecretHash

    def __init__(
        self,
        recipient: Address,
        channel_identifier: ChannelID,
        message_identifier: MessageID,
        secret: Secret,
    ) -> None:
        secrethash = sha3(secret)

        super().__init__(recipient, channel_identifier, message_identifier)

        self.secret = secret
        self.secrethash = secrethash


@dataclass(init=False)
class SendBalanceProof(SendMessageEvent):
    """ Event to send a balance-proof to the counter-party, used after a lock
    is unlocked locally allowing the counter-party to claim it.

    Used by payers: The initiator and mediator nodes.

    Note:
        This event has a dual role, it serves as a synchronization and as
        balance-proof for the netting channel smart contract.

        Nodes need to keep the last known merkle root synchronized. This is
        required by the receiving end of a transfer in order to properly
        validate. The rule is "only the party that owns the current payment
        channel may change it" (remember that a netting channel is composed of
        two uni-directional channels), as a consequence the merkle root is only
        updated by the recipient once a balance proof message is received.
    """

    payment_identifier: PaymentID
    token_address: TokenAddress
    secret: Secret = field(repr=False)
    balance_proof: BalanceProofUnsignedState = field(repr=False)

    def __init__(
        self,
        recipient: Address,
        channel_identifier: ChannelID,
        message_identifier: MessageID,
        payment_identifier: PaymentID,
        token_address: TokenAddress,
        secret: Secret,
        balance_proof: BalanceProofUnsignedState,
    ) -> None:
        super().__init__(recipient, channel_identifier, message_identifier)

        self.payment_identifier = payment_identifier
        self.token = token_address
        self.secret = secret
        self.secrethash = sha3(secret)
        self.balance_proof = balance_proof


@dataclass(init=False)
class SendSecretRequest(SendMessageEvent):
    """ Event used by a target node to request the secret from the initiator
    (`recipient`).
    """

    payment_identifier: PaymentID
    amount: PaymentWithFeeAmount
    expiration: BlockExpiration
    secrethash: SecretHash

    def __init__(
        self,
        recipient: Address,
        channel_identifier: ChannelID,
        message_identifier: MessageID,
        payment_identifier: PaymentID,
        amount: PaymentWithFeeAmount,
        expiration: BlockExpiration,
        secrethash: SecretHash,
    ) -> None:

        super().__init__(recipient, channel_identifier, message_identifier)

        self.payment_identifier = payment_identifier
        self.amount = amount
        self.expiration = expiration
        self.secrethash = secrethash


@dataclass(init=False)
class SendRefundTransfer(SendMessageEvent):
    """ Event used to cleanly backtrack the current node in the route.
    This message will pay back the same amount of token from the recipient to
    the sender, allowing the sender to try a different route without the risk
    of losing token.
    """

    transfer: LockedTransferUnsignedState

    def __init__(
        self,
        recipient: Address,
        channel_identifier: ChannelID,
        message_identifier: MessageID,
        transfer: LockedTransferUnsignedState,
    ) -> None:

        super().__init__(recipient, channel_identifier, message_identifier)

        self.transfer = transfer

    @property
    def balance_proof(self) -> BalanceProofUnsignedState:
        return self.transfer.balance_proof


@dataclass
class EventUnlockSuccess(Event):
    """ Event emitted when a lock unlock succeded. """

    identifier: PaymentID
    secrethash: SecretHash


@dataclass
class EventUnlockFailed(Event):
    """ Event emitted when a lock unlock failed. """

    identifier: PaymentID
    secrethash: SecretHash
    reason: str


@dataclass
class EventUnlockClaimSuccess(Event):
    """ Event emitted when a lock claim succeded. """

    identifier: PaymentID
    secrethash: SecretHash


@dataclass
class EventUnlockClaimFailed(Event):
    """ Event emitted when a lock claim failed. """

    identifier: PaymentID
    secrethash: SecretHash
    reason: str


@dataclass
class EventUnexpectedSecretReveal(Event):
    """ Event emitted when an unexpected secret reveal message is received. """

    secrethash: SecretHash
    reason: str
