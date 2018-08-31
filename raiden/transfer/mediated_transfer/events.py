# pylint: disable=too-many-arguments,too-few-public-methods
from raiden.transfer.architecture import (
    Event,
    SendMessageEvent,
)
from raiden.transfer.mediated_transfer.state import LockedTransferUnsignedState
from raiden.transfer.state import BalanceProofUnsignedState, HashTimeLockState
from raiden.utils import pex, sha3
from raiden.utils import typing


# According to the smart contracts as of 07/08:
# https://github.com/raiden-network/raiden-contracts/blob/fff8646ebcf2c812f40891c2825e12ed03cc7628/raiden_contracts/contracts/TokenNetwork.sol#L213
# channel_identifier can never be 0. We make this a requirement in the client and use this fact
# to signify that a channel_identifier of `0` passed to the messages adds them to the
# global queue
CHANNEL_IDENTIFIER_GLOBAL_QUEUE = 0


def refund_from_sendmediated(send_lockedtransfer_event):
    transfer = send_lockedtransfer_event.transfer
    return SendRefundTransfer(
        recipient=send_lockedtransfer_event.recipient,
        channel_identifier=send_lockedtransfer_event.queue_identifier[1],
        message_identifier=send_lockedtransfer_event.message_identifier,
        payment_identifier=transfer.payment_identifier,
        token_address=transfer.token,
        balance_proof=transfer.balance_proof,
        lock=transfer.lock,
        initiator=transfer.initiator,
        target=transfer.target,
    )


class SendLockedTransfer(SendMessageEvent):
    """ A locked transfer that must be sent to `recipient`. """

    def __init__(
            self,
            recipient: typing.Address,
            channel_identifier: typing.ChannelID,
            message_identifier: typing.MessageID,
            transfer: LockedTransferUnsignedState,
    ):
        if not isinstance(transfer, LockedTransferUnsignedState):
            raise ValueError('transfer must be a LockedTransferUnsignedState instance')

        super().__init__(recipient, channel_identifier, message_identifier)

        self.transfer = transfer

    def __repr__(self):
        return '<SendLockedTransfer msgid:{} transfer:{} recipient:{}>'.format(
            self.message_identifier,
            self.transfer,
            pex(self.recipient),
        )

    def __eq__(self, other):
        return (
            isinstance(other, SendLockedTransfer) and
            self.transfer == other.transfer and
            super().__eq__(other)
        )

    def __ne__(self, other):
        return not self.__eq__(other)


class SendRevealSecret(SendMessageEvent):
    """ Sends a RevealSecret to another node.

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

    def __init__(
            self,
            recipient: typing.Address,
            channel_identifier: typing.ChannelID,
            message_identifier: typing.MessageID,
            secret: typing.Secret,
    ):
        secrethash = sha3(secret)

        super().__init__(recipient, channel_identifier, message_identifier)

        self.secret = secret
        self.secrethash = secrethash

    def __repr__(self):
        return '<SendRevealSecret msgid:{} secrethash:{} recipient:{}>'.format(
            self.message_identifier,
            pex(self.secrethash),
            pex(self.recipient),
        )

    def __eq__(self, other):
        return (
            isinstance(other, SendRevealSecret) and
            self.secret == other.secret and
            self.secrethash == other.secrethash and
            super().__eq__(other)
        )

    def __ne__(self, other):
        return not self.__eq__(other)


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

    def __init__(
            self,
            recipient: typing.Address,
            channel_identifier: typing.ChannelID,
            message_identifier: typing.MessageID,
            payment_identifier: typing.PaymentID,
            token_address: typing.TokenAddress,
            secret: typing.Secret,
            balance_proof: BalanceProofUnsignedState,
    ):
        super().__init__(recipient, channel_identifier, message_identifier)

        self.payment_identifier = payment_identifier
        self.token = token_address
        self.secret = secret
        self.balance_proof = balance_proof

    def __repr__(self):
        return (
            '<SendBalanceProof msgid:{} paymentid:{} token:{} recipient:{} balance_proof:{}>'
        ).format(
            self.message_identifier,
            self.payment_identifier,
            pex(self.token),
            pex(self.recipient),
            self.balance_proof,
        )

    def __eq__(self, other):
        return (
            isinstance(other, SendBalanceProof) and
            self.payment_identifier == other.payment_identifier and
            self.token == other.token and
            self.recipient == other.recipient and
            self.secret == other.secret and
            self.balance_proof == other.balance_proof and
            super().__eq__(other)
        )

    def __ne__(self, other):
        return not self.__eq__(other)


class SendSecretRequest(SendMessageEvent):
    """ Event used by a target node to request the secret from the initiator
    (`recipient`).
    """

    def __init__(
            self,
            recipient: typing.Address,
            channel_identifier: typing.ChannelID,
            message_identifier: typing.MessageID,
            payment_identifier: typing.PaymentID,
            amount: typing.TokenAmount,
            expiration: typing.BlockExpiration,
            secrethash: typing.SecretHash,
    ):

        super().__init__(recipient, channel_identifier, message_identifier)

        self.payment_identifier = payment_identifier
        self.amount = amount
        self.expiration = expiration
        self.secrethash = secrethash

    def __repr__(self):
        return (
            '<SendSecretRequest '
            'msgid:{} paymentid:{} amount:{} expiration:{} secrethash:{} recipient:{}'
            '>'
        ).format(
            self.message_identifier,
            self.payment_identifier,
            self.amount,
            self.expiration,
            pex(self.secrethash),
            pex(self.recipient),
        )

    def __eq__(self, other):
        return (
            isinstance(other, SendSecretRequest) and
            self.payment_identifier == other.payment_identifier and
            self.amount == other.amount and
            self.expiration == other.expiration and
            self.secrethash == other.secrethash and
            self.recipient == other.recipient and
            super().__eq__(other)
        )

    def __ne__(self, other):
        return not self.__eq__(other)


class SendRefundTransfer(SendMessageEvent):
    """ Event used to cleanly backtrack the current node in the route.
    This message will pay back the same amount of token from the recipient to
    the sender, allowing the sender to try a different route without the risk
    of losing token.
    """

    def __init__(
            self,
            recipient: typing.Address,
            channel_identifier: typing.ChannelID,
            message_identifier: typing.MessageID,
            payment_identifier: typing.PaymentID,
            token_address: typing.TokenAddress,
            balance_proof: BalanceProofUnsignedState,
            lock: HashTimeLockState,
            initiator: typing.InitiatorAddress,
            target: typing.TargetAddress,
    ):

        super().__init__(recipient, channel_identifier, message_identifier)

        self.payment_identifier = payment_identifier
        self.token = token_address
        self.balance_proof = balance_proof
        self.lock = lock
        self.initiator = initiator
        self.target = target

    def __repr__(self):
        return (
            '<'
            'SendRefundTransfer msgid:{} paymentid:{} token:{} '
            'balance_proof:{} lock:{} initiator:{} target:{} recipient:{}'
            '>'
        ).format(
            self.message_identifier,
            self.payment_identifier,
            pex(self.token),
            self.balance_proof,
            self.lock,
            pex(self.initiator),
            pex(self.target),
            pex(self.recipient),
        )

    def __eq__(self, other):
        return (
            isinstance(other, SendRefundTransfer) and
            self.payment_identifier == other.payment_identifier and
            self.token == other.token and
            self.balance_proof == other.balance_proof and
            self.lock == other.lock and
            self.initiator == other.initiator and
            self.target == other.target and
            self.recipient == other.recipient and
            super().__eq__(other)
        )

    def __ne__(self, other):
        return not self.__eq__(other)


class EventUnlockSuccess(Event):
    """ Event emitted when a lock unlock succeded. """

    def __init__(self, identifier, secrethash):
        self.identifier = identifier
        self.secrethash = secrethash

    def __repr__(self):
        return '<EventUnlockSuccess id:{} secrethash:{}>'.format(
            self.identifier,
            pex(self.secrethash),
        )

    def __eq__(self, other):
        return (
            isinstance(other, EventUnlockSuccess) and
            self.identifier == other.identifier and
            self.secrethash == other.secrethash
        )

    def __ne__(self, other):
        return not self.__eq__(other)


class EventUnlockFailed(Event):
    """ Event emitted when a lock unlock failed. """

    def __init__(self, identifier, secrethash, reason):
        self.identifier = identifier
        self.secrethash = secrethash
        self.reason = reason

    def __repr__(self):
        return '<EventUnlockFailed id:{} secrethash:{} reason:{}>'.format(
            self.identifier,
            pex(self.secrethash),
            self.reason,
        )

    def __eq__(self, other):
        return (
            isinstance(other, EventUnlockFailed) and
            self.identifier == other.identifier and
            self.secrethash == other.secrethash
        )

    def __ne__(self, other):
        return not self.__eq__(other)


class EventUnlockClaimSuccess(Event):
    """ Event emitted when a lock claim succeded. """

    def __init__(self, identifier, secrethash):
        self.identifier = identifier
        self.secrethash = secrethash

    def __repr__(self):
        return '<EventUnlockClaimSuccess id:{} secrethash:{}>'.format(
            self.identifier,
            pex(self.secrethash),
        )

    def __eq__(self, other):
        return (
            isinstance(other, EventUnlockClaimSuccess) and
            self.identifier == other.identifier and
            self.secrethash == other.secrethash
        )

    def __ne__(self, other):
        return not self.__eq__(other)


class EventUnlockClaimFailed(Event):
    """ Event emitted when a lock claim failed. """

    def __init__(self, identifier, secrethash, reason):
        self.identifier = identifier
        self.secrethash = secrethash
        self.reason = reason

    def __repr__(self):
        return '<EventUnlockClaimFailed id:{} secrethash:{} reason:{}>'.format(
            self.identifier,
            pex(self.secrethash),
            self.reason,
        )

    def __eq__(self, other):
        return (
            isinstance(other, EventUnlockClaimFailed) and
            self.identifier == other.identifier and
            self.secrethash == other.secrethash
        )

    def __ne__(self, other):
        return not self.__eq__(other)
