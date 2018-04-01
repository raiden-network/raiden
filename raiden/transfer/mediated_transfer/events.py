# -*- coding: utf-8 -*-
# pylint: disable=too-many-arguments,too-few-public-methods
from raiden.transfer.architecture import Event
from raiden.transfer.mediated_transfer.state import LockedTransferUnsignedState
from raiden.utils import pex, sha3


def refund_from_sendmediated(send_mediatedtransfer_event):
    transfer = send_mediatedtransfer_event.transfer
    return SendRefundTransfer2(
        transfer.identifier,
        transfer.token,
        transfer.balance_proof,
        transfer.lock,
        transfer.initiator,
        transfer.target,
        send_mediatedtransfer_event.recipient,
    )


class SendMediatedTransfer2(Event):
    """ A locked transfer that must be sent to `recipient`. """

    def __init__(self, transfer, recipient):
        if not isinstance(transfer, LockedTransferUnsignedState):
            raise ValueError('transfer must be a LockedTransferUnsignedState instance')

        self.transfer = transfer
        self.recipient = recipient

    def __repr__(self):
        return '<SendMediatedTransfer2 transfer:{} recipient:{}>'.format(
            self.transfer,
            pex(self.recipient),
        )

    def __eq__(self, other):
        return (
            isinstance(other, SendMediatedTransfer2) and
            self.transfer == other.transfer and
            self.recipient == other.recipient
        )

    def __ne__(self, other):
        return not self.__eq__(other)


class SendRevealSecret2(Event):
    """ Sends a RevealSecret to another node.
    This event is used once the secret is known locally and an action must be
    performed on the receiver:
        - For receivers in the payee role, it informs the node that the lock has
            been released and the token can be withdrawn, either on-chain or
            off-chain.
        - For receivers in the payer role, it tells the payer that the payee
            knows the secret and wants to withdraw the lock off-chain, so the payer
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
        nodes synchronized. The reveal secret message flows from the receiver
        to the sender, so when the secret is learned it is not yet time to
        update the balance.
    """
    def __init__(self, identifier, secret, token, receiver):
        hashlock = sha3(secret)

        self.identifier = identifier
        self.secret = secret
        self.hashlock = hashlock
        self.token = token
        self.receiver = receiver

    def __repr__(self):
        return '<SendRevealSecret2 id:{} hashlock:{} token:{} receiver:{}>'.format(
            self.identifier,
            pex(self.hashlock),
            pex(self.token),
            pex(self.receiver),
        )

    def __eq__(self, other):
        return (
            isinstance(other, SendRevealSecret2) and
            self.identifier == other.identifier and
            self.secret == other.secret and
            self.hashlock == other.hashlock and
            self.token == other.token and
            self.receiver == other.receiver
        )

    def __ne__(self, other):
        return not self.__eq__(other)


class SendBalanceProof2(Event):
    """ Event to send a balance-proof to the counter-party, used after a lock
    is unlocked locally allowing the counter-party to withdraw.
    Used by payers: The initiator and mediator nodes.
    Note:
        This event has a dual role, it serves as a synchronization and as
        balance-proof for the netting channel smart contract.
        Nodes need to keep the last known merkle root synchronized. This is
        required by the receiving end of a transfer in order to properly
        validate. The rule is "only the party that owns the current payment
        channel may change it" (remember that a netting channel is composed of
        two uni-directional channels), as a consequence the merkle root is only
        updated by the receiver once a balance proof message is received.
    """
    def __init__(self, identifier, token, receiver, secret, balance_proof):
        self.identifier = identifier
        self.token = token
        self.receiver = receiver
        self.secret = secret
        self.balance_proof = balance_proof

    def __repr__(self):
        return '<SendBalanceProof2 id: {} token: {} receiver: {} balance_proof: {}>'.format(
            self.identifier,
            pex(self.token),
            pex(self.receiver),
            self.balance_proof,
        )

    def __eq__(self, other):
        return (
            isinstance(other, SendBalanceProof2) and
            self.identifier == other.identifier and
            self.token == other.token and
            self.receiver == other.receiver and
            self.secret == other.secret and
            self.balance_proof == other.balance_proof
        )

    def __ne__(self, other):
        return not self.__eq__(other)


class SendSecretRequest(Event):
    """ Event used by a target node to request the secret from the initiator
    (`receiver`).
    """
    def __init__(self, identifier, amount, hashlock, receiver):
        self.identifier = identifier
        self.amount = amount
        self.hashlock = hashlock
        self.receiver = receiver

    def __repr__(self):
        return '<SendSecretRequest id:{} amount:{} hashlock:{} receiver:{}>'.format(
            self.identifier,
            self.amount,
            pex(self.hashlock),
            pex(self.receiver),
        )

    def __eq__(self, other):
        return (
            isinstance(other, SendSecretRequest) and
            self.identifier == other.identifier and
            self.amount == other.amount and
            self.hashlock == other.hashlock and
            self.receiver == other.receiver
        )

    def __ne__(self, other):
        return not self.__eq__(other)


class SendRefundTransfer2(Event):
    """ Event used to cleanly backtrack the current node in the route.
    This message will pay back the same amount of token from the receiver to
    the sender, allowing the sender to try a different route without the risk
    of losing token.
    """
    def __init__(
            self,
            identifier,
            token,
            balance_proof,
            lock,
            initiator,
            target,
            recipient):

        self.identifier = identifier
        self.token = token
        self.balance_proof = balance_proof
        self.lock = lock
        self.initiator = initiator
        self.target = target
        self.recipient = recipient

    def __repr__(self):
        return (
            '<'
            'SendRefundTransfer2 id:{} token:{} balance_proof:{} lock:{} '
            'initiator:{} target:{} recipient:{}'
            '>'
        ).format(
            self.identifier,
            pex(self.token),
            self.balance_proof,
            self.lock,
            pex(self.initiator),
            pex(self.target),
            pex(self.recipient),
        )

    def __eq__(self, other):
        return (
            isinstance(other, SendRefundTransfer2) and
            self.identifier == other.identifier and
            self.token == other.token and
            self.balance_proof == other.balance_proof and
            self.lock == other.lock and
            self.initiator == other.initiator and
            self.target == other.target and
            self.recipient == other.recipient
        )

    def __ne__(self, other):
        return not self.__eq__(other)


class EventUnlockSuccess(Event):
    """ Event emitted when a lock unlock succeded. """
    def __init__(self, identifier, hashlock):
        self.identifier = identifier
        self.hashlock = hashlock

    def __repr__(self):
        return '<EventUnlockSuccess id:{} hashlock:{}>'.format(
            self.identifier,
            pex(self.hashlock),
        )

    def __eq__(self, other):
        return (
            isinstance(other, EventUnlockSuccess) and
            self.identifier == other.identifier and
            self.hashlock == other.hashlock
        )

    def __ne__(self, other):
        return not self.__eq__(other)


class EventUnlockFailed(Event):
    """ Event emitted when a lock unlock failed. """
    def __init__(self, identifier, hashlock, reason):
        self.identifier = identifier
        self.hashlock = hashlock
        self.reason = reason

    def __repr__(self):
        return '<EventUnlockFailed id:{} hashlock:{} reason:{}>'.format(
            self.identifier,
            pex(self.hashlock),
            self.reason,
        )

    def __eq__(self, other):
        return (
            isinstance(other, EventUnlockFailed) and
            self.identifier == other.identifier and
            self.hashlock == other.hashlock
        )

    def __ne__(self, other):
        return not self.__eq__(other)


class EventWithdrawSuccess(Event):
    """ Event emitted when a lock withdraw succeded. """
    def __init__(self, identifier, hashlock):
        self.identifier = identifier
        self.hashlock = hashlock

    def __repr__(self):
        return '<EventWithdrawSuccess id:{} hashlock:{}>'.format(
            self.identifier,
            pex(self.hashlock),
        )

    def __eq__(self, other):
        return (
            isinstance(other, EventWithdrawSuccess) and
            self.identifier == other.identifier and
            self.hashlock == other.hashlock
        )

    def __ne__(self, other):
        return not self.__eq__(other)


class EventWithdrawFailed(Event):
    """ Event emitted when a lock withdraw failed. """
    def __init__(self, identifier, hashlock, reason):
        self.identifier = identifier
        self.hashlock = hashlock
        self.reason = reason

    def __repr__(self):
        return '<EventWithdrawFailed id:{} hashlock:{} reason:{}>'.format(
            self.identifier,
            pex(self.hashlock),
            self.reason,
        )

    def __eq__(self, other):
        return (
            isinstance(other, EventWithdrawFailed) and
            self.identifier == other.identifier and
            self.hashlock == other.hashlock
        )

    def __ne__(self, other):
        return not self.__eq__(other)
