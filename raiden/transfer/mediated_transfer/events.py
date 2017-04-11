# -*- coding: utf-8 -*-
from raiden.transfer.architecture import Event
# pylint: disable=too-many-arguments,too-few-public-methods


def mediatedtransfer(transfer, receiver):
    """ Create SendMediatedTransfer from LockedTransferState. """
    return SendMediatedTransfer(
        transfer.identifier,
        transfer.token,
        transfer.amount,
        transfer.hashlock,
        transfer.initiator,
        transfer.target,
        transfer.expiration,
        receiver,
    )


class SendMediatedTransfer(Event):
    """ A mediated transfer that must be sent to `node_address`. """
    def __init__(
            self,
            identifier,
            token,
            amount,
            hashlock,
            initiator,
            target,
            expiration,
            receiver):

        self.identifier = identifier
        self.token = token
        self.amount = amount
        self.hashlock = hashlock
        self.initiator = initiator
        self.target = target
        self.expiration = expiration
        self.receiver = receiver


class SendRevealSecret(Event):
    """ Event used to send a reveal the secret to another node, not the same as
    a balance-proof.

    Used by payees: The target and mediator nodes.

    Note:
        The payee must only update it's local balance once the payer sends an
        update message with a balance-proof. This is a requirement for keeping
        the nodes synchronized. The reveal secret message flows from the
        receiver to the sender, so when the secret is learned it is not yet
        time to update the balance.
    """
    def __init__(self, identifier, secret, token, receiver, sender):
        self.identifier = identifier
        self.secret = secret
        self.token = token
        self.receiver = receiver
        self.sender = sender


class SendBalanceProof(Event):
    """ Event used to release a lock locally and send a balance-proof to the
    counter-party, allowing the counter-party to withdraw the lock.

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
    def __init__(self, identifier, channel_address, token, receiver, secret):
        self.identifier = identifier
        self.channel_address = channel_address
        self.token = token
        self.receiver = receiver

        # XXX: Secret is not required for the balance proof to dispatch the message
        self.secret = secret


class SendSecretRequest(Event):
    """ Event used by a target node to request the secret from the initiator
    (`receiver`).
    """
    def __init__(self, identifier, amount, hashlock, receiver):
        self.identifier = identifier
        self.amount = amount
        self.hashlock = hashlock
        self.receiver = receiver


class SendRefundTransfer(Event):
    """ Event used to cleanly backtrack the current node in the route.

    This message will pay back the same amount of token from the receiver to
    the sender, allowing the sender to try a different route without the risk
    of losing token.
    """
    def __init__(
            self,
            identifier,
            token,
            amount,
            hashlock,
            expiration,
            receiver):

        self.identifier = identifier
        self.token = token
        self.amount = amount
        self.hashlock = hashlock
        self.expiration = expiration
        self.receiver = receiver


class EventTransferFailed(Event):
    """ Event emitted by the initiator when a transfer cannot be completed.

    Note:
        Mediator and target nodes cannot emit this event since they cannot
        cancel the transfer, these nodes may only reject the transfer before
        intereacting or wait for the lock expiration.
    """

    def __init__(self, identifier, reason):
        self.identifier = identifier
        self.reason = reason


class EventTransferCompleted(Event):
    """ Event emitted when the transfer is complete for the given node.  """

    def __init__(self, identifier, secret, hashlock):
        self.identifier = identifier
        self.secret = secret
        self.hashlock = hashlock


class ContractSendChannelClose(Event):
    """ Event emitted to close the netting channel.

    This event is used when a node needs to prepare the channel to withdraw
    on-chain.
    """

    def __init__(self, channel_address):
        self.channel_address = channel_address


class ContractSendWithdraw(Event):
    """ Event emitted when the lock must be withdrawn on-chain. """

    def __init__(self, transfer, channel_address):
        if transfer.secret is None:
            raise ValueError('Transfer must have the secret set.')

        self.transfer = transfer
        self.channel_address = channel_address
