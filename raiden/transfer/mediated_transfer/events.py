# -*- coding: utf-8 -*-
from raiden.transfer.architecture import Event
# pylint: disable=too-many-arguments,too-few-public-methods


class SendMediatedTransfer(Event):
    """ A mediated transfer that must be sent to `node_address`. """
    def __init__(self,
                 identifier,
                 token,
                 amount,
                 hashlock,
                 target,
                 expiration,
                 node_address):

        self.identifier = identifier
        self.token = token
        self.amount = amount
        self.hashlock = hashlock
        self.target = target
        self.expiration = expiration
        self.node_address = node_address


class SendRevealSecret(Event):
    """ Event used to send a reveal the secret to another node, not the same as
    a balance-proof.

    Used by payees: The target and mediator nodes.

    Note:
        The payee must only update it's local balance once the payer sends an
        update message with a balance-proof, this is a requirement for keeping
        the nodes synchronized. The reveal secret message flows from the
        receiver to the sender, so when the secret is learned it is not yet
        time to update the balance.
    """
    def __init__(self, identifier, secret, target, sender):
        self.identifier = identifier
        self.secret = secret
        self.target = target
        self.sender = sender


class SendBalanceProof(Event):
    """ Event used to release a lock locally and send a balance-proof to the
    counter-party, allowing the counter-party to withdraw the lock.

    Used by payers: The initiator and mediator nodes.

    Note:
        This is event has a dual role, it serves as a synchronization and as
        balance-proof for the netting channel smart contract.
    """
    def __init__(self, identifier, target):
        self.identifier = identifier
        self.target = target


class SendSecretRequest(Event):
    """ Event used by a target node to request the secret from the initiator. """
    def __init__(self, identifier, amount, hashlock):
        self.identifier = identifier
        self.amount = amount
        self.hashlock = hashlock


class SendRefundTransfer(Event):
    """ Event used to cleanly backtrack the current node in the route.

    This message will pay back the same amount of token from the receiver to
    the sender, allowing the sender to try a different route without the risk
    of losing token.
    """
    def __init__(self,
                 identifier,
                 token,
                 amount,
                 hashlock,
                 expiration,
                 node_address):

        self.identifier = identifier
        self.token = token
        self.amount = amount
        self.hashlock = hashlock
        self.expiration = expiration
        self.node_address = node_address


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


class ContractSendWithdraw(Event):
    """ Event emitted when the lock must withdrawn on-chain. """

    def __init__(self, transfer, channel_address):
        self.transfer = transfer
        self.channel_address = channel_address
