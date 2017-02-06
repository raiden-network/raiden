# -*- coding: utf-8 -*-
from raiden.transfer.architecture import Event


class MediatedTransfer(Event):
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


class RevealSecretTo(Event):
    """ Event used to reveal a secret.

    Used by all roles in a mediate transfer to reveal the secret to a specific
    node.

    Note:
        The receiver must only update it's local balance once the payer sends
        an update message, this is a requirement for keeping the nodes
        synchronized. The reveal secret message flows from the receiver to the
        sender, so once the message is received it must not update the balance.
    """
    def __init__(self, identifier, secret, target, sender):
        self.identifier = identifier
        self.secret = secret
        self.target = target
        self.sender = sender


class SecretRequest(Event):
    """ Event used by a target node to request the secret from the initiator. """
    def __init__(self, identifier, amount, hashlock):
        self.identifier = identifier
        self.amount = amount
        self.hashlock = hashlock


class RefundTransfer(Event):
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


class TransferFailed(Event):
    """ Event emitted by the initiator when a transfer cannot be completed.

    Note:
        Mediator and target nodes cannot emit this event since they cannot
        cancel the transfer, these nodes may only reject the transfer before
        intereacting or wait for the lock expiration.
    """

    def __init__(self, identifier, reason):
        self.identifier = identifier
        self.reason = reason


class TransferCompleted(Event):
    """ Event emitted when the transfer is complete for the given node.  """

    def __init__(self, identifier, secret, hashlock):
        self.identifier = identifier
        self.secret = secret
        self.hashlock = hashlock


class SettleOnChain(Event):
    """ Event emitted when the settlement must go on-chain. """

    def __init__(self, transfer, channel_address):
        self.transfer = transfer
        self.channel_address = channel_address
