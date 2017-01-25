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
    def __init__(self, transfer_id, secret, target, sender):
        self.transfer_id = transfer_id
        self.secret = secret
        self.target = target
        self.sender = sender


class SecretRequest(Event):
    """ Event used by a target node to request the secret from the initiator.
    """
    def __init__(self, transfer_id, amount, hashlock):
        self.transfer_id = transfer_id
        self.amount = amount
        self.hashlock = hashlock


class RefundTransfer(Event):
    """ Event used to cleanly backtrack the current node in the route.

    This message will pay back the same amount of token from the receiver to
    the sender, allowing the sender to try a different route without the risk
    of losing token.
    """
    def __init__(self, locked_transfer):
        self.locked_transfer = locked_transfer


class CancelTransfer(Event):
    """ Event used to inform the nodes in the mediation chain that an
    unrecoverable error occurred and the transfer cannot proceed. The initiator
    may try a new route.
    """

    def __init__(self, transfer_id, reason):
        self.transfer_id = transfer_id
        self.reason = reason


class UnlockLock(Event):
    """ Unlock the asset locked by hashlock and send the Secret message to
    update the partner node.
    """

    def __init__(self, transfer_id, node_address, token, secret, hashlock):
        self.transfer_id = transfer_id
        self.node_address = node_address
        self.token = token
        self.secret = secret
        self.hashlock = hashlock
