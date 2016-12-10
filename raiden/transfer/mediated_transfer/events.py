# -*- coding: utf-8 -*-
from raiden.transfer.architecture import Event


class MediatedTransfer(Event):
    """ A mediated transfer that must be sent to `node_address`. """
    def __init__(self,
                 transfer_id,
                 message_id,
                 token,
                 amount,
                 expiration,
                 hashlock,
                 target,
                 node_address):

        self.transfer_id = transfer_id
        self.message_id = message_id
        self.token = token
        self.amount = amount
        self.expiration = expiration
        self.hashlock = hashlock
        self.target = target
        self.node_address = node_address


class RevealSecret(Event):
    """ Event used to reveal a secret.

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
    def __init__(self, transfer_id, hashlock, amount, sender):
        self.transfer_id = transfer_id
        self.amount = amount
        self.hashlock = hashlock
        self.sender = sender


class CancelMediatedTransfer(Event):
    """ Event used to inform the nodes in the mediation chain that an
    unrecoverable error occurred and the transfer cannot proceed. The initiator
    may try a new route.
    """

    def __init__(self, transfer_id, message_id):
        self.transfer_id = transfer_id

        # the message_id of the canceled message. Note this is not the same
        # value as the transfer_id, transfer_id contains the agreed transfer
        # identifier between the sender/receiver, message_id is this node
        # identifier for a message, that means a single transfer_id could have
        # multiple messages sent each with a unique identifier.
        self.message_id = message_id
