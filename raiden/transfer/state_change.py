# -*- coding: utf-8 -*-
from raiden.transfer.architecture import StateChange
# pylint: disable=too-few-public-methods,too-many-arguments


class Blocknumber(StateChange):
    """ Transition used when a new block is mined.

    Args:
        block_number: The current block_number.
    """
    def __init__(self, block_number):
        self.block_number = block_number


class Timeout(StateChange):
    """ Transition used to indicate that a timeout happened.

    Args:
        transfer_id: The transfer that timed-out.
    """
    def __init__(self, transfer_id):
        self.transfer_id = transfer_id


class CancelMediatedTransfer(StateChange):
    """ Cannot proceed and finish the transfer, cancel it.

    Args:
        transfer_id: The transfer identifer.
    """

    def __init__(self, transfer_id):
        self.transfer_id = transfer_id


class GetRoutes(StateChange):
    """ A request for the available routes.

    Args:
        transfer_id: Identifier used to match the result.
        target: The transfer target.
        token: The token address for the transfer.
    """
    def __init__(self, transfer_id, target, token):
        self.transfer_id = transfer_id
        self.target = target
        self.token = token


class Route(StateChange):
    """ Route state for the same asset as `transfer_id`. """
    def __init__(self,
                 transfer_id,
                 state,
                 next_hop,
                 capacity,
                 settle_timeout,
                 reveal_timeout):

        self.transfer_id = transfer_id
        self.state = state
        self.next_hop = next_hop
        self.capacity = capacity
        self.settle_timeout = settle_timeout
        self.reveal_timeout = reveal_timeout


class MediatedTransferMessageSend(StateChange):
    """ A mediated transfer that must be sent to `next_hop`. """
    def __init__(self,
                 transfer_id,
                 message_id,
                 token,
                 amount,
                 expiration,
                 network_timeout,
                 hashlock,
                 target,
                 next_hop):

        self.transfer_id = transfer_id
        self.message_id = message_id
        self.token = token
        self.amount = amount
        self.expiration = expiration
        self.network_timeout = network_timeout
        self.hashlock = hashlock
        self.target = target
        self.next_hop = next_hop


class RefundTransfer(StateChange):
    def __init__(self, transfer_id, hashlock, amount, sender):
        self.transfer_id = transfer_id
        self.amount = amount
        self.hashlock = hashlock
        self.sender = sender


class RevealSecret(StateChange):
    def __init__(self, transfer_id, secret, target, sender):
        self.transfer_id = transfer_id
        self.secret = secret
        self.target = target
        self.sender = sender


class RegisterSecret(StateChange):
    def __init__(self, transfer_id, secret):
        self.transfer_id = transfer_id
        self.secret = secret


class Secret(StateChange):
    def __init__(self, transfer_id, secret, hashlock):
        self.transfer_id = transfer_id
        self.secret = secret
        self.hashlock = hashlock


class UnlockLock(StateChange):
    def __init__(self, transfer_id, token, secret, hashlock):
        self.transfer_id = transfer_id
        self.token = token
        self.secret = secret
        self.hashlock = hashlock


class CancelMediatedTransferMessage(StateChange):
    """ Cancel a message, used to inform the previous node to ignore this
    route.

    Args:
        transfer_id: The transfer identifer.
        message_id: The message identifier.
    """

    def __init__(self, transfer_id, message_id):
        self.transfer_id = transfer_id

        # the message_id of the canceled message. Note this is not the same
        # value as the transfer_id, transfer_id contains the agreed transfer
        # identifier between the sender/receiver, message_id is this node
        # identifier for a message, that means a single transfer_id could have
        # multiple messages sent each with a unique identifier.
        self.message_id = message_id
