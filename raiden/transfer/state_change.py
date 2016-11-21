# -*- coding: utf-8 -*-
from raiden.transfer.architecture import StateChange
# pylint: disable=too-few-public-methods,too-many-arguments,too-many-instance-attributes


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


class CancelTimeout(StateChange):
    """ Transition used to indicate that a timeout can be canceled.

    Args:
        transfer_id: The transfer that timed-out.
        node_address: Partner address.
    """
    def __init__(self, transfer_id, node_address):
        self.transfer_id = transfer_id
        self.node_address = node_address


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


class InitInitiator(StateChange):
    """ Initial state of a new mediated transfer.

    Args:
        our_address: This node address.
        target: The mediated transfer target.
        transfer: A state object containing the transfer details.
        block_number: The current block number.
        config (dict): This node configuration.
    """
    def __init__(self, our_address, transfer, block_number, config):
        self.our_address = our_address
        self.transfer = transfer
        self.block_number = block_number
        self.config = config


class InitMediator(StateChange):
    """ Initial state for a new mediator.

    Args:
        our_address: This node address.
        originating_route: The route from which the MediatedTransfer was received.
        originating_transfer: The received MediatedTransfer.
        block_number: The current block number.
        config (dict): This node configuration.
    """
    def __init__(self,
                 our_address,
                 originating_route,
                 originating_transfer,
                 block_number,
                 config):

        self.our_address = our_address
        self.originating_route = originating_route
        self.originating_transfer = originating_transfer
        self.block_number = block_number
        self.config = config


class InitTarget(StateChange):
    """ The target received a mediated transfer.

    Args:
        target: The mediated transfer target.
        originating_route: The route from which the MediatedTransfer was received.
        originating_transfer: The received MediatedTransfer.
        block_number: The current block number.
        config (dict): This node configuration.
    """
    def __init__(self,
                 our_address,
                 originating_route,
                 originating_transfer,
                 hashlock,
                 block_number):

        self.our_address = our_address
        self.originating_route = originating_route
        self.originating_transfer = originating_transfer
        self.hashlock = hashlock
        self.block_number = block_number


class Route(StateChange):
    """ Route state for the same asset as `transfer_id`. """
    def __init__(self,
                 transfer_id,
                 state,
                 node_address,
                 capacity,
                 settle_timeout,
                 reveal_timeout):

        self.transfer_id = transfer_id
        self.state = state
        self.node_address = node_address
        self.capacity = capacity
        self.settle_timeout = settle_timeout
        self.reveal_timeout = reveal_timeout


class MediatedTransferMessageSend(StateChange):
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


class RefundTransfer(StateChange):
    def __init__(self, transfer_id, hashlock, amount, sender):
        self.transfer_id = transfer_id
        self.amount = amount
        self.hashlock = hashlock
        self.sender = sender


class RevealSecret(StateChange):
    """ A RevealSecret message received.

    Note:
        The node that is sending this message must use the UnlockLock state
        change, RevealSecret is used for transitions on the receiving end.
    """
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


class NewSecret(StateChange):
    """ Request a new secret. """
    def __init__(self, transfer_id):
        self.transfer_id = transfer_id


class SecretRequestReceived(StateChange):
    """ A SecretRequest message received. """
    def __init__(self, transfer_id, amount, hashlock, identifier, sender):
        self.transfer_id = transfer_id
        self.amount = amount
        self.hashlock = hashlock
        self.identifier = identifier
        self.sender = sender


class SecretRequestMessageSend(StateChange):
    def __init__(self, transfer_id, amount, hashlock):
        self.transfer_id = transfer_id
        self.amount = amount
        self.hashlock = hashlock


class UnlockLock(StateChange):
    """ Unlock the asset locked by hashlock and send the Secret message to
    update the partner node.
    """
    def __init__(self, transfer_id, node_address, token, secret, hashlock):
        self.transfer_id = transfer_id
        self.node_address = node_address
        self.token = token
        self.secret = secret
        self.hashlock = hashlock


class WithdrawLock(StateChange):
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
