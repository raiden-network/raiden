# -*- coding: utf-8 -*-
from raiden.transfer.architecture import StateChange
# pylint: disable=too-few-public-methods,too-many-arguments,too-many-instance-attributes


# Note: The init states must contain all the required data for trying doing
# useful work, ie. there must /not/ be an event for requesting new data.


class InitInitiator(StateChange):
    """ Initial state of a new mediated transfer.

    Args:
        our_address (address): This node address.
        transfer (LockedTransferState): A state object containing the transfer details.
        routes (RoutesState): The current available routes.
        random_generator (generator): A generator for secrets.
        block_number (int): The current block number.
    """

    def __init__(self,
                 our_address,
                 transfer,
                 routes,
                 random_generator,
                 block_number):

        self.our_address = our_address
        self.transfer = transfer
        self.routes = routes
        self.random_generator = random_generator
        self.block_number = block_number


class InitMediator(StateChange):
    """ Initial state for a new mediator.

    Args:
        our_address (address): This node address.
        from_transfer (LockedTransferState): The received MediatedTransfer.
        routes (RoutesState): The current available routes.
        from_route (RouteState): The route from which the MediatedTransfer was received.
        block_number (int): The current block number.
    """

    def __init__(self,
                 our_address,
                 from_transfer,
                 routes,
                 from_route,
                 block_number):

        self.our_address = our_address
        self.from_transfer = from_transfer
        self.routes = routes
        self.from_route = from_route
        self.block_number = block_number


class InitTarget(StateChange):
    """ Initial state for a new target.

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


class CancelRoute(StateChange):
    """ Cancel the current route.

    Notes:
        Used to cancel a specific route but not the transfer, may be used for
        timeouts.
    """
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


class SecretRevealReceived(StateChange):
    """ A SecretReveal message received. """
    def __init__(self, transfer_id, secret, target, sender):
        self.transfer_id = transfer_id
        self.secret = secret
        self.target = target
        self.sender = sender


class TransferRefundReceived(StateChange):
    """ A RefundTransfer message received. """
    def __init__(self, transfer_id, hashlock, amount, sender):
        self.transfer_id = transfer_id
        self.amount = amount
        self.hashlock = hashlock
        self.sender = sender
