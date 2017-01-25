# -*- coding: utf-8 -*-
from raiden.transfer.architecture import State
# pylint: disable=too-few-public-methods,too-many-arguments,too-many-instance-attributes


class InitiatorState(State):
    """ State of a node initiating a mediated transfer.

    Args:
        our_address (address): This node address.
        transfer (TransferState): The description of the mediated transfer.
        routes (RoutesState): An route state object with the available_routes filled.
        block_number (int): Latest known block number.
        config (dict): This node configuration.
    """
    def __init__(self, our_address, transfer, routes, random_generator, block_number):
        self.our_address = our_address
        self.transfer = transfer
        self.routes = routes
        self.random_generator = random_generator
        self.block_number = block_number

        self.message = None  #: current message in-transit
        self.route = None  #: current route being used
        self.secretrequest = None
        self.revealsecret = None
        self.canceled_transfers = list()


class MediatorState(State):
    """ State of a node mediating a transfer.  """
    def __init__(self,
                 our_address,
                 routes,
                 from_route,
                 from_transfer,
                 block_number):

        self.our_address = our_address
        self.routes = routes
        self.from_route = from_route
        self.from_transfer = from_transfer
        self.block_number = block_number

        self.message = None  #: current message in-transit
        self.route = None  #: current route being used
        self.sent_refund = None  #: set with the refund transfer if it was sent

        self.routes = None
        self.sent_transfers_refunded = list()


class TargetState(State):
    """ State of mediated transfer target.  """
    def __init__(self,
                 our_address,
                 from_route,
                 from_transfer,
                 hashlock,
                 block_number):

        self.our_address = our_address
        self.from_route = from_route
        self.from_transfer = from_transfer
        self.hashlock = hashlock
        self.block_number = block_number

        self.secret = None

        self.message = None  #: current message in-transit
        self.route = None  #: current route being used
        self.sent_refund = None  #: set with the refund transfer if it was sent

        self.routes = None
        self.sent_transfers_refunded = list()


class LockedTransferState(State):
    """ State of a transfer that is time hash locked.

    Args:
        identifier (int): A unique identifer for the transfer.
        amount (int): Amount of `token' being transferred.
        token (address): Token being transferred.
        target (address): Transfer target address.
        expiration (int): The absolute block number that the lock expires.
        hashlock (bin): The hashlock.
        secret (bin): The secret that unlocks the lock, may be None.
    """
    def __init__(self,
                 identifier,
                 amount,
                 token,
                 target,
                 expiration,
                 hashlock,
                 secret):

        self.identifier = identifier
        self.amount = amount
        self.token = token
        self.target = target
        self.expiration = expiration
        self.hashlock = hashlock
        self.secret = secret
