# -*- coding: utf-8 -*-
from raiden.transfer.architecture import State
# pylint: disable=too-few-public-methods,too-many-arguments,too-many-instance-attributes


class TransferState(State):
    """ Transfer state.

    Args:
        amount (int): Amount of `token' being transferred.
        token (address): Token being transferred.
        identifier (int): Transfer identifier agreed among the parties.
        target (address): The address of the the transfer target.
    """
    def __init__(self, amount, token, identifier, target):
        self.amount = amount
        self.token = token
        self.identifier = identifier
        self.target = target


class RoutesState(State):
    """ Routing state.

    Args:
        available_routes (list): A list of Route.
    """
    def __init__(self, available_routes):
        self.available_routes = available_routes
        self.ignored_routes = list()
        self.refunded_routes = list()
        self.canceled_routes = list()


class InitiatorState(State):
    """ State of a node initiating a mediated transfer.

    Args:
        our_address (address): This node address.
        transfer (TransferState): The description of the mediated transfer.
        block_number (int): Latest known block number.
        config (dict): This node configuration.
    """
    def __init__(self, our_address, transfer, block_number):
        self.our_address = our_address
        self.transfer = transfer
        self.block_number = block_number

        self.secret = None  #: the secret used to lock the current transfer
        self.hashlock = None  #: the corresponding hashlock for the current secret

        self.message = None  #: current message in-transit
        self.route = None  #: current route being used
        self.secretrequest = None
        self.revealsecret = None

        self.routes = None


class MediatorState(State):
    """ State of a node mediating a transfer.  """
    def __init__(self,
                 our_address,
                 transfer,
                 target,
                 originating_route,
                 originating_transfer,
                 block_number):

        self.our_address = our_address
        self.transfer = transfer
        self.target = target
        self.originating_route = originating_route
        self.originating_transfer = originating_transfer
        self.block_number = block_number

        self.secret = None
        self.hashlock = None  #: the corresponding hashlock for the current secret

        self.message = None  #: current message in-transit
        self.route = None  #: current route being used
        self.sent_refund = None  #: set with the refund transfer if it was sent

        self.routes = None
        self.sent_transfers_refunded = list()


class TargetState(State):
    """ State of mediated transfer target.  """
    def __init__(self,
                 our_address,
                 originating_route,
                 originating_transfer,
                 hashlock,
                 block_number,
                 network_timeout):

        self.our_address = our_address
        self.originating_route = originating_route
        self.originating_transfer = originating_transfer
        self.hashlock = hashlock
        self.block_number = block_number
        self.network_timeout = network_timeout

        self.secret = None

        self.message = None  #: current message in-transit
        self.route = None  #: current route being used
        self.sent_refund = None  #: set with the refund transfer if it was sent

        self.routes = None
        self.sent_transfers_refunded = list()
