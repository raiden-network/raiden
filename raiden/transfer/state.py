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
