# -*- coding: utf-8 -*-
from raiden.transfer.architecture import State
# pylint: disable=too-few-public-methods,too-many-arguments,too-many-instance-attributes


class MediatedTransferState(State):
    """ State of a transfer.  """
    def __init__(self, amount, token, identifier):
        self.amount = amount
        self.token = token
        self.identifier = identifier


class RoutesState(State):
    def __init__(self, available_routes):
        self.available_routes = available_routes
        self.ignored_routes = list()
        self.refunded_routes = list()
        self.canceled_routes = list()
