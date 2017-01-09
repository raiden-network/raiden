# -*- coding: utf-8 -*-
from raiden.transfer.architecture import StateChange
from raiden.transfer.state import RouteState
# pylint: disable=too-few-public-methods,too-many-arguments,too-many-instance-attributes


class Blocknumber(StateChange):
    """ Transition used when a new block is mined.

    Args:
        block_number: The current block_number.
    """
    def __init__(self, block_number):
        self.block_number = block_number


class RouteChange(StateChange):
    def __init__(self, transfer_id, route):
        if not isinstance(route, RouteState):
            raise ValueError('route must be a RouteState')

        self.transfer_id = transfer_id
        self.route = route
