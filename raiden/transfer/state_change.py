# -*- coding: utf-8 -*-
from raiden.transfer.architecture import StateChange
from raiden.transfer.state import RouteState
# pylint: disable=too-few-public-methods,too-many-arguments,too-many-instance-attributes


class Block(StateChange):
    """ Transition used when a new block is mined.

    Args:
        block_number: The current block_number.
    """

    def __init__(self, block_number):
        self.block_number = block_number


class ActionRouteChange(StateChange):
    """ A route change.

    State change used for:
        - when a new route is added.
        - when the counter party is unresponsive (fails the healthcheck) and the
          route cannot be used.
        - when a different transfer uses the channel, changing the available
          balance.
    """

    def __init__(self, identifier, route):
        if not isinstance(route, RouteState):
            raise ValueError('route must be a RouteState')

        self.identifier = identifier
        self.route = route


class ActionCancelTransfer(StateChange):
    """ The user requests the transfer to be cancelled.

    This state change can fail, it depends on the node's role and the current
    state of the transfer.
    """

    def __init__(self, identifier):
        self.identifier = identifier
