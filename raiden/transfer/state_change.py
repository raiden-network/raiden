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
    """ A route change.

    State change used for:
        - when a new route is added.
        - when the counter party is unresponsive (fails the healtcheck) and the
          route cannot be used.
        - when a different transfer uses the channel, changing the available
          balance.
    """

    def __init__(self, transfer_id, route):
        if not isinstance(route, RouteState):
            raise ValueError('route must be a RouteState')

        self.transfer_id = transfer_id
        self.route = route


class UserCancel(StateChange):
    """ The user request the transfer to be cancelled.

    This state change can fail, it depends on the node's role and the current
    state of the transfer.
    """

    def __init__(self, transfer_id):
        self.transfer_id = transfer_id
