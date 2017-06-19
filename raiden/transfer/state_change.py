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

    def __eq__(self, other):
        if not isinstance(other, Block):
            return False

        return (
            self.block_number == other.block_number
        )

    def __ne__(self, other):
        return not self.__eq__(other)

    def __str__(self):
        return 'Block({})'.format(self.block_number)


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

    def __str__(self):
        return 'ActionRouteChange(identifier:{} route:{})'.format(
            self.identifier,
            self.route,
        )


class ActionCancelTransfer(StateChange):
    """ The user requests the transfer to be cancelled.

    This state change can fail, it depends on the node's role and the current
    state of the transfer.
    """

    def __init__(self, identifier):
        self.identifier = identifier

    def __eq__(self, other):
        if not isinstance(other, ActionCancelTransfer):
            return False

        return (
            self.identifier == other.identifier
        )

    def __ne__(self, other):
        return not self.__eq__(other)

    def __str__(self):
        return 'ActionCancelTransfer(identifier:{})'.format(
            self.identifier,
        )


class ActionTransferDirect(StateChange):
    def __init__(
            self,
            identifier,
            amount,
            token_address,
            node_address):

        self.identifier = identifier
        self.amount = amount
        self.token_address = token_address
        self.node_address = node_address

    def __eq__(self, other):
        if not isinstance(other, ActionTransferDirect):
            return False

        return (
            self.identifier == other.identifier and
            self.amount == other.amount and
            self.token_address == other.token_address and
            self.node_address == other.node_address
        )

    def __ne__(self, other):
        return not self.__eq__(other)

    def __str__(self):
        return (
            'ActionTransferDirect('
            'identifier:{} amount:{} token_address:{} node_address:{}'
            ')'
        ).format(
            self.identifier,
            self.amount,
            self.token_address,
            self.node_address,
        )


class ReceiveTransferDirect(StateChange):
    def __init__(
            self,
            identifier,
            amount,
            token_address,
            sender):

        self.identifier = identifier
        self.amount = amount
        self.token_address = token_address
        self.sender = sender

    def __eq__(self, other):
        if not isinstance(other, ReceiveTransferDirect):
            return False

        return (
            self.identifier == other.identifier and
            self.amount == other.amount and
            self.token_address == other.token_address and
            self.sender == other.sender
        )

    def __ne__(self, other):
        return not self.__eq__(other)

    def __str__(self):
        return (
            'ReceiveTransferDirect('
            'identifier:{} amount:{} token_address:{} sender:{}'
            ')'
        ).format(
            self.identifier,
            self.amount,
            self.token_address,
            self.sender,
        )
