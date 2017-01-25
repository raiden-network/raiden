# -*- coding: utf-8 -*-
from raiden.transfer.architecture import State
from raiden.utils import pex
# pylint: disable=too-few-public-methods,too-many-arguments,too-many-instance-attributes


class RouteState(State):
    """ Route state.

    Args:
        state (string): The current state of the route (available or
            unavailable).
        node_address (address): The address of the next_hop.
        capacity (int): The current available balance that can be transferred
            through `node_address`.
        settle_timeout (int): The settle_timeout of the channel set in the
            smart contract.
        reveal_timeout (int): The channel configured reveal_timeout.
    """

    valid_states = (
        'unavailable',
        'available',
    )

    def __init__(self,
                 state,
                 node_address,
                 capacity,
                 settle_timeout,
                 reveal_timeout):

        if state not in self.valid_states:
            raise ValueError('invalid value for state')

        self.state = state
        self.node_address = node_address
        self.capacity = capacity  # TODO: rename to available_balance
        self.settle_timeout = settle_timeout
        self.reveal_timeout = reveal_timeout

    def __repr__(self):
        return (
            '<Route {state} hop:{address} capacity:{capacity} '
            'settle:{settle_timeout} reveal:{reveal_timeout}>'
        ).format(
            state=self.state,
            address=pex(self.node_address),
            capacity=self.capacity,
            settle_timeout=self.settle_timeout,
            reveal_timeout=self.reveal_timeout,
        )

    def __eq__(self, other):
        if isinstance(other, RouteState):
            return (
                self.state == other.state and
                self.node_address == other.node_address and
                self.capacity == other.capacity and
                self.settle_timeout == other.settle_timeout and
                self.reveal_timeout == other.reveal_timeout
            )
        return False


class RoutesState(State):
    """ Routing state.

    Args:
        available_routes (list): A list of RouteState instances.
    """
    def __init__(self, available_routes):
        if not all(isinstance(r, RouteState) for r in available_routes):
            raise ValueError('available_routes must be comprised of RouteState objects only.')

        duplicated = len(available_routes) != len(set(r.node_address for r in available_routes))
        if duplicated:
            raise ValueError('duplicate route for the same address supplied.')

        self.available_routes = available_routes
        self.ignored_routes = list()
        self.refunded_routes = list()
        self.canceled_routes = list()
