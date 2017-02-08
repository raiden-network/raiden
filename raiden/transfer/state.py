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
        channel_address (address): The address of the on chain netting channel.
        available_balance (int): The current available balance that can be transferred
            through `node_address`.
        settle_timeout (int): The settle_timeout of the channel set in the
            smart contract.
        reveal_timeout (int): The channel configured reveal_timeout.
    """

    valid_states = (
        'available',
        'closed',
        'settled',
    )

    def __init__(self,
                 state,
                 node_address,
                 chanel_address,
                 available_balance,
                 settle_timeout,
                 reveal_timeout,
                 blocks_until_settlement):

        if state not in self.valid_states:
            raise ValueError('invalid value for state')

        self.state = state
        self.node_address = node_address
        self.channel_address = chanel_address
        self.available_balance = available_balance
        self.settle_timeout = settle_timeout
        self.reveal_timeout = reveal_timeout
        self.blocks_until_settlement = blocks_until_settlement

    def __repr__(self):
        return (
            '<Route {state} hop:{address} available_balance:{available_balance} '
            'settle:{settle_timeout} reveal:{reveal_timeout}>'
        ).format(
            state=self.state,
            address=pex(self.node_address),
            available_balance=self.available_balance,
            settle_timeout=self.settle_timeout,
            reveal_timeout=self.reveal_timeout,
        )

    def __eq__(self, other):
        if isinstance(other, RouteState):
            return (
                self.state == other.state and
                self.node_address == other.node_address and
                self.available_balance == other.available_balance and
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

    def __repr__(self):
        return '<Routes available={} ignored={} refunded={} canceled={}>'.format(
            len(self.available_routes),
            len(self.ignored_routes),
            len(self.refunded_routes),
            len(self.canceled_routes),
        )

    def __eq__(self, other):
        same = lambda routes1, routes2: (all(
            routes1[i] == routes2[i] for i in range(len(routes1)))
            and len(routes1) == len(routes2)
        )
        if isinstance(other, RoutesState):
            return all(t for t in [
                same(self.available_routes, other.available_routes),
                same(self.ignored_routes, other.ignored_routes),
                same(self.refunded_routes, other.refunded_routes),
                same(self.canceled_routes, other.canceled_routes),
            ])
        return False
