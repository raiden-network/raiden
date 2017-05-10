# -*- coding: utf-8 -*-
from raiden.transfer.architecture import State
from raiden.utils import pex
# pylint: disable=too-few-public-methods,too-many-arguments,too-many-instance-attributes

CHANNEL_STATE_OPENED = 'opened'
CHANNEL_STATE_CLOSED = 'closed'
CHANNEL_STATE_SETTLED = 'settled'
CHANNEL_STATE_INITIALIZING = 'initializing'


class RouteState(State):
    """ Route state.

    Args:
        state (string): The current state of the route (opened, closed or settled).
        node_address (address): The address of the next_hop.
        channel_address (address): The address of the on chain netting channel.
        available_balance (int): The current available balance that can be transferred
            through `node_address`.
        settle_timeout (int): The settle_timeout of the channel set in the
            smart contract.
        reveal_timeout (int): The channel configured reveal_timeout.
        closed_block (Nullable[int]): None if the channel is open, otherwise
            the block number at which the channel was closed.
    """
    __slots__ = (
        'state',
        'node_address',
        'channel_address',
        'available_balance',
        'settle_timeout',
        'reveal_timeout',
        'closed_block',
    )

    valid_states = (
        CHANNEL_STATE_OPENED,
        CHANNEL_STATE_CLOSED,
        CHANNEL_STATE_SETTLED,
        CHANNEL_STATE_INITIALIZING,
    )

    def __init__(self,
                 state,
                 node_address,
                 channel_address,
                 available_balance,
                 settle_timeout,
                 reveal_timeout,
                 closed_block):

        if state not in self.valid_states:
            raise ValueError('invalid value for state')

        self.state = state
        self.node_address = node_address
        self.channel_address = channel_address
        self.available_balance = available_balance
        self.settle_timeout = settle_timeout
        self.reveal_timeout = reveal_timeout
        self.closed_block = closed_block

    def __repr__(self):
        return (
            '<RouteState {state} hop:{address} available_balance:{available_balance} '
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
    __slots__ = (
        'available_routes',
        'ignored_routes',
        'refunded_routes',
        'canceled_routes',
    )

    def __init__(self, available_routes):
        # consume possible generators and make a copy of the routes since the
        # tasks will modify this list in-place
        available_routes = list(available_routes)

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
        if isinstance(other, RoutesState):
            return (
                self.available_routes == other.available_routes and
                self.ignored_routes == other.ignored_routes and
                self.refunded_routes == other.refunded_routes and
                self.canceled_routes == other.canceled_routes
            )

        return False
