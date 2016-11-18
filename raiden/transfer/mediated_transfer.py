# -*- coding: utf-8 -*-
from copy import deepcopy

from raiden.transfer.architecture import (
    State,
    StateChange,
    Iteration,
)
from raiden.transfer.transition import update_route
from raiden.transfer.state_change import (
    Blocknumber,
    CancelMediatedTransferMessage,
    GetRoutes,
    MediatedTransferMessageSend,
    Route,
    RefundTransfer,
    RevealSecret,
    RegisterSecret,
    Secret,
    Timeout,
)
from raiden.transfer.state import RoutesState
from raiden.utils import sha3

# pylint: disable=too-few-public-methods,too-many-arguments,too-many-instance-attributes


def try_next_route(next_state):
    try_route = None
    while next_state.routes.available_routes:
        route = next_state.routes.available_routes.pop()
        reveal_expiration = route.reveal_timeout + next_state.block_number

        # Dont use this route if we cannot decrease the expiration by
        # `reveal_timeout`, this is time required to learn the secret
        # through the blockchain that needs to consider DoS attacks.
        under_reveal_expiration = next_state.originating_transfer.expiration <= reveal_expiration

        if route.capacity < next_state.transfer.amount or under_reveal_expiration:
            next_state.routes.ignored_routes.append(route)
        else:
            try_route = route
            break

    # No available route has sufficient capacity for the current
    # transfer, refund the transfer so that the previous hop can try a
    # new route.
    if try_route is None:
        refund = RefundTransfer(
            next_state.transfer.identifier,
            next_state.transfer.amount,
            next_state.hashlock,
            next_state.sender,
        )
        next_state.sent_refund = refund

        next_state.route = None
        next_state.message = None

        iteration = Iteration(next_state, [refund])

    else:
        network_timeout = next_state.network_timeout

        lock_timeout = (
            next_state.originating_transfer.expiration -
            next_state.block_number
        )
        new_lock_timeout = lock_timeout - try_route.reveal_timeout

        # A timeout larger than settle_timeout will be rejected, this
        # /needs/ to be validated in state_initialize.
        if new_lock_timeout > try_route.settle_timeout:
            new_lock_timeout = try_route.settle_timeout - try_route.reveal_timeout

        message_id = len(next_state.sent_transfers_refunded)
        new_lock_expiration = new_lock_timeout + next_state.block_number
        message = MediatedTransferMessageSend(
            next_state.transfer.id,
            message_id,
            next_state.transfer.token,
            next_state.transfer.amount,
            new_lock_expiration,
            network_timeout,
            next_state.hashlock,
            next_state.target,
            try_route.next_hop,
        )
        next_state.message = message

        iteration = Iteration(next_state, [message])

    return iteration


class InitMediatedTransfer(StateChange):
    """ A new mediated transfer was requested.

    Args:
        target: The mediated transfer target.
        transfer: A state object containing the transfer details.
        block_number: The current block number.
    """
    def __init__(self,
                 our_address,
                 transfer,
                 originating_route,
                 originating_channel,
                 block_number,
                 config):

        self.our_address = our_address
        self.transfer = transfer
        self.originating_route = originating_route
        self.originating_channel = originating_channel
        self.block_number = block_number
        self.config = config


class MediatedTransferState(State):
    """ State representation of a mediated transfre. This object should never
    be modified in-place.
    """
    def __init__(self,
                 our_address,
                 transfer,
                 target,
                 originating_route,
                 originating_transfer,
                 block_number,
                 network_timeout):

        self.our_address = our_address
        self.transfer = transfer
        self.target = target
        self.originating_route = originating_route
        self.originating_transfer = originating_transfer
        self.block_number = block_number
        self.network_timeout = network_timeout

        self.secret = None
        self.hashlock = None  #: the corresponding hashlock for the current secret

        self.message = None  #: current message in-transit
        self.route = None  #: current route being used
        self.sent_refund = None  #: set with the refund transfer if it was sent

        self.routes = None
        self.sent_transfers_refunded = list()


def state_transition(current_state, state_change):
    """ Transition logic for a mediated transfer being intermediated by this node, this
    function needs to be referentially transparent.
    """
    # pylint: disable=too-many-locals,too-many-branches,too-many-statements

    state_initialize = current_state is None
    state_wait_routes = current_state.routes is None
    state_wait_secret = current_state.message is not None
    state_wait_withdraw = current_state.secret is not None

    iteration = Iteration(current_state, list())
    next_state = deepcopy(current_state)

    # Init state and request routes
    if state_initialize:
        if isinstance(state_change, InitMediatedTransfer):
            our_address = state_change.our_address
            target = state_change.target
            transfer = state_change.transfer
            originating_route = state_change.originating_route
            originating_transfer = state_change.originating_transfer
            block_number = state_change.block_number
            network_timeout = state_change.config['network_timeout']

            next_state = MediatedTransferState(
                our_address,
                transfer,
                target,
                originating_route,
                originating_transfer,
                block_number,
                network_timeout,
            )

            settle_expiration = originating_route.settle_timeout + state_change.block_number
            over_settle_expiration = originating_transfer.expiration >= settle_expiration

            # An expiration /must/ be lower than settle_timeout, otherwise we
            # cannot guarantee the transfer will settled.
            # TODO: It may be valid to relax this constraint, given that the
            # node is online when the channel is closed.
            #
            # Notes:
            # - This node didn't send a transfer forward, so it can not lose
            #   asset.
            # - The previous_node knowns the settle_timeout because this value
            #   is in the smart contract.
            # - It's not sending a RefundTransfer to the previous_node, so it
            #   will force a retry with a new path/different hashlock, this
            #   could make the bad behaving node lose it's fees but it will
            #   also increase latency.
            if over_settle_expiration:
                iteration = Iteration(None, [])

            else:
                get_routes = GetRoutes(
                    transfer.identifier,
                    target,
                    transfer.token,
                )

                iteration = Iteration(next_state, [get_routes])

    # Set the routes and mediate the transfer
    elif state_wait_routes:
        valid_routes = (
            isinstance(state_change, list) and
            all(isinstance(item, Route) for item in state_change) and
            all(item.transfer_id == current_state.transfer.identifier for item in state_change)
        )
        if valid_routes:
            next_state.routes = RoutesState([
                route
                for route in state_change
                if route.state == 'available'
            ])

            iteration = try_next_route(next_state)

    elif state_wait_secret:
        valid_refund = (
            isinstance(state_change, RefundTransfer) and
            state_change.identifier == state_change.message.identifier and
            state_change.amount == state_change.message.amount and
            state_change.hashlock == state_change.message.hashlock and
            state_change.sender == next_state.message.next_hop
        )

        valid_reveal_secret = (
            isinstance(state_change, RevealSecret) and
            sha3(state_change.secret) == next_state.hashlock
        )

        if valid_refund:
            next_state.routes.refund_routes.append(next_state.route)
            next_state.sent_transfers_refunded.append(next_state.message)

            iteration = try_next_route(next_state)

        elif valid_reveal_secret:
            next_state.secret = state_change.secret

            register = RegisterSecret(
                state_change.originating_transfer.transfer.identifier,
                state_change.secret,
            )

            reveal_secret = [
                RevealSecret(
                    next_state.originating_transfer.identifier,
                    next_state.secret,
                    refunded_transfer.next_hop,
                    next_state.our_address,
                )
                for refunded_transfer in next_state.sent_transfers_refunded
            ]
            iteration = Iteration(next_state, [register] + reveal_secret)

    elif state_wait_withdraw:
        valid_secret = (
            isinstance(state_change, Secret) and
            state_change.sender == next_state.originating_transfer.sender
        )

        if valid_secret:
            iteration = Iteration(None, [])

    else:
        if isinstance(state_change, Blocknumber):
            next_state.block_number = state_change.block_number

        elif isinstance(state_change, Timeout):
            cancel_message = CancelMediatedTransferMessage(
                transfer_id=next_state.transfer.transfer_id,
                message_id=next_state.message.message_id
            )

            next_state.cancel = cancel_message
            next_state.hashlock = None
            next_state.message = None
            next_state.route = None

            iteration = Iteration(next_state, [cancel_message])

        elif isinstance(state_change, Route):
            update_route(next_state, state_change)

    return iteration
