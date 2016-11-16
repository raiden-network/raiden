# -*- coding: utf-8 -*-
from copy import deepcopy

from raiden.transfer.architecture import (
    State,
    StateChange,
    StateTransition,
    Iteration,
)


class InitMediatedTransfer(StateChange):
    """ A new mediated transfer was requested. """

    def __init__(self, target, transfer):
        self.target = target
        self.transfer = transfer


class Blocknumber(StateChange):
    """ A new block was mined. """
    def __init__(self, block_number):
        self.block_number = block_number


class GetRoutes(StateChange):
    def __init__(self, transfer_id, target, token):
        self.transfer_id = transfer_id
        self.target = target
        self.token = token


class Route(StateChange):
    def __init__(self, transfer_id, next_hop, capacity):
        self.transfer_id = transfer_id
        self.next_hop = next_hop
        self.capacity = capacity


class NewSecret(StateChange):
    def __init__(self, transfer_id):
        self.transfer_id = transfer_id


class Secret(StateChange):
    def __init__(self, transfer_id, secret, hashlock):
        self.transfer_id = transfer_id
        self.secret = secret
        self.hashlock = hashlock


class MediatedTransferMessageSend(StateChange):
    def __init__(self, transfer_id, token, amount, expiration, hashlock, target, next_hop):
        self.transfer_id = transfer_id
        self.token = token
        self.amount = amount
        self.expiration = expiration
        self.hashlock = hashlock
        self.target = target
        self.next_hop = next_hop


class TransferState(State):
    """ State representation of a transfer. This object should never be
    modified in-place.
    """
    def __init__(self, amount, token, identifier, target):
        self.amount = amount
        self.token = token
        self.identifier = identifier


class StartMediatedTransferState(State):
    """ State representation of a mediated transfre. This object should never
    be modified in-place.
    """
    def __init__(self, target, transfer):
        self.target = target
        self.transfer = transfer

        self.secret = None  #: the secret used to lock the current transfer
        self.hashlock = None  #: the corresponding hashlock for the current secret

        # Note: to implement a multiple routes for the mediated transfer we
        # need an transfer identifier scheme that allows for sub-identifiers.
        self.route = None  #: current route being used

        self.available_routes = None  #: routes available to complete the transfer
        self.tried_routes = None  #: routes that were used but failed


def state_transition(current_state, state_change):
    """ Transition logic for a mediated transfer started by this node, this
    function needs to be referentially transparent.
    """

    valid_state_change = (
        current_state is None or
        state_change.transfer_id == current_state.transfer.identifier
    )
    assert valid_state_change, 'state change to a different transfer informed.'

    state_initialize = (
        current_state is None or
        current_state.available_routes is None
    )

    state_send_transfer = (
        current_state.unconfirmed
    )

    state_finilize = (
        not current_state.unconfirmed
    )

    if state_initialize:
        # we start a new mediated transfer by setting initializing current_state
        # with a target and transfer, and then by getting the available routes
        state = 'initialize'

    elif state_send_transfer:
        # with the transfer and routes set we can send off mediated transfers and
        # wait for the SecretRequest
        state = 'send_transfer'

    elif state_finilize:
        # after the sent message is confirmed we can finilize the transaction
        # by revealing the secret
        state = 'reveal_secret'

    else:
        state = 'unknown'

    next_state = deepcopy(current_state)

    init_transition = (
        isinstance(state_change, InitMediatedTransfer)
    )
    routes_transition = (
        isinstance(state_change, list) and
        all(isinstance(item, Route) for item in state_change) and
        all(item.transfer_id == current_state.transfer.item for item in state_change)
    )
    secret_transition = (
        isinstance(state_change, Secret)
    )

    if state == 'initialize':
        if current_state is None and init_transition:
            target = state_change.target
            transfer = state_change.transfer

            next_state = StartMediatedTransferState(
                target,
                transfer,
            )

            get_routes = GetRoutes(
                transfer.identifier,
                transfer.target,
                transfer.token,
            )

            iteration = Iteration(next_state, [get_routes])

        elif routes_transition:
            next_state.available_routes = state_change
            next_state.routes_failed = list()
            new_secret = NewSecret(next_state.transfer.identifier)

            iteration = Iteration(next_state, [new_secret])

    elif state == 'send_transfer':
        if secret_transition:
            next_state.secret = state_change.secret
            next_state.hashlock = state_change.hashlock

            if next_state.available_routes:

                try_route = None
                while next_state.available_routes:
                    route = next_state.available_routes.pop()

                    if route.capacity < next_state.transfer.amount:
                        next_state.tried_routes.append(route)
                    else:
                        try_route = route
                        break

                if try_route is None:
                    # no avaiable route has sufficient capacity for the current
                    # transfer, cancel it
                    cancel = Cancel(transfer_id=next_state.transfer.identifier)
                    iteration = Iteration(None, [cancel])

                else:
                    message = MediatedTransferMessageSend(
                        next_state.transfer.id,
                        next_state.transfer.token,
                        next_state.transfer.amount,
                        expiration,
                        next_state.hashlock,
                        next_state.target,
                        route.next_hop,
                    )
                    mediated_messages.append()
                    routes.append(route)

                    if pending_amount == 0:  # this cannot be negative
                        break

            iteration = Iteration(next_state, [new_secret])

    elif state == 'reveal_secret':
        pass

    return iteration
