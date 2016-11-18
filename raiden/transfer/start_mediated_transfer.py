# -*- coding: utf-8 -*-
from copy import deepcopy

from raiden.transfer.architecture import (
    State,
    StateChange,
    Iteration,
)

# pylint: disable=too-few-public-methods,too-many-arguments,too-many-instance-attributes


def cancel_current_transfer(next_state):
    """ Discard current secret/hashlock, set the current route as canceled
    transfer and clear current state.
    """
    new_secret = NewSecret(next_state.transfer.identifier)
    cancel_message = CancelMediatedTransferMessage(
        transfer_id=next_state.transfer.transfer_id,
        message_id=next_state.message.message_id
    )

    next_state.canceled_routes.append(next_state.route)
    next_state.canceled_transfers.append(next_state.message)

    next_state.secret = None
    next_state.hashlock = None
    next_state.message = None
    next_state.route = None
    next_state.secretrequest = None

    iteration = Iteration(next_state, [cancel_message, new_secret])

    return iteration


class InitMediatedTransfer(StateChange):
    """ A new mediated transfer was requested.

    Args:
        target: The mediated transfer target.
        transfer: A state object containing the transfer details.
        block_number: The current block number.
    """

    def __init__(self, our_address, transfer, block_number, config):
        self.our_address = our_address
        self.transfer = transfer
        self.block_number = block_number
        self.config = config


class Blocknumber(StateChange):
    """ Transition used when a new block is mined.

    Args:
        block_number: The current block_number.
    """

    def __init__(self, block_number):
        self.block_number = block_number


class GetRoutes(StateChange):
    """ A request for the available routes.

    Args:
        transfer_id: Identifier used to match the result.
        target: The transfer target.
        token: The token address for the transfer.
    """
    def __init__(self, transfer_id, target, token):
        self.transfer_id = transfer_id
        self.target = target
        self.token = token


class RefundTransfer(StateChange):
    def __init__(self, transfer_id, hashlock, amount, sender):
        self.transfer_id = transfer_id
        self.amount = amount
        self.hashlock = hashlock
        self.sender = sender


class Route(StateChange):
    def __init__(self,
                 transfer_id,
                 next_hop,
                 capacity,
                 settle_timeout,
                 reveal_timeout):

        self.transfer_id = transfer_id
        self.next_hop = next_hop
        self.capacity = capacity
        self.settle_timeout = settle_timeout
        self.reveal_timeout = reveal_timeout


class NewSecret(StateChange):
    def __init__(self, transfer_id):
        self.transfer_id = transfer_id


class Secret(StateChange):
    def __init__(self, transfer_id, secret, hashlock):
        self.transfer_id = transfer_id
        self.secret = secret
        self.hashlock = hashlock


class SecretRequest(StateChange):
    def __init__(self, transfer_id, amount, hashlock, identifier, sender):
        self.transfer_id = transfer_id
        self.amount = amount
        self.hashlock = hashlock
        self.identifier = identifier
        self.sender = sender


class RevealSecret(StateChange):
    def __init__(self, transfer_id, secret, target, sender):
        self.transfer_id = transfer_id
        self.secret = secret
        self.target = target
        self.sender = sender


class UnlockLock(StateChange):
    def __init__(self, transfer_id, token, secret, hashlock):
        self.transfer_id = transfer_id
        self.token = token
        self.secret = secret
        self.hashlock = hashlock


class Timeout(StateChange):
    def __init__(self, transfer_id):
        self.transfer_id = transfer_id


class MediatedTransferMessageSend(StateChange):
    def __init__(self,
                 transfer_id,
                 message_id,
                 token,
                 amount,
                 expiration,
                 network_timeout,
                 hashlock,
                 target,
                 next_hop):

        self.transfer_id = transfer_id
        self.message_id = message_id
        self.token = token
        self.amount = amount
        self.expiration = expiration
        self.network_timeout = network_timeout
        self.hashlock = hashlock
        self.target = target
        self.next_hop = next_hop


class CancelMediatedTransfer(StateChange):
    """ Cannot proceed and finish the transfer, cancel it.

    Args:
        transfer_id: The transfer identifer.
    """

    def __init__(self, transfer_id):
        self.transfer_id = transfer_id


class CancelMediatedTransferMessage(StateChange):
    """ Cancel a message, used to ignore a route.

    Args:
        transfer_id: The transfer identifer.
        message_id: The message identifier.
    """

    def __init__(self, transfer_id, message_id):
        self.transfer_id = transfer_id

        # the message_id of the canceled message. Note this is not the same
        # value as the transfer_id, transfer_id contains the agreed transfer
        # identifier between the sender/receiver, message_id is this node
        # identifier for a message, that means a single transfer_id could have
        # multiple messages sent each with a unique identifier.
        self.message_id = message_id


class MediatedTransferState(State):
    """ State representation of a transfer. This object should never be
    modified in-place.
    """
    def __init__(self, amount, token, identifier):
        self.amount = amount
        self.token = token
        self.identifier = identifier


class StartMediatedTransferState(State):
    """ State representation of a mediated transfre. This object should never
    be modified in-place.
    """
    def __init__(self, our_address, transfer, target, block_number, network_timeout):
        self.our_address = our_address
        self.transfer = transfer
        self.target = target
        self.block_number = block_number
        self.network_timeout = network_timeout

        self.secret = None  #: the secret used to lock the current transfer
        self.hashlock = None  #: the corresponding hashlock for the current secret

        self.message = None  #: current message in-transit
        self.route = None  #: current route being used
        self.secretrequest = None
        self.revealsecret = None

        self.available_routes = None  #: routes available to complete the transfer
        self.canceled_routes = list()  #: routes that were used but canceled
        self.canceled_transfers = list()  #: canceled transfers


def state_transition(current_state, state_change):
    """ Transition logic for a mediated transfer started by this node, this
    function needs to be referentially transparent.
    """
    # pylint: disable=too-many-locals,too-many-branches,too-many-statements

    state_initialize = (
        current_state is None or
        current_state.available_routes is None
    )

    state_send_transfer = (
        current_state.secretrequest is None
    )

    state_target_reply = (
        current_state.secretrequest is not None
    )

    state_finalize = (
        current_state.revealsecret is not None
    )

    # default iteration for an unknown transition keeps the current state
    # unchange and do no new actions
    iteration = Iteration(current_state, list())

    next_state = deepcopy(current_state)

    # Initialize the current state, request the routes, and request a secret
    if state_initialize:
        routes_transition = (
            isinstance(state_change, list) and
            all(isinstance(item, Route) for item in state_change) and
            all(item.transfer_id == current_state.transfer.identifier for item in state_change)
        )

        if isinstance(state_change, InitMediatedTransfer):
            our_address = state_change.our_address
            target = state_change.target
            transfer = state_change.transfer
            block_number = state_change.block_number
            network_timeout = state_change.config['network_timeout']

            next_state = StartMediatedTransferState(
                our_address,
                transfer,
                target,
                block_number,
                network_timeout,
            )

            get_routes = GetRoutes(
                transfer.identifier,
                target,
                transfer.token,
            )

            iteration = Iteration(next_state, [get_routes])

        elif routes_transition:
            next_state.available_routes = state_change
            next_state.canceled_routes = list()
            new_secret = NewSecret(next_state.transfer.identifier)

            iteration = Iteration(next_state, [new_secret])

    # Got a new secret, choose a route and send the transfer message
    elif state_send_transfer:
        if isinstance(state_change, Secret):
            next_state.secret = state_change.secret
            next_state.hashlock = state_change.hashlock

            # Note: to implement multiple routes for a mediated transfer we
            # need an transfer identifier scheme that allows for
            # sub-identifiers.
            try_route = None
            while next_state.available_routes:
                route = next_state.available_routes.pop()

                if route.capacity < next_state.transfer.amount:
                    next_state.canceled_routes.append(route)
                else:
                    try_route = route
                    break

            # no avaiable route has sufficient capacity for the current
            # transfer, cancel it
            if try_route is None:
                cancel = CancelMediatedTransfer(
                    transfer_id=next_state.transfer.identifier,
                )
                iteration = Iteration(None, [cancel])

            else:
                network_timeout = next_state.network_timeout
                lock_timeout = try_route.settle_timeout - try_route.reveal_timeout
                lock_expiration = next_state.block_number + lock_timeout
                message_id = len(next_state.canceled_transfers)

                message = MediatedTransferMessageSend(
                    next_state.transfer.id,
                    message_id,
                    next_state.transfer.token,
                    next_state.transfer.amount,
                    lock_expiration,
                    network_timeout,
                    next_state.hashlock,
                    next_state.target,
                    try_route.next_hop,
                )

                iteration = Iteration(next_state, [message])

    # target received the mediated transfer, check the transfer and reveal the
    # secret
    elif state_target_reply:

        if isinstance(state_change, SecretRequest):
            valid_secretrequest = (
                state_change.transfer_id == next_state.transfer.id and
                state_change.amount == next_state.transfer.amount and
                state_change.hashlock == next_state.hashlock and
                state_change.identifier == next_state.transfer.identifier and
                state_change.sender == next_state.target
            )

            invalid_secretrequest = not valid_secretrequest
        else:
            valid_secretrequest = False
            invalid_secretrequest = False

        refund_transfer = (
            isinstance(state_change, RefundTransfer) and
            state_change.sender == next_state.route.next_hop
        )

        if valid_secretrequest:
            reveal_secret = RevealSecret(
                next_state.transfer.id,
                next_state.secret,
                next_state.transfer.target,
                next_state.our_address,
            )
            next_state.revealsecret = reveal_secret
            iteration = Iteration(next_state, [reveal_secret])

        elif invalid_secretrequest or refund_transfer:
            return cancel_current_transfer(next_state)

    # next_hop learned the secret, unlock the token locally and allow
    # send the withdraw message to next_hop
    elif state_finalize:
        secret_reveal = (
            isinstance(state_change, RevealSecret) and
            state_change.sender == next_state.route.next_hop
        )

        if secret_reveal:
            unlock_lock = UnlockLock(
                next_state.transfer.id,
                next_state.transfer.token,
                next_state.secret,
                next_state.hashlock,
            )

            iteration = Iteration(None, [unlock_lock])

    else:
        if isinstance(state_change, Blocknumber):
            next_state.block_number = state_change.block_number

        elif isinstance(state_change, Timeout):
            cancel_current_transfer(next_state)

    return iteration
