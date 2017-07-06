# -*- coding: utf-8 -*-
# pylint: disable=too-few-public-methods,too-many-arguments,too-many-instance-attributes
from __future__ import absolute_import

from raiden.transfer.architecture import StateChange
from .state import LockedTransferState


# Note: The init states must contain all the required data for trying doing
# useful work, ie. there must /not/ be an event for requesting new data.


class ActionInitInitiator(StateChange):
    """ Initial state of a new mediated transfer.

    Args:
        our_address (address): This node address.
        transfer (LockedTransferState): A state object containing the transfer details.
        routes (RoutesState): The current available routes.
        random_generator (generator): A generator for secrets.
        block_number (int): The current block number.
    """

    def __init__(
            self,
            our_address,
            transfer,
            routes,
            random_generator,
            block_number):

        self.our_address = our_address
        self.transfer = transfer
        self.routes = routes
        self.random_generator = random_generator
        self.block_number = block_number


class ActionInitMediator(StateChange):
    """ Initial state for a new mediator.

    Args:
        our_address (address): This node's address.
        from_transfer (LockedTransferState): The received MediatedTransfer.
        routes (RoutesState): The current available routes.
        from_route (RouteState): The route from which the MediatedTransfer was received.
        block_number (int): The current block number.
    """

    def __init__(
            self,
            our_address,
            from_transfer,
            routes,
            from_route,
            block_number):

        self.our_address = our_address
        self.from_transfer = from_transfer
        self.routes = routes
        self.from_route = from_route
        self.block_number = block_number


class ActionInitTarget(StateChange):
    """ Initial state for a new target.

    Args:
        target: The mediated transfer target.
        from_route: The route from which the MediatedTransfer was received.
        from_transfer: The received MediatedTransfer.
        block_number: The current block number.
        config (dict): This node configuration.
    """

    def __init__(self,
                 our_address,
                 from_route,
                 from_transfer,
                 block_number):

        self.our_address = our_address
        self.from_route = from_route
        self.from_transfer = from_transfer
        self.block_number = block_number


class ActionCancelRoute(StateChange):
    """ Cancel the current route.

    Notes:
        Used to cancel a specific route but not the transfer, may be used for
        timeouts.
    """
    def __init__(self, identifier):
        self.identifier = identifier


class ReceiveSecretRequest(StateChange):
    """ A SecretRequest message received. """

    def __init__(self, identifier, amount, hashlock, sender):
        self.identifier = identifier
        self.amount = amount
        self.hashlock = hashlock
        self.sender = sender
        self.revealsecret = None


class ReceiveSecretReveal(StateChange):
    """ A SecretReveal message received. """
    def __init__(self, secret, sender):
        self.secret = secret
        self.sender = sender


class ReceiveTransferRefund(StateChange):
    """ A RefundTransfer message received. """
    def __init__(self, sender, transfer):
        if not isinstance(transfer, LockedTransferState):
            raise ValueError('transfer must be an instance of LockedTransferState')

        self.sender = sender
        self.transfer = transfer


class ReceiveBalanceProof(StateChange):
    """ A balance proof `identifier` was received. """
    def __init__(self, identifier, channel_address, node_address):
        self.identifier = identifier
        self.channel_address = channel_address
        self.node_address = node_address


class ContractReceiveWithdraw(StateChange):
    """ A lock was withdrawn via the blockchain.

    Used when a hash time lock was withdrawn and a log ChannelSecretRevealed is
    emited by the netting channel.

    Note:
        For this state change the contract caller is not important but only the
        receiving address. `receiver` is the address to which the lock's token
        was transferred, this may be either of the channel participants.

        If the channel was used for a mediated transfer that was refunded, this
        event must be used twice, once for each receiver.
    """
    def __init__(self, channel_address, secret, receiver):
        self.channel_address = channel_address
        self.secret = secret
        self.receiver = receiver


class ContractReceiveClosed(StateChange):
    def __init__(self, channel_address, closing_address, block_number):
        self.channel_address = channel_address
        self.closing_address = closing_address
        self.block_number = block_number  # TODO: rename to closed_block


class ContractReceiveSettled(StateChange):
    def __init__(self, channel_address, block_number):
        self.channel_address = channel_address
        self.block_number = block_number  # TODO: rename to settle_block_number


class ContractReceiveBalance(StateChange):
    def __init__(
            self,
            channel_address,
            token_address,
            participant_address,
            balance,
            block_number):

        self.channel_address = channel_address
        self.token_address = token_address
        self.participant_address = participant_address
        self.balance = balance
        self.block_number = block_number


class ContractReceiveNewChannel(StateChange):
    def __init__(
            self,
            manager_address,
            channel_address,
            participant1,
            participant2,
            settle_timeout):

        self.manager_address = manager_address
        self.channel_address = channel_address
        self.participant1 = participant1
        self.participant2 = participant2
        self.settle_timeout = settle_timeout


class ContractReceiveTokenAdded(StateChange):
    def __init__(self, registry_address, token_address, manager_address):
        self.registry_address = registry_address
        self.token_address = token_address
        self.manager_address = manager_address
