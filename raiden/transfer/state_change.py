# -*- coding: utf-8 -*-
from raiden.transfer.architecture import StateChange
from raiden.transfer.state import RouteState
from raiden.utils import pex, sha3
from raiden.utils.typing import address
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

    def __repr__(self):
        return 'Block({})'.format(self.block_number)


class ActionChannelClose(StateChange):
    """ User is closing an existing channel. """

    def __init__(self, channel_identifier):
        self.channel_identifier = channel_identifier

    def __repr__(self):
        return '<ActionChannelClose channel:{}>'.format(
            pex(self.channel_identifier),
        )

    def __eq__(self, other):
        return (
            isinstance(other, ActionChannelClose) and
            self.channel_identifier == other.channel_identifier
        )

    def __ne__(self, other):
        return not self.__eq__(other)


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

    def __repr__(self):
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

    def __repr__(self):
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

    def __repr__(self):
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


class ContractReceiveChannelClosed(StateChange):
    """ A channel to which this node IS a participant was closed. """

    def __init__(self, channel_identifier, closing_address: address, closed_block_number: int):
        if not isinstance(closing_address, address):
            raise ValueError('closing_address must be of type address')

        if not isinstance(closed_block_number, int):
            raise ValueError('closed_block_number must be of type int')

        self.channel_identifier = channel_identifier
        self.closing_address = closing_address
        self.closed_block_number = closed_block_number

    def __repr__(self):
        return '<ContractReceiveChannelClosed channel:{} closer:{} closed_at:{}>'.format(
            pex(self.channel_identifier),
            pex(self.closing_address),
            self.closed_block_number
        )

    def __eq__(self, other):
        return (
            isinstance(other, ContractReceiveChannelClosed) and
            self.channel_identifier == other.channel_identifier and
            self.closing_address == other.closing_address and
            self.closed_block_number == other.closing_address
        )

    def __ne__(self, other):
        return not self.__eq__(other)


class ContractReceiveChannelNewBalance(StateChange):
    """ A channel to which this node IS a participant had a deposit. """

    def __init__(self, channel_identifier, participant_address: address, contract_balance: int):
        if not isinstance(participant_address, address):
            raise ValueError('participant_address must be of type address')

        if not isinstance(contract_balance, int):
            raise ValueError('contract_balance must be of type int')

        self.channel_identifier = channel_identifier
        self.participant_address = participant_address
        self.contract_balance = contract_balance

    def __repr__(self):
        return '<ContractReceiveChannelNewBalance channel:{} participant:{} balance:{}>'.format(
            pex(self.channel_identifier),
            pex(self.participant_address),
            self.contract_balance,
        )

    def __eq__(self, other):
        return (
            isinstance(other, ContractReceiveChannelNewBalance) and
            self.channel_identifier == other.channel_identifier and
            self.participant_address == other.participant_address and
            self.contract_balance == other.contract_balance
        )

    def __ne__(self, other):
        return not self.__eq__(other)


class ContractReceiveChannelSettled(StateChange):
    """ A channel to which this node IS a participant was settled. """

    def __init__(self, channel_identifier, settle_block_number: int):
        if not isinstance(settle_block_number, int):
            raise ValueError('settle_block_number must be of type int')

        self.channel_identifier = channel_identifier
        self.settle_block_number = settle_block_number

    def __repr__(self):
        return '<ContractReceiveChannelSettled channel:{} settle_block:{}>'.format(
            pex(self.channel_identifier),
            self.settle_block_number,
        )

    def __eq__(self, other):
        return (
            isinstance(other, ContractReceiveChannelSettled) and
            self.channel_identifier == other.channel_identifier and
            self.settle_block_number == other.settle_block_number
        )

    def __ne__(self, other):
        return not self.__eq__(other)


class ContractReceiveChannelWithdraw(StateChange):
    """ A lock was withdrawn via the blockchain.
    Used when a hash time lock was withdrawn and a log ChannelSecretRevealed is
    emitted by the netting channel.
    Note:
        For this state change the contract caller is not important but only the
        receiving address. `receiver` is the address to which the lock's token
        was transferred, this may be either of the channel participants.
        If the channel was used for a mediated transfer that was refunded, this
        event must be used twice, once for each receiver.
    """

    def __init__(
            self,
            payment_network_identifier,
            token_network_identifier,
            channel_identifier,
            secret,
            receiver: address):

        if not isinstance(receiver, address):
            raise ValueError('receiver must be of type address')

        hashlock = sha3(secret)

        self.payment_network_identifier = payment_network_identifier
        self.token_network_identifier = token_network_identifier
        self.channel_identifier = channel_identifier
        self.secret = secret
        self.hashlock = hashlock
        self.receiver = receiver

    def __repr__(self):
        return '<ContractReceiveChannelWithdraw channel:{} receive:{} hashlock:{}>'.format(
            pex(self.channel_identifier),
            pex(self.receiver),
            pex(self.hashlock),
        )

    def __eq__(self, other):
        return (
            isinstance(other, ContractReceiveChannelWithdraw) and
            self.channel_identifier == other.channel_identifier and
            self.secret == other.secret and
            self.hashlock == other.hashlock and
            self.receiver == other.receiver
        )

    def __ne__(self, other):
        return not self.__eq__(other)


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

    def __repr__(self):
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
