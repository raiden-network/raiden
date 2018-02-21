# -*- coding: utf-8 -*-
from raiden.transfer.architecture import State
from raiden.utils import pex, typing
# pylint: disable=too-few-public-methods,too-many-arguments,too-many-instance-attributes

CHANNEL_STATE_CLOSED = 'closed'
CHANNEL_STATE_CLOSING = 'waiting_for_close'
CHANNEL_STATE_OPENED = 'opened'
CHANNEL_STATE_SETTLED = 'settled'
CHANNEL_STATE_SETTLING = 'waiting_for_settle'


def balanceproof_from_envelope(envelope_message):
    return BalanceProofState2(
        envelope_message.nonce,
        envelope_message.transferred_amount,
        envelope_message.locksroot,
        envelope_message.channel,
        envelope_message.message_hash,
        envelope_message.signature,
        envelope_message.sender,
    )


class RouteState(State):
    """ Route state.

    this describes a route state


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
    )

    def __init__(
            self,
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

    def __ne__(self, other):
        return not self.__eq__(other)


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

    def __ne__(self, other):
        return not self.__eq__(other)


class BalanceProofUnsignedState(State):
    """ Balance proof from the local node without the signature. """

    __slots__ = (
        'nonce',
        'transferred_amount',
        'locksroot',
        'channel_address',
    )

    def __init__(
            self,
            nonce: int,
            transferred_amount: typing.token_amount,
            locksroot: typing.keccak256,
            channel_address: typing.address):

        if not isinstance(nonce, int):
            raise ValueError('nonce must be int')

        if not isinstance(transferred_amount, typing.token_amount):
            raise ValueError('transferred_amount must be a token_amount instance')

        if not isinstance(locksroot, typing.keccak256):
            raise ValueError('locksroot must be an keccak256 instance')

        if not isinstance(channel_address, typing.address):
            raise ValueError('channel_address must be an address instance')

        if nonce <= 0:
            raise ValueError('nonce cannot be zero or negative')

        if nonce >= 2 ** 64:
            raise ValueError('nonce is too large')

        if transferred_amount < 0:
            raise ValueError('transferred_amount cannot be negative')

        if transferred_amount >= 2 ** 256:
            raise ValueError('transferred_amount is too large')

        if len(locksroot) != 32:
            raise ValueError('locksroot must have length 32')

        if len(channel_address) != 20:
            raise ValueError('channel is an invalid address')

        self.nonce = nonce
        self.transferred_amount = transferred_amount
        self.locksroot = locksroot
        self.channel_address = channel_address

    def __str__(self):
        return (
            '<'
            'BalanceProofUnsignedState nonce:{} transferred_amount:{} '
            'locksroot:{} channel_address:{}'
            '>'
        ).format(
            self.nonce,
            self.transferred_amount,
            pex(self.locksroot),
            pex(self.channel_address),
        )

    def __eq__(self, other):
        return (
            isinstance(other, BalanceProofUnsignedState) and
            self.nonce == other.nonce and
            self.transferred_amount == other.transferred_amount and
            self.locksroot == other.locksroot and
            self.channel_address == other.channel_address
        )

    def __ne__(self, other):
        return not self.__eq__(other)


class BalanceProofState2(State):
    """ Proof of a channel balance that can be used on-chain to resolve
    disputes.
    """

    __slots__ = (
        'nonce',
        'transferred_amount',
        'locksroot',
        'channel_address',
        'message_hash',
        'signature',
        'sender',
    )

    def __init__(
            self,
            nonce: int,
            transferred_amount: typing.token_amount,
            locksroot: typing.keccak256,
            channel_address: typing.address,
            message_hash: typing.keccak256,
            signature: typing.signature,
            sender: typing.address):

        if not isinstance(nonce, int):
            raise ValueError('nonce must be int')

        if not isinstance(transferred_amount, typing.token_amount):
            raise ValueError('transferred_amount must be a token_amount instance')

        if not isinstance(locksroot, typing.keccak256):
            raise ValueError('locksroot must be a keccak256 instance')

        if not isinstance(channel_address, typing.address):
            raise ValueError('channel_address must be an address instance')

        if not isinstance(message_hash, typing.keccak256):
            raise ValueError('message_hash must be a keccak256 instance')

        if not isinstance(signature, typing.signature):
            raise ValueError('signature must be an signature instance')

        if not isinstance(sender, typing.address):
            raise ValueError('sender must be an address instance')

        if nonce <= 0:
            raise ValueError('nonce cannot be zero or negative')

        if nonce >= 2 ** 64:
            raise ValueError('nonce is too large')

        if transferred_amount < 0:
            raise ValueError('transferred_amount cannot be negative')

        if transferred_amount >= 2 ** 256:
            raise ValueError('transferred_amount is too large')

        if len(locksroot) != 32:
            raise ValueError('locksroot must have length 32')

        if len(channel_address) != 20:
            raise ValueError('channel is an invalid address')

        if len(message_hash) != 32:
            raise ValueError('message_hash is an invalid hash')

        if len(signature) != 65:
            raise ValueError('signature is an invalid signature')

        self.nonce = nonce
        self.transferred_amount = transferred_amount
        self.locksroot = locksroot
        self.channel_address = channel_address
        self.message_hash = message_hash
        self.signature = signature
        self.sender = sender

    def __str__(self):
        return (
            '<'
            'BalanceProofState nonce:{} transferred_amount:{} '
            'locksroot:{} channel_address:{} message_hash:{}'
            'signature:{} sender:{}'
            '>'
        ).format(
            self.nonce,
            self.transferred_amount,
            pex(self.locksroot),
            pex(self.channel_address),
            pex(self.message_hash),
            pex(self.signature),
            pex(self.sender),
        )

    def __eq__(self, other):
        return (
            isinstance(other, BalanceProofState) and
            self.nonce == other.nonce and
            self.transferred_amount == other.transferred_amount and
            self.locksroot == other.locksroot and
            self.channel_address == other.channel_address and
            self.message_hash == other.message_hash and
            self.signature == other.signature and
            self.sender == other.sender
        )

    def __ne__(self, other):
        return not self.__eq__(other)


class BalanceProofState(State):
    def __init__(
            self,
            nonce,
            transferred_amount,
            locksroot,
            channel_address,
            message_hash,
            signature):

        self.nonce = nonce
        self.transferred_amount = transferred_amount
        self.locksroot = locksroot
        self.channel_address = channel_address
        self.message_hash = message_hash
        self.signature = signature

    def __eq__(self, other):
        if isinstance(other, BalanceProofState):
            return (
                self.nonce == other.nonce and
                self.transferred_amount == other.transferred_amount and
                self.locksroot == other.locksroot and
                self.channel_address == other.channel_address and
                self.message_hash == other.message_hash and
                self.signature == other.signature
            )

        return False

    def __ne__(self, other):
        return not self.__eq__(other)


class MerkleTreeState(State):
    def __init__(self, layers):
        self.layers = layers

    def __eq__(self, other):
        if isinstance(other, MerkleTreeState):
            return self.layers == other.layers

        return False

    def __ne__(self, other):
        return not self.__eq__(other)
