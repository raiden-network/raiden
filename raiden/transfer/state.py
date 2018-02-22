# -*- coding: utf-8 -*-
from raiden.encoding.format import buffer_for
from raiden.encoding import messages
from raiden.transfer.architecture import State
from raiden.constants import UINT256_MAX, UINT64_MAX
from raiden.utils import pex, sha3, typing
# pylint: disable=too-few-public-methods,too-many-arguments,too-many-instance-attributes

CHANNEL_STATE_CLOSED = 'closed'
CHANNEL_STATE_CLOSING = 'waiting_for_close'
CHANNEL_STATE_OPENED = 'opened'
CHANNEL_STATE_SETTLED = 'settled'
CHANNEL_STATE_SETTLING = 'waiting_for_settle'
CHANNEL_STATE_UNUSABLE = 'channel_unusable'

CHANNEL_ALL_VALID_STATES = (
    CHANNEL_STATE_CLOSED,
    CHANNEL_STATE_CLOSING,
    CHANNEL_STATE_OPENED,
    CHANNEL_STATE_SETTLED,
    CHANNEL_STATE_SETTLING,
    CHANNEL_STATE_UNUSABLE,
)

CHANNEL_STATES_PRIOR_TO_CLOSED = (
    CHANNEL_STATE_OPENED,
    CHANNEL_STATE_CLOSING,
)

CHANNEL_AFTER_CLOSE_STATES = (
    CHANNEL_STATE_CLOSED,
    CHANNEL_STATE_SETTLING,
    CHANNEL_STATE_SETTLED,
)


def balanceproof_from_envelope(envelope_message):
    return BalanceProofSignedState(
        envelope_message.nonce,
        envelope_message.transferred_amount,
        envelope_message.locksroot,
        envelope_message.channel,
        envelope_message.message_hash,
        envelope_message.signature,
        envelope_message.sender,
    )


class PaymentNetworkState(State):
    """ Corresponds to a registry smart contract. """

    __slots__ = (
        'address',
        'tokensidentifiers_to_tokennetworks',
        'tokenaddresses_to_tokennetworks',
    )

    def __init__(
            self,
            address: typing.address,
            token_network_list: typing.List['TokenNetworkState']):

        if not isinstance(address, typing.address):
            raise ValueError('address must be an address instance')

        self.address = address
        self.tokensidentifiers_to_tokennetworks = {
            token_network.address: token_network
            for token_network in token_network_list
        }
        self.tokenaddresses_to_tokennetworks = {
            token_network.token_address: token_network
            for token_network in token_network_list
        }

    def __repr__(self):
        return '<PaymentNetworkState id:{}>'.format(pex(self.address))

    def __eq__(self, other):
        return (
            isinstance(other, PaymentNetworkState) and
            self.address == other.address and
            self.tokenaddresses_to_tokennetworks == other.tokenaddresses_to_tokennetworks and
            self.tokensidentifiers_to_tokennetworks == other.tokensidentifiers_to_tokennetworks
        )

    def __ne__(self, other):
        return not self.__eq__(other)


class TokenNetworkState(State):
    """ Corresponds to a channel manager smart contract. """

    __slots__ = (
        'address',
        'token_address',
        'network_graph',
        'channelidentifiers_to_channels',
        'partneraddresses_to_channels',
    )

    def __init__(
            self,
            address: typing.address,
            token_address: typing.address,
            network_graph: 'TokenNetworkGraphState',
            partner_channels: typing.List['NettingChannelState']):

        if not isinstance(address, typing.address):
            raise ValueError('address must be an address instance')

        if not isinstance(token_address, typing.address):
            raise ValueError('token_address must be an address instance')

        if not isinstance(network_graph, TokenNetworkGraphState):
            raise ValueError('network_graph must be a TokenNetworkGraphState instance')

        self.address = address
        self.token_address = token_address
        self.network_graph = network_graph

        self.channelidentifiers_to_channels = {
            channel.identifier: channel
            for channel in partner_channels
        }
        self.partneraddresses_to_channels = {
            channel.partner_state.address: channel
            for channel in partner_channels
        }

    def __repr__(self):
        return '<TokenNetworkState id:{}>'.format(pex(self.address))

    def __eq__(self, other):
        return (
            isinstance(other, TokenNetworkState) and
            self.address == other.address and
            self.token_address == other.token_address and
            self.network_graph == other.network_graph and
            self.channelidentifiers_to_channels == other.channelidentifiers_to_channels and
            self.partneraddresses_to_channels == other.partneraddresses_to_channels
        )

    def __ne__(self, other):
        return not self.__eq__(other)


# This is necessary for the routing only, maybe it should be transient state
# outside of the state tree.
class TokenNetworkGraphState(State):
    """ Stores the existing channels in the channel manager contract, used for
    route finding.
    """

    __slots__ = (
        'network',
    )

    def __init__(self, network):
        self.network = network

    def __repr__(self):
        return '<TokenNetworkGraphState>'

    def __eq__(self, other):
        return (
            isinstance(other, TokenNetworkGraphState) and
            self.network == other.network
        )

    def __ne__(self, other):
        return not self.__eq__(other)


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
            raise ValueError('locksroot must be a keccak256 instance')

        if not isinstance(channel_address, typing.address):
            raise ValueError('channel_address must be an address instance')

        if nonce <= 0:
            raise ValueError('nonce cannot be zero or negative')

        if nonce > UINT64_MAX:
            raise ValueError('nonce is too large')

        if transferred_amount < 0:
            raise ValueError('transferred_amount cannot be negative')

        if transferred_amount > UINT256_MAX:
            raise ValueError('transferred_amount is too large')

        if len(locksroot) != 32:
            raise ValueError('locksroot must have length 32')

        if len(channel_address) != 20:
            raise ValueError('channel is an invalid address')

        self.nonce = nonce
        self.transferred_amount = transferred_amount
        self.locksroot = locksroot
        self.channel_address = channel_address

    def __repr__(self):
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


class BalanceProofSignedState(State):
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
            raise ValueError('signature must be a signature instance')

        if not isinstance(sender, typing.address):
            raise ValueError('sender must be an address instance')

        if nonce <= 0:
            raise ValueError('nonce cannot be zero or negative')

        if nonce > UINT64_MAX:
            raise ValueError('nonce is too large')

        if transferred_amount < 0:
            raise ValueError('transferred_amount cannot be negative')

        if transferred_amount > UINT256_MAX:
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

    def __repr__(self):
        return (
            '<'
            'BalanceProofSignedState nonce:{} transferred_amount:{} '
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
            isinstance(other, BalanceProofSignedState) and
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


class HashTimeLockState(State):
    """ Represents a hash time lock. """

    __slots__ = (
        'amount',
        'expiration',
        'hashlock',
        'encoded',
        'lockhash',
    )

    def __init__(
            self,
            amount: typing.token_amount,
            expiration: typing.block_number,
            hashlock: typing.keccak256):

        if not isinstance(amount, typing.token_amount):
            raise ValueError('amount must be a token_amount instance')

        if not isinstance(expiration, typing.block_number):
            raise ValueError('expiration must be a block_number instance')

        if not isinstance(hashlock, typing.keccak256):
            raise ValueError('hashlock must be a keccak256 instance')

        packed = messages.Lock(buffer_for(messages.Lock))
        packed.amount = amount
        packed.expiration = expiration
        packed.hashlock = hashlock
        encoded = bytes(packed.data)

        self.amount = amount
        self.expiration = expiration
        self.hashlock = hashlock
        self.encoded = encoded
        self.lockhash = sha3(encoded)

    def __repr__(self):
        return '<HashTimeLockState amount:{} expiration:{} hashlock:{}>'.format(
            self.amount,
            self.expiration,
            pex(self.hashlock),
        )

    def __eq__(self, other):
        return (
            isinstance(other, HashTimeLockState) and
            self.amount == other.amount and
            self.expiration == other.expiration and
            self.hashlock == other.hashlock
        )

    def __ne__(self, other):
        return not self.__eq__(other)

    def __hash__(self):
        return self.lockhash


class UnlockPartialProofState(State):
    """ Stores the lock along with its unlocking secret. """

    __slots__ = (
        'lock',
        'secret',
    )

    def __init__(self, lock: HashTimeLockState, secret: typing.secret):
        if not isinstance(lock, HashTimeLockState):
            raise ValueError('lock must be a HashTimeLockState instance')

        if not isinstance(secret, typing.secret):
            raise ValueError('secret must be a secret instance')

        self.lock = lock
        self.secret = secret

    def __repr__(self):
        return '<UnlockPartialProofState lock:{}>'.format(
            self.lock,
        )

    def __eq__(self, other):
        return (
            isinstance(other, UnlockPartialProofState) and
            self.lock == other.lock and
            self.secret == other.secret
        )

    def __ne__(self, other):
        return not self.__eq__(other)


class UnlockProofState(State):
    """ An unlock proof for a given lock. """

    __slots__ = (
        'merkle_proof',
        'lock_encoded',
        'secret',
    )

    def __init__(
            self,
            merkle_proof: typing.List[typing.keccak256],
            lock_encoded,
            secret: typing.secret):

        if not isinstance(secret, typing.secret):
            raise ValueError('secret must be a secret instance')

        self.merkle_proof = merkle_proof
        self.lock_encoded = lock_encoded
        self.secret = secret

    def __repr__(self):
        return '<UnlockProofState>'

    def __eq__(self, other):
        return (
            isinstance(other, UnlockProofState) and
            self.merkle_proof == other.merkle_proof and
            self.lock_encoded == other.lock_encoded and
            self.secret == other.secret
        )

    def __ne__(self, other):
        return not self.__eq__(other)


class TransactionExecutionStatus(State):
    """ Represents the status of a transaction. """
    SUCCESS = 'success'
    FAILURE = 'failure'
    VALID_RESULT_VALUES = (
        SUCCESS,
        FAILURE,
        None,
    )

    def __init__(
            self,
            started_block_number: typing.Optional[typing.block_number],
            finished_block_number: typing.Optional[typing.block_number],
            result):

        # started_block_number is set for the node that sent the transaction,
        # None otherwise
        if not (started_block_number is None or isinstance(started_block_number, int)):
            raise ValueError('started_block_number must be None or a block_number')

        if not (finished_block_number is None or isinstance(finished_block_number, int)):
            raise ValueError('finished_block_number must be None or a block_number')

        if result not in self.VALID_RESULT_VALUES:
            raise ValueError('result must be one of {}'.format(
                ','.join(self.VALID_RESULT_VALUES),
            ))

        self.started_block_number = started_block_number
        self.finished_block_number = finished_block_number
        self.result = result

    def __repr__(self):
        return '<TransactionExecutionStatus started:{} finished:{} result:{}>'.format(
            self.started_block_number,
            self.finished_block_number,
            self.result,
        )

    def __eq__(self, other):
        return (
            isinstance(other, TransactionExecutionStatus) and
            self.started_block_number == other.started_block_number and
            self.finished_block_number == other.finished_block_number and
            self.result == other.result
        )

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


class NettingChannelEndState(State):
    """ The state of one of the nodes in a two party netting channel. """

    __slots__ = (
        'address',
        'contract_balance',
        'hashlocks_to_pendinglocks',
        'hashlocks_to_unclaimedlocks',
        'merkletree',
        'balance_proof',
    )

    def __init__(self, address: typing.address, balance: typing.token_amount):
        if not isinstance(address, typing.address):
            raise ValueError('address must be an address instance')

        if not isinstance(balance, typing.token_amount):
            raise ValueError('balance must be a token_amount isinstance')

        self.address = address
        self.contract_balance = balance

        self.hashlocks_to_pendinglocks = dict()
        self.hashlocks_to_unclaimedlocks = dict()
        self.merkletree = EMPTY_MERKLE_TREE
        self.balance_proof = None

    def __repr__(self):
        return '<NettingChannelEndState address:{} contract_balance:{} merkletree:{}>'.format(
            pex(self.address),
            self.contract_balance,
            self.merkletree,
        )

    def __eq__(self, other):
        return (
            isinstance(other, NettingChannelEndState) and
            self.address == other.address and
            self.contract_balance == other.contract_balance and
            self.hashlocks_to_pendinglocks == other.hashlocks_to_pendinglocks and
            self.hashlocks_to_unclaimedlocks == other.hashlocks_to_unclaimedlocks and
            self.merkletree == other.merkletree and
            self.balance_proof == other.balance_proof
        )

    def __ne__(self, other):
        return not self.__eq__(other)


class NettingChannelState(State):
    """ The state of a netting channel. """

    __slots__ = (
        'identifier',
        'our_state',
        'partner_state',
        'token_address',
        'reveal_timeout',
        'settle_timeout',
        'open_transaction',
        'close_transaction',
        'settle_transaction',
    )

    def __init__(
            self,
            identifier,
            token_address: typing.address,
            reveal_timeout: typing.block_number,
            settle_timeout: typing.block_number,
            our_state: NettingChannelEndState,
            partner_state: NettingChannelEndState,
            open_transaction: TransactionExecutionStatus,
            close_transaction: typing.Optional[TransactionExecutionStatus],
            settle_transaction: typing.Optional[TransactionExecutionStatus]):

        if reveal_timeout >= settle_timeout:
            raise ValueError('reveal_timeout must be smaller than settle_timeout')

        if not isinstance(reveal_timeout, int) or reveal_timeout <= 0:
            raise ValueError('reveal_timeout must be a positive integer')

        if not isinstance(settle_timeout, int) or settle_timeout <= 0:
            raise ValueError('settle_timeout must be a positive integer')

        if not isinstance(open_transaction, TransactionExecutionStatus):
            raise ValueError('open_transaction must be a TransactionExecutionStatus instance')

        if open_transaction.result != TransactionExecutionStatus.SUCCESS:
            raise ValueError(
                'Cannot create a NettingChannelState with a non sucessfull open_transaction'
            )

        valid_close_transaction = (
            close_transaction is None or
            isinstance(close_transaction, TransactionExecutionStatus)
        )
        if not valid_close_transaction:
            raise ValueError('close_transaction must be a TransactionExecutionStatus instance')

        valid_settle_transaction = (
            settle_transaction is None or
            isinstance(settle_transaction, TransactionExecutionStatus)
        )
        if not valid_settle_transaction:
            raise ValueError(
                'settle_transaction must be a TransactionExecutionStatus instance or None'
            )

        self.identifier = identifier
        self.token_address = token_address
        self.reveal_timeout = reveal_timeout
        self.settle_timeout = settle_timeout
        self.our_state = our_state
        self.partner_state = partner_state
        self.open_transaction = open_transaction
        self.close_transaction = close_transaction
        self.settle_transaction = settle_transaction

    def __repr__(self):
        return '<NettingChannelState id:{} opened:{} closed:{} settled:{}>'.format(
            pex(self.identifier),
            self.open_transaction,
            self.close_transaction,
            self.settle_transaction,
        )

    def __eq__(self, other):
        return (
            isinstance(other, NettingChannelState) and
            self.identifier == other.identifier and
            self.our_state == other.our_state and
            self.partner_state == other.partner_state and
            self.token_address == other.token_address and
            self.reveal_timeout == other.reveal_timeout and
            self.settle_timeout == other.settle_timeout and
            self.open_transaction == other.open_transaction and
            self.close_transaction == other.close_transaction and
            self.settle_transaction == other.settle_transaction
        )

    def __ne__(self, other):
        return not self.__eq__(other)


EMPTY_MERKLE_ROOT = b'\x00' * 32
EMPTY_MERKLE_TREE = MerkleTreeState([
    [],                   # the leaves are empty
    [EMPTY_MERKLE_ROOT],  # the root is the constant 0
])
