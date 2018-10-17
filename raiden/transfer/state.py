# pylint: disable=too-few-public-methods,too-many-arguments,too-many-instance-attributes
import random
from collections import defaultdict
from functools import total_ordering

import networkx
from eth_utils import encode_hex, to_canonical_address, to_checksum_address

from raiden.constants import UINT64_MAX, UINT256_MAX
from raiden.encoding import messages
from raiden.encoding.format import buffer_for
from raiden.transfer.architecture import SendMessageEvent, State
from raiden.transfer.merkle_tree import merkleroot
from raiden.transfer.queue_identifier import QueueIdentifier
from raiden.transfer.utils import hash_balance_data, pseudo_random_generator_from_json
from raiden.utils import lpex, pex, serialization, sha3, typing
from raiden.utils.serialization import map_dict, map_list

SecretHashToLock = typing.Dict[typing.SecretHash, 'HashTimeLockState']
SecretHashToPartialUnlockProof = typing.Dict[typing.SecretHash, 'UnlockPartialProofState']
QueueIdsToQueues = typing.Dict[QueueIdentifier, typing.List[SendMessageEvent]]
OptionalBalanceProofState = typing.Optional[typing.Union[
    'BalanceProofSignedState',
    'BalanceProofUnsignedState',
]]

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

NODE_NETWORK_UNKNOWN = 'unknown'
NODE_NETWORK_UNREACHABLE = 'unreachable'
NODE_NETWORK_REACHABLE = 'reachable'


def balanceproof_from_envelope(envelope_message):
    return BalanceProofSignedState(
        envelope_message.nonce,
        envelope_message.transferred_amount,
        envelope_message.locked_amount,
        envelope_message.locksroot,
        envelope_message.token_network_address,
        envelope_message.channel_identifier,
        envelope_message.message_hash,
        envelope_message.signature,
        envelope_message.sender,
        envelope_message.chain_id,
    )


def lockstate_from_lock(lock):
    return HashTimeLockState(
        lock.amount,
        lock.expiration,
        lock.secrethash,
    )


def message_identifier_from_prng(prng):
    return prng.randint(0, UINT64_MAX)


class InitiatorTask(State):
    __slots__ = (
        'token_network_identifier',
        'manager_state',
    )

    def __init__(
            self,
            token_network_identifier: typing.TokenNetworkID,
            manager_state: State,
    ):
        self.token_network_identifier = token_network_identifier
        self.manager_state = manager_state

    def __repr__(self):
        return '<InitiatorTask token_network_identifier:{} state:{}>'.format(
            pex(self.token_network_identifier),
            self.manager_state,
        )

    def __eq__(self, other):
        return (
            isinstance(other, InitiatorTask) and
            self.token_network_identifier == other.token_network_identifier and
            self.manager_state == other.manager_state
        )

    def __ne__(self, other):
        return not self.__eq__(other)

    def to_dict(self) -> typing.Dict[str, typing.Any]:
        return {
            'token_network_identifier': to_checksum_address(self.token_network_identifier),
            'manager_state': self.manager_state,
        }

    @classmethod
    def from_dict(cls, data: typing.Dict[str, typing.Any]) -> 'InitiatorTask':
        return cls(
            token_network_identifier=to_canonical_address(data['token_network_identifier']),
            manager_state=data['manager_state'],
        )


class MediatorTask(State):
    __slots__ = (
        'token_network_identifier',
        'mediator_state',
    )

    def __init__(
            self,
            token_network_identifier: typing.TokenNetworkID,
            mediator_state,
    ):
        self.token_network_identifier = token_network_identifier
        self.mediator_state = mediator_state

    def __repr__(self):
        return '<MediatorTask token_network_identifier:{} state:{}>'.format(
            pex(self.token_network_identifier),
            self.mediator_state,
        )

    def __eq__(self, other):
        return (
            isinstance(other, MediatorTask) and
            self.token_network_identifier == other.token_network_identifier and
            self.mediator_state == other.mediator_state
        )

    def __ne__(self, other):
        return not self.__eq__(other)

    def to_dict(self) -> typing.Dict[str, typing.Any]:
        return {
            'token_network_identifier': to_checksum_address(self.token_network_identifier),
            'mediator_state': self.mediator_state,
        }

    @classmethod
    def from_dict(cls, data: typing.Dict[str, typing.Any]) -> 'MediatorTask':
        restored = cls(
            token_network_identifier=to_canonical_address(data['token_network_identifier']),
            mediator_state=data['mediator_state'],
        )

        return restored


class TargetTask(State):
    __slots__ = (
        'token_network_identifier',
        'channel_identifier',
        'target_state',
    )

    def __init__(
            self,
            token_network_identifier: typing.TokenNetworkID,
            channel_identifier: typing.ChannelID,
            target_state,
    ):
        self.token_network_identifier = token_network_identifier
        self.target_state = target_state
        self.channel_identifier = channel_identifier

    def __repr__(self):
        return '<TargetTask token_network_identifier:{} channel_identifier:{} state:{}>'.format(
            pex(self.token_network_identifier),
            self.channel_identifier,
            self.target_state,
        )

    def __eq__(self, other):
        return (
            isinstance(other, TargetTask) and
            self.token_network_identifier == other.token_network_identifier and
            self.target_state == other.target_state and
            self.channel_identifier == other.channel_identifier
        )

    def __ne__(self, other):
        return not self.__eq__(other)

    def to_dict(self) -> typing.Dict[str, typing.Any]:
        return {
            'token_network_identifier': to_checksum_address(self.token_network_identifier),
            'channel_identifier': self.channel_identifier,
            'target_state': self.target_state,
        }

    @classmethod
    def from_dict(cls, data: typing.Dict[str, typing.Any]) -> 'TargetTask':
        restored = cls(
            token_network_identifier=to_canonical_address(data['token_network_identifier']),
            channel_identifier=data['channel_identifier'],
            target_state=data['target_state'],
        )

        return restored


class ChainState(State):
    """ Umbrella object that stores the per blockchain state.
    For each registry smart contract there must be a payment network. Within the
    payment network the existing token networks and channels are registered.

    TODO: Split the node specific attributes to a "NodeState" class
    """

    __slots__ = (
        'block_number',
        'chain_id',
        'identifiers_to_paymentnetworks',
        'nodeaddresses_to_networkstates',
        'our_address',
        'payment_mapping',
        'pending_transactions',
        'pseudo_random_generator',
        'queueids_to_queues',
    )

    def __init__(
            self,
            pseudo_random_generator: random.Random,
            block_number: typing.BlockNumber,
            our_address: typing.Address,
            chain_id: typing.ChainID,
    ):
        if not isinstance(block_number, typing.T_BlockNumber):
            raise ValueError('block_number must be of BlockNumber type')

        if not isinstance(chain_id, typing.T_ChainID):
            raise ValueError('chain_id must be of ChainID type')

        self.block_number = block_number
        self.chain_id = chain_id
        self.identifiers_to_paymentnetworks = dict()
        self.nodeaddresses_to_networkstates = dict()
        self.our_address = our_address
        self.payment_mapping = PaymentMappingState()
        self.pending_transactions = list()
        self.pseudo_random_generator = pseudo_random_generator
        self.queueids_to_queues: QueueIdsToQueues = dict()

    def __repr__(self):
        return '<ChainState block:{} networks:{} qty_transfers:{} chain_id:{}>'.format(
            self.block_number,
            lpex(self.identifiers_to_paymentnetworks.keys()),
            len(self.payment_mapping.secrethashes_to_task),
            self.chain_id,
        )

    def __eq__(self, other):
        return (
            isinstance(other, ChainState) and
            self.block_number == other.block_number and
            self.pseudo_random_generator.getstate() == other.pseudo_random_generator.getstate() and
            self.queueids_to_queues == other.queueids_to_queues and
            self.identifiers_to_paymentnetworks == other.identifiers_to_paymentnetworks and
            self.nodeaddresses_to_networkstates == other.nodeaddresses_to_networkstates and
            self.payment_mapping == other.payment_mapping and
            self.chain_id == other.chain_id
        )

    def __ne__(self, other):
        return not self.__eq__(other)

    def to_dict(self) -> typing.Dict[str, typing.Any]:
        return {
            'block_number': self.block_number,
            'chain_id': self.chain_id,
            'pseudo_random_generator': self.pseudo_random_generator.getstate(),
            'identifiers_to_paymentnetworks': map_dict(
                to_checksum_address,
                serialization.identity,
                self.identifiers_to_paymentnetworks,
            ),
            'nodeaddresses_to_networkstates': map_dict(
                to_checksum_address,
                serialization.identity,
                self.nodeaddresses_to_networkstates,
            ),
            'our_address': to_checksum_address(self.our_address),
            'payment_mapping': self.payment_mapping,
            'pending_transactions': self.pending_transactions,
            'queueids_to_queues': serialization.serialize_queueid_to_queue(
                self.queueids_to_queues,
            ),
        }

    @classmethod
    def from_dict(cls, data: typing.Dict[str, typing.Any]) -> 'ChainState':
        pseudo_random_generator = pseudo_random_generator_from_json(data)

        restored = cls(
            pseudo_random_generator=pseudo_random_generator,
            block_number=data['block_number'],
            our_address=to_canonical_address(data['our_address']),
            chain_id=data['chain_id'],
        )

        restored.identifiers_to_paymentnetworks = map_dict(
            to_canonical_address,
            serialization.identity,
            data['identifiers_to_paymentnetworks'],
        )
        restored.nodeaddresses_to_networkstates = map_dict(
            to_canonical_address,
            serialization.identity,
            data['nodeaddresses_to_networkstates'],
        )
        restored.payment_mapping = data['payment_mapping']
        restored.pending_transactions = data['pending_transactions']
        restored.queueids_to_queues = serialization.deserialize_queueid_to_queue(
            data['queueids_to_queues'],
        )

        return restored


class PaymentNetworkState(State):
    """ Corresponds to a registry smart contract. """

    __slots__ = (
        'address',
        'tokenidentifiers_to_tokennetworks',
        'tokenaddresses_to_tokennetworks',
    )

    def __init__(
            self,
            address: typing.Address,
            token_network_list: typing.List['TokenNetworkState'],
    ):
        if not isinstance(address, typing.T_Address):
            raise ValueError('address must be an address instance')

        self.address = address
        self.tokenidentifiers_to_tokennetworks = {
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
            self.tokenidentifiers_to_tokennetworks == other.tokenidentifiers_to_tokennetworks
        )

    def __ne__(self, other):
        return not self.__eq__(other)

    def to_dict(self) -> typing.Dict[str, typing.Any]:
        return {
            'address': to_checksum_address(self.address),
            'tokennetworks': [
                network for network in self.tokenidentifiers_to_tokennetworks.values()
            ],
        }

    @classmethod
    def from_dict(cls, data: typing.Dict[str, typing.Any]) -> 'PaymentNetworkState':
        restored = cls(
            address=to_canonical_address(data['address']),
            token_network_list=[
                network for network in data['tokennetworks']
            ],
        )

        return restored


class TokenNetworkState(State):
    """ Corresponds to a token network smart contract. """

    __slots__ = (
        'address',
        'token_address',
        'network_graph',
        'channelidentifiers_to_channels',
        'partneraddresses_to_channels',
    )

    def __init__(self, address: typing.TokenNetworkID, token_address: typing.TokenAddress):

        if not isinstance(address, typing.T_Address):
            raise ValueError('address must be an address instance')

        if not isinstance(token_address, typing.T_Address):
            raise ValueError('token_address must be an address instance')

        self.address = address
        self.token_address = token_address
        self.network_graph = TokenNetworkGraphState(self.address)

        self.channelidentifiers_to_channels = dict()
        self.partneraddresses_to_channels = defaultdict(dict)

    def __repr__(self):
        return '<TokenNetworkState id:{} token:{}>'.format(
            pex(self.address),
            pex(self.token_address),
        )

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

    def to_dict(self) -> typing.Dict[str, typing.Any]:
        return {
            'address': to_checksum_address(self.address),
            'token_address': to_checksum_address(self.token_address),
            'network_graph': self.network_graph,
            'partneraddresses_to_channels': map_dict(
                to_checksum_address,
                serialization.identity,
                self.partneraddresses_to_channels,
            ),
        }

    @classmethod
    def from_dict(cls, data: typing.Dict[str, typing.Any]) -> 'TokenNetworkState':
        restored = cls(
            address=to_canonical_address(data['address']),
            token_address=to_canonical_address(data['token_address']),
        )
        restored.network_graph = data['network_graph']

        recovered_partneraddresses_to_channels = map_dict(
            to_canonical_address,
            serialization.identity,
            data['partneraddresses_to_channels'],
        )

        # for some reason the identifier becomes a string in the dict, recover it
        # recover id -> channel map
        for partner, channelmap in recovered_partneraddresses_to_channels.items():
            restored.partneraddresses_to_channels[partner] = {}
            for channel in channelmap.values():
                restored.channelidentifiers_to_channels[channel.identifier] = channel
                restored.partneraddresses_to_channels[partner][channel.identifier] = channel

        return restored


# This is necessary for the routing only, maybe it should be transient state
# outside of the state tree.
class TokenNetworkGraphState(State):
    """ Stores the existing channels in the channel manager contract, used for
    route finding.
    """

    __slots__ = (
        'token_network_id',
        'network',
        'channel_identifier_to_participants',
    )

    def __init__(self, token_network_address: typing.TokenNetworkID):
        self.token_network_id = token_network_address
        self.network = networkx.Graph()
        self.channel_identifier_to_participants = {}

    def __repr__(self):
        return '<TokenNetworkGraphState num_edges:{}>'.format(len(self.network.edges))

    def __eq__(self, other):
        return (
            isinstance(other, TokenNetworkGraphState) and
            self.token_network_id == other.token_network_id and
            self._to_comparable_graph() == other._to_comparable_graph() and
            self.channel_identifier_to_participants == other.channel_identifier_to_participants
        )

    def __ne__(self, other):
        return not self.__eq__(other)

    def _to_comparable_graph(self):
        return sorted([
            sorted(edge) for edge in self.network.edges()
        ])

    def to_dict(self) -> typing.Dict[str, typing.Any]:
        return {
            'token_network_id': to_checksum_address(self.token_network_id),
            'network': serialization.serialize_networkx_graph(self.network),
            'channel_identifier_to_participants': map_dict(
                str,
                serialization.serialize_participants_tuple,
                self.channel_identifier_to_participants,
            ),
        }

    @classmethod
    def from_dict(cls, data: typing.Dict[str, typing.Any]) -> 'TokenNetworkGraphState':
        restored = cls(
            token_network_address=to_canonical_address(data['token_network_id']),
        )
        restored.network = serialization.deserialize_networkx_graph(data['network'])
        restored.channel_identifier_to_participants = map_dict(
            int,
            serialization.deserialize_participants_tuple,
            data['channel_identifier_to_participants'],
        )

        return restored


class PaymentMappingState(State):
    """ Global map from secrethash to a transfer task.
    This mapping is used to quickly dispatch state changes by secrethash, for
    those that dont have a balance proof, e.g. SecretReveal.
    This mapping forces one task per secrethash, assuming that secrethash collision
    is unlikely. Features like token swaps, that span multiple networks, must
    be encapsulated in a single task to work with this structure.
    """

    # Because of retries, there may be multiple transfers for the same payment,
    # IOW there may be more than one task for the same transfer identifier. For
    # this reason the mapping uses the secrethash as key.
    #
    # Because token swaps span multiple token networks, the state of the
    # payment task is kept in this mapping, instead of inside an arbitrary
    # token network.
    __slots__ = (
        'secrethashes_to_task',
    )

    def __init__(self):
        self.secrethashes_to_task = dict()

    def __repr__(self):
        return '<PaymentMappingState qtd_transfers:{}>'.format(
            len(self.secrethashes_to_task),
        )

    def __eq__(self, other):
        return (
            isinstance(other, PaymentMappingState) and
            self.secrethashes_to_task == other.secrethashes_to_task
        )

    def __ne__(self, other):
        return not self.__eq__(other)

    def to_dict(self) -> typing.Dict[str, typing.Any]:
        return {
            'secrethashes_to_task': map_dict(
                serialization.serialize_bytes,
                serialization.identity,
                self.secrethashes_to_task,
            ),
        }

    @classmethod
    def from_dict(cls, data: typing.Dict[str, typing.Any]) -> 'PaymentMappingState':
        restored = cls()
        restored.secrethashes_to_task = map_dict(
            serialization.deserialize_bytes,
            serialization.identity,
            data['secrethashes_to_task'],
        )

        return restored


class RouteState(State):
    """ A possible route provided by a routing service.

    Args:
        node_address: The address of the next_hop.
        channel_identifier: The channel identifier.
    """

    __slots__ = (
        'node_address',
        'channel_identifier',
    )

    def __init__(
            self,
            node_address: typing.Address,
            channel_identifier: typing.ChannelID,
    ):
        if not isinstance(node_address, typing.T_Address):
            raise ValueError('node_address must be an address instance')

        self.node_address = node_address
        self.channel_identifier = channel_identifier

    def __repr__(self):
        return '<RouteState hop:{node} channel_identifier:{channel_identifier}>'.format(
            node=pex(self.node_address),
            channel_identifier=self.channel_identifier,
        )

    def __eq__(self, other):
        return (
            isinstance(other, RouteState) and
            self.node_address == other.node_address and
            self.channel_identifier == other.channel_identifier
        )

    def __ne__(self, other):
        return not self.__eq__(other)

    def to_dict(self) -> typing.Dict[str, typing.Any]:
        return {
            'node_address': to_checksum_address(self.node_address),
            'channel_identifier': self.channel_identifier,
        }

    @classmethod
    def from_dict(cls, data: typing.Dict[str, typing.Any]) -> 'RouteState':
        restored = cls(
            to_canonical_address(data['node_address']),
            data['channel_identifier'],
        )

        return restored


class BalanceProofUnsignedState(State):
    """ Balance proof from the local node without the signature. """

    __slots__ = (
        'nonce',
        'transferred_amount',
        'locked_amount',
        'locksroot',
        'token_network_identifier',
        'channel_identifier',
        'chain_id',
    )

    def __init__(
            self,
            nonce: int,
            transferred_amount: typing.TokenAmount,
            locked_amount: typing.TokenAmount,
            locksroot: typing.Locksroot,
            token_network_identifier: typing.TokenNetworkID,
            channel_identifier: typing.ChannelID,  # FIXME: is this used anywhere
            chain_id: typing.ChainID,
    ):
        if not isinstance(nonce, int):
            raise ValueError('nonce must be int')

        if not isinstance(transferred_amount, typing.T_TokenAmount):
            raise ValueError('transferred_amount must be a token_amount instance')

        if not isinstance(locked_amount, typing.T_TokenAmount):
            raise ValueError('locked_amount must be a token_amount instance')

        if not isinstance(locksroot, typing.T_Keccak256):
            raise ValueError('locksroot must be a keccak256 instance')

        if not isinstance(channel_identifier, typing.T_ChannelID):
            raise ValueError('channel_identifier must be an T_ChannelID instance')

        if not isinstance(chain_id, typing.T_ChainID):
            raise ValueError('chain_id must be a ChainID instance')

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

        if channel_identifier < 0 or channel_identifier > UINT256_MAX:
            raise ValueError('channel id is invalid')

        self.nonce = nonce
        self.transferred_amount = transferred_amount
        self.locked_amount = locked_amount
        self.locksroot = locksroot
        self.token_network_identifier = token_network_identifier
        self.channel_identifier = channel_identifier
        self.chain_id = chain_id

    def __repr__(self):
        return (
            '<'
            'BalanceProofUnsignedState nonce:{} transferred_amount:{} '
            'locked_amount:{} locksroot:{} token_network:{} channel_identifier:{} chain_id: {}'
            '>'
        ).format(
            self.nonce,
            self.transferred_amount,
            self.locked_amount,
            pex(self.locksroot),
            pex(self.token_network_identifier),
            self.channel_identifier,
            self.chain_id,
        )

    def __eq__(self, other):
        return (
            isinstance(other, BalanceProofUnsignedState) and
            self.nonce == other.nonce and
            self.transferred_amount == other.transferred_amount and
            self.locked_amount == other.locked_amount and
            self.locksroot == other.locksroot and
            self.token_network_identifier == other.token_network_identifier and
            self.channel_identifier == other.channel_identifier and
            self.chain_id == other.chain_id
        )

    def __ne__(self, other):
        return not self.__eq__(other)

    @property
    def balance_hash(self):
        return hash_balance_data(
            transferred_amount=self.transferred_amount,
            locked_amount=self.locked_amount,
            locksroot=self.locksroot,
        )

    def to_dict(self) -> typing.Dict[str, typing.Any]:
        return {
            'nonce': self.nonce,
            'transferred_amount': self.transferred_amount,
            'locked_amount': self.locked_amount,
            'locksroot': serialization.serialize_bytes(self.locksroot),
            'token_network_identifier': to_checksum_address(self.token_network_identifier),
            'channel_identifier': self.channel_identifier,
            'chain_id': self.chain_id,
        }

    @classmethod
    def from_dict(cls, data: typing.Dict[str, typing.Any]) -> 'BalanceProofUnsignedState':
        restored = cls(
            nonce=data['nonce'],
            transferred_amount=data['transferred_amount'],
            locked_amount=data['locked_amount'],
            locksroot=serialization.deserialize_bytes(data['locksroot']),
            token_network_identifier=to_canonical_address(data['token_network_identifier']),
            channel_identifier=data['channel_identifier'],
            chain_id=data['chain_id'],
        )

        return restored


class BalanceProofSignedState(State):
    """ Proof of a channel balance that can be used on-chain to resolve
    disputes.
    """

    __slots__ = (
        'nonce',
        'transferred_amount',
        'locked_amount',
        'locksroot',
        'token_network_identifier',
        'channel_identifier',
        'message_hash',
        'signature',
        'sender',
        'chain_id',
    )

    def __init__(
            self,
            nonce: int,
            transferred_amount: typing.TokenAmount,
            locked_amount: typing.TokenAmount,
            locksroot: typing.Locksroot,
            token_network_identifier: typing.TokenNetworkID,
            channel_identifier: typing.ChannelID,
            message_hash: typing.Keccak256,
            signature: typing.Signature,
            sender: typing.Address,
            chain_id: typing.ChainID,
    ):
        if not isinstance(nonce, int):
            raise ValueError('nonce must be int')

        if not isinstance(transferred_amount, typing.T_TokenAmount):
            raise ValueError('transferred_amount must be a token_amount instance')

        if not isinstance(locked_amount, typing.T_TokenAmount):
            raise ValueError('locked_amount must be a token_amount instance')

        if not isinstance(locksroot, typing.T_Keccak256):
            raise ValueError('locksroot must be a keccak256 instance')

        if not isinstance(token_network_identifier, typing.T_Address):
            raise ValueError('token_network_identifier must be an address instance')

        if not isinstance(channel_identifier, typing.T_ChannelID):
            raise ValueError('channel_identifier must be an ChannelID instance')

        if not isinstance(message_hash, typing.T_Keccak256):
            raise ValueError('message_hash must be a keccak256 instance')

        if not isinstance(signature, typing.T_Signature):
            raise ValueError('signature must be a signature instance')

        if not isinstance(sender, typing.T_Address):
            raise ValueError('sender must be an address instance')

        if not isinstance(chain_id, typing.T_ChainID):
            raise ValueError('chain_id must be a ChainID instance')

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

        if channel_identifier < 0 or channel_identifier > UINT256_MAX:
            raise ValueError('channel id is invalid')

        if len(message_hash) != 32:
            raise ValueError('message_hash is an invalid hash')

        if len(signature) != 65:
            raise ValueError('signature is an invalid signature')

        self.nonce = nonce
        self.transferred_amount = transferred_amount
        self.locked_amount = locked_amount
        self.locksroot = locksroot
        self.token_network_identifier = token_network_identifier
        self.channel_identifier = channel_identifier
        self.message_hash = message_hash
        self.signature = signature
        self.sender = sender
        self.chain_id = chain_id

    def __repr__(self):
        return (
            '<'
            'BalanceProofSignedState nonce:{} transferred_amount:{} '
            'locked_amount:{} locksroot:{} token_network:{} channel_identifier:{} '
            'message_hash:{} signature:{} sender:{} chain_id:{}'
            '>'
        ).format(
            self.nonce,
            self.transferred_amount,
            self.locked_amount,
            pex(self.locksroot),
            pex(self.token_network_identifier),
            self.channel_identifier,
            pex(self.message_hash),
            pex(self.signature),
            pex(self.sender),
            self.chain_id,
        )

    def __eq__(self, other):
        return (
            isinstance(other, BalanceProofSignedState) and
            self.nonce == other.nonce and
            self.transferred_amount == other.transferred_amount and
            self.locked_amount == other.locked_amount and
            self.locksroot == other.locksroot and
            self.token_network_identifier == other.token_network_identifier and
            self.channel_identifier == other.channel_identifier and
            self.message_hash == other.message_hash and
            self.signature == other.signature and
            self.sender == other.sender and
            self.chain_id == other.chain_id
        )

    def __ne__(self, other):
        return not self.__eq__(other)

    @property
    def balance_hash(self):
        return hash_balance_data(
            transferred_amount=self.transferred_amount,
            locked_amount=self.locked_amount,
            locksroot=self.locksroot,
        )

    def to_dict(self) -> typing.Dict[str, typing.Any]:
        return {
            'nonce': self.nonce,
            'transferred_amount': self.transferred_amount,
            'locked_amount': self.locked_amount,
            'locksroot': serialization.serialize_bytes(self.locksroot),
            'token_network_identifier': to_checksum_address(self.token_network_identifier),
            'channel_identifier': self.channel_identifier,
            'message_hash': serialization.serialize_bytes(self.message_hash),
            'signature': serialization.serialize_bytes(self.signature),
            'sender': to_checksum_address(self.sender),
            'chain_id': self.chain_id,
        }

    @classmethod
    def from_dict(cls, data: typing.Dict[str, typing.Any]) -> 'BalanceProofSignedState':
        restored = cls(
            nonce=data['nonce'],
            transferred_amount=data['transferred_amount'],
            locked_amount=data['locked_amount'],
            locksroot=serialization.deserialize_bytes(data['locksroot']),
            token_network_identifier=to_canonical_address(data['token_network_identifier']),
            channel_identifier=data['channel_identifier'],
            message_hash=serialization.deserialize_bytes(data['message_hash']),
            signature=serialization.deserialize_bytes(data['signature']),
            sender=to_canonical_address(data['sender']),
            chain_id=data['chain_id'],
        )

        return restored


class HashTimeLockState(State):
    """ Represents a hash time lock. """

    __slots__ = (
        'amount',
        'expiration',
        'secrethash',
        'encoded',
        'lockhash',
    )

    def __init__(
            self,
            amount: typing.PaymentAmount,
            expiration: typing.BlockExpiration,
            secrethash: typing.SecretHash,
    ):
        if not isinstance(amount, typing.T_TokenAmount):
            raise ValueError('amount must be a token_amount instance')

        if not isinstance(expiration, typing.T_BlockNumber):
            raise ValueError('expiration must be a block_number instance')

        if not isinstance(secrethash, typing.T_Keccak256):
            raise ValueError('secrethash must be a keccak256 instance')

        packed = messages.Lock(buffer_for(messages.Lock))
        packed.amount = amount
        packed.expiration = expiration
        packed.secrethash = secrethash
        encoded = bytes(packed.data)

        self.amount = amount
        self.expiration = expiration
        self.secrethash = secrethash
        self.encoded = encoded
        self.lockhash: typing.LockHash = typing.LockHash(sha3(encoded))

    def __repr__(self):
        return '<HashTimeLockState amount:{} expiration:{} secrethash:{}>'.format(
            self.amount,
            self.expiration,
            pex(self.secrethash),
        )

    def __eq__(self, other):
        return (
            isinstance(other, HashTimeLockState) and
            self.amount == other.amount and
            self.expiration == other.expiration and
            self.secrethash == other.secrethash
        )

    def __ne__(self, other):
        return not self.__eq__(other)

    def __hash__(self):
        return self.lockhash

    def to_dict(self) -> typing.Dict[str, typing.Any]:
        return {
            'amount': self.amount,
            'expiration': self.expiration,
            'secrethash': serialization.serialize_bytes(self.secrethash),
        }

    @classmethod
    def from_dict(cls, data: typing.Dict[str, typing.Any]) -> 'HashTimeLockState':
        restored = cls(
            amount=data['amount'],
            expiration=data['expiration'],
            secrethash=serialization.deserialize_bytes(data['secrethash']),
        )

        return restored


class UnlockPartialProofState(State):
    """ Stores the lock along with its unlocking secret. """

    __slots__ = (
        'lock',
        'secret',
        'amount',
        'expiration',
        'secrethash',
        'encoded',
        'lockhash',
    )

    def __init__(self, lock: HashTimeLockState, secret: typing.Secret):
        if not isinstance(lock, HashTimeLockState):
            raise ValueError('lock must be a HashTimeLockState instance')

        if not isinstance(secret, typing.T_Secret):
            raise ValueError('secret must be a secret instance')

        self.lock = lock
        self.secret = secret
        self.amount = lock.amount
        self.expiration = lock.expiration
        self.secrethash = lock.secrethash
        self.encoded = lock.encoded
        self.lockhash = lock.lockhash

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

    def to_dict(self) -> typing.Dict[str, typing.Any]:
        return {
            'lock': self.lock,
            'secret': serialization.serialize_bytes(self.secret),
        }

    @classmethod
    def from_dict(cls, data: typing.Dict[str, typing.Any]) -> 'UnlockPartialProofState':
        restored = cls(
            lock=data['lock'],
            secret=serialization.deserialize_bytes(data['secret']),
        )

        return restored


class UnlockProofState(State):
    """ An unlock proof for a given lock. """

    __slots__ = (
        'merkle_proof',
        'lock_encoded',
        'secret',
    )

    def __init__(
            self,
            merkle_proof: typing.List[typing.Keccak256],
            lock_encoded: bytes,
            secret: typing.Secret,
    ):

        if not isinstance(secret, typing.T_Secret):
            raise ValueError('secret must be a secret instance')

        self.merkle_proof = merkle_proof
        self.lock_encoded = lock_encoded
        self.secret = secret

    def __repr__(self):
        full_proof = [encode_hex(entry) for entry in self.merkle_proof]
        return f'<UnlockProofState proof:{full_proof} lock:{encode_hex(self.lock_encoded)}>'

    def __eq__(self, other):
        return (
            isinstance(other, UnlockProofState) and
            self.merkle_proof == other.merkle_proof and
            self.lock_encoded == other.lock_encoded and
            self.secret == other.secret
        )

    def __ne__(self, other):
        return not self.__eq__(other)

    def to_dict(self) -> typing.Dict[str, typing.Any]:
        return {
            'merkle_proof': map_list(serialization.serialize_bytes, self.merkle_proof),
            'lock_encoded': serialization.serialize_bytes(self.lock_encoded),
            'secret': serialization.serialize_bytes(self.secret),
        }

    @classmethod
    def from_dict(cls, data: typing.Dict[str, typing.Any]) -> 'UnlockProofState':
        restored = cls(
            merkle_proof=map_list(serialization.deserialize_bytes, data['merkle_proof']),
            lock_encoded=serialization.deserialize_bytes(data['lock_encoded']),
            secret=serialization.deserialize_bytes(data['secret']),
        )

        return restored


class TransactionExecutionStatus(State):
    """ Represents the status of a transaction. """
    SUCCESS = 'success'
    FAILURE = 'failure'
    VALID_RESULT_VALUES = (
        SUCCESS,
        FAILURE,
    )

    def __init__(
            self,
            started_block_number: typing.BlockNumber = None,
            finished_block_number: typing.BlockNumber = None,
            result: str = None,
    ):

        is_valid_start = (
            started_block_number is None or
            isinstance(started_block_number, typing.T_BlockNumber)
        )
        is_valid_finish = (
            finished_block_number is None or
            isinstance(finished_block_number, typing.T_BlockNumber)
        )
        is_valid_result = (
            result is None or
            result in self.VALID_RESULT_VALUES
        )

        if not is_valid_start:
            raise ValueError('started_block_number must be None or a block_number')

        if not is_valid_finish:
            raise ValueError('finished_block_number must be None or a block_number')

        if not is_valid_result:
            raise ValueError(f"result must be one of '{self.SUCCESS}', '{self.FAILURE}' or 'None'")

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

    def to_dict(self) -> typing.Dict[str, typing.Any]:
        result: typing.Dict[str, typing.Any] = {}
        if self.started_block_number is not None:
            result['started_block_number'] = self.started_block_number
        if self.finished_block_number is not None:
            result['finished_block_number'] = self.finished_block_number
        if self.result is not None:
            result['result'] = self.result

        return result

    @classmethod
    def from_dict(cls, data: typing.Dict[str, typing.Any]) -> 'TransactionExecutionStatus':
        restored = cls(
            started_block_number=data.get('started_block_number'),
            finished_block_number=data.get('finished_block_number'),
            result=data.get('result'),
        )

        return restored


class MerkleTreeState(State):
    __slots__ = (
        'layers',
    )

    def __init__(self, layers: typing.List[typing.List[typing.Keccak256]]):
        self.layers = layers

    def __repr__(self):
        return '<MerkleTreeState root:{}>'.format(
            pex(merkleroot(self)),
        )

    def __eq__(self, other):
        return (
            isinstance(other, MerkleTreeState) and
            self.layers == other.layers
        )

    def __ne__(self, other):
        return not self.__eq__(other)

    def to_dict(self) -> typing.Dict[str, typing.Any]:
        return {
            'layers': serialization.serialize_merkletree_layers(self.layers),
        }

    @classmethod
    def from_dict(cls, data: typing.Dict[str, typing.Any]) -> 'MerkleTreeState':
        restored = cls(
            layers=serialization.deserialize_merkletree_layers(data['layers']),
        )

        return restored


class NettingChannelEndState(State):
    """ The state of one of the nodes in a two party netting channel. """

    __slots__ = (
        'address',
        'contract_balance',
        'secrethashes_to_lockedlocks',
        'secrethashes_to_unlockedlocks',
        'secrethashes_to_onchain_unlockedlocks',
        'merkletree',
        'balance_proof',
    )

    def __init__(self, address: typing.Address, balance: typing.Balance):
        if not isinstance(address, typing.T_Address):
            raise ValueError('address must be an address instance')

        if not isinstance(balance, typing.T_TokenAmount):
            raise ValueError('balance must be a token_amount isinstance')

        self.address = address
        self.contract_balance = balance

        self.secrethashes_to_lockedlocks: SecretHashToLock = dict()
        self.secrethashes_to_unlockedlocks: SecretHashToPartialUnlockProof = dict()
        self.secrethashes_to_onchain_unlockedlocks: SecretHashToPartialUnlockProof = dict()
        self.merkletree = EMPTY_MERKLE_TREE
        self.balance_proof: OptionalBalanceProofState = None

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
            self.secrethashes_to_lockedlocks == other.secrethashes_to_lockedlocks and
            self.secrethashes_to_unlockedlocks == other.secrethashes_to_unlockedlocks and
            (
                self.secrethashes_to_onchain_unlockedlocks ==
                other.secrethashes_to_onchain_unlockedlocks
            ) and
            self.merkletree == other.merkletree and
            self.balance_proof == other.balance_proof
        )

    def __ne__(self, other):
        return not self.__eq__(other)

    def to_dict(self) -> typing.Dict[str, typing.Any]:
        result = {
            'address': to_checksum_address(self.address),
            'contract_balance': self.contract_balance,
            'secrethashes_to_lockedlocks': map_dict(
                serialization.serialize_bytes,
                serialization.identity,
                self.secrethashes_to_lockedlocks,
            ),
            'secrethashes_to_unlockedlocks': map_dict(
                serialization.serialize_bytes,
                serialization.identity,
                self.secrethashes_to_unlockedlocks,
            ),
            'secrethashes_to_onchain_unlockedlocks': map_dict(
                serialization.serialize_bytes,
                serialization.identity,
                self.secrethashes_to_onchain_unlockedlocks,
            ),
            'merkletree': self.merkletree,
        }
        if self.balance_proof is not None:
            result['balance_proof'] = self.balance_proof

        return result

    @classmethod
    def from_dict(cls, data: typing.Dict[str, typing.Any]) -> 'NettingChannelEndState':
        restored = cls(
            address=to_canonical_address(data['address']),
            balance=data['contract_balance'],
        )
        restored.secrethashes_to_lockedlocks = map_dict(
            serialization.deserialize_bytes,
            serialization.identity,
            data['secrethashes_to_lockedlocks'],
        )
        restored.secrethashes_to_unlockedlocks = map_dict(
            serialization.deserialize_bytes,
            serialization.identity,
            data['secrethashes_to_unlockedlocks'],
        )
        restored.secrethashes_to_onchain_unlockedlocks = map_dict(
            serialization.deserialize_bytes,
            serialization.identity,
            data['secrethashes_to_onchain_unlockedlocks'],
        )
        restored.merkletree = data['merkletree']

        balance_proof = data.get('balance_proof')
        if data is not None:
            restored.balance_proof = balance_proof

        return restored


class NettingChannelState(State):
    """ The state of a netting channel. """

    __slots__ = (
        'identifier',
        'chain_id',
        'token_address',
        'payment_network_identifier',
        'token_network_identifier',
        'reveal_timeout',
        'settle_timeout',
        'our_state',
        'partner_state',
        'deposit_transaction_queue',
        'open_transaction',
        'close_transaction',
        'settle_transaction',
        'update_transaction',
        'our_unlock_transaction',
    )

    def __init__(
            self,
            identifier: typing.ChannelID,
            chain_id: typing.ChainID,
            token_address: typing.Address,
            payment_network_identifier: typing.PaymentNetworkID,
            token_network_identifier: typing.TokenNetworkID,
            reveal_timeout: typing.BlockNumber,
            settle_timeout: typing.BlockNumber,
            our_state: NettingChannelEndState,
            partner_state: NettingChannelEndState,
            open_transaction: TransactionExecutionStatus,
            close_transaction: TransactionExecutionStatus = None,
            settle_transaction: TransactionExecutionStatus = None,
            update_transaction: TransactionExecutionStatus = None,
    ):

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
                'Cannot create a NettingChannelState with a non successfull open_transaction',
            )

        if not isinstance(identifier, typing.T_ChannelID):
            raise ValueError('channel identifier must be of type T_ChannelID')

        if identifier < 0 or identifier > UINT256_MAX:
            raise ValueError('channel identifier should be a uint256')

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
                'settle_transaction must be a TransactionExecutionStatus instance or None',
            )

        self.identifier = identifier
        self.chain_id = chain_id
        self.token_address = token_address
        self.payment_network_identifier = payment_network_identifier
        self.token_network_identifier = token_network_identifier
        self.reveal_timeout = reveal_timeout
        self.settle_timeout = settle_timeout
        self.our_state = our_state
        self.partner_state = partner_state
        self.deposit_transaction_queue: typing.List[TransactionOrder] = list()
        self.open_transaction = open_transaction
        self.close_transaction = close_transaction
        self.settle_transaction = settle_transaction
        self.update_transaction = update_transaction
        self.our_unlock_transaction: TransactionExecutionStatus = None

    def __repr__(self):
        return '<NettingChannelState id:{} opened:{} closed:{} settled:{} updated:{}>'.format(
            self.identifier,
            self.open_transaction,
            self.close_transaction,
            self.settle_transaction,
            self.update_transaction,
        )

    def __eq__(self, other):
        return (
            isinstance(other, NettingChannelState) and
            self.identifier == other.identifier and
            self.payment_network_identifier == other.payment_network_identifier and
            self.our_state == other.our_state and
            self.partner_state == other.partner_state and
            self.token_address == other.token_address and
            self.token_network_identifier == other.token_network_identifier and
            self.reveal_timeout == other.reveal_timeout and
            self.settle_timeout == other.settle_timeout and
            self.deposit_transaction_queue == other.deposit_transaction_queue and
            self.open_transaction == other.open_transaction and
            self.close_transaction == other.close_transaction and
            self.settle_transaction == other.settle_transaction and
            self.update_transaction == other.update_transaction and
            self.our_unlock_transaction == other.our_unlock_transaction and
            self.chain_id == other.chain_id
        )

    @property
    def our_total_deposit(self):
        return self.our_state.contract_balance

    @property
    def partner_total_deposit(self):
        return self.partner_state.contract_balance

    def __ne__(self, other):
        return not self.__eq__(other)

    def to_dict(self) -> typing.Dict[str, typing.Any]:
        result = {
            'identifier': self.identifier,
            'chain_id': self.chain_id,
            'token_address': to_checksum_address(self.token_address),
            'payment_network_identifier': to_checksum_address(self.payment_network_identifier),
            'token_network_identifier': to_checksum_address(self.token_network_identifier),
            'reveal_timeout': self.reveal_timeout,
            'settle_timeout': self.settle_timeout,
            'our_state': self.our_state,
            'partner_state': self.partner_state,
            'open_transaction': self.open_transaction,
            'deposit_transaction_queue': self.deposit_transaction_queue,
        }

        if self.close_transaction is not None:
            result['close_transaction'] = self.close_transaction
        if self.settle_transaction is not None:
            result['settle_transaction'] = self.settle_transaction
        if self.update_transaction is not None:
            result['update_transaction'] = self.update_transaction
        if self.our_unlock_transaction is not None:
            result['our_unlock_transaction'] = self.our_unlock_transaction

        return result

    @classmethod
    def from_dict(cls, data: typing.Dict[str, typing.Any]) -> 'NettingChannelState':
        restored = cls(
            identifier=data['identifier'],
            chain_id=data['chain_id'],
            token_address=to_canonical_address(data['token_address']),
            payment_network_identifier=to_canonical_address(data['payment_network_identifier']),
            token_network_identifier=to_canonical_address(data['token_network_identifier']),
            reveal_timeout=data['reveal_timeout'],
            settle_timeout=data['settle_timeout'],
            our_state=data['our_state'],
            partner_state=data['partner_state'],
            open_transaction=data['open_transaction'],
        )
        close_transaction = data.get('close_transaction')
        if close_transaction is not None:
            restored.close_transaction = close_transaction
        settle_transaction = data.get('settle_transaction')
        if settle_transaction is not None:
            restored.settle_transaction = settle_transaction
        update_transaction = data.get('update_transaction')
        if update_transaction is not None:
            restored.update_transaction = update_transaction
        our_unlock_transaction = data.get('our_unlock_transaction')
        if our_unlock_transaction is not None:
            restored.our_unlock_transaction = our_unlock_transaction

        restored.deposit_transaction_queue = data['deposit_transaction_queue']

        return restored


@total_ordering
class TransactionChannelNewBalance(State):

    __slots__ = (
        'participant_address',
        'contract_balance',
        'deposit_block_number',
    )

    def __init__(
            self,
            participant_address: typing.Address,
            contract_balance: typing.TokenAmount,
            deposit_block_number: typing.BlockNumber,
    ):
        if not isinstance(participant_address, typing.T_Address):
            raise ValueError('participant_address must be of type address')

        if not isinstance(contract_balance, typing.T_TokenAmount):
            raise ValueError('contract_balance must be of type token_amount')

        if not isinstance(deposit_block_number, typing.T_BlockNumber):
            raise ValueError('deposit_block_number must be of type block_number')

        self.participant_address = participant_address
        self.contract_balance = contract_balance
        self.deposit_block_number = deposit_block_number

    def __repr__(self):
        return '<TransactionChannelNewBalance participant:{} balance:{} at_block:{}>'.format(
            pex(self.participant_address),
            self.contract_balance,
            self.deposit_block_number,
        )

    def __eq__(self, other):
        if not isinstance(other, TransactionChannelNewBalance):
            return NotImplemented
        return (
            self.participant_address == other.participant_address and
            self.contract_balance == other.contract_balance and
            self.deposit_block_number == other.deposit_block_number
        )

    def __lt__(self, other):
        if not isinstance(other, TransactionChannelNewBalance):
            return NotImplemented
        return (
            self.participant_address < other.participant_address and
            self.contract_balance < other.contract_balance and
            self.deposit_block_number < other.deposit_block_number
        )

    def to_dict(self) -> typing.Dict[str, typing.Any]:
        return {
            'participant_address': to_checksum_address(self.participant_address),
            'contract_balance': self.contract_balance,
            'deposit_block_number': self.deposit_block_number,
        }

    @classmethod
    def from_dict(cls, data: typing.Dict[str, typing.Any]) -> 'TransactionChannelNewBalance':
        restored = cls(
            participant_address=to_canonical_address(data['participant_address']),
            contract_balance=data['contract_balance'],
            deposit_block_number=data['deposit_block_number'],
        )

        return restored


@total_ordering
class TransactionOrder(State):
    def __init__(
            self,
            block_number: typing.BlockNumber,
            transaction: TransactionChannelNewBalance,
    ):
        self.block_number = block_number
        self.transaction = transaction

    def __repr__(self):
        return '<TransactionOrder block_number:{} transaction:{}>'.format(
            self.block_number,
            self.transaction,
        )

    def __eq__(self, other):
        return (
            isinstance(other, TransactionOrder) and
            self.block_number == other.block_number and
            self.transaction == other.transaction
        )

    def __ne__(self, other):
        return not self.__eq__(other)

    def __lt__(self, other):
        if not isinstance(other, TransactionOrder):
            return NotImplemented
        return (
            self.block_number < other.block_number and
            self.transaction < other.transaction
        )

    def to_dict(self) -> typing.Dict[str, typing.Any]:
        return {
            'block_number': self.block_number,
            'transaction': self.transaction,
        }

    @classmethod
    def from_dict(cls, data: typing.Dict[str, typing.Any]) -> 'TransactionOrder':
        restored = cls(
            block_number=data['block_number'],
            transaction=data['transaction'],
        )

        return restored


EMPTY_MERKLE_ROOT: typing.Locksroot = bytes(32)
EMPTY_MERKLE_TREE = MerkleTreeState([
    [],                   # the leaves are empty
    [EMPTY_MERKLE_ROOT],  # the root is the constant 0
])
