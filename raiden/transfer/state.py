# pylint: disable=too-few-public-methods,too-many-arguments,too-many-instance-attributes
import random
from collections import defaultdict
from functools import total_ordering
from random import Random
from typing import TYPE_CHECKING, Tuple

import networkx
from eth_utils import encode_hex, to_canonical_address, to_checksum_address

from raiden.constants import EMPTY_MERKLE_ROOT, UINT64_MAX, UINT256_MAX
from raiden.encoding import messages
from raiden.encoding.format import buffer_for
from raiden.transfer.architecture import ContractSendEvent, SendMessageEvent, State
from raiden.transfer.identifiers import CanonicalIdentifier, QueueIdentifier
from raiden.transfer.merkle_tree import merkleroot
from raiden.transfer.utils import hash_balance_data, pseudo_random_generator_from_json
from raiden.utils import lpex, pex, serialization, sha3
from raiden.utils.serialization import map_dict, map_list, serialize_bytes
from raiden.utils.typing import (
    AdditionalHash,
    Address,
    Any,
    Balance,
    BalanceHash,
    BlockExpiration,
    BlockHash,
    BlockNumber,
    BlockTimeout,
    ChainID,
    ChannelID,
    ChannelMap,
    Dict,
    FeeAmount,
    Keccak256,
    List,
    LockHash,
    Locksroot,
    MessageID,
    Nonce,
    Optional,
    PaymentNetworkID,
    PaymentWithFeeAmount,
    Secret,
    SecretHash,
    Signature,
    T_Address,
    T_BlockHash,
    T_BlockNumber,
    T_ChainID,
    T_ChannelID,
    T_Keccak256,
    T_PaymentWithFeeAmount,
    T_Secret,
    T_Signature,
    T_TokenAmount,
    TokenAddress,
    TokenAmount,
    TokenNetworkAddress,
    TokenNetworkID,
    Union,
)

if TYPE_CHECKING:
    # pylint: disable=unused-import
    from messages import EnvelopeMessage
    from raiden.transfer.mediated_transfer.state import MediatorTransferState, TargetTransferState
    from raiden.transfer.mediated_transfer.state import InitiatorPaymentState

SecretHashToLock = Dict[SecretHash, "HashTimeLockState"]
SecretHashToPartialUnlockProof = Dict[SecretHash, "UnlockPartialProofState"]
QueueIdsToQueues = Dict[QueueIdentifier, List[SendMessageEvent]]
OptionalBalanceProofState = Optional[Union["BalanceProofSignedState", "BalanceProofUnsignedState"]]

CHANNEL_STATE_CLOSED = "closed"
CHANNEL_STATE_CLOSING = "waiting_for_close"
CHANNEL_STATE_OPENED = "opened"
CHANNEL_STATE_SETTLED = "settled"
CHANNEL_STATE_SETTLING = "waiting_for_settle"
CHANNEL_STATE_UNUSABLE = "channel_unusable"

CHANNEL_ALL_VALID_STATES = (
    CHANNEL_STATE_CLOSED,
    CHANNEL_STATE_CLOSING,
    CHANNEL_STATE_OPENED,
    CHANNEL_STATE_SETTLED,
    CHANNEL_STATE_SETTLING,
    CHANNEL_STATE_UNUSABLE,
)

CHANNEL_STATES_PRIOR_TO_CLOSED = (CHANNEL_STATE_OPENED, CHANNEL_STATE_CLOSING)

CHANNEL_AFTER_CLOSE_STATES = (CHANNEL_STATE_CLOSED, CHANNEL_STATE_SETTLING, CHANNEL_STATE_SETTLED)

NODE_NETWORK_UNKNOWN = "unknown"
NODE_NETWORK_UNREACHABLE = "unreachable"
NODE_NETWORK_REACHABLE = "reachable"


def balanceproof_from_envelope(envelope_message: "EnvelopeMessage",) -> "BalanceProofSignedState":
    return BalanceProofSignedState(
        nonce=envelope_message.nonce,
        transferred_amount=envelope_message.transferred_amount,
        locked_amount=envelope_message.locked_amount,
        locksroot=envelope_message.locksroot,
        message_hash=envelope_message.message_hash,
        signature=envelope_message.signature,
        sender=envelope_message.sender,
        canonical_identifier=CanonicalIdentifier(
            chain_identifier=envelope_message.chain_id,
            token_network_address=envelope_message.token_network_address,
            channel_identifier=envelope_message.channel_identifier,
        ),
    )


def make_empty_merkle_tree() -> "MerkleTreeState":
    return MerkleTreeState(
        [[], [Keccak256(EMPTY_MERKLE_ROOT)]]  # the leaves are empty  # the root is the constant 0
    )


def message_identifier_from_prng(prng: Random) -> MessageID:
    return MessageID(prng.randint(0, UINT64_MAX))


def to_comparable_graph(network: networkx.Graph) -> List[List[Any]]:
    return sorted(sorted(edge) for edge in network.edges())


class TransferTask(State):
    # TODO: When we turn these into dataclasses it would be a good time to move common attributes
    # of all transfer tasks like the `token_network_identifier` into the common subclass
    pass


class InitiatorTask(TransferTask):
    __slots__ = ("token_network_identifier", "manager_state")

    def __init__(
        self, token_network_identifier: TokenNetworkID, manager_state: "InitiatorPaymentState"
    ) -> None:
        self.token_network_identifier = token_network_identifier
        self.manager_state = manager_state

    def __repr__(self) -> str:
        return "<InitiatorTask token_network_identifier:{} state:{}>".format(
            pex(self.token_network_identifier), self.manager_state
        )

    def __eq__(self, other: Any) -> bool:
        return (
            isinstance(other, InitiatorTask)
            and self.token_network_identifier == other.token_network_identifier
            and self.manager_state == other.manager_state
        )

    def __ne__(self, other: Any) -> bool:
        return not self.__eq__(other)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "token_network_identifier": to_checksum_address(self.token_network_identifier),
            "manager_state": self.manager_state,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "InitiatorTask":
        return cls(
            token_network_identifier=to_canonical_address(data["token_network_identifier"]),
            manager_state=data["manager_state"],
        )


class MediatorTask(TransferTask):
    __slots__ = ("token_network_identifier", "mediator_state")

    def __init__(
        self, token_network_identifier: TokenNetworkID, mediator_state: "MediatorTransferState"
    ) -> None:
        self.token_network_identifier = token_network_identifier
        self.mediator_state = mediator_state

    def __repr__(self) -> str:
        return "<MediatorTask token_network_identifier:{} state:{}>".format(
            pex(self.token_network_identifier), self.mediator_state
        )

    def __eq__(self, other: Any) -> bool:
        return (
            isinstance(other, MediatorTask)
            and self.token_network_identifier == other.token_network_identifier
            and self.mediator_state == other.mediator_state
        )

    def __ne__(self, other: Any) -> bool:
        return not self.__eq__(other)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "token_network_identifier": to_checksum_address(self.token_network_identifier),
            "mediator_state": self.mediator_state,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "MediatorTask":
        restored = cls(
            token_network_identifier=to_canonical_address(data["token_network_identifier"]),
            mediator_state=data["mediator_state"],
        )

        return restored


class TargetTask(TransferTask):
    __slots__ = ("canonical_identifier", "target_state")

    def __init__(
        self, canonical_identifier: CanonicalIdentifier, target_state: "TargetTransferState"
    ) -> None:
        self.canonical_identifier = canonical_identifier
        self.target_state = target_state

    def __repr__(self) -> str:
        return "<TargetTask token_network_identifier:{} channel_identifier:{} state:{}>".format(
            pex(self.token_network_identifier), self.channel_identifier, self.target_state
        )

    def __eq__(self, other: Any) -> bool:
        return (
            isinstance(other, TargetTask)
            and self.token_network_identifier == other.token_network_identifier
            and self.target_state == other.target_state
            and self.channel_identifier == other.channel_identifier
        )

    def __ne__(self, other: Any) -> bool:
        return not self.__eq__(other)

    @property
    def token_network_identifier(self) -> TokenNetworkID:
        return TokenNetworkID(self.canonical_identifier.token_network_address)

    @property
    def channel_identifier(self) -> ChannelID:
        return self.canonical_identifier.channel_identifier

    def to_dict(self) -> Dict[str, Any]:
        return {
            "canonical_identifier": self.canonical_identifier.to_dict(),
            "target_state": self.target_state,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "TargetTask":
        restored = cls(
            canonical_identifier=CanonicalIdentifier.from_dict(data["canonical_identifier"]),
            target_state=data["target_state"],
        )

        return restored


class ChainState(State):
    """ Umbrella object that stores the per blockchain state.
    For each registry smart contract there must be a payment network. Within the
    payment network the existing token networks and channels are registered.

    TODO: Split the node specific attributes to a "NodeState" class
    """

    def __init__(
        self,
        pseudo_random_generator: random.Random,
        block_number: BlockNumber,
        block_hash: BlockHash,
        our_address: Address,
        chain_id: ChainID,
    ) -> None:
        if not isinstance(block_number, T_BlockNumber):
            raise ValueError("block_number must be of BlockNumber type")

        if not isinstance(block_hash, T_BlockHash):
            raise ValueError("block_hash must be of BlockHash type")

        if not isinstance(chain_id, T_ChainID):
            raise ValueError("chain_id must be of ChainID type")

        self.block_number = block_number
        self.block_hash = block_hash
        self.chain_id = chain_id
        self.identifiers_to_paymentnetworks: Dict[PaymentNetworkID, PaymentNetworkState] = dict()
        self.nodeaddresses_to_networkstates: Dict[Address, str] = dict()
        self.our_address = our_address
        self.payment_mapping = PaymentMappingState()
        self.pending_transactions: List[ContractSendEvent] = list()
        self.pseudo_random_generator = pseudo_random_generator
        self.queueids_to_queues: QueueIdsToQueues = dict()
        self.last_transport_authdata: Optional[str] = None
        self.tokennetworkaddresses_to_paymentnetworkaddresses: Dict[
            TokenNetworkAddress, PaymentNetworkID
        ] = {}

    def __repr__(self) -> str:
        return (
            "<ChainState block_number:{} block_hash:{} networks:{} "
            "qty_transfers:{} chain_id:{}>"
        ).format(
            self.block_number,
            pex(self.block_hash),
            lpex(self.identifiers_to_paymentnetworks.keys()),
            len(self.payment_mapping.secrethashes_to_task),
            self.chain_id,
        )

    def __eq__(self, other: Any) -> bool:
        if other is None:
            return False

        our_tnpn = self.tokennetworkaddresses_to_paymentnetworkaddresses
        other_tnpn = other.tokennetworkaddresses_to_paymentnetworkaddresses

        return (
            isinstance(other, ChainState)
            and self.block_number == other.block_number
            and self.block_hash == other.block_hash
            and self.pseudo_random_generator.getstate() == other.pseudo_random_generator.getstate()
            and self.queueids_to_queues == other.queueids_to_queues
            and self.identifiers_to_paymentnetworks == other.identifiers_to_paymentnetworks
            and self.nodeaddresses_to_networkstates == other.nodeaddresses_to_networkstates
            and self.payment_mapping == other.payment_mapping
            and self.chain_id == other.chain_id
            and self.last_transport_authdata == other.last_transport_authdata
            and our_tnpn == other_tnpn
        )

    def __ne__(self, other: Any) -> bool:
        return not self.__eq__(other)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "block_number": str(self.block_number),
            "block_hash": serialize_bytes(self.block_hash),
            "chain_id": self.chain_id,
            "pseudo_random_generator": self.pseudo_random_generator.getstate(),
            "identifiers_to_paymentnetworks": map_dict(
                to_checksum_address, serialization.identity, self.identifiers_to_paymentnetworks
            ),
            "nodeaddresses_to_networkstates": map_dict(
                to_checksum_address, serialization.identity, self.nodeaddresses_to_networkstates
            ),
            "our_address": to_checksum_address(self.our_address),
            "payment_mapping": self.payment_mapping,
            "pending_transactions": self.pending_transactions,
            "queueids_to_queues": serialization.serialize_queueid_to_queue(
                self.queueids_to_queues
            ),
            "last_transport_authdata": self.last_transport_authdata,
            "tokennetworkaddresses_to_paymentnetworkaddresses": map_dict(
                to_checksum_address,
                to_checksum_address,
                self.tokennetworkaddresses_to_paymentnetworkaddresses,
            ),
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ChainState":
        pseudo_random_generator = pseudo_random_generator_from_json(data)

        restored = cls(
            pseudo_random_generator=pseudo_random_generator,
            block_number=BlockNumber(T_BlockNumber(data["block_number"])),
            block_hash=BlockHash(serialization.deserialize_bytes(data["block_hash"])),
            our_address=to_canonical_address(data["our_address"]),
            chain_id=data["chain_id"],
        )

        restored.identifiers_to_paymentnetworks = map_dict(
            to_canonical_address, serialization.identity, data["identifiers_to_paymentnetworks"]
        )
        restored.nodeaddresses_to_networkstates = map_dict(
            to_canonical_address, serialization.identity, data["nodeaddresses_to_networkstates"]
        )
        restored.payment_mapping = data["payment_mapping"]
        restored.pending_transactions = data["pending_transactions"]
        restored.queueids_to_queues = serialization.deserialize_queueid_to_queue(
            data["queueids_to_queues"]
        )
        restored.last_transport_authdata = data.get("last_transport_authdata")
        restored.tokennetworkaddresses_to_paymentnetworkaddresses = map_dict(
            to_canonical_address,
            to_canonical_address,
            data["tokennetworkaddresses_to_paymentnetworkaddresses"],
        )

        return restored


class PaymentNetworkState(State):
    """ Corresponds to a registry smart contract. """

    __slots__ = (
        "address",
        "tokenidentifiers_to_tokennetworks",
        "tokenaddresses_to_tokenidentifiers",
    )

    def __init__(
        self, address: PaymentNetworkID, token_network_list: List["TokenNetworkState"]
    ) -> None:
        if not isinstance(address, T_Address):
            raise ValueError("address must be an address instance")

        self.address = address
        self.tokenidentifiers_to_tokennetworks: Dict[TokenNetworkID, TokenNetworkState] = {
            token_network.address: token_network for token_network in token_network_list
        }
        self.tokenaddresses_to_tokenidentifiers: Dict[TokenAddress, TokenNetworkID] = {
            token_network.token_address: token_network.address
            for token_network in token_network_list
        }

    def __repr__(self) -> str:
        return "<PaymentNetworkState id:{}>".format(pex(self.address))

    def __eq__(self, other: Any) -> bool:
        return (
            isinstance(other, PaymentNetworkState)
            and self.address == other.address
            and self.tokenaddresses_to_tokenidentifiers == other.tokenaddresses_to_tokenidentifiers
            and self.tokenidentifiers_to_tokennetworks == other.tokenidentifiers_to_tokennetworks
        )

    def __ne__(self, other: Any) -> bool:
        return not self.__eq__(other)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "address": to_checksum_address(self.address),
            "tokennetworks": [
                network for network in self.tokenidentifiers_to_tokennetworks.values()
            ],
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "PaymentNetworkState":
        restored = cls(
            address=to_canonical_address(data["address"]),
            token_network_list=[network for network in data["tokennetworks"]],
        )

        return restored


class TokenNetworkState(State):
    """ Corresponds to a token network smart contract. """

    __slots__ = (
        "address",
        "token_address",
        "network_graph",
        "channelidentifiers_to_channels",
        "partneraddresses_to_channelidentifiers",
    )

    def __init__(self, address: TokenNetworkID, token_address: TokenAddress) -> None:

        if not isinstance(address, T_Address):
            raise ValueError("address must be an address instance")

        if not isinstance(token_address, T_Address):
            raise ValueError("token_address must be an address instance")

        self.address = address
        self.token_address = token_address
        self.network_graph = TokenNetworkGraphState(self.address)

        self.channelidentifiers_to_channels: ChannelMap = dict()
        self.partneraddresses_to_channelidentifiers: Dict[Address, List[ChannelID]] = defaultdict(
            list
        )

    def __repr__(self) -> str:
        return "<TokenNetworkState id:{} token:{}>".format(
            pex(self.address), pex(self.token_address)
        )

    def __eq__(self, other: Any) -> bool:
        return (
            isinstance(other, TokenNetworkState)
            and self.address == other.address
            and self.token_address == other.token_address
            and self.network_graph == other.network_graph
            and self.channelidentifiers_to_channels == other.channelidentifiers_to_channels
            and (
                self.partneraddresses_to_channelidentifiers
                == other.partneraddresses_to_channelidentifiers
            )
        )

    def __ne__(self, other: Any) -> bool:
        return not self.__eq__(other)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "address": to_checksum_address(self.address),
            "token_address": to_checksum_address(self.token_address),
            "network_graph": self.network_graph,
            "channelidentifiers_to_channels": map_dict(
                str,  # keys in json can only be strings
                serialization.identity,
                self.channelidentifiers_to_channels,
            ),
            "partneraddresses_to_channelidentifiers": map_dict(
                to_checksum_address,
                serialization.identity,
                self.partneraddresses_to_channelidentifiers,
            ),
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "TokenNetworkState":
        restored = cls(
            address=to_canonical_address(data["address"]),
            token_address=to_canonical_address(data["token_address"]),
        )
        restored.network_graph = data["network_graph"]
        restored.channelidentifiers_to_channels = map_dict(
            serialization.deserialize_channel_id,
            serialization.identity,
            data["channelidentifiers_to_channels"],
        )

        restored_partneraddresses_to_channelidentifiers = map_dict(
            to_canonical_address,
            serialization.identity,
            data["partneraddresses_to_channelidentifiers"],
        )
        restored.partneraddresses_to_channelidentifiers = defaultdict(
            list, restored_partneraddresses_to_channelidentifiers
        )

        return restored


# This is necessary for the routing only, maybe it should be transient state
# outside of the state tree.
class TokenNetworkGraphState(State):
    """ Stores the existing channels in the channel manager contract, used for
    route finding.
    """

    __slots__ = ("token_network_id", "network", "channel_identifier_to_participants")

    def __init__(self, token_network_address: TokenNetworkID) -> None:
        self.token_network_id = token_network_address
        self.network = networkx.Graph()
        self.channel_identifier_to_participants: Dict[ChannelID, Tuple[Address, Address]] = {}

    def __repr__(self) -> str:
        return "<TokenNetworkGraphState num_edges:{}>".format(len(self.network.edges))

    def __eq__(self, other: Any) -> bool:
        return (
            isinstance(other, TokenNetworkGraphState)
            and self.token_network_id == other.token_network_id
            and to_comparable_graph(self.network) == to_comparable_graph(other.network)
            and self.channel_identifier_to_participants == other.channel_identifier_to_participants
        )

    def __ne__(self, other: Any) -> bool:
        return not self.__eq__(other)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "token_network_id": to_checksum_address(self.token_network_id),
            "network": serialization.serialize_networkx_graph(self.network),
            "channel_identifier_to_participants": map_dict(
                str,  # keys in json can only be strings
                serialization.serialize_participants_tuple,
                self.channel_identifier_to_participants,
            ),
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "TokenNetworkGraphState":
        restored = cls(token_network_address=to_canonical_address(data["token_network_id"]))
        restored.network = serialization.deserialize_networkx_graph(data["network"])
        restored.channel_identifier_to_participants = map_dict(
            serialization.deserialize_channel_id,
            serialization.deserialize_participants_tuple,
            data["channel_identifier_to_participants"],
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
    __slots__ = ("secrethashes_to_task",)

    def __init__(self) -> None:
        self.secrethashes_to_task: Dict[SecretHash, TransferTask] = dict()

    def __repr__(self) -> str:
        return "<PaymentMappingState qtd_transfers:{}>".format(len(self.secrethashes_to_task))

    def __eq__(self, other: Any) -> bool:
        return (
            isinstance(other, PaymentMappingState)
            and self.secrethashes_to_task == other.secrethashes_to_task
        )

    def __ne__(self, other: Any) -> bool:
        return not self.__eq__(other)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "secrethashes_to_task": map_dict(
                serialization.serialize_bytes, serialization.identity, self.secrethashes_to_task
            )
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "PaymentMappingState":
        restored = cls()
        restored.secrethashes_to_task = map_dict(
            serialization.deserialize_secret_hash,
            serialization.identity,
            data["secrethashes_to_task"],
        )

        return restored


class RouteState(State):
    """ A possible route provided by a routing service.

    Args:
        node_address: The address of the next_hop.
        channel_identifier: The channel identifier.
    """

    __slots__ = ("node_address", "channel_identifier")

    def __init__(self, node_address: Address, channel_identifier: ChannelID) -> None:
        if not isinstance(node_address, T_Address):
            raise ValueError("node_address must be an address instance")

        self.node_address = node_address
        self.channel_identifier = channel_identifier

    def __repr__(self) -> str:
        return "<RouteState hop:{node} channel_identifier:{channel_identifier}>".format(
            node=pex(self.node_address), channel_identifier=self.channel_identifier
        )

    def __eq__(self, other: Any) -> bool:
        return (
            isinstance(other, RouteState)
            and self.node_address == other.node_address
            and self.channel_identifier == other.channel_identifier
        )

    def __ne__(self, other: Any) -> bool:
        return not self.__eq__(other)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "node_address": to_checksum_address(self.node_address),
            "channel_identifier": str(self.channel_identifier),
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "RouteState":
        restored = cls(
            node_address=to_canonical_address(data["node_address"]),
            channel_identifier=ChannelID(int(data["channel_identifier"])),
        )

        return restored


class BalanceProofUnsignedState(State):
    """ Balance proof from the local node without the signature. """

    __slots__ = (
        "nonce",
        "transferred_amount",
        "locked_amount",
        "locksroot",
        "canonical_identifier",
    )

    def __init__(
        self,
        nonce: Nonce,
        transferred_amount: TokenAmount,
        locked_amount: TokenAmount,
        locksroot: Locksroot,
        canonical_identifier: CanonicalIdentifier,
    ) -> None:
        if not isinstance(nonce, int):
            raise ValueError("nonce must be int")

        if not isinstance(transferred_amount, T_TokenAmount):
            raise ValueError("transferred_amount must be a token_amount instance")

        if not isinstance(locked_amount, T_TokenAmount):
            raise ValueError("locked_amount must be a token_amount instance")

        if not isinstance(locksroot, T_Keccak256):
            raise ValueError("locksroot must be a keccak256 instance")

        if nonce <= 0:
            raise ValueError("nonce cannot be zero or negative")

        if nonce > UINT64_MAX:
            raise ValueError("nonce is too large")

        if transferred_amount < 0:
            raise ValueError("transferred_amount cannot be negative")

        if transferred_amount > UINT256_MAX:
            raise ValueError("transferred_amount is too large")

        if len(locksroot) != 32:
            raise ValueError("locksroot must have length 32")

        canonical_identifier.validate()

        self.nonce = nonce
        self.transferred_amount = transferred_amount
        self.locked_amount = locked_amount
        self.locksroot = locksroot
        self.canonical_identifier = canonical_identifier

    @property
    def chain_id(self) -> ChainID:
        return self.canonical_identifier.chain_identifier

    @property
    def token_network_identifier(self) -> TokenNetworkAddress:
        return TokenNetworkAddress(self.canonical_identifier.token_network_address)

    @property
    def channel_identifier(self) -> ChannelID:
        return self.canonical_identifier.channel_identifier

    def __repr__(self) -> str:
        return (
            "<"
            "BalanceProofUnsignedState nonce:{} transferred_amount:{} "
            "locked_amount:{} locksroot:{} token_network:{} channel_identifier:{} chain_id:{}"
            ">"
        ).format(
            self.nonce,
            self.transferred_amount,
            self.locked_amount,
            pex(self.locksroot),
            pex(self.token_network_identifier),
            self.channel_identifier,
            self.chain_id,
        )

    def __eq__(self, other: Any) -> bool:
        return (
            isinstance(other, BalanceProofUnsignedState)
            and self.nonce == other.nonce
            and self.transferred_amount == other.transferred_amount
            and self.locked_amount == other.locked_amount
            and self.locksroot == other.locksroot
            and self.canonical_identifier == other.canonical_identifier
        )

    def __ne__(self, other: Any) -> bool:
        return not self.__eq__(other)

    @property
    def balance_hash(self) -> BalanceHash:
        return hash_balance_data(
            transferred_amount=self.transferred_amount,
            locked_amount=self.locked_amount,
            locksroot=self.locksroot,
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "nonce": self.nonce,
            "transferred_amount": str(self.transferred_amount),
            "locked_amount": str(self.locked_amount),
            "locksroot": serialization.serialize_bytes(self.locksroot),
            "canonical_identifier": self.canonical_identifier.to_dict(),
            # Makes the balance hash available to query
            "balance_hash": serialize_bytes(self.balance_hash),
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "BalanceProofUnsignedState":
        restored = cls(
            nonce=data["nonce"],
            transferred_amount=TokenAmount(int(data["transferred_amount"])),
            locked_amount=TokenAmount(int(data["locked_amount"])),
            locksroot=Locksroot(serialization.deserialize_bytes(data["locksroot"])),
            canonical_identifier=CanonicalIdentifier.from_dict(data["canonical_identifier"]),
        )

        return restored


class BalanceProofSignedState(State):
    """ Proof of a channel balance that can be used on-chain to resolve
    disputes.
    """

    __slots__ = (
        "nonce",
        "transferred_amount",
        "locked_amount",
        "locksroot",
        "message_hash",
        "signature",
        "sender",
        "canonical_identifier",
    )

    def __init__(
        self,
        nonce: Nonce,
        transferred_amount: TokenAmount,
        locked_amount: TokenAmount,
        locksroot: Locksroot,
        message_hash: AdditionalHash,
        signature: Signature,
        sender: Address,
        canonical_identifier: CanonicalIdentifier,
    ) -> None:
        if not isinstance(nonce, int):
            raise ValueError("nonce must be int")

        if not isinstance(transferred_amount, T_TokenAmount):
            raise ValueError("transferred_amount must be a token_amount instance")

        if not isinstance(locked_amount, T_TokenAmount):
            raise ValueError("locked_amount must be a token_amount instance")

        if not isinstance(locksroot, T_Keccak256):
            raise ValueError("locksroot must be a keccak256 instance")

        if not isinstance(message_hash, T_Keccak256):
            raise ValueError("message_hash must be a keccak256 instance")

        if not isinstance(signature, T_Signature):
            raise ValueError("signature must be a signature instance")

        if not isinstance(sender, T_Address):
            raise ValueError("sender must be an address instance")

        if nonce <= 0:
            raise ValueError("nonce cannot be zero or negative")

        if nonce > UINT64_MAX:
            raise ValueError("nonce is too large")

        if transferred_amount < 0:
            raise ValueError("transferred_amount cannot be negative")

        if transferred_amount > UINT256_MAX:
            raise ValueError("transferred_amount is too large")

        if len(locksroot) != 32:
            raise ValueError("locksroot must have length 32")

        if len(message_hash) != 32:
            raise ValueError("message_hash is an invalid hash")

        if len(signature) != 65:
            raise ValueError("signature is an invalid signature")

        canonical_identifier.validate()

        self.nonce = nonce
        self.transferred_amount = transferred_amount
        self.locked_amount = locked_amount
        self.locksroot = locksroot
        self.message_hash = message_hash
        self.signature = signature
        self.sender = sender
        self.canonical_identifier = canonical_identifier

    def __repr__(self) -> str:
        return (
            "<"
            "BalanceProofSignedState nonce:{} transferred_amount:{} "
            "locked_amount:{} locksroot:{} token_network:{} channel_identifier:{} "
            "message_hash:{} signature:{} sender:{} chain_id:{}"
            ">"
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

    def __eq__(self, other: Any) -> bool:
        return (
            isinstance(other, BalanceProofSignedState)
            and self.nonce == other.nonce
            and self.transferred_amount == other.transferred_amount
            and self.locked_amount == other.locked_amount
            and self.locksroot == other.locksroot
            and self.token_network_identifier == other.token_network_identifier
            and self.channel_identifier == other.channel_identifier
            and self.message_hash == other.message_hash
            and self.signature == other.signature
            and self.sender == other.sender
            and self.chain_id == other.chain_id
        )

    def __ne__(self, other: Any) -> bool:
        return not self.__eq__(other)

    @property
    def balance_hash(self) -> BalanceHash:
        return hash_balance_data(
            transferred_amount=self.transferred_amount,
            locked_amount=self.locked_amount,
            locksroot=self.locksroot,
        )

    @property
    def chain_id(self) -> ChainID:
        return self.canonical_identifier.chain_identifier

    @property
    def token_network_identifier(self) -> TokenNetworkAddress:
        return TokenNetworkAddress(self.canonical_identifier.token_network_address)

    @property
    def channel_identifier(self) -> ChannelID:
        return self.canonical_identifier.channel_identifier

    def to_dict(self) -> Dict[str, Any]:
        return {
            "nonce": self.nonce,
            "transferred_amount": str(self.transferred_amount),
            "locked_amount": str(self.locked_amount),
            "locksroot": serialization.serialize_bytes(self.locksroot),
            "message_hash": serialization.serialize_bytes(self.message_hash),
            "signature": serialization.serialize_bytes(self.signature),
            "sender": to_checksum_address(self.sender),
            "canonical_identifier": self.canonical_identifier.to_dict(),
            # Makes the balance hash available to query
            "balance_hash": serialize_bytes(self.balance_hash),
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "BalanceProofSignedState":
        restored = cls(
            nonce=Nonce(data["nonce"]),
            transferred_amount=TokenAmount(int(data["transferred_amount"])),
            locked_amount=TokenAmount(int(data["locked_amount"])),
            locksroot=Locksroot(serialization.deserialize_bytes(data["locksroot"])),
            message_hash=AdditionalHash(serialization.deserialize_bytes(data["message_hash"])),
            signature=Signature(serialization.deserialize_bytes(data["signature"])),
            sender=to_canonical_address(data["sender"]),
            canonical_identifier=CanonicalIdentifier.from_dict(data["canonical_identifier"]),
        )

        return restored


class HashTimeLockState(State):
    """ Represents a hash time lock. """

    __slots__ = (
        "amount",
        "expiration",  # latest block number when the secret has to be revealed
        "secrethash",
        "encoded",  # serialization of the above fields
        "lockhash",  # hash of 'encoded'
    )

    def __init__(
        self, amount: PaymentWithFeeAmount, expiration: BlockExpiration, secrethash: SecretHash
    ) -> None:
        if not isinstance(amount, T_PaymentWithFeeAmount):
            raise ValueError("amount must be a PaymentWithFeeAmount instance")

        if not isinstance(expiration, T_BlockNumber):
            raise ValueError("expiration must be a BlockNumber instance")

        if not isinstance(secrethash, T_Keccak256):
            raise ValueError("secrethash must be a Keccak256 instance")

        packed = messages.Lock(buffer_for(messages.Lock))
        # pylint: disable=assigning-non-slot
        packed.amount = amount
        packed.expiration = expiration
        packed.secrethash = secrethash
        # pylint: enable=assigning-non-slot
        encoded = bytes(packed.data)

        self.amount = amount
        self.expiration = expiration
        self.secrethash = secrethash
        self.encoded = encoded
        self.lockhash: LockHash = LockHash(sha3(encoded))

    def __repr__(self) -> str:
        return "<HashTimeLockState amount:{} expiration:{} secrethash:{}>".format(
            self.amount, self.expiration, pex(self.secrethash)
        )

    def __eq__(self, other: Any) -> bool:
        return (
            isinstance(other, HashTimeLockState)
            and self.amount == other.amount
            and self.expiration == other.expiration
            and self.secrethash == other.secrethash
        )

    def __ne__(self, other: Any) -> bool:
        return not self.__eq__(other)

    def __hash__(self):
        return self.lockhash

    def to_dict(self) -> Dict[str, Any]:
        return {
            "amount": self.amount,
            "expiration": self.expiration,
            "secrethash": serialization.serialize_bytes(self.secrethash),
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "HashTimeLockState":
        restored = cls(
            amount=data["amount"],
            expiration=data["expiration"],
            secrethash=SecretHash(serialization.deserialize_bytes(data["secrethash"])),
        )

        return restored


class UnlockPartialProofState(State):
    """ Stores the lock along with its unlocking secret. """

    __slots__ = ("lock", "secret", "amount", "expiration", "secrethash", "encoded", "lockhash")

    def __init__(self, lock: HashTimeLockState, secret: Secret) -> None:
        if not isinstance(lock, HashTimeLockState):
            raise ValueError("lock must be a HashTimeLockState instance")

        if not isinstance(secret, T_Secret):
            raise ValueError("secret must be a secret instance")

        self.lock = lock
        self.secret = secret
        self.amount = lock.amount
        self.expiration = lock.expiration
        self.secrethash = lock.secrethash
        self.encoded = lock.encoded
        self.lockhash = lock.lockhash

    def __repr__(self) -> str:
        return "<UnlockPartialProofState lock:{}>".format(self.lock)

    def __eq__(self, other: Any) -> bool:
        return (
            isinstance(other, UnlockPartialProofState)
            and self.lock == other.lock
            and self.secret == other.secret
        )

    def __ne__(self, other: Any) -> bool:
        return not self.__eq__(other)

    def to_dict(self) -> Dict[str, Any]:
        return {"lock": self.lock, "secret": serialization.serialize_bytes(self.secret)}

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "UnlockPartialProofState":
        restored = cls(
            lock=data["lock"], secret=Secret(serialization.deserialize_bytes(data["secret"]))
        )

        return restored


class UnlockProofState(State):
    """ An unlock proof for a given lock. """

    __slots__ = ("merkle_proof", "lock_encoded", "secret")

    def __init__(self, merkle_proof: List[Keccak256], lock_encoded: bytes, secret: Secret):

        if not isinstance(secret, T_Secret):
            raise ValueError("secret must be a secret instance")

        self.merkle_proof = merkle_proof
        self.lock_encoded = lock_encoded
        self.secret = secret

    def __repr__(self) -> str:
        full_proof = [encode_hex(entry) for entry in self.merkle_proof]
        return f"<UnlockProofState proof:{full_proof} lock:{encode_hex(self.lock_encoded)}>"

    def __eq__(self, other: Any) -> bool:
        return (
            isinstance(other, UnlockProofState)
            and self.merkle_proof == other.merkle_proof
            and self.lock_encoded == other.lock_encoded
            and self.secret == other.secret
        )

    def __ne__(self, other: Any) -> bool:
        return not self.__eq__(other)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "merkle_proof": map_list(serialization.serialize_bytes, self.merkle_proof),
            "lock_encoded": serialization.serialize_bytes(self.lock_encoded),
            "secret": serialization.serialize_bytes(self.secret),
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "UnlockProofState":
        restored = cls(
            merkle_proof=map_list(serialization.deserialize_keccak, data["merkle_proof"]),
            lock_encoded=serialization.deserialize_bytes(data["lock_encoded"]),
            secret=Secret(serialization.deserialize_bytes(data["secret"])),
        )

        return restored


class TransactionExecutionStatus(State):
    """ Represents the status of a transaction. """

    SUCCESS = "success"
    FAILURE = "failure"
    VALID_RESULT_VALUES = (SUCCESS, FAILURE)

    def __init__(
        self,
        started_block_number: Optional[BlockNumber] = None,
        finished_block_number: Optional[BlockNumber] = None,
        result: str = None,
    ) -> None:

        is_valid_start = started_block_number is None or isinstance(
            started_block_number, T_BlockNumber
        )
        is_valid_finish = finished_block_number is None or isinstance(
            finished_block_number, T_BlockNumber
        )
        is_valid_result = result is None or result in self.VALID_RESULT_VALUES

        if not is_valid_start:
            raise ValueError("started_block_number must be None or a block_number")

        if not is_valid_finish:
            raise ValueError("finished_block_number must be None or a block_number")

        if not is_valid_result:
            raise ValueError(f"result must be one of '{self.SUCCESS}', '{self.FAILURE}' or 'None'")

        self.started_block_number = started_block_number
        self.finished_block_number = finished_block_number
        self.result = result

    def __repr__(self) -> str:
        return "<TransactionExecutionStatus started:{} finished:{} result:{}>".format(
            self.started_block_number, self.finished_block_number, self.result
        )

    def __eq__(self, other: Any) -> bool:
        return (
            isinstance(other, TransactionExecutionStatus)
            and self.started_block_number == other.started_block_number
            and self.finished_block_number == other.finished_block_number
            and self.result == other.result
        )

    def __ne__(self, other: Any) -> bool:
        return not self.__eq__(other)

    def to_dict(self) -> Dict[str, Any]:
        result: Dict[str, Any] = {}
        if self.started_block_number is not None:
            result["started_block_number"] = str(self.started_block_number)
        if self.finished_block_number is not None:
            result["finished_block_number"] = str(self.finished_block_number)
        if self.result is not None:
            result["result"] = self.result

        return result

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "TransactionExecutionStatus":
        started_optional = data.get("started_block_number")
        started_block_number = BlockNumber(int(started_optional)) if started_optional else None
        finished_optional = data.get("finished_block_number")
        finished_block_number = BlockNumber(int(finished_optional)) if finished_optional else None

        restored = cls(
            started_block_number=started_block_number,
            finished_block_number=finished_block_number,
            result=data.get("result"),
        )

        return restored


class MerkleTreeState(State):
    __slots__ = ("layers",)

    def __init__(self, layers: List[List[Keccak256]]) -> None:
        self.layers = layers

    def __repr__(self) -> str:
        return "<MerkleTreeState root:{}>".format(pex(merkleroot(self)))

    def __eq__(self, other: Any) -> bool:
        return isinstance(other, MerkleTreeState) and self.layers == other.layers

    def __ne__(self, other: Any) -> bool:
        return not self.__eq__(other)

    def to_dict(self) -> Dict[str, Any]:
        return {"layers": serialization.serialize_merkletree_layers(self.layers)}

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "MerkleTreeState":
        restored = cls(layers=serialization.deserialize_merkletree_layers(data["layers"]))

        return restored


class NettingChannelEndState(State):
    """ The state of one of the nodes in a two party netting channel. """

    __slots__ = (
        "address",
        "contract_balance",
        "secrethashes_to_lockedlocks",
        "secrethashes_to_unlockedlocks",
        "secrethashes_to_onchain_unlockedlocks",
        "merkletree",
        "balance_proof",
        "onchain_locksroot",
    )

    def __init__(self, address: Address, balance: Balance) -> None:
        if not isinstance(address, T_Address):
            raise ValueError("address must be an address instance")

        if not isinstance(balance, T_TokenAmount):
            raise ValueError("balance must be a token_amount isinstance")

        self.address = address
        self.contract_balance = balance

        #: Locks which have been introduced with a locked transfer, however the
        #: secret is not known yet
        self.secrethashes_to_lockedlocks: SecretHashToLock = dict()
        #: Locks for which the secret is known, but the partner has not sent an
        #: unlock off chain yet.
        self.secrethashes_to_unlockedlocks: SecretHashToPartialUnlockProof = dict()
        #: Locks for which the secret is known, the partner has not sent an
        #: unlocked off chain yet, and the secret has been registered onchain
        #: before the lock has expired.
        self.secrethashes_to_onchain_unlockedlocks: SecretHashToPartialUnlockProof = dict()
        self.merkletree = make_empty_merkle_tree()
        self.balance_proof: OptionalBalanceProofState = None
        self.onchain_locksroot: Locksroot = EMPTY_MERKLE_ROOT

    def __repr__(self) -> str:
        return "<NettingChannelEndState address:{} contract_balance:{} merkletree:{}>".format(
            pex(self.address), self.contract_balance, self.merkletree
        )

    def __eq__(self, other: Any) -> bool:
        return (
            isinstance(other, NettingChannelEndState)
            and self.address == other.address
            and self.contract_balance == other.contract_balance
            and self.secrethashes_to_lockedlocks == other.secrethashes_to_lockedlocks
            and self.secrethashes_to_unlockedlocks == other.secrethashes_to_unlockedlocks
            and (
                self.secrethashes_to_onchain_unlockedlocks
                == other.secrethashes_to_onchain_unlockedlocks
            )
            and self.merkletree == other.merkletree
            and self.balance_proof == other.balance_proof
            and self.onchain_locksroot == other.onchain_locksroot
        )

    def __ne__(self, other: Any) -> bool:
        return not self.__eq__(other)

    def to_dict(self) -> Dict[str, Any]:
        result = {
            "address": to_checksum_address(self.address),
            "contract_balance": str(self.contract_balance),
            "secrethashes_to_lockedlocks": map_dict(
                serialization.serialize_bytes,
                serialization.identity,
                self.secrethashes_to_lockedlocks,
            ),
            "secrethashes_to_unlockedlocks": map_dict(
                serialization.serialize_bytes,
                serialization.identity,
                self.secrethashes_to_unlockedlocks,
            ),
            "secrethashes_to_onchain_unlockedlocks": map_dict(
                serialization.serialize_bytes,
                serialization.identity,
                self.secrethashes_to_onchain_unlockedlocks,
            ),
            "merkletree": self.merkletree,
            "onchain_locksroot": serialization.serialize_bytes(self.onchain_locksroot),
        }
        if self.balance_proof is not None:
            result["balance_proof"] = self.balance_proof

        return result

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "NettingChannelEndState":
        onchain_locksroot = EMPTY_MERKLE_ROOT
        if data["onchain_locksroot"]:
            onchain_locksroot = Locksroot(
                serialization.deserialize_bytes(data["onchain_locksroot"])
            )

        restored = cls(
            address=to_canonical_address(data["address"]),
            balance=Balance(int(data["contract_balance"])),
        )
        restored.secrethashes_to_lockedlocks = map_dict(
            serialization.deserialize_secret_hash,
            serialization.identity,
            data["secrethashes_to_lockedlocks"],
        )
        restored.secrethashes_to_unlockedlocks = map_dict(
            serialization.deserialize_secret_hash,
            serialization.identity,
            data["secrethashes_to_unlockedlocks"],
        )
        restored.secrethashes_to_onchain_unlockedlocks = map_dict(
            serialization.deserialize_secret_hash,
            serialization.identity,
            data["secrethashes_to_onchain_unlockedlocks"],
        )
        restored.merkletree = data["merkletree"]
        restored.balance_proof = data.get("balance_proof")
        restored.onchain_locksroot = onchain_locksroot

        return restored


class NettingChannelState(State):
    """ The state of a netting channel. """

    __slots__ = (
        "canonical_identifier",
        "token_address",
        "payment_network_identifier",
        "reveal_timeout",
        "settle_timeout",
        "mediation_fee",
        "our_state",
        "partner_state",
        "deposit_transaction_queue",
        "open_transaction",
        "close_transaction",
        "settle_transaction",
        "update_transaction",
    )

    def __init__(
        self,
        canonical_identifier: CanonicalIdentifier,
        token_address: TokenAddress,
        payment_network_identifier: PaymentNetworkID,
        reveal_timeout: BlockTimeout,
        settle_timeout: BlockTimeout,
        mediation_fee: FeeAmount,
        our_state: NettingChannelEndState,
        partner_state: NettingChannelEndState,
        open_transaction: TransactionExecutionStatus,
        close_transaction: TransactionExecutionStatus = None,
        settle_transaction: TransactionExecutionStatus = None,
        update_transaction: TransactionExecutionStatus = None,
    ) -> None:
        if reveal_timeout >= settle_timeout:
            raise ValueError("reveal_timeout must be smaller than settle_timeout")

        if not isinstance(reveal_timeout, int) or reveal_timeout <= 0:
            raise ValueError("reveal_timeout must be a positive integer")

        if not isinstance(settle_timeout, int) or settle_timeout <= 0:
            raise ValueError("settle_timeout must be a positive integer")

        if not isinstance(open_transaction, TransactionExecutionStatus):
            raise ValueError("open_transaction must be a TransactionExecutionStatus instance")

        if open_transaction.result != TransactionExecutionStatus.SUCCESS:
            raise ValueError(
                "Cannot create a NettingChannelState with a non successfull open_transaction"
            )

        if not isinstance(canonical_identifier.channel_identifier, T_ChannelID):
            raise ValueError("channel identifier must be of type T_ChannelID")

        if (
            canonical_identifier.channel_identifier < 0
            or canonical_identifier.channel_identifier > UINT256_MAX
        ):
            raise ValueError("channel identifier should be a uint256")

        valid_close_transaction = close_transaction is None or isinstance(
            close_transaction, TransactionExecutionStatus
        )
        if not valid_close_transaction:
            raise ValueError("close_transaction must be a TransactionExecutionStatus instance")

        valid_settle_transaction = settle_transaction is None or isinstance(
            settle_transaction, TransactionExecutionStatus
        )
        if not valid_settle_transaction:
            raise ValueError(
                "settle_transaction must be a TransactionExecutionStatus instance or None"
            )

        self.canonical_identifier = canonical_identifier
        self.token_address = token_address
        self.payment_network_identifier = payment_network_identifier
        self.reveal_timeout = reveal_timeout
        self.settle_timeout = settle_timeout
        self.our_state = our_state
        self.partner_state = partner_state
        self.deposit_transaction_queue: List[TransactionOrder] = list()
        self.open_transaction = open_transaction
        self.close_transaction = close_transaction
        self.settle_transaction = settle_transaction
        self.update_transaction = update_transaction
        self.mediation_fee = mediation_fee

    def __repr__(self) -> str:
        return "<NettingChannelState id:{} opened:{} closed:{} settled:{} updated:{}>".format(
            self.canonical_identifier.channel_identifier,
            self.open_transaction,
            self.close_transaction,
            self.settle_transaction,
            self.update_transaction,
        )

    @property
    def identifier(self) -> ChannelID:
        return self.canonical_identifier.channel_identifier

    @property
    def token_network_identifier(self) -> TokenNetworkID:
        return TokenNetworkID(self.canonical_identifier.token_network_address)

    @property
    def chain_id(self) -> ChainID:
        return self.canonical_identifier.chain_identifier

    def __eq__(self, other: Any) -> bool:
        return (
            isinstance(other, NettingChannelState)
            and self.canonical_identifier == other.canonical_identifier
            and self.payment_network_identifier == other.payment_network_identifier
            and self.our_state == other.our_state
            and self.partner_state == other.partner_state
            and self.token_address == other.token_address
            and self.reveal_timeout == other.reveal_timeout
            and self.settle_timeout == other.settle_timeout
            and self.mediation_fee == other.mediation_fee
            and self.deposit_transaction_queue == other.deposit_transaction_queue
            and self.open_transaction == other.open_transaction
            and self.close_transaction == other.close_transaction
            and self.settle_transaction == other.settle_transaction
            and self.update_transaction == other.update_transaction
        )

    @property
    def our_total_deposit(self) -> Balance:
        return self.our_state.contract_balance

    @property
    def partner_total_deposit(self) -> Balance:
        return self.partner_state.contract_balance

    def __ne__(self, other: Any) -> bool:
        return not self.__eq__(other)

    # FIXME: changed serialization will need a migration
    def to_dict(self) -> Dict[str, Any]:
        result = {
            "canonical_identifier": self.canonical_identifier.to_dict(),
            "token_address": to_checksum_address(self.token_address),
            "payment_network_identifier": to_checksum_address(self.payment_network_identifier),
            "reveal_timeout": str(self.reveal_timeout),
            "settle_timeout": str(self.settle_timeout),
            "mediation_fee": str(self.mediation_fee),
            "our_state": self.our_state,
            "partner_state": self.partner_state,
            "open_transaction": self.open_transaction,
            "deposit_transaction_queue": self.deposit_transaction_queue,
        }

        if self.close_transaction is not None:
            result["close_transaction"] = self.close_transaction
        if self.settle_transaction is not None:
            result["settle_transaction"] = self.settle_transaction
        if self.update_transaction is not None:
            result["update_transaction"] = self.update_transaction

        return result

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "NettingChannelState":
        restored = cls(
            canonical_identifier=CanonicalIdentifier.from_dict(data["canonical_identifier"]),
            token_address=to_canonical_address(data["token_address"]),
            payment_network_identifier=to_canonical_address(data["payment_network_identifier"]),
            reveal_timeout=BlockTimeout(int(data["reveal_timeout"])),
            settle_timeout=BlockTimeout(int(data["settle_timeout"])),
            mediation_fee=FeeAmount(int(data["mediation_fee"])),
            our_state=data["our_state"],
            partner_state=data["partner_state"],
            open_transaction=data["open_transaction"],
        )
        close_transaction = data.get("close_transaction")
        if close_transaction is not None:
            restored.close_transaction = close_transaction
        settle_transaction = data.get("settle_transaction")
        if settle_transaction is not None:
            restored.settle_transaction = settle_transaction
        update_transaction = data.get("update_transaction")
        if update_transaction is not None:
            restored.update_transaction = update_transaction

        restored.deposit_transaction_queue = data["deposit_transaction_queue"]

        return restored


@total_ordering
class TransactionChannelNewBalance(State):

    __slots__ = ("participant_address", "contract_balance", "deposit_block_number")

    def __init__(
        self,
        participant_address: Address,
        contract_balance: TokenAmount,
        deposit_block_number: BlockNumber,
    ) -> None:
        if not isinstance(participant_address, T_Address):
            raise ValueError("participant_address must be of type address")

        if not isinstance(contract_balance, T_TokenAmount):
            raise ValueError("contract_balance must be of type token_amount")

        if not isinstance(deposit_block_number, T_BlockNumber):
            raise ValueError("deposit_block_number must be of type block_number")

        self.participant_address = participant_address
        self.contract_balance = contract_balance
        self.deposit_block_number = deposit_block_number

    def __repr__(self) -> str:
        return "<TransactionChannelNewBalance participant:{} balance:{} at_block:{}>".format(
            pex(self.participant_address), self.contract_balance, self.deposit_block_number
        )

    def __eq__(self, other: Any) -> bool:
        if not isinstance(other, TransactionChannelNewBalance):
            return NotImplemented
        return (
            self.participant_address == other.participant_address
            and self.contract_balance == other.contract_balance
            and self.deposit_block_number == other.deposit_block_number
        )

    def __lt__(self, other: Any) -> bool:
        if not isinstance(other, TransactionChannelNewBalance):
            return NotImplemented
        return (self.participant_address, self.contract_balance, self.deposit_block_number) < (
            other.participant_address,
            other.contract_balance,
            other.deposit_block_number,
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "participant_address": to_checksum_address(self.participant_address),
            "contract_balance": str(self.contract_balance),
            "deposit_block_number": str(self.deposit_block_number),
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "TransactionChannelNewBalance":
        restored = cls(
            participant_address=to_canonical_address(data["participant_address"]),
            contract_balance=TokenAmount(int(data["contract_balance"])),
            deposit_block_number=BlockNumber(int(data["deposit_block_number"])),
        )

        return restored


@total_ordering
class TransactionOrder(State):
    def __init__(
        self, block_number: BlockNumber, transaction: TransactionChannelNewBalance
    ) -> None:
        self.block_number = block_number
        self.transaction = transaction

    def __repr__(self) -> str:
        return "<TransactionOrder block_number:{} transaction:{}>".format(
            self.block_number, self.transaction
        )

    def __eq__(self, other: Any) -> bool:
        return (
            isinstance(other, TransactionOrder)
            and self.block_number == other.block_number
            and self.transaction == other.transaction
        )

    def __ne__(self, other: Any) -> bool:
        return not self.__eq__(other)

    def __lt__(self, other: Any) -> bool:
        if not isinstance(other, TransactionOrder):
            return NotImplemented
        return (self.block_number, self.transaction) < (other.block_number, other.transaction)

    def to_dict(self) -> Dict[str, Any]:
        return {"block_number": str(self.block_number), "transaction": self.transaction}

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "TransactionOrder":
        restored = cls(
            block_number=BlockNumber(int(data["block_number"])), transaction=data["transaction"]
        )

        return restored
