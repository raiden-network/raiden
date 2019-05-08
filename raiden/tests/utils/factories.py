# pylint: disable=too-many-arguments
import random
import string
from dataclasses import dataclass, fields, replace
from functools import singledispatch

from eth_utils import to_checksum_address

from raiden.constants import EMPTY_MERKLE_ROOT, UINT64_MAX, UINT256_MAX
from raiden.messages import Lock, LockedTransfer, RefundTransfer
from raiden.transfer import balance_proof, channel, token_network
from raiden.transfer.identifiers import CanonicalIdentifier
from raiden.transfer.mediated_transfer import mediator
from raiden.transfer.mediated_transfer.state import (
    HashTimeLockState,
    LockedTransferSignedState,
    LockedTransferUnsignedState,
    MediationPairState,
    TransferDescriptionWithSecretState,
    lockedtransfersigned_from_message,
)
from raiden.transfer.mediated_transfer.state_change import ActionInitMediator
from raiden.transfer.merkle_tree import compute_layers, merkleroot
from raiden.transfer.state import (
    NODE_NETWORK_REACHABLE,
    BalanceProofSignedState,
    BalanceProofUnsignedState,
    MerkleTreeState,
    NettingChannelEndState,
    NettingChannelState,
    RouteState,
    TokenNetworkState,
    TransactionExecutionStatus,
    message_identifier_from_prng,
)
from raiden.transfer.state_change import ContractReceiveChannelNew, ContractReceiveRouteNew
from raiden.transfer.utils import hash_balance_data
from raiden.utils import privatekey_to_address, random_secret, sha3
from raiden.utils.signer import LocalSigner, Signer
from raiden.utils.typing import (
    AdditionalHash,
    Address,
    AddressHex,
    Any,
    Balance,
    BlockExpiration,
    BlockHash,
    BlockNumber,
    BlockTimeout,
    ChainID,
    ChannelID,
    ChannelMap,
    ClassVar,
    Dict,
    FeeAmount,
    InitiatorAddress,
    Keccak256,
    List,
    Locksroot,
    MerkleTreeLeaves,
    MessageID,
    NamedTuple,
    NodeNetworkStateMap,
    Nonce,
    Optional,
    PaymentID,
    PaymentNetworkID,
    Secret,
    SecretHash,
    Signature,
    TargetAddress,
    TokenAddress,
    TokenAmount,
    TokenNetworkAddress,
    TokenNetworkID,
    TransactionHash,
    Tuple,
    Type,
    TypeVar,
)

EMPTY = "empty"
GENERATE = "generate"

K = TypeVar("K")
V = TypeVar("V")


def _partial_dict(full_dict: Dict[K, V], *args) -> Dict[K, V]:
    return {key: full_dict[key] for key in args}


class Properties:
    """ Base class for all properties classes. """

    DEFAULTS: ClassVar["Properties"] = None
    TARGET_TYPE: ClassVar[Type] = None

    @property
    def kwargs(self):
        return {key: value for key, value in self.__dict__.items() if value is not EMPTY}

    def extract(self, subset_type: Type) -> "Properties":
        field_names = [field.name for field in fields(subset_type)]
        return subset_type(**_partial_dict(self.__dict__, *field_names))

    def partial_dict(self, *args) -> Dict[str, Any]:
        return _partial_dict(self.__dict__, *args)


def if_empty(value, default):
    return value if value is not EMPTY else default


def _replace_properties(properties, defaults):
    replacements = {
        k: create_properties(v, defaults.__dict__[k]) if isinstance(v, Properties) else v
        for k, v in properties.kwargs.items()
    }
    return replace(defaults, **replacements)


def create_properties(properties: Properties, defaults: Properties = None) -> Properties:
    full_defaults = type(properties).DEFAULTS
    if defaults is not None:
        full_defaults = _replace_properties(defaults, full_defaults)
    return _replace_properties(properties, full_defaults)


def make_uint256() -> int:
    return random.randint(0, UINT256_MAX)


def make_channel_identifier() -> ChannelID:
    return ChannelID(make_uint256())


def make_uint64() -> int:
    return random.randint(0, UINT64_MAX)


def make_balance() -> Balance:
    return Balance(random.randint(0, UINT256_MAX))


def make_block_number() -> BlockNumber:
    return BlockNumber(random.randint(0, UINT256_MAX))


def make_chain_id() -> ChainID:
    return ChainID(random.randint(0, UINT64_MAX))


def make_message_identifier() -> MessageID:
    return MessageID(random.randint(0, UINT64_MAX))


def make_20bytes() -> bytes:
    return bytes("".join(random.choice(string.printable) for _ in range(20)), encoding="utf-8")


def make_address() -> Address:
    return Address(make_20bytes())


def make_checksum_address() -> AddressHex:
    return to_checksum_address(make_address())


def make_additional_hash() -> AdditionalHash:
    return AdditionalHash(make_32bytes())


def make_32bytes() -> bytes:
    return bytes("".join(random.choice(string.printable) for _ in range(32)), encoding="utf-8")


def make_transaction_hash() -> TransactionHash:
    return TransactionHash(make_32bytes())


def make_locksroot() -> Locksroot:
    return Locksroot(make_32bytes())


def make_block_hash() -> BlockHash:
    return BlockHash(make_32bytes())


def make_privatekey_bin() -> bin:
    return make_32bytes()


def make_payment_network_identifier() -> PaymentNetworkID:
    return PaymentNetworkID(make_address())


def make_keccak_hash() -> Keccak256:
    return Keccak256(make_32bytes())


def make_secret(i: int = EMPTY) -> Secret:
    if i is not EMPTY:
        return format(i, ">032").encode()
    else:
        return make_32bytes()


def make_privkey_address(privatekey: bytes = EMPTY,) -> Tuple[bytes, Address]:
    privatekey = if_empty(privatekey, make_privatekey_bin())
    address = privatekey_to_address(privatekey)
    return privatekey, address


def make_signer() -> Signer:
    privatekey = make_privatekey_bin()
    return LocalSigner(privatekey)


def make_route_from_channel(channel_state: NettingChannelState = EMPTY) -> RouteState:
    channel_state = if_empty(channel_state, create(NettingChannelStateProperties()))
    return RouteState(channel_state.partner_state.address, channel_state.identifier)


def make_route_to_channel(channel_state: NettingChannelState = EMPTY) -> RouteState:
    channel_state = if_empty(channel_state, create(NettingChannelStateProperties()))
    return RouteState(channel_state.our_state.address, channel_state.identifier)


# CONSTANTS
# In this module constants are in the bottom because we need some of the
# factories.
# Prefixing with UNIT_ to differ from the default globals.
UNIT_SETTLE_TIMEOUT = 50
UNIT_REVEAL_TIMEOUT = 5
UNIT_TRANSFER_AMOUNT = 10
UNIT_TRANSFER_FEE = 5
UNIT_SECRET = b"secretsecretsecretsecretsecretse"
UNIT_SECRETHASH = sha3(UNIT_SECRET)
UNIT_REGISTRY_IDENTIFIER = b"registryregistryregi"
UNIT_TOKEN_ADDRESS = b"tokentokentokentoken"
UNIT_TOKEN_NETWORK_ADDRESS = b"networknetworknetwor"
UNIT_CHANNEL_ID = 1338
UNIT_CHAIN_ID = 337
UNIT_CANONICAL_ID = CanonicalIdentifier(
    chain_identifier=UNIT_CHAIN_ID,
    token_network_address=UNIT_TOKEN_NETWORK_ADDRESS,
    channel_identifier=UNIT_CHANNEL_ID,
)
UNIT_PAYMENT_NETWORK_IDENTIFIER = b"paymentnetworkidentifier"
UNIT_TRANSFER_IDENTIFIER = 37
UNIT_TRANSFER_INITIATOR = b"initiatorinitiatorin"
UNIT_TRANSFER_TARGET = b"targettargettargetta"
UNIT_TRANSFER_PKEY_BIN = sha3(b"transfer pkey")
UNIT_TRANSFER_PKEY = UNIT_TRANSFER_PKEY_BIN
UNIT_TRANSFER_SENDER = privatekey_to_address(sha3(b"transfer pkey"))
HOP1_KEY = b"11111111111111111111111111111111"
HOP2_KEY = b"22222222222222222222222222222222"
HOP3_KEY = b"33333333333333333333333333333333"
HOP4_KEY = b"44444444444444444444444444444444"
HOP5_KEY = b"55555555555555555555555555555555"
HOP1 = privatekey_to_address(HOP1_KEY)
HOP2 = privatekey_to_address(HOP2_KEY)
ADDR = b"addraddraddraddraddr"


def make_merkletree_leaves(width: int) -> List[Keccak256]:
    return [make_secret() for _ in range(width)]


def make_merkletree(leaves: List[SecretHash]) -> MerkleTreeState:
    return MerkleTreeState(compute_layers(leaves))


@singledispatch
def create(properties: Any, defaults: Optional[Properties] = None) -> Any:
    """Create objects from their associated property class.

    E. g. a NettingChannelState from NettingChannelStateProperties. For any field in
    properties set to EMPTY a default will be used. The default values can be changed
    by giving another object of the same property type as the defaults argument.
    """
    if isinstance(properties, Properties):
        return properties.TARGET_TYPE(**_properties_to_kwargs(properties, defaults))
    return properties


def _properties_to_kwargs(properties: Properties, defaults: Properties) -> Dict:
    properties = create_properties(properties, defaults or properties.DEFAULTS)
    return {key: create(value) for key, value in properties.__dict__.items()}


@dataclass(frozen=True)
class CanonicalIdentifierProperties(Properties):
    chain_identifier: ChainID = EMPTY
    token_network_address: TokenNetworkAddress = EMPTY
    channel_identifier: ChannelID = EMPTY
    TARGET_TYPE = CanonicalIdentifier


CanonicalIdentifierProperties.DEFAULTS = CanonicalIdentifierProperties(
    chain_identifier=UNIT_CHAIN_ID,
    token_network_address=UNIT_TOKEN_NETWORK_ADDRESS,
    channel_identifier=GENERATE,
)


@create.register(CanonicalIdentifierProperties)
def _(properties, defaults=None):
    kwargs = _properties_to_kwargs(properties, defaults)
    if kwargs["channel_identifier"] == GENERATE:
        kwargs["channel_identifier"] = make_channel_identifier()
    return CanonicalIdentifier(**kwargs)


def make_canonical_identifier(
    chain_identifier=EMPTY, token_network_address=EMPTY, channel_identifier=EMPTY
) -> CanonicalIdentifier:
    """ Alias of the CanonicalIdentifier create function """
    return create(
        CanonicalIdentifierProperties(
            chain_identifier=chain_identifier,
            token_network_address=token_network_address,
            channel_identifier=channel_identifier or make_channel_identifier(),
        )
    )


@dataclass(frozen=True)
class TransactionExecutionStatusProperties(Properties):
    started_block_number: BlockNumber = EMPTY
    finished_block_number: BlockNumber = EMPTY
    result: str = EMPTY
    TARGET_TYPE = TransactionExecutionStatus


TransactionExecutionStatusProperties.DEFAULTS = TransactionExecutionStatusProperties(
    started_block_number=None,
    finished_block_number=None,
    result=TransactionExecutionStatus.SUCCESS,
)


@dataclass(frozen=True)
class NettingChannelEndStateProperties(Properties):
    address: Address = EMPTY
    privatekey: bytes = EMPTY
    balance: TokenAmount = EMPTY
    merkletree_leaves: MerkleTreeLeaves = EMPTY
    merkletree_width: int = EMPTY
    TARGET_TYPE = NettingChannelEndState


NettingChannelEndStateProperties.DEFAULTS = NettingChannelEndStateProperties(
    address=None, privatekey=None, balance=100, merkletree_leaves=None, merkletree_width=0
)


@create.register(NettingChannelEndStateProperties)  # noqa: F811
def _(properties, defaults=None) -> NettingChannelEndState:
    args = _properties_to_kwargs(properties, defaults or NettingChannelEndStateProperties.DEFAULTS)
    state = NettingChannelEndState(args["address"] or make_address(), args["balance"])

    merkletree_leaves = (
        args["merkletree_leaves"] or make_merkletree_leaves(args["merkletree_width"]) or None
    )
    if merkletree_leaves:
        state.merkletree = MerkleTreeState(compute_layers(merkletree_leaves))

    return state


@dataclass(frozen=True)
class NettingChannelStateProperties(Properties):
    canonical_identifier: CanonicalIdentifier = EMPTY
    token_address: TokenAddress = EMPTY
    payment_network_identifier: PaymentNetworkID = EMPTY

    reveal_timeout: BlockTimeout = EMPTY
    settle_timeout: BlockTimeout = EMPTY
    mediation_fee: FeeAmount = EMPTY

    our_state: NettingChannelEndStateProperties = EMPTY
    partner_state: NettingChannelEndStateProperties = EMPTY

    open_transaction: TransactionExecutionStatusProperties = EMPTY
    close_transaction: TransactionExecutionStatusProperties = EMPTY
    settle_transaction: TransactionExecutionStatusProperties = EMPTY

    TARGET_TYPE = NettingChannelState


NettingChannelStateProperties.DEFAULTS = NettingChannelStateProperties(
    canonical_identifier=CanonicalIdentifierProperties.DEFAULTS,
    token_address=UNIT_TOKEN_ADDRESS,
    payment_network_identifier=UNIT_PAYMENT_NETWORK_IDENTIFIER,
    reveal_timeout=UNIT_REVEAL_TIMEOUT,
    settle_timeout=UNIT_SETTLE_TIMEOUT,
    mediation_fee=0,
    our_state=NettingChannelEndStateProperties.DEFAULTS,
    partner_state=NettingChannelEndStateProperties.DEFAULTS,
    open_transaction=TransactionExecutionStatusProperties.DEFAULTS,
    close_transaction=None,
    settle_transaction=None,
)


@dataclass(frozen=True)
class TransferDescriptionProperties(Properties):
    payment_network_identifier: PaymentNetworkID = EMPTY
    payment_identifier: PaymentID = EMPTY
    amount: TokenAmount = EMPTY
    token_network_identifier: TokenNetworkID = EMPTY
    initiator: InitiatorAddress = EMPTY
    target: TargetAddress = EMPTY
    secret: Secret = EMPTY
    allocated_fee: FeeAmount = EMPTY
    TARGET_TYPE = TransferDescriptionWithSecretState


TransferDescriptionProperties.DEFAULTS = TransferDescriptionProperties(
    payment_network_identifier=UNIT_PAYMENT_NETWORK_IDENTIFIER,
    payment_identifier=UNIT_TRANSFER_IDENTIFIER,
    amount=UNIT_TRANSFER_AMOUNT,
    token_network_identifier=UNIT_TOKEN_NETWORK_ADDRESS,
    initiator=UNIT_TRANSFER_INITIATOR,
    target=UNIT_TRANSFER_TARGET,
    secret=GENERATE,
    allocated_fee=0,
)


@create.register(TransferDescriptionProperties)
def _(properties, defaults=None) -> TransferDescriptionWithSecretState:
    properties: TransferDescriptionProperties = create_properties(properties, defaults)
    params = {key: value for key, value in properties.__dict__.items()}
    if params["secret"] == GENERATE:
        params["secret"] = random_secret()
    return TransferDescriptionWithSecretState(**params)


UNIT_TRANSFER_DESCRIPTION = create(TransferDescriptionProperties(secret=UNIT_SECRET))


@dataclass(frozen=True)
class BalanceProofProperties(Properties):
    nonce: Nonce = EMPTY
    transferred_amount: TokenAmount = EMPTY
    locked_amount: TokenAmount = EMPTY
    locksroot: Locksroot = EMPTY
    canonical_identifier: CanonicalIdentifier = EMPTY
    TARGET_TYPE = BalanceProofUnsignedState


BalanceProofProperties.DEFAULTS = BalanceProofProperties(
    nonce=1,
    transferred_amount=UNIT_TRANSFER_AMOUNT,
    locked_amount=0,
    locksroot=EMPTY_MERKLE_ROOT,
    canonical_identifier=UNIT_CANONICAL_ID,
)


@dataclass(frozen=True)
class BalanceProofSignedStateProperties(BalanceProofProperties):
    message_hash: AdditionalHash = EMPTY
    signature: Signature = GENERATE
    sender: Address = EMPTY
    pkey: bytes = EMPTY
    TARGET_TYPE = BalanceProofSignedState


BalanceProofSignedStateProperties.DEFAULTS = BalanceProofSignedStateProperties(
    **BalanceProofProperties.DEFAULTS.__dict__,
    message_hash=UNIT_SECRETHASH,
    sender=UNIT_TRANSFER_SENDER,
    pkey=UNIT_TRANSFER_PKEY,
)


def make_signed_balance_proof_from_unsigned(
    unsigned: BalanceProofUnsignedState, signer: Signer
) -> BalanceProofSignedState:
    balance_hash = hash_balance_data(
        transferred_amount=unsigned.transferred_amount,
        locked_amount=unsigned.locked_amount,
        locksroot=unsigned.locksroot,
    )

    additional_hash = make_additional_hash()
    data_to_sign = balance_proof.pack_balance_proof(
        balance_hash=balance_hash,
        additional_hash=additional_hash,
        canonical_identifier=unsigned.canonical_identifier,
        nonce=unsigned.nonce,
    )

    signature = signer.sign(data=data_to_sign)
    sender = signer.address

    return BalanceProofSignedState(
        nonce=unsigned.nonce,
        transferred_amount=unsigned.transferred_amount,
        locked_amount=unsigned.locked_amount,
        locksroot=unsigned.locksroot,
        message_hash=additional_hash,
        signature=signature,
        sender=sender,
        canonical_identifier=unsigned.canonical_identifier,
    )


@create.register(BalanceProofSignedStateProperties)  # noqa: F811
def _(properties: BalanceProofSignedStateProperties, defaults=None) -> BalanceProofSignedState:
    defaults = defaults or BalanceProofSignedStateProperties.DEFAULTS
    params = create_properties(properties, defaults).__dict__
    signer = LocalSigner(params.pop("pkey"))

    if params["signature"] is GENERATE:
        keys = ("transferred_amount", "locked_amount", "locksroot")
        balance_hash = hash_balance_data(**_partial_dict(params, *keys))

        data_to_sign = balance_proof.pack_balance_proof(
            balance_hash=balance_hash,
            additional_hash=params["message_hash"],
            canonical_identifier=params["canonical_identifier"],
            nonce=params.get("nonce"),
        )

        params["signature"] = signer.sign(data=data_to_sign)

    return BalanceProofSignedState(**params)


@dataclass(frozen=True)
class LockedTransferUnsignedStateProperties(BalanceProofProperties):
    amount: TokenAmount = EMPTY
    expiration: BlockExpiration = EMPTY
    initiator: InitiatorAddress = EMPTY
    target: TargetAddress = EMPTY
    payment_identifier: PaymentID = EMPTY
    token: TokenAddress = EMPTY
    secret: Secret = EMPTY
    TARGET_TYPE = LockedTransferUnsignedState


LockedTransferUnsignedStateProperties.DEFAULTS = LockedTransferUnsignedStateProperties(
    **create_properties(
        BalanceProofProperties(locked_amount=UNIT_TRANSFER_AMOUNT, transferred_amount=0)
    ).__dict__,
    amount=UNIT_TRANSFER_AMOUNT,
    expiration=UNIT_REVEAL_TIMEOUT,
    initiator=UNIT_TRANSFER_INITIATOR,
    target=UNIT_TRANSFER_TARGET,
    payment_identifier=1,
    token=UNIT_TOKEN_ADDRESS,
    secret=UNIT_SECRET,
)


@create.register(LockedTransferUnsignedStateProperties)  # noqa: F811
def _(properties, defaults=None) -> LockedTransferUnsignedState:
    transfer: LockedTransferUnsignedStateProperties = create_properties(properties, defaults)
    lock = HashTimeLockState(
        amount=transfer.amount, expiration=transfer.expiration, secrethash=sha3(transfer.secret)
    )
    if transfer.locksroot == EMPTY_MERKLE_ROOT:
        transfer = replace(transfer, locksroot=lock.lockhash)

    return LockedTransferUnsignedState(
        balance_proof=create(transfer.extract(BalanceProofProperties)),
        lock=lock,
        **transfer.partial_dict("initiator", "target", "payment_identifier", "token"),
    )


@dataclass(frozen=True)
class LockedTransferSignedStateProperties(LockedTransferUnsignedStateProperties):
    sender: Address = EMPTY
    recipient: Address = EMPTY
    pkey: bytes = EMPTY
    message_identifier: MessageID = EMPTY
    TARGET_TYPE = LockedTransferSignedState


LockedTransferSignedStateProperties.DEFAULTS = LockedTransferSignedStateProperties(
    **LockedTransferUnsignedStateProperties.DEFAULTS.__dict__,
    sender=UNIT_TRANSFER_SENDER,
    recipient=UNIT_TRANSFER_TARGET,
    pkey=UNIT_TRANSFER_PKEY,
    message_identifier=1,
)


@create.register(LockedTransferSignedStateProperties)  # noqa: F811
def _(properties, defaults=None) -> LockedTransferSignedState:
    transfer: LockedTransferSignedStateProperties = create_properties(properties, defaults)
    params = {key: value for key, value in transfer.__dict__.items()}

    lock = Lock(
        amount=transfer.amount, expiration=transfer.expiration, secrethash=sha3(transfer.secret)
    )

    pkey = params.pop("pkey")
    signer = LocalSigner(pkey)
    sender = params.pop("sender")
    canonical_identifier = params.pop("canonical_identifier")
    params["chain_id"] = int(canonical_identifier.chain_identifier)
    params["channel_identifier"] = int(canonical_identifier.channel_identifier)
    params["token_network_address"] = canonical_identifier.token_network_address
    if params["locksroot"] == EMPTY_MERKLE_ROOT:
        params["locksroot"] = lock.lockhash

    locked_transfer = LockedTransfer(lock=lock, **params)
    locked_transfer.sign(signer)

    assert locked_transfer.sender == sender

    return lockedtransfersigned_from_message(locked_transfer)


@dataclass(frozen=True)
class LockedTransferProperties(LockedTransferSignedStateProperties):
    fee: FeeAmount = EMPTY
    TARGET_TYPE = LockedTransfer


LockedTransferProperties.DEFAULTS = LockedTransferProperties(
    **replace(LockedTransferSignedStateProperties.DEFAULTS, locksroot=GENERATE).__dict__, fee=0
)


def prepare_locked_transfer(properties, defaults):
    properties: LockedTransferProperties = create_properties(properties, defaults)
    params = {key: value for key, value in properties.__dict__.items()}

    canonical_identifier = params.pop("canonical_identifier")
    params["chain_id"] = canonical_identifier.chain_identifier
    params["token_network_address"] = canonical_identifier.token_network_address
    params["channel_identifier"] = canonical_identifier.channel_identifier

    secrethash = sha3(params.pop("secret"))
    params["lock"] = Lock(
        amount=properties.amount, expiration=properties.expiration, secrethash=secrethash
    )
    if params["locksroot"] == GENERATE:
        params["locksroot"] = sha3(params["lock"].as_bytes)

    return params, LocalSigner(params.pop("pkey"))


@create.register(LockedTransferProperties)
def _(properties, defaults=None) -> LockedTransfer:
    params, signer = prepare_locked_transfer(properties, defaults)
    transfer = LockedTransfer(**params)
    transfer.sign(signer)

    assert params["sender"] == transfer.sender
    return transfer


@dataclass(frozen=True)
class RefundTransferProperties(LockedTransferProperties):
    TARGET_TYPE = RefundTransfer


RefundTransferProperties.DEFAULTS = RefundTransferProperties(
    **LockedTransferProperties.DEFAULTS.__dict__
)


@create.register(RefundTransferProperties)
def _(properties, defaults=None) -> RefundTransfer:
    params, signer = prepare_locked_transfer(properties, defaults)
    transfer = RefundTransfer(**params)
    transfer.sign(signer)

    assert params["sender"] == transfer.sender
    return transfer


SIGNED_TRANSFER_FOR_CHANNEL_DEFAULTS = create_properties(
    LockedTransferSignedStateProperties(expiration=UNIT_SETTLE_TIMEOUT - UNIT_REVEAL_TIMEOUT)
)


def make_signed_transfer_for(
    channel_state: NettingChannelState = EMPTY,
    properties: LockedTransferSignedStateProperties = None,
    defaults: LockedTransferSignedStateProperties = None,
    compute_locksroot: bool = False,
    allow_invalid: bool = False,
    only_transfer: bool = True,
) -> LockedTransferSignedState:
    properties: LockedTransferSignedStateProperties = create_properties(
        properties or LockedTransferSignedStateProperties(),
        defaults or SIGNED_TRANSFER_FOR_CHANNEL_DEFAULTS,
    )

    channel_state = if_empty(channel_state, create(NettingChannelStateProperties()))

    if not allow_invalid:
        ok = channel_state.reveal_timeout < properties.expiration < channel_state.settle_timeout
        assert ok, "Expiration must be between reveal_timeout and settle_timeout."

    assert privatekey_to_address(properties.pkey) == properties.sender

    if properties.sender == channel_state.our_state.address:
        recipient = channel_state.partner_state.address
    elif properties.sender == channel_state.partner_state.address:
        recipient = channel_state.our_state.address
    else:
        assert False, "Given sender does not participate in given channel."

    if compute_locksroot:
        lock = Lock(
            amount=properties.amount,
            expiration=properties.expiration,
            secrethash=sha3(properties.secret),
        )
        locksroot = merkleroot(
            channel.compute_merkletree_with(
                merkletree=channel_state.partner_state.merkletree, lockhash=sha3(lock.as_bytes)
            )
        )
    else:
        locksroot = properties.locksroot

    if only_transfer:
        transfer_properties = LockedTransferUnsignedStateProperties(
            locksroot=locksroot,
            canonical_identifier=channel_state.canonical_identifier,
            locked_amount=properties.amount,
        )
    else:
        transfer_properties = LockedTransferUnsignedStateProperties(
            locksroot=locksroot, canonical_identifier=channel_state.canonical_identifier
        )
    transfer = create(
        LockedTransferSignedStateProperties(recipient=recipient, **transfer_properties.__dict__),
        defaults=properties,
    )

    if not allow_invalid:
        is_valid, msg, _ = channel.is_valid_lockedtransfer(
            transfer_state=transfer,
            channel_state=channel_state,
            sender_state=channel_state.partner_state,
            receiver_state=channel_state.our_state,
        )
        assert is_valid, msg

    return transfer


def pkeys_from_channel_state(
    properties: NettingChannelStateProperties,
    defaults: NettingChannelStateProperties = NettingChannelStateProperties.DEFAULTS,
) -> Tuple[Optional[bytes], Optional[bytes]]:
    our_key = None
    if properties.our_state is not EMPTY:
        our_key = properties.our_state.privatekey
    elif defaults is not None:
        our_key = defaults.our_state.privatekey

    partner_key = None
    if properties.partner_state is not EMPTY:
        partner_key = properties.partner_state.privatekey
    elif defaults is not None:
        partner_key = defaults.partner_state.privatekey

    return our_key, partner_key


class ChannelSet:
    """Manage a list of channels. The channels can be accessed by subscript."""

    HOP3_KEY, HOP3 = make_privkey_address()
    HOP4_KEY, HOP4 = make_privkey_address()
    HOP5_KEY, HOP5 = make_privkey_address()

    PKEYS = (HOP1_KEY, HOP2_KEY, HOP3_KEY, HOP4_KEY, HOP5_KEY)
    ADDRESSES = (HOP1, HOP2, HOP3, HOP4, HOP5)

    def __init__(
        self,
        channels: List[NettingChannelState],
        our_privatekeys: List[bytes],
        partner_privatekeys: List[bytes],
    ):
        self.channels = channels
        self.our_privatekeys = our_privatekeys
        self.partner_privatekeys = partner_privatekeys

    @property
    def channel_map(self) -> ChannelMap:
        return {channel.identifier: channel for channel in self.channels}

    @property
    def nodeaddresses_to_networkstates(self) -> NodeNetworkStateMap:
        return {channel.partner_state.address: NODE_NETWORK_REACHABLE for channel in self.channels}

    def our_address(self, index: int) -> Address:
        return self.channels[index].our_state.address

    def partner_address(self, index: int) -> Address:
        return self.channels[index].partner_state.address

    def get_route(self, channel_index: int) -> RouteState:
        return make_route_from_channel(self.channels[channel_index])

    def get_routes(self, *args) -> List[RouteState]:
        return [self.get_route(index) for index in (args or range(len(self.channels)))]

    def __getitem__(self, item: int) -> NettingChannelState:
        return self.channels[item]


def make_channel_set(
    properties: List[NettingChannelStateProperties] = None,
    defaults: NettingChannelStateProperties = NettingChannelStateProperties.DEFAULTS,
    number_of_channels: int = None,
) -> ChannelSet:
    if number_of_channels is None:
        number_of_channels = len(properties)

    channels = list()
    our_pkeys = [None] * number_of_channels
    partner_pkeys = [None] * number_of_channels

    if properties is None:
        properties = list()
    while len(properties) < number_of_channels:
        properties.append(NettingChannelStateProperties())

    for i in range(number_of_channels):
        our_pkeys[i], partner_pkeys[i] = pkeys_from_channel_state(properties[i], defaults)
        channels.append(create(properties[i], defaults))

    return ChannelSet(channels, our_pkeys, partner_pkeys)


def make_channel_set_from_amounts(amounts: List[TokenAmount]) -> ChannelSet:
    properties = [
        NettingChannelStateProperties(our_state=NettingChannelEndStateProperties(balance=amount))
        for amount in amounts
    ]
    return make_channel_set(properties)


def mediator_make_channel_pair(
    defaults: NettingChannelStateProperties = None, amount: TokenAmount = UNIT_TRANSFER_AMOUNT
) -> ChannelSet:
    properties_list = [
        NettingChannelStateProperties(
            canonical_identifier=make_canonical_identifier(channel_identifier=1),
            partner_state=NettingChannelEndStateProperties(
                address=UNIT_TRANSFER_SENDER, balance=amount
            ),
        ),
        NettingChannelStateProperties(
            canonical_identifier=make_canonical_identifier(channel_identifier=2),
            our_state=NettingChannelEndStateProperties(balance=amount),
            partner_state=NettingChannelEndStateProperties(address=UNIT_TRANSFER_TARGET),
        ),
    ]

    return make_channel_set(properties_list, defaults)


def mediator_make_init_action(
    channels: ChannelSet, transfer: LockedTransferSignedState
) -> ActionInitMediator:
    return ActionInitMediator(channels.get_routes(1), channels.get_route(0), transfer)


class MediatorTransfersPair(NamedTuple):
    channels: ChannelSet
    transfers_pair: List[MediationPairState]
    amount: int
    block_number: BlockNumber
    block_hash: BlockHash

    @property
    def channel_map(self) -> ChannelMap:
        return self.channels.channel_map


def make_transfers_pair(
    number_of_channels: int, amount: int = UNIT_TRANSFER_AMOUNT, block_number: int = 5
) -> MediatorTransfersPair:

    deposit = 5 * amount
    defaults = create_properties(
        NettingChannelStateProperties(
            our_state=NettingChannelEndStateProperties(balance=deposit),
            partner_state=NettingChannelEndStateProperties(balance=deposit),
            open_transaction=TransactionExecutionStatusProperties(finished_block_number=10),
        )
    )
    properties_list = [
        NettingChannelStateProperties(
            canonical_identifier=make_canonical_identifier(channel_identifier=i),
            our_state=NettingChannelEndStateProperties(
                address=ChannelSet.ADDRESSES[0], privatekey=ChannelSet.PKEYS[0]
            ),
            partner_state=NettingChannelEndStateProperties(
                address=ChannelSet.ADDRESSES[i + 1], privatekey=ChannelSet.PKEYS[i + 1]
            ),
        )
        for i in range(number_of_channels)
    ]
    channels = make_channel_set(properties_list, defaults)

    lock_expiration = block_number + UNIT_REVEAL_TIMEOUT * 2
    pseudo_random_generator = random.Random()
    transfers_pairs = list()

    for payer_index in range(number_of_channels - 1):
        payee_index = payer_index + 1

        receiver_channel = channels[payer_index]
        received_transfer = create(
            LockedTransferSignedStateProperties(
                amount=amount,
                expiration=lock_expiration,
                payment_identifier=UNIT_TRANSFER_IDENTIFIER,
                canonical_identifier=receiver_channel.canonical_identifier,
                sender=channels.partner_address(payer_index),
                pkey=channels.partner_privatekeys[payer_index],
            )
        )

        is_valid, _, msg = channel.handle_receive_lockedtransfer(
            receiver_channel, received_transfer
        )
        assert is_valid, msg

        message_identifier = message_identifier_from_prng(pseudo_random_generator)
        lockedtransfer_event = channel.send_lockedtransfer(
            channel_state=channels[payee_index],
            initiator=UNIT_TRANSFER_INITIATOR,
            target=UNIT_TRANSFER_TARGET,
            amount=amount,
            message_identifier=message_identifier,
            payment_identifier=UNIT_TRANSFER_IDENTIFIER,
            expiration=lock_expiration,
            secrethash=UNIT_SECRETHASH,
        )
        assert lockedtransfer_event

        lock_timeout = lock_expiration - block_number
        assert mediator.is_channel_usable(
            candidate_channel_state=channels[payee_index],
            transfer_amount=amount,
            lock_timeout=lock_timeout,
        )
        sent_transfer = lockedtransfer_event.transfer

        pair = MediationPairState(received_transfer, lockedtransfer_event.recipient, sent_transfer)
        transfers_pairs.append(pair)

    return MediatorTransfersPair(
        channels=channels,
        transfers_pair=transfers_pairs,
        amount=amount,
        block_number=block_number,
        block_hash=make_block_hash(),
    )


def make_node_availability_map(nodes):
    return {node: NODE_NETWORK_REACHABLE for node in nodes}


@dataclass(frozen=True)
class RouteProperties(Properties):
    address1: Address
    address2: Address
    capacity1to2: TokenAmount
    capacity2to1: TokenAmount = 0


def route_properties_to_channel(route: RouteProperties) -> NettingChannelState:
    channel = create(
        NettingChannelStateProperties(
            canonical_identifier=make_canonical_identifier(),
            our_state=NettingChannelEndStateProperties(
                address=route.address1, balance=route.capacity1to2
            ),
            partner_state=NettingChannelEndStateProperties(
                address=route.address2, balance=route.capacity2to1
            ),
        )
    )
    return channel  # type: ignore


def create_network(
    token_network_state: TokenNetworkState,
    our_address: Address,
    routes: List[RouteProperties],
    block_number: BlockNumber,
    block_hash: BlockHash = None,
) -> Tuple[Any, List[NettingChannelState]]:
    """Creates a network from route properties.

    If the address in the route is our_address, create a channel also.
    Returns a list of created channels and the new state.
    """

    block_hash = block_hash or make_block_hash()
    state = token_network_state
    channels = list()

    for count, route in enumerate(routes, 1):
        if route.address1 == our_address:
            channel = route_properties_to_channel(route)
            state_change = ContractReceiveChannelNew(
                transaction_hash=make_transaction_hash(),
                channel_state=channel,
                block_number=block_number,
                block_hash=block_hash,
            )
            channels.append(channel)
        else:
            state_change = ContractReceiveRouteNew(
                transaction_hash=make_transaction_hash(),
                canonical_identifier=make_canonical_identifier(),
                participant1=route.address1,
                participant2=route.address2,
                block_number=block_number,
                block_hash=block_hash,
            )

        iteration = token_network.state_transition(
            token_network_state=state,
            state_change=state_change,
            block_number=block_number,
            block_hash=block_hash,
        )
        state = iteration.new_state

        assert len(state.network_graph.channel_identifier_to_participants) == count
        assert len(state.network_graph.network.edges()) == count

    return state, channels
