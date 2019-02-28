# pylint: disable=too-many-arguments
import random
import string
from functools import singledispatch
from typing import NamedTuple

from raiden.constants import EMPTY_MERKLE_ROOT, UINT64_MAX, UINT256_MAX
from raiden.messages import Lock, LockedTransfer
from raiden.transfer import balance_proof, channel
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
    TransactionExecutionStatus,
    message_identifier_from_prng,
)
from raiden.transfer.utils import hash_balance_data
from raiden.utils import CanonicalIdentifier, privatekey_to_address, random_secret, sha3, typing
from raiden.utils.signer import LocalSigner, Signer

EMPTY = object()


def if_empty(value, default):
    return value if value is not EMPTY else default


def make_uint256() -> int:
    return random.randint(0, UINT256_MAX)


def make_channel_identifier() -> typing.ChannelID:
    return typing.ChannelID(make_uint256())


def make_uint64() -> int:
    return random.randint(0, UINT64_MAX)


def make_balance() -> typing.Balance:
    return typing.Balance(random.randint(0, UINT256_MAX))


def make_block_number() -> typing.BlockNumber:
    return typing.BlockNumber(random.randint(0, UINT256_MAX))


def make_chain_id() -> typing.ChainID:
    return typing.ChainID(random.randint(0, UINT64_MAX))


def make_message_identifier() -> typing.MessageID:
    return typing.MessageID(random.randint(0, UINT64_MAX))


def make_20bytes() -> bytes:
    return bytes(''.join(random.choice(string.printable) for _ in range(20)), encoding='utf-8')


def make_address() -> typing.Address:
    return typing.Address(make_20bytes())


def make_32bytes() -> bytes:
    return bytes(''.join(random.choice(string.printable) for _ in range(32)), encoding='utf-8')


def make_transaction_hash() -> typing.TransactionHash:
    return typing.TransactionHash(make_32bytes())


def make_block_hash() -> typing.BlockHash:
    return typing.BlockHash(make_32bytes())


def make_privatekey_bin() -> bin:
    return make_32bytes()


def make_payment_network_identifier() -> typing.PaymentNetworkID:
    return typing.PaymentNetworkID(make_address())


def make_keccak_hash() -> typing.Keccak256:
    return typing.Keccak256(make_32bytes())


def make_secret(i: int = EMPTY) -> bytes:
    if i is not EMPTY:
        return format(i, '>032').encode()
    else:
        return make_32bytes()


def make_privatekey(privatekey_bin: bytes = EMPTY) -> bytes:
    return if_empty(privatekey_bin, make_privatekey_bin())


def make_privatekey_address(
        privatekey: bytes = EMPTY,
) -> typing.Tuple[bytes, typing.Address]:
    privatekey = if_empty(privatekey, make_privatekey())
    address = privatekey_to_address(privatekey)
    return privatekey, address


def make_signer(privatekey: bytes = EMPTY) -> Signer:
    privatekey = if_empty(privatekey, make_privatekey())
    return LocalSigner(privatekey)


def make_route_from_channel(channel_state: NettingChannelState = EMPTY) -> RouteState:
    channel_state = if_empty(channel_state, make_channel_state())
    return RouteState(channel_state.partner_state.address, channel_state.identifier)


def make_channel_endstate(
        address: typing.Address = EMPTY,
        balance: typing.Balance = EMPTY,
) -> NettingChannelEndState:
    address = if_empty(address, make_address())
    balance = if_empty(balance, 0)
    return NettingChannelEndState(address, balance)


def make_channel_state(
        our_balance: typing.Balance = EMPTY,
        partner_balance: typing.Balance = EMPTY,
        our_address: typing.Address = EMPTY,
        partner_address: typing.Address = EMPTY,
        token_address: typing.TokenAddress = EMPTY,
        payment_network_identifier: typing.PaymentNetworkID = EMPTY,
        token_network_identifier: typing.TokenNetworkID = EMPTY,
        channel_identifier: typing.ChannelID = EMPTY,
        reveal_timeout: typing.BlockTimeout = EMPTY,
        settle_timeout: int = EMPTY,
) -> NettingChannelState:

    our_balance = if_empty(our_balance, 0)
    partner_balance = if_empty(partner_balance, 0)
    our_address = if_empty(our_address, make_address())
    partner_address = if_empty(partner_address, make_address())
    token_address = if_empty(token_address, make_address())
    payment_network_identifier = if_empty(
        payment_network_identifier,
        make_payment_network_identifier(),
    )
    token_network_identifier = if_empty(token_network_identifier, make_address())
    channel_identifier = if_empty(channel_identifier, make_channel_identifier())
    reveal_timeout = if_empty(reveal_timeout, UNIT_REVEAL_TIMEOUT)
    settle_timeout = if_empty(settle_timeout, UNIT_SETTLE_TIMEOUT)

    opened_block_number = 10
    close_transaction: TransactionExecutionStatus = None
    settle_transaction: TransactionExecutionStatus = None
    our_state = make_channel_endstate(
        address=our_address,
        balance=our_balance,
    )
    partner_state = make_channel_endstate(
        address=partner_address,
        balance=partner_balance,
    )
    open_transaction = TransactionExecutionStatus(
        started_block_number=None,
        finished_block_number=opened_block_number,
        result=TransactionExecutionStatus.SUCCESS,
    )

    return NettingChannelState(
        identifier=channel_identifier,
        chain_id=UNIT_CHAIN_ID,
        token_address=token_address,
        payment_network_identifier=payment_network_identifier,
        token_network_identifier=token_network_identifier,
        reveal_timeout=reveal_timeout,
        settle_timeout=settle_timeout,
        our_state=our_state,
        partner_state=partner_state,
        open_transaction=open_transaction,
        close_transaction=close_transaction,
        settle_transaction=settle_transaction,
    )


def make_transfer_description(
        payment_network_identifier: typing.PaymentNetworkID = EMPTY,
        payment_identifier: typing.PaymentID = EMPTY,
        amount: typing.TokenAmount = EMPTY,
        token_network: typing.TokenNetworkID = EMPTY,
        initiator: typing.InitiatorAddress = EMPTY,
        target: typing.TargetAddress = EMPTY,
        secret: typing.Secret = EMPTY,
) -> TransferDescriptionWithSecretState:
    payment_network_identifier = if_empty(
        payment_network_identifier,
        UNIT_PAYMENT_NETWORK_IDENTIFIER,
    )
    payment_identifier = if_empty(payment_identifier, UNIT_TRANSFER_IDENTIFIER)
    amount = if_empty(amount, UNIT_TRANSFER_AMOUNT)
    token_network = if_empty(token_network, UNIT_TOKEN_NETWORK_ADDRESS)
    initiator = if_empty(initiator, UNIT_TRANSFER_INITIATOR)
    target = if_empty(target, UNIT_TRANSFER_TARGET)
    secret = if_empty(secret, random_secret())

    return TransferDescriptionWithSecretState(
        payment_network_identifier=payment_network_identifier,
        payment_identifier=payment_identifier,
        amount=amount,
        token_network_identifier=token_network,
        initiator=initiator,
        target=target,
        secret=secret,
    )


def make_transfer(
        amount: typing.TokenAmount = EMPTY,
        initiator: typing.InitiatorAddress = EMPTY,
        target: typing.TargetAddress = EMPTY,
        expiration: typing.BlockExpiration = EMPTY,
        secret: typing.Secret = EMPTY,
        identifier: typing.PaymentID = EMPTY,
        nonce: typing.Nonce = EMPTY,
        transferred_amount: typing.TokenAmount = EMPTY,
        locked_amount: typing.TokenAmount = EMPTY,
        token_network_identifier: typing.TokenNetworkID = EMPTY,
        channel_identifier: typing.ChannelID = EMPTY,
        locksroot: typing.Locksroot = EMPTY,
        token: typing.TargetAddress = EMPTY,
) -> LockedTransferUnsignedState:
    amount = if_empty(amount, UNIT_TRANSFER_AMOUNT)
    initiator = if_empty(initiator, make_address())
    target = if_empty(target, make_address())
    expiration = if_empty(expiration, UNIT_REVEAL_TIMEOUT)
    secret = if_empty(secret, make_secret())
    identifier = if_empty(identifier, 1)
    nonce = if_empty(nonce, 1)
    transferred_amount = if_empty(transferred_amount, 0)
    token_network_identifier = if_empty(token_network_identifier, UNIT_TOKEN_NETWORK_ADDRESS)
    channel_identifier = if_empty(channel_identifier, UNIT_CHANNEL_ID)
    token = if_empty(token, UNIT_TOKEN_ADDRESS)

    secrethash = sha3(secret)
    lock = HashTimeLockState(
        amount=amount,
        expiration=expiration,
        secrethash=secrethash,
    )

    if locksroot is EMPTY:
        locksroot = lock.lockhash
        locked_amount = amount
    else:
        assert locked_amount

    unsigned_balance_proof = BalanceProofUnsignedState(
        nonce=nonce,
        transferred_amount=transferred_amount,
        locked_amount=locked_amount,
        locksroot=locksroot,
        canonical_identifier=CanonicalIdentifier(
            chain_identifier=UNIT_CHAIN_ID,
            token_network_address=token_network_identifier,
            channel_identifier=channel_identifier,
        ),
    )

    return LockedTransferUnsignedState(
        payment_identifier=identifier,
        token=token,
        balance_proof=unsigned_balance_proof,
        lock=lock,
        initiator=initiator,
        target=target,
    )


def make_signed_transfer(
        amount: typing.TokenAmount = EMPTY,
        initiator: typing.InitiatorAddress = EMPTY,
        target: typing.TargetAddress = EMPTY,
        expiration: typing.BlockExpiration = EMPTY,
        secret: typing.Secret = EMPTY,
        payment_identifier: typing.PaymentID = EMPTY,
        message_identifier: typing.MessageID = EMPTY,
        nonce: typing.Nonce = EMPTY,
        transferred_amount: typing.TokenAmount = EMPTY,
        locked_amount: typing.TokenAmount = EMPTY,
        locksroot: typing.Locksroot = EMPTY,
        recipient: typing.Address = EMPTY,
        channel_identifier: typing.ChannelID = EMPTY,
        token_network_address: typing.TokenNetworkID = EMPTY,
        token: typing.TargetAddress = EMPTY,
        pkey: bytes = EMPTY,
        sender: typing.Address = EMPTY,
) -> LockedTransfer:

    amount = if_empty(amount, UNIT_TRANSFER_AMOUNT)
    initiator = if_empty(initiator, make_address())
    target = if_empty(target, make_address())
    expiration = if_empty(expiration, UNIT_REVEAL_TIMEOUT)
    secret = if_empty(secret, make_secret())
    payment_identifier = if_empty(payment_identifier, 1)
    message_identifier = if_empty(message_identifier, make_message_identifier())
    nonce = if_empty(nonce, 1)
    transferred_amount = if_empty(transferred_amount, 0)
    locked_amount = if_empty(locked_amount, amount)
    locksroot = if_empty(locksroot, EMPTY_MERKLE_ROOT)
    recipient = if_empty(recipient, UNIT_TRANSFER_TARGET)
    channel_identifier = if_empty(channel_identifier, UNIT_CHANNEL_ID)
    token_network_address = if_empty(token_network_address, UNIT_TOKEN_NETWORK_ADDRESS)
    token = if_empty(token, UNIT_TOKEN_ADDRESS)
    pkey = if_empty(pkey, UNIT_TRANSFER_PKEY)
    signer = LocalSigner(pkey)
    sender = if_empty(sender, UNIT_TRANSFER_SENDER)

    assert locked_amount >= amount

    secrethash = sha3(secret)
    lock = Lock(
        amount=amount,
        expiration=expiration,
        secrethash=secrethash,
    )

    if locksroot == EMPTY_MERKLE_ROOT:
        locksroot = sha3(lock.as_bytes)

    transfer = LockedTransfer(
        chain_id=UNIT_CHAIN_ID,
        message_identifier=message_identifier,
        payment_identifier=payment_identifier,
        nonce=nonce,
        token_network_address=token_network_address,
        token=token,
        channel_identifier=channel_identifier,
        transferred_amount=transferred_amount,
        locked_amount=locked_amount,
        recipient=recipient,
        locksroot=locksroot,
        lock=lock,
        target=target,
        initiator=initiator,
    )
    transfer.sign(signer)
    assert transfer.sender == sender
    return transfer


def make_signed_transfer_state(
        amount: typing.TokenAmount = EMPTY,
        initiator: typing.InitiatorAddress = EMPTY,
        target: typing.TargetAddress = EMPTY,
        expiration: typing.BlockExpiration = EMPTY,
        secret: typing.Secret = EMPTY,
        payment_identifier: typing.PaymentID = EMPTY,
        message_identifier: typing.MessageID = EMPTY,
        nonce: typing.Nonce = EMPTY,
        transferred_amount: typing.TokenAmount = EMPTY,
        locked_amount: typing.TokenAmount = EMPTY,
        locksroot: typing.Locksroot = EMPTY,
        recipient: typing.Address = EMPTY,
        channel_identifier: typing.ChannelID = EMPTY,
        token_network_address: typing.TokenNetworkID = EMPTY,
        token: typing.TargetAddress = EMPTY,
        pkey: bytes = EMPTY,
        sender: typing.Address = EMPTY,
) -> LockedTransferSignedState:

    transfer = make_signed_transfer(
        amount=amount,
        initiator=initiator,
        target=target,
        expiration=expiration,
        secret=secret,
        payment_identifier=payment_identifier,
        message_identifier=message_identifier,
        nonce=nonce,
        transferred_amount=transferred_amount,
        locked_amount=locked_amount,
        locksroot=locksroot,
        recipient=recipient,
        channel_identifier=channel_identifier,
        token_network_address=token_network_address,
        token=token,
        pkey=pkey,
        sender=sender,
    )
    return lockedtransfersigned_from_message(transfer)


def make_signed_balance_proof(
        nonce: typing.Nonce = EMPTY,
        transferred_amount: typing.TokenAmount = EMPTY,
        locked_amount: typing.TokenAmount = EMPTY,
        token_network_address: typing.TokenNetworkID = EMPTY,
        channel_identifier: typing.ChannelID = EMPTY,
        locksroot: typing.Locksroot = EMPTY,
        extra_hash: typing.Keccak256 = EMPTY,
        private_key: bytes = EMPTY,
        sender_address: typing.Address = EMPTY,
) -> BalanceProofSignedState:

    nonce = if_empty(nonce, make_uint256())
    transferred_amount = if_empty(transferred_amount, make_uint256())
    locked_amount = if_empty(locked_amount, make_uint256())
    token_network_address = if_empty(token_network_address, make_address())
    channel_identifier = if_empty(channel_identifier, make_uint256())
    locksroot = if_empty(locksroot, make_32bytes())
    extra_hash = if_empty(extra_hash, make_keccak_hash())
    private_key = if_empty(private_key, make_privatekey())
    sender_address = if_empty(sender_address, make_address())
    signer = LocalSigner(private_key)

    balance_hash = hash_balance_data(
        transferred_amount=transferred_amount,
        locked_amount=locked_amount,
        locksroot=locksroot,
    )
    data_to_sign = balance_proof.pack_balance_proof(
        nonce=nonce,
        balance_hash=balance_hash,
        additional_hash=extra_hash,
        canonical_identifier=CanonicalIdentifier(
            chain_identifier=UNIT_CHAIN_ID,
            token_network_address=token_network_address,
            channel_identifier=channel_identifier,
        ),
    )

    signature = signer.sign(data=data_to_sign)

    return BalanceProofSignedState(
        nonce=nonce,
        transferred_amount=transferred_amount,
        locked_amount=locked_amount,
        locksroot=locksroot,
        message_hash=extra_hash,
        signature=signature,
        sender=sender_address,
        canonical_identifier=CanonicalIdentifier(
            chain_identifier=UNIT_CHAIN_ID,
            token_network_address=token_network_address,
            channel_identifier=channel_identifier,
        ),
    )


# ALIASES
make_channel = make_channel_state
route_from_channel = make_route_from_channel
make_endstate = make_channel_endstate
make_privkey_address = make_privatekey_address

# CONSTANTS
# In this module constants are in the bottom because we need some of the
# factories.
# Prefixing with UNIT_ to differ from the default globals.
UNIT_SETTLE_TIMEOUT = 50
UNIT_REVEAL_TIMEOUT = 5
UNIT_TRANSFER_AMOUNT = 10
UNIT_SECRET = b'secretsecretsecretsecretsecretse'
UNIT_SECRETHASH = sha3(UNIT_SECRET)
UNIT_REGISTRY_IDENTIFIER = b'registryregistryregi'
UNIT_TOKEN_ADDRESS = b'tokentokentokentoken'
UNIT_TOKEN_NETWORK_ADDRESS = b'networknetworknetwor'
UNIT_CHANNEL_ID = 1338
UNIT_PAYMENT_NETWORK_IDENTIFIER = b'paymentnetworkidentifier'
UNIT_TRANSFER_IDENTIFIER = 37
UNIT_TRANSFER_INITIATOR = b'initiatorinitiatorin'
UNIT_TRANSFER_TARGET = b'targettargettargetta'
UNIT_TRANSFER_PKEY_BIN = sha3(b'transfer pkey')
UNIT_TRANSFER_PKEY = UNIT_TRANSFER_PKEY_BIN
UNIT_TRANSFER_SENDER = privatekey_to_address(sha3(b'transfer pkey'))
HOP1_KEY = b'11111111111111111111111111111111'
HOP2_KEY = b'22222222222222222222222222222222'
HOP3_KEY = b'33333333333333333333333333333333'
HOP4_KEY = b'44444444444444444444444444444444'
HOP5_KEY = b'55555555555555555555555555555555'
HOP6_KEY = b'66666666666666666666666666666666'
HOP1 = privatekey_to_address(HOP1_KEY)
HOP2 = privatekey_to_address(HOP2_KEY)
HOP3 = privatekey_to_address(HOP3_KEY)
HOP4 = privatekey_to_address(HOP4_KEY)
HOP5 = privatekey_to_address(HOP5_KEY)
HOP6 = privatekey_to_address(HOP6_KEY)
UNIT_CHAIN_ID = 337
ADDR = b'addraddraddraddraddr'
UNIT_TRANSFER_DESCRIPTION = make_transfer_description(secret=UNIT_SECRET)


RANDOM_FACTORIES = {
    typing.Address: make_address,
    typing.Balance: make_balance,
    typing.BlockNumber: make_block_number,
    typing.BlockTimeout: make_block_number,
    typing.ChainID: make_chain_id,
    typing.ChannelID: make_channel_identifier,
    typing.PaymentNetworkID: make_payment_network_identifier,
    typing.TokenNetworkID: make_payment_network_identifier,
    NettingChannelState: make_channel_state,
}


def make_merkletree_leaves(width: int) -> typing.List[typing.Secret]:
    return [make_secret() for _ in range(width)]


@singledispatch
def create(properties, defaults=None):
    """Create objects from their associated property class.

    E. g. a NettingChannelState from NettingChannelStateProperties. For any field in
    properties set to EMPTY a default will be used. The default values can be changed
    by giving another object of the same property type as the defaults argument.
    """
    return None


# the default implementation of create() must return None to not confuse pylint.
def _create_or_echo(properties, defaults=None):
    created = create(properties, defaults)
    return created if created is not None else properties


def _properties_to_dict(properties: NamedTuple, defaults: NamedTuple) -> typing.Dict:
    defaults_dict = defaults._asdict()
    return {
        key: if_empty(value, defaults_dict[key])
        for key, value in properties._asdict().items()
    }


def _dict_to_kwargs(properties_dict: typing.Dict) -> typing.Dict:
    return {key: _create_or_echo(value) for key, value in properties_dict.items()}


def _properties_to_kwargs(properties: NamedTuple, defaults: NamedTuple) -> typing.Dict:
    return _dict_to_kwargs(_properties_to_dict(properties, defaults))


def _partial_dict(full_dict: typing.Dict, *args) -> typing.Dict:
    return {key: full_dict[key] for key in args}


class TransactionExecutionStatusProperties(NamedTuple):
    started_block_number: typing.BlockNumber = EMPTY
    finished_block_number: typing.BlockNumber = EMPTY
    result: str = EMPTY


TRANSACTION_EXECUTION_STATUS_DEFAULTS = TransactionExecutionStatusProperties(
    started_block_number=None,
    finished_block_number=None,
    result=TransactionExecutionStatus.SUCCESS,
)


@create.register(TransactionExecutionStatusProperties)  # noqa: F811
def _(properties, defaults=None) -> TransactionExecutionStatus:
    return TransactionExecutionStatus(
        **_properties_to_kwargs(properties, defaults or TRANSACTION_EXECUTION_STATUS_DEFAULTS),
    )


class NettingChannelEndStateProperties(NamedTuple):
    address: typing.Address = EMPTY
    privatekey: bytes = EMPTY
    balance: typing.TokenAmount = EMPTY
    merkletree_leaves: typing.MerkleTreeLeaves = EMPTY
    merkletree_width: int = EMPTY


NETTING_CHANNEL_END_STATE_DEFAULTS = NettingChannelEndStateProperties(
    address=None,
    privatekey=None,
    balance=100,
    merkletree_leaves=None,
    merkletree_width=0,
)


@create.register(NettingChannelEndStateProperties)  # noqa: F811
def _(properties, defaults=None) -> NettingChannelEndState:
    args = _properties_to_kwargs(properties, defaults or NETTING_CHANNEL_END_STATE_DEFAULTS)
    state = NettingChannelEndState(args['address'] or make_address(), args['balance'])

    merkletree_leaves = (
        args['merkletree_leaves'] or
        make_merkletree_leaves(args['merkletree_width']) or
        None
    )
    if merkletree_leaves:
        state.merkletree = MerkleTreeState(compute_layers(merkletree_leaves))

    return state


class NettingChannelStateProperties(NamedTuple):
    identifier: typing.ChannelID = EMPTY
    chain_id: typing.ChainID = EMPTY
    token_address: typing.TokenAddress = EMPTY
    payment_network_identifier: typing.PaymentNetworkID = EMPTY
    token_network_identifier: typing.TokenNetworkID = EMPTY

    reveal_timeout: typing.BlockTimeout = EMPTY
    settle_timeout: typing.BlockTimeout = EMPTY

    our_state: NettingChannelEndStateProperties = EMPTY
    partner_state: NettingChannelEndStateProperties = EMPTY

    open_transaction: TransactionExecutionStatusProperties = EMPTY
    close_transaction: TransactionExecutionStatusProperties = EMPTY
    settle_transaction: TransactionExecutionStatusProperties = EMPTY


NETTING_CHANNEL_STATE_DEFAULTS = NettingChannelStateProperties(
    identifier=UNIT_CHANNEL_ID,
    chain_id=UNIT_CHAIN_ID,
    token_address=UNIT_TOKEN_ADDRESS,
    payment_network_identifier=UNIT_PAYMENT_NETWORK_IDENTIFIER,
    token_network_identifier=UNIT_TOKEN_NETWORK_ADDRESS,
    reveal_timeout=UNIT_REVEAL_TIMEOUT,
    settle_timeout=UNIT_SETTLE_TIMEOUT,
    our_state=NETTING_CHANNEL_END_STATE_DEFAULTS,
    partner_state=NETTING_CHANNEL_END_STATE_DEFAULTS,
    open_transaction=TRANSACTION_EXECUTION_STATUS_DEFAULTS,
    close_transaction=None,
    settle_transaction=None,
)


@create.register(NettingChannelStateProperties)  # noqa: F811
def _(properties, defaults=None) -> NettingChannelState:
    return NettingChannelState(
        **_properties_to_kwargs(properties, defaults or NETTING_CHANNEL_STATE_DEFAULTS),
    )


class BalanceProofProperties(NamedTuple):
    nonce: typing.Nonce = EMPTY
    transferred_amount: typing.TokenAmount = EMPTY
    locked_amount: typing.TokenAmount = EMPTY
    locksroot: typing.Locksroot = EMPTY
    token_network_identifier: typing.TokenNetworkID = EMPTY
    channel_identifier: typing.ChannelID = EMPTY
    chain_id: typing.ChainID = EMPTY


BALANCE_PROOF_DEFAULTS = BalanceProofProperties(
    nonce=1,
    transferred_amount=UNIT_TRANSFER_AMOUNT,
    locked_amount=0,
    locksroot=EMPTY_MERKLE_ROOT,
    token_network_identifier=UNIT_TOKEN_NETWORK_ADDRESS,
    channel_identifier=UNIT_CHANNEL_ID,
    chain_id=UNIT_CHAIN_ID,
)


@create.register(BalanceProofProperties)  # noqa: F811
def _(properties, defaults=None) -> BalanceProofUnsignedState:
    return BalanceProofUnsignedState(
        **_properties_to_kwargs(properties, defaults or BALANCE_PROOF_DEFAULTS),
    )


class BalanceProofSignedStateProperties(NamedTuple):
    balance_proof: BalanceProofProperties = EMPTY
    message_hash: typing.AdditionalHash = EMPTY
    signature: typing.Signature = EMPTY
    sender: typing.Address = EMPTY
    pkey: bytes = EMPTY


BALANCE_PROOF_SIGNED_STATE_DEFAULTS = BalanceProofSignedStateProperties(
    balance_proof=BALANCE_PROOF_DEFAULTS,
    sender=UNIT_TRANSFER_SENDER,
    pkey=UNIT_TRANSFER_PKEY,
)


@create.register(BalanceProofSignedStateProperties)  # noqa: F811
def _(properties: BalanceProofSignedStateProperties, defaults=None) -> BalanceProofSignedState:
    defaults = defaults or BALANCE_PROOF_SIGNED_STATE_DEFAULTS
    params = _properties_to_dict(properties, defaults)
    params.update(
        _properties_to_dict(params.pop('balance_proof'), defaults.balance_proof),
    )
    signer = LocalSigner(params.pop('pkey'))

    if params['signature'] is EMPTY:
        keys = ('transferred_amount', 'locked_amount', 'locksroot')
        balance_hash = hash_balance_data(**_partial_dict(params, *keys))

        canonical_identifier = CanonicalIdentifier(
            chain_identifier=params.pop('chain_id'),
            token_network_address=params.pop('token_network_identifier'),
            channel_identifier=params.pop('channel_identifier'),
        )
        params['canonical_identifier'] = canonical_identifier

        data_to_sign = balance_proof.pack_balance_proof(
            balance_hash=balance_hash,
            additional_hash=params['message_hash'],
            canonical_identifier=canonical_identifier,
            nonce=params.get('nonce'),
        )

        params['signature'] = signer.sign(data=data_to_sign)

    return BalanceProofSignedState(**params)


class LockedTransferProperties(NamedTuple):
    balance_proof: BalanceProofProperties = EMPTY
    amount: typing.TokenAmount = EMPTY
    expiration: typing.BlockExpiration = EMPTY
    initiator: typing.InitiatorAddress = EMPTY
    target: typing.TargetAddress = EMPTY
    payment_identifier: typing.PaymentID = EMPTY
    token: typing.TokenAddress = EMPTY
    secret: typing.Secret = EMPTY


LOCKED_TRANSFER_DEFAULTS = LockedTransferProperties(
    balance_proof=BALANCE_PROOF_DEFAULTS,
    amount=UNIT_TRANSFER_AMOUNT,
    expiration=UNIT_REVEAL_TIMEOUT,
    initiator=UNIT_TRANSFER_INITIATOR,
    target=UNIT_TRANSFER_TARGET,
    payment_identifier=1,
    token=UNIT_TOKEN_ADDRESS,
    secret=UNIT_SECRET,
)


@create.register(LockedTransferProperties)  # noqa: F811
def _(properties, defaults=None) -> LockedTransferUnsignedState:
    defaults = defaults or LOCKED_TRANSFER_DEFAULTS
    parameters = _properties_to_dict(properties, defaults)

    lock = HashTimeLockState(
        amount=parameters.pop('amount'),
        expiration=parameters.pop('expiration'),
        secrethash=sha3(parameters.pop('secret')),
    )

    balance_proof_parameters = _properties_to_dict(
        parameters.pop('balance_proof'),
        defaults.balance_proof,
    )
    balance_proof_parameters['canonical_identifier'] = CanonicalIdentifier(
        chain_identifier=balance_proof_parameters.pop('chain_id'),
        token_network_address=balance_proof_parameters.pop('token_network_identifier'),
        channel_identifier=balance_proof_parameters.pop('channel_identifier'),
    )
    if balance_proof_parameters['locksroot'] == EMPTY_MERKLE_ROOT:
        balance_proof_parameters['locksroot'] = lock.lockhash
    balance_proof = BalanceProofUnsignedState(**balance_proof_parameters)

    return LockedTransferUnsignedState(balance_proof=balance_proof, lock=lock, **parameters)


class LockedTransferSignedStateProperties(NamedTuple):
    transfer: LockedTransferProperties = EMPTY
    sender: typing.Address = EMPTY
    recipient: typing.Address = EMPTY
    pkey: bytes = EMPTY
    message_identifier: typing.MessageID = EMPTY


LOCKED_TRANSFER_SIGNED_STATE_DEFAULTS = LockedTransferSignedStateProperties(
    transfer=LOCKED_TRANSFER_DEFAULTS,
    sender=UNIT_TRANSFER_SENDER,
    recipient=UNIT_TRANSFER_TARGET,
    pkey=UNIT_TRANSFER_PKEY,
    message_identifier=1,
)


@create.register(LockedTransferSignedStateProperties)  # noqa: F811
def _(properties, defaults=None) -> LockedTransferSignedState:
    defaults = defaults or LOCKED_TRANSFER_SIGNED_STATE_DEFAULTS
    params = _properties_to_dict(properties, defaults)

    transfer_params = _properties_to_dict(params.pop('transfer'), defaults.transfer)
    balance_proof_params = _properties_to_dict(
        transfer_params.pop('balance_proof'),
        defaults.transfer.balance_proof,
    )

    lock = Lock(
        amount=transfer_params.pop('amount'),
        expiration=transfer_params.pop('expiration'),
        secrethash=sha3(transfer_params.pop('secret')),
    )

    pkey = params.pop('pkey')
    signer = LocalSigner(pkey)
    sender = params.pop('sender')
    params.update(transfer_params)
    params.update(balance_proof_params)
    params['token_network_address'] = params.pop('token_network_identifier')
    if params['locksroot'] == EMPTY_MERKLE_ROOT:
        params['locksroot'] = lock.lockhash

    locked_transfer = LockedTransfer(lock=lock, **params)
    locked_transfer.sign(signer)

    assert locked_transfer.sender == sender

    return lockedtransfersigned_from_message(locked_transfer)


DEFAULTS_BY_TYPE = {
    TransactionExecutionStatusProperties: TRANSACTION_EXECUTION_STATUS_DEFAULTS,
    NettingChannelEndStateProperties: NETTING_CHANNEL_END_STATE_DEFAULTS,
    NettingChannelStateProperties: NETTING_CHANNEL_STATE_DEFAULTS,
    BalanceProofProperties: BALANCE_PROOF_DEFAULTS,
    BalanceProofSignedStateProperties: BALANCE_PROOF_SIGNED_STATE_DEFAULTS,
    LockedTransferProperties: LOCKED_TRANSFER_DEFAULTS,
    LockedTransferSignedStateProperties: LOCKED_TRANSFER_SIGNED_STATE_DEFAULTS,
}


def create_properties(properties: NamedTuple, defaults: NamedTuple = None) -> NamedTuple:
    parameters = (defaults or DEFAULTS_BY_TYPE[type(properties)])._asdict()
    for key, value in properties._asdict().items():
        if type(value) in DEFAULTS_BY_TYPE.keys():
            parameters[key] = create_properties(value, parameters[key])
        elif value is not EMPTY:
            parameters[key] = value
    return type(properties)(**parameters)


SIGNED_TRANSFER_FOR_CHANNEL_DEFAULTS = create_properties(LockedTransferSignedStateProperties(
    transfer=LockedTransferProperties(expiration=UNIT_SETTLE_TIMEOUT - UNIT_REVEAL_TIMEOUT),
))


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
        expiration = properties.transfer.expiration
        valid = channel_state.reveal_timeout < expiration < channel_state.settle_timeout
        assert valid, 'Expiration must be between reveal_timeout and settle_timeout.'

    assert privatekey_to_address(properties.pkey) == properties.sender

    if properties.sender == channel_state.our_state.address:
        recipient = channel_state.partner_state.address
    elif properties.sender == channel_state.partner_state.address:
        recipient = channel_state.our_state.address
    else:
        assert False, 'Given sender does not participate in given channel.'

    if compute_locksroot:
        lock = Lock(
            amount=properties.transfer.amount,
            expiration=properties.transfer.expiration,
            secrethash=sha3(properties.transfer.secret),
        )
        locksroot = merkleroot(channel.compute_merkletree_with(
            merkletree=channel_state.partner_state.merkletree,
            lockhash=sha3(lock.as_bytes),
        ))
    else:
        locksroot = properties.transfer.balance_proof.locksroot

    if only_transfer:
        balance_proof_properties = BalanceProofProperties(
            locksroot=locksroot,
            channel_identifier=channel_state.identifier,
            transferred_amount=0,
            locked_amount=properties.transfer.amount,
        )
    else:
        balance_proof_properties = BalanceProofProperties(
            locksroot=locksroot,
            channel_identifier=channel_state.identifier,
        )
    transfer = create(
        LockedTransferSignedStateProperties(
            recipient=recipient,
            transfer=LockedTransferProperties(
                balance_proof=balance_proof_properties,
            ),
        ),
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
        defaults: NettingChannelStateProperties = NETTING_CHANNEL_STATE_DEFAULTS,
) -> typing.Tuple[typing.Optional[bytes], typing.Optional[bytes]]:

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
    PKEYS = (HOP1_KEY, HOP2_KEY, HOP3_KEY, HOP4_KEY, HOP5_KEY)
    ADDRESSES = (HOP1, HOP2, HOP3, HOP4, HOP5)

    def __init__(
            self,
            channels: typing.List[NettingChannelState],
            our_privatekeys: typing.List[bytes],
            partner_privatekeys: typing.List[bytes],
    ):
        self.channels = channels
        self.our_privatekeys = our_privatekeys
        self.partner_privatekeys = partner_privatekeys

    @property
    def channel_map(self) -> typing.ChannelMap:
        return {channel.identifier: channel for channel in self.channels}

    @property
    def nodeaddresses_to_networkstates(self) -> typing.NodeNetworkStateMap:
        return {
            channel.partner_state.address: NODE_NETWORK_REACHABLE
            for channel in self.channels
        }

    def our_address(self, index: int) -> typing.Address:
        return self.channels[index].our_state.address

    def partner_address(self, index: int) -> typing.Address:
        return self.channels[index].partner_state.address

    def get_route(self, channel_index: int) -> RouteState:
        return route_from_channel(self.channels[channel_index])

    def get_routes(self, *args) -> typing.List[RouteState]:
        return [self.get_route(channel_index) for channel_index in args]

    def __getitem__(self, item: int) -> NettingChannelState:
        return self.channels[item]


def make_channel_set(
        properties: typing.List[NettingChannelStateProperties] = None,
        defaults: NettingChannelStateProperties = NETTING_CHANNEL_STATE_DEFAULTS,
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


def mediator_make_channel_pair(
        defaults: NettingChannelStateProperties = None,
        amount: typing.TokenAmount = UNIT_TRANSFER_AMOUNT,
) -> ChannelSet:
    properties_list = [
        NettingChannelStateProperties(
            identifier=1,
            partner_state=NettingChannelEndStateProperties(
                address=UNIT_TRANSFER_SENDER,
                balance=amount,
            ),
        ),
        NettingChannelStateProperties(
            identifier=2,
            our_state=NettingChannelEndStateProperties(balance=amount),
            partner_state=NettingChannelEndStateProperties(address=UNIT_TRANSFER_TARGET),
        ),
    ]

    return make_channel_set(properties_list, defaults)


def mediator_make_init_action(
        channels: ChannelSet,
        transfer: LockedTransferSignedState,
) -> ActionInitMediator:
    return ActionInitMediator(channels.get_routes(1), channels.get_route(0), transfer)


class MediatorTransfersPair(NamedTuple):
    channels: ChannelSet
    transfers_pair: typing.List[MediationPairState]
    amount: int
    block_number: typing.BlockNumber
    block_hash: typing.BlockHash

    @property
    def channel_map(self) -> typing.ChannelMap:
        return self.channels.channel_map


def make_transfers_pair(
        number_of_channels: int,
        amount: int = UNIT_TRANSFER_AMOUNT,
        block_number: int = 5,
) -> MediatorTransfersPair:

    deposit = 5 * amount
    defaults = create_properties(NettingChannelStateProperties(
        our_state=NettingChannelEndStateProperties(balance=deposit),
        partner_state=NettingChannelEndStateProperties(balance=deposit),
        open_transaction=TransactionExecutionStatusProperties(finished_block_number=10),
    ))
    properties_list = [
        NettingChannelStateProperties(
            identifier=i,
            our_state=NettingChannelEndStateProperties(
                address=ChannelSet.ADDRESSES[0],
                privatekey=ChannelSet.PKEYS[0],
            ),
            partner_state=NettingChannelEndStateProperties(
                address=ChannelSet.ADDRESSES[i + 1],
                privatekey=ChannelSet.PKEYS[i + 1],
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
        received_transfer = make_signed_transfer_state(
            amount=amount,
            initiator=UNIT_TRANSFER_INITIATOR,
            target=UNIT_TRANSFER_TARGET,
            expiration=lock_expiration,
            secret=UNIT_SECRET,
            payment_identifier=UNIT_TRANSFER_IDENTIFIER,
            channel_identifier=receiver_channel.identifier,
            pkey=channels.partner_privatekeys[payer_index],
            sender=channels.partner_address(payer_index),
        )

        is_valid, _, msg = channel.handle_receive_lockedtransfer(
            receiver_channel,
            received_transfer,
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

        pair = MediationPairState(
            received_transfer,
            lockedtransfer_event.recipient,
            sent_transfer,
        )
        transfers_pairs.append(pair)

    return MediatorTransfersPair(
        channels=channels,
        transfers_pair=transfers_pairs,
        amount=amount,
        block_number=block_number,
        block_hash=make_block_hash(),
    )


def make_node_availability_map(nodes):
    return {
        node: NODE_NETWORK_REACHABLE
        for node in nodes
    }
