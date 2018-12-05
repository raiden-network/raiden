# pylint: disable=too-many-arguments
import random
import string
from copy import deepcopy
from typing import NamedTuple

from coincurve import PrivateKey

from raiden.constants import UINT64_MAX, UINT256_MAX
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
    EMPTY_MERKLE_ROOT,
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
from raiden.utils import privatekey_to_address, publickey_to_address, random_secret, sha3, typing
from raiden.utils.signing import eth_sign

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


def make_privatekey(privatekey_bin: bytes = EMPTY) -> PrivateKey:
    privatekey_bin = if_empty(privatekey_bin, make_privatekey_bin())
    return PrivateKey(privatekey_bin)


def make_privatekey_address(
        privatekey: PrivateKey = EMPTY,
) -> typing.Tuple[PrivateKey, typing.Address]:
    privatekey = if_empty(privatekey, make_privatekey())
    publickey = privatekey.public_key.format(compressed=False)
    address = publickey_to_address(publickey)
    return (privatekey, address)


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
        token_network_identifier=token_network_identifier,
        channel_identifier=channel_identifier,
        chain_id=UNIT_CHAIN_ID,
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
        pkey: PrivateKey = EMPTY,
        sender: typing.Address = EMPTY,
) -> LockedTransferSignedState:

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
    transfer.sign(pkey)
    assert transfer.sender == sender

    return lockedtransfersigned_from_message(transfer)


def make_signed_balance_proof(
        nonce: typing.Nonce = EMPTY,
        transferred_amount: typing.TokenAmount = EMPTY,
        locked_amount: typing.TokenAmount = EMPTY,
        token_network_address: typing.TokenNetworkID = EMPTY,
        channel_identifier: typing.ChannelID = EMPTY,
        locksroot: typing.Locksroot = EMPTY,
        extra_hash: typing.Keccak256 = EMPTY,
        private_key: PrivateKey = EMPTY,
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

    balance_hash = hash_balance_data(
        transferred_amount=transferred_amount,
        locked_amount=locked_amount,
        locksroot=locksroot,
    )
    data_to_sign = balance_proof.pack_balance_proof(
        nonce=nonce,
        balance_hash=balance_hash,
        additional_hash=extra_hash,
        channel_identifier=channel_identifier,
        token_network_identifier=token_network_address,
        chain_id=UNIT_CHAIN_ID,
    )

    signature = eth_sign(privkey=private_key, data=data_to_sign)

    return BalanceProofSignedState(
        nonce=nonce,
        transferred_amount=transferred_amount,
        locked_amount=locked_amount,
        locksroot=locksroot,
        token_network_identifier=token_network_address,
        channel_identifier=channel_identifier,
        message_hash=extra_hash,
        signature=signature,
        sender=sender_address,
        chain_id=UNIT_CHAIN_ID,
    )


def make_signed_transfer_for(
        channel_state: NettingChannelState = EMPTY,
        amount: typing.TokenAmount = EMPTY,
        initiator: typing.InitiatorAddress = EMPTY,
        target: typing.TargetAddress = EMPTY,
        expiration: typing.BlockExpiration = EMPTY,
        secret: typing.Secret = EMPTY,
        identifier: typing.PaymentID = EMPTY,
        nonce: typing.Nonce = EMPTY,
        transferred_amount: typing.TokenAmount = EMPTY,
        locked_amount: typing.TokenAmount = EMPTY,
        pkey: PrivateKey = EMPTY,
        sender: typing.Address = EMPTY,
        compute_locksroot: typing.Locksroot = EMPTY,
        allow_invalid: bool = EMPTY,
) -> LockedTransferSignedState:

    channel_state = if_empty(channel_state, make_channel_state())
    amount = if_empty(amount, 0)
    initiator = if_empty(initiator, make_address())
    target = if_empty(target, make_address())
    expiration = if_empty(expiration, UNIT_REVEAL_TIMEOUT)
    secret = if_empty(secret, make_secret())
    identifier = if_empty(identifier, 1)
    nonce = if_empty(nonce, 1)
    transferred_amount = if_empty(transferred_amount, 0)
    pkey = if_empty(pkey, UNIT_TRANSFER_PKEY)
    sender = if_empty(sender, UNIT_TRANSFER_SENDER)
    compute_locksroot = if_empty(compute_locksroot, False)
    allow_invalid = if_empty(allow_invalid, False)

    if not allow_invalid:
        msg = 'expiration must be lower than settle_timeout'
        assert expiration < channel_state.settle_timeout, msg
        msg = 'expiration must be larger than reveal_timeout'
        assert expiration > channel_state.reveal_timeout, msg

    pubkey = pkey.public_key.format(compressed=False)
    assert publickey_to_address(pubkey) == sender

    assert sender in (channel_state.our_state.address, channel_state.partner_state.address)
    if sender == channel_state.our_state.address:
        recipient = channel_state.partner_state.address
    else:
        recipient = channel_state.our_state.address

    channel_identifier = channel_state.identifier
    token_address = channel_state.token_address

    if compute_locksroot:
        locksroot = merkleroot(channel.compute_merkletree_with(
            channel_state.partner_state.merkletree,
            sha3(Lock(amount, expiration, sha3(secret)).as_bytes),
        ))
    else:
        locksroot = EMPTY_MERKLE_ROOT

    mediated_transfer = make_signed_transfer(
        amount=amount,
        initiator=initiator,
        target=target,
        expiration=expiration,
        secret=secret,
        payment_identifier=identifier,
        nonce=nonce,
        transferred_amount=transferred_amount,
        locksroot=locksroot,
        locked_amount=locked_amount,
        recipient=recipient,
        channel_identifier=channel_identifier,
        token_network_address=channel_state.token_network_identifier,
        token=token_address,
        pkey=pkey,
        sender=sender,
    )

    # Do *not* register the transfer here
    if not allow_invalid:
        is_valid, msg, _ = channel.is_valid_lockedtransfer(
            transfer_state=mediated_transfer,
            channel_state=channel_state,
            sender_state=channel_state.partner_state,
            receiver_state=channel_state.our_state,
        )
        assert is_valid, msg

    return mediated_transfer


def make_default_signed_transfer_for(
        channel_state: NettingChannelState,
        **kwargs,
) -> LockedTransferSignedState:
    parameters = {
        'amount': UNIT_TRANSFER_AMOUNT,
        'initiator': UNIT_TRANSFER_SENDER,
        'target': HOP2,
        'expiration': UNIT_SETTLE_TIMEOUT - UNIT_REVEAL_TIMEOUT,
        'secret': UNIT_SECRET,
    }
    parameters.update(kwargs)
    return make_signed_transfer_for(channel_state, **parameters)


def make_transfers_pair(privatekeys, amount, block_number):
    transfers_pair = list()
    channel_map = dict()
    pseudo_random_generator = random.Random()

    addresses = list()
    for pkey in privatekeys:
        pubkey = pkey.public_key.format(compressed=False)
        address = publickey_to_address(pubkey)
        addresses.append(address)

    key_address = list(zip(privatekeys, addresses))

    deposit_amount = amount * 5
    channels_state = {
        address: make_channel(
            our_address=HOP1,
            our_balance=deposit_amount,
            partner_balance=deposit_amount,
            partner_address=address,
            token_address=UNIT_TOKEN_ADDRESS,
            token_network_identifier=UNIT_TOKEN_NETWORK_ADDRESS,
        )
        for address in addresses
    }

    lock_expiration = block_number + UNIT_REVEAL_TIMEOUT * 2
    for (payer_key, payer_address), payee_address in zip(key_address[:-1], addresses[1:]):
        pay_channel = channels_state[payee_address]
        receive_channel = channels_state[payer_address]

        received_transfer = make_signed_transfer(
            amount=amount,
            initiator=UNIT_TRANSFER_INITIATOR,
            target=UNIT_TRANSFER_TARGET,
            expiration=lock_expiration,
            secret=UNIT_SECRET,
            payment_identifier=UNIT_TRANSFER_IDENTIFIER,
            channel_identifier=receive_channel.identifier,
            pkey=payer_key,
            sender=payer_address,
        )

        is_valid, _, msg = channel.handle_receive_lockedtransfer(
            receive_channel,
            received_transfer,
        )
        assert is_valid, msg

        message_identifier = message_identifier_from_prng(pseudo_random_generator)
        lockedtransfer_event = channel.send_lockedtransfer(
            channel_state=pay_channel,
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
            candidate_channel_state=pay_channel,
            transfer_amount=amount,
            lock_timeout=lock_timeout,
        )
        sent_transfer = lockedtransfer_event.transfer

        pair = MediationPairState(
            received_transfer,
            lockedtransfer_event.recipient,
            sent_transfer,
        )
        transfers_pair.append(pair)

        channel_map[receive_channel.identifier] = receive_channel
        channel_map[pay_channel.identifier] = pay_channel

        assert channel.is_lock_locked(receive_channel.partner_state, UNIT_SECRETHASH)
        assert channel.is_lock_locked(pay_channel.our_state, UNIT_SECRETHASH)

    return channel_map, transfers_pair


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
UNIT_TRANSFER_PKEY = PrivateKey(UNIT_TRANSFER_PKEY_BIN)
UNIT_TRANSFER_SENDER = privatekey_to_address(sha3(b'transfer pkey'))
HOP1_KEY = PrivateKey(b'11111111111111111111111111111111')
HOP2_KEY = PrivateKey(b'22222222222222222222222222222222')
HOP3_KEY = PrivateKey(b'33333333333333333333333333333333')
HOP4_KEY = PrivateKey(b'44444444444444444444444444444444')
HOP5_KEY = PrivateKey(b'55555555555555555555555555555555')
HOP6_KEY = PrivateKey(b'66666666666666666666666666666666')
HOP1 = privatekey_to_address(b'11111111111111111111111111111111')
HOP2 = privatekey_to_address(b'22222222222222222222222222222222')
HOP3 = privatekey_to_address(b'33333333333333333333333333333333')
HOP4 = privatekey_to_address(b'44444444444444444444444444444444')
HOP5 = privatekey_to_address(b'55555555555555555555555555555555')
HOP6 = privatekey_to_address(b'66666666666666666666666666666666')
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


def make_transaction_execution_status(
        started_block_number: typing.BlockNumber = None,
        finished_block_number: typing.BlockNumber = None,
        success: bool = True,
) -> TransactionExecutionStatus:
    status = TransactionExecutionStatus.SUCCESS if success else TransactionExecutionStatus.FAILURE
    return TransactionExecutionStatus(started_block_number, finished_block_number, status)


class NettingChannelEndStateRecord(NamedTuple):
    address: typing.Address = None
    balance: typing.TokenAmount = 100
    merkletree_leaves: typing.MerkleTreeLeaves = None
    merkletree_width: int = 0

    def create(self) -> NettingChannelEndState:
        state = NettingChannelEndState(self.address or make_address(), self.balance)

        merkletree_leaves = (
            self.merkletree_leaves or
            make_merkletree_leaves(self.merkletree_width) or
            None
        )
        if merkletree_leaves:
            state.merkletree = MerkleTreeState(compute_layers(merkletree_leaves))

        return state


class NettingChannelStateRecord(NamedTuple):
    identifier: typing.ChannelID = UNIT_CHANNEL_ID
    chain_id: typing.ChainID = UNIT_CHAIN_ID
    token_address: typing.TokenAddress = UNIT_TOKEN_ADDRESS
    payment_network_identifier: typing.PaymentNetworkID = UNIT_PAYMENT_NETWORK_IDENTIFIER
    token_network_identifier: typing.TokenNetworkID = UNIT_TOKEN_NETWORK_ADDRESS

    reveal_timeout: typing.BlockTimeout = UNIT_REVEAL_TIMEOUT
    settle_timeout: typing.BlockTimeout = UNIT_SETTLE_TIMEOUT

    our_state: NettingChannelEndStateRecord = None
    partner_state: NettingChannelEndStateRecord = None

    open_transaction: TransactionExecutionStatus = make_transaction_execution_status()
    close_transaction: TransactionExecutionStatus = None
    settle_transaction: TransactionExecutionStatus = None


def make_netting_channel_end_state_record(
        base: NettingChannelEndStateRecord = None,
        **kwargs,
) -> NettingChannelEndStateRecord:
    parameters = base._asdict() if base is not None else dict()
    parameters.update(**kwargs)
    return NettingChannelEndStateRecord(**parameters)


def make_netting_channel_end_state(
        base: NettingChannelEndStateRecord = None,
        **kwargs,
) -> NettingChannelEndState:
    return make_netting_channel_end_state_record(base, **kwargs).create()


def _base_to_dict(base: typing.Union[None, typing.Dict, typing.NamedTuple]) -> typing.Dict:
    if base is None:
        return dict()
    elif isinstance(base, dict):
        return base
    else:
        return base._asdict()


def make_record_netting_channel_state(
        base: NettingChannelStateRecord = None,
        **kwargs,
) -> NettingChannelStateRecord:
    parameters = _base_to_dict(base)
    parameters.update(**kwargs)
    return NettingChannelStateRecord(**parameters)


def _create_end_state(
        data: typing.Union[typing.Dict, NettingChannelEndStateRecord, NettingChannelEndState],
) -> NettingChannelEndState:

    if data is None:
        data = dict()
    if isinstance(data, dict):
        data = make_netting_channel_end_state_record(**data)
    if isinstance(data, NettingChannelEndStateRecord):
        data = data.create()
    return data


def _record_to_channel_state(record: NettingChannelStateRecord) -> NettingChannelState:
    parameters = record._asdict()

    parameters['our_state'] = _create_end_state(record.our_state)
    parameters['partner_state'] = _create_end_state(record.partner_state)

    state = NettingChannelState(**parameters)

    return state


def make_netting_channel_state(
        base: NettingChannelStateRecord = None,
        **kwargs,
) -> NettingChannelState:
    return _record_to_channel_state(make_record_netting_channel_state(base, **kwargs))


class ChannelSet:
    """Manage a list of channels from one address to different partner addresses.

    The channels can be accessed by subscript
    """
    DEFAULT_PARTNER_PKEYS = (HOP1_KEY, HOP2_KEY, HOP3_KEY, HOP4_KEY, HOP5_KEY)
    DEFAULT_PARTNER_ADDRESSES = (HOP1, HOP2, HOP3, HOP4, HOP5)

    def __init__(
            self,
            channels: typing.List[NettingChannelState],
            privatekeys: typing.List[PrivateKey],
    ):
        self.channels = channels
        self.privatekeys = privatekeys

    @property
    def channel_map(self) -> typing.ChannelMap:
        return {channel.identifier: channel for channel in self.channels}

    @property
    def our_address(self) -> typing.Address:
        return self.channels[0].our_state.address

    def partner_address(self, index: int) -> typing.Address:
        return self.channels[index].partner_state.address

    def partner_privatekey(self, index: int) -> PrivateKey:
        return self.privatekeys[index]

    def get_route(self, channel_index: int) -> RouteState:
        return route_from_channel(self.channels[channel_index])

    def get_routes(self, *args) -> typing.List[RouteState]:
        return [self.get_route(channel_index) for channel_index in args]

    def __getitem__(self, item: int) -> NettingChannelState:
        return self.channels[item]


def make_channel_set(
        channel_parameters: typing.List[typing.Dict],
        base: NettingChannelStateRecord = None,
        number_of_channels: int = 0,
) -> ChannelSet:
    channels = list()
    pkeys = list()

    for i in range(max(number_of_channels, len(channel_parameters))):
        parameters = deepcopy(channel_parameters[i])
        parameters.setdefault('identifier', make_channel_identifier())
        parameters.setdefault('partner_state', dict())

        if 'address' not in parameters['partner_state']:
            parameters['partner_state'] = {'address': ChannelSet.DEFAULT_PARTNER_ADDRESSES[i]}
            pkeys.append(ChannelSet.DEFAULT_PARTNER_PKEYS[i])
        else:
            pkeys.append(None)
        channels.append(make_netting_channel_state(base, **parameters))

    return ChannelSet(channels, pkeys)


def mediator_make_channel_pair(
        base: NettingChannelStateRecord = None,
        amount: typing.TokenAmount = UNIT_TRANSFER_AMOUNT,
) -> ChannelSet:
    channel_data = [
        {'partner_state': {'address': UNIT_TRANSFER_SENDER, 'balance': amount}},
        {'our_state': {'balance': amount}, 'partner_state': {'address': UNIT_TRANSFER_TARGET}},
    ]
    return make_channel_set(channel_data, base)


def mediator_make_init_action(
        channels: ChannelSet,
        transfer: LockedTransferSignedState,
) -> ActionInitMediator:
    return ActionInitMediator(channels.get_routes(1), channels.get_route(0), transfer)
