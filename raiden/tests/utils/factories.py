# -*- coding: utf8 -*-
# pylint: disable=too-many-arguments
import os
import random
import string

from coincurve import PrivateKey

from raiden.messages import (
    Lock,
    MediatedTransfer,
    signing,
)
from raiden.utils import (
    sha3,
    publickey_to_address,
    privatekey_to_address,
)
from raiden.transfer import balance_proof, channel
from raiden.transfer.state import (
    BalanceProofSignedState,
    NettingChannelEndState,
    NettingChannelState,
    RouteState,
    TransactionExecutionStatus,
)
from raiden.transfer.state import BalanceProofUnsignedState
from raiden.transfer.mediated_transfer.state import (
    LockedTransferState,
    lockedtransfer_from_message,
    HashTimeLockState,
    TransferDescriptionWithSecretState,
    LockedTransferUnsignedState,
)
from raiden.transfer.state import CHANNEL_STATE_OPENED

# prefixing with UNIT_ to differ from the default globals
UNIT_SETTLE_TIMEOUT = 50
UNIT_REVEAL_TIMEOUT = 5
UNIT_TRANSFER_AMOUNT = 10

UNIT_SECRET = b'secretsecretsecretsecretsecretse'
UNIT_HASHLOCK = sha3(UNIT_SECRET)

UNIT_REGISTRY_IDENTIFIER = b'registryregistryregi'
UNIT_TOKEN_ADDRESS = b'tokentokentokentoken'
UNIT_CHANNEL_ADDRESS = b'channelchannelchanne'

UNIT_TRANSFER_IDENTIFIER = 37
UNIT_TRANSFER_INITIATOR = b'initiatorinitiatorin'
UNIT_TRANSFER_TARGET = b'targettargettargetta'
UNIT_TRANSFER_DESCRIPTION = TransferDescriptionWithSecretState(
    UNIT_TRANSFER_IDENTIFIER,
    UNIT_TRANSFER_AMOUNT,
    UNIT_REGISTRY_IDENTIFIER,
    UNIT_TOKEN_ADDRESS,
    UNIT_TRANSFER_INITIATOR,
    UNIT_TRANSFER_TARGET,
    UNIT_SECRET,
)
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

ADDR = b'addraddraddraddraddr'

# add the current block number to get the expiration
HOP1_TIMEOUT = UNIT_SETTLE_TIMEOUT
HOP2_TIMEOUT = HOP1_TIMEOUT - UNIT_REVEAL_TIMEOUT
HOP3_TIMEOUT = HOP2_TIMEOUT - UNIT_REVEAL_TIMEOUT


def make_address():
    return bytes(''.join(random.choice(string.printable) for _ in range(20)), encoding='utf-8')


def make_privkey_address():
    private_key_bin = os.urandom(32)
    privkey = PrivateKey(private_key_bin)
    pubkey = privkey.public_key.format(compressed=False)
    address = publickey_to_address(pubkey)
    return privkey, address


def make_route(
        node_address,
        available_balance,
        settle_timeout=UNIT_SETTLE_TIMEOUT,
        reveal_timeout=UNIT_REVEAL_TIMEOUT,
        closed_block=None,
        channel_address=None):
    """ Helper for creating a route.

    Args:
        node_address (address): The node address.
        available_balance (int): The available capacity of the route.
        settle_timeout (int): The settle_timeout of the route, as agreed in the netting contract.
        reveal_timeout (int): The configure reveal_timeout of the raiden node.
        channel_address (address): The correspoding channel address.
    """
    if channel_address is None:
        channel_address = ('channel' + node_address)[:40]

    state = CHANNEL_STATE_OPENED
    route = RouteState(
        state,
        node_address,
        channel_address,
        available_balance,
        settle_timeout,
        reveal_timeout,
        closed_block,
    )
    return route


def make_transfer(
        amount,
        initiator,
        target,
        expiration,
        secret=None,
        hashlock=UNIT_HASHLOCK,
        identifier=1,
        token=UNIT_TOKEN_ADDRESS):

    if secret is not None:
        assert sha3(secret) == hashlock

    transfer = LockedTransferState(
        identifier,
        amount,
        token,
        initiator,
        target,
        expiration,
        hashlock=hashlock,
        secret=secret,
    )
    return transfer


def make_from(amount, target, from_expiration, initiator=HOP6, secret=None):
    from_route = make_route(
        initiator,
        available_balance=amount,
    )

    from_transfer = make_transfer(
        amount,
        initiator,
        target,
        from_expiration,
        identifier=0,
        secret=secret,
    )

    return from_route, from_transfer


def make_endstate(address, balance):
    end_state = NettingChannelEndState(
        address,
        balance,
    )

    return end_state


def make_channel(
        our_balance=0,
        partner_balance=0,
        our_address=None,
        partner_address=None,
        token_address=None,
        channel_address=None,
        reveal_timeout=10):

    our_address = our_address or make_address()
    partner_address = partner_address or make_address()
    token_address = token_address or make_address()
    channel_address = channel_address or make_address()

    our_state = make_endstate(our_address, our_balance)
    partner_state = make_endstate(partner_address, partner_balance)

    settle_timeout = 50
    opened_block_number = 10

    open_transaction = TransactionExecutionStatus(
        None,
        opened_block_number,
        TransactionExecutionStatus.SUCCESS,
    )
    close_transaction = None
    settle_transaction = None

    channel_state = NettingChannelState(
        channel_address,
        token_address,
        reveal_timeout,
        settle_timeout,
        our_state,
        partner_state,
        open_transaction,
        close_transaction,
        settle_transaction,
    )

    return channel_state


def make_channel_mapping(channels_descriptions):
    mapping = {}
    for description in channels_descriptions:
        channel_state = make_channel(**description)
        mapping[channel_state.identifier] = channel_state

    return mapping


def make_transfer2(
        amount,
        initiator,
        target,
        expiration,
        secret,
        identifier=1,
        nonce=1,
        transferred_amount=0,
        channel_identifier=UNIT_CHANNEL_ADDRESS,
        locksroot=None,
        token=UNIT_TOKEN_ADDRESS):

    hashlock = sha3(secret)
    lock = HashTimeLockState(
        amount,
        expiration,
        hashlock,
    )

    if locksroot is None:
        locksroot = lock.lockhash

    unsigned_balance_proof = BalanceProofUnsignedState(
        nonce,
        transferred_amount,
        locksroot,
        channel_identifier,
    )

    transfer_state = LockedTransferUnsignedState(
        identifier,
        token,
        unsigned_balance_proof,
        lock,
        initiator,
        target,
    )

    return transfer_state


def make_signed_transfer(
        amount,
        initiator,
        target,
        expiration,
        secret,
        identifier=1,
        nonce=1,
        transferred_amount=0,
        recipient=UNIT_TRANSFER_TARGET,
        channel_identifier=UNIT_CHANNEL_ADDRESS,
        token=UNIT_TOKEN_ADDRESS,
        pkey=UNIT_TRANSFER_PKEY,
        sender=UNIT_TRANSFER_SENDER):

    hashlock = sha3(secret)
    lock = Lock(
        amount,
        expiration,
        hashlock,
    )

    transfer = MediatedTransfer(
        identifier,
        nonce,
        token,
        channel_identifier,
        transferred_amount,
        recipient,
        lock.lockhash,
        lock,
        target,
        initiator,
    )
    transfer.sign(pkey, sender)

    return lockedtransfer_from_message(transfer)


def make_signed_balance_proof(
        nonce,
        transferred_amount,
        channel_address,
        locksroot,
        extra_hash,
        private_key,
        sender_address):

    data_to_sign = balance_proof.signing_data(
        nonce,
        transferred_amount,
        channel_address,
        locksroot,
        extra_hash,
    )
    signature = signing.sign(data_to_sign, private_key)

    signed_balance_proof = BalanceProofSignedState(
        nonce,
        transferred_amount,
        locksroot,
        channel_address,
        extra_hash,
        signature,
        sender_address,
    )

    return signed_balance_proof


def make_signed_transfer_for(
        channel_state,
        amount,
        initiator,
        target,
        expiration,
        secret,
        identifier=1,
        nonce=1,
        transferred_amount=0,
        pkey=UNIT_TRANSFER_PKEY,
        sender=UNIT_TRANSFER_SENDER):

    pubkey = pkey.public_key.format(compressed=False)
    assert publickey_to_address(pubkey) == sender

    assert sender in (channel_state.our_state.address, channel_state.partner_state.address)
    if sender == channel_state.our_state.address:
        recipient = channel_state.partner_state.address
    else:
        recipient = channel_state.our_state.address

    channel_address = channel_state.identifier
    token_address = channel_state.token_address
    mediated_transfer = make_signed_transfer(
        amount,
        initiator,
        target,
        expiration,
        secret,
        identifier,
        nonce,
        transferred_amount,
        recipient,
        channel_address,
        token_address,
        pkey,
        sender,
    )

    # Do *not* register the transfer here
    is_valid, msg, _ = channel.is_valid_mediatedtransfer(
        mediated_transfer,
        channel_state,
        channel_state.partner_state,
        channel_state.our_state,
    )
    assert is_valid, msg

    return mediated_transfer


def make_transfer_description(
        amount,
        secret,
        identifier,
        initiator=None,
        target=None,
        token_address=UNIT_TOKEN_ADDRESS,
        registry=UNIT_REGISTRY_IDENTIFIER):

    initiator = initiator or make_address()
    target = target or make_address()

    transfer_description = TransferDescriptionWithSecretState(
        identifier,
        amount,
        registry,
        token_address,
        initiator,
        target,
        secret,
    )

    return transfer_description
