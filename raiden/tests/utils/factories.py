# pylint: disable=too-many-arguments
import os
import random
import string

from coincurve import PrivateKey

from raiden.constants import UINT64_MAX
from raiden.messages import (
    Lock,
    LockedTransfer,
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
from raiden.transfer.state import BalanceProofUnsignedState, EMPTY_MERKLE_ROOT
from raiden.transfer.mediated_transfer.state import (
    lockedtransfersigned_from_message,
    HashTimeLockState,
    TransferDescriptionWithSecretState,
    LockedTransferUnsignedState,
)
from raiden.transfer.utils import hash_balance_data

# prefixing with UNIT_ to differ from the default globals
UNIT_SETTLE_TIMEOUT = 50
UNIT_REVEAL_TIMEOUT = 5
UNIT_TRANSFER_AMOUNT = 10

UNIT_SECRET = b'secretsecretsecretsecretsecretse'
UNIT_SECRETHASH = sha3(UNIT_SECRET)

UNIT_REGISTRY_IDENTIFIER = b'registryregistryregi'
UNIT_TOKEN_ADDRESS = b'tokentokentokentoken'
UNIT_TOKEN_NETWORK_ADDRESS = b'networknetworknetwor'
UNIT_CHANNEL_ADDRESS = b'channelchannelchanne'
UNIT_CHANNEL_ID = sha3(UNIT_CHANNEL_ADDRESS)

UNIT_TRANSFER_IDENTIFIER = 37
UNIT_TRANSFER_INITIATOR = b'initiatorinitiatorin'
UNIT_TRANSFER_TARGET = b'targettargettargetta'
UNIT_TRANSFER_DESCRIPTION = TransferDescriptionWithSecretState(
    UNIT_TRANSFER_IDENTIFIER,
    UNIT_TRANSFER_AMOUNT,
    UNIT_TOKEN_NETWORK_ADDRESS,
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
UNIT_CHAIN_ID = 337

ADDR = b'addraddraddraddraddr'


def make_address():
    return bytes(''.join(random.choice(string.printable) for _ in range(20)), encoding='utf-8')


def make_channel_identifier():
    return bytes(''.join(random.choice(string.printable) for _ in range(32)), encoding='utf-8')


def make_privkey_address():
    private_key_bin = os.urandom(32)
    privkey = PrivateKey(private_key_bin)
    pubkey = privkey.public_key.format(compressed=False)
    address = publickey_to_address(pubkey)
    return privkey, address


def make_secret(i):
    return format(i, '>032').encode()


def route_from_channel(channel_state):
    route = RouteState(
        channel_state.partner_state.address,
        channel_state.identifier,
    )
    return route


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
        token_network_identifier=None,
        channel_identifier=None,
        reveal_timeout=10,
        settle_timeout=50,
):

    our_address = our_address or make_address()
    partner_address = partner_address or make_address()
    token_address = token_address or make_address()
    token_network_identifier = token_network_identifier or make_address()
    channel_identifier = channel_identifier or make_channel_identifier()

    our_state = make_endstate(our_address, our_balance)
    partner_state = make_endstate(partner_address, partner_balance)

    opened_block_number = 10
    open_transaction = TransactionExecutionStatus(
        None,
        opened_block_number,
        TransactionExecutionStatus.SUCCESS,
    )
    close_transaction = None
    settle_transaction = None

    channel_state = NettingChannelState(
        identifier=channel_identifier,
        chain_id=UNIT_CHAIN_ID,
        token_address=token_address,
        token_network_identifier=token_network_identifier,
        reveal_timeout=reveal_timeout,
        settle_timeout=settle_timeout,
        our_state=our_state,
        partner_state=partner_state,
        open_transaction=open_transaction,
        close_transaction=close_transaction,
        settle_transaction=settle_transaction,
    )

    return channel_state


def make_transfer(
        amount,
        initiator,
        target,
        expiration,
        secret,
        identifier=1,
        nonce=1,
        transferred_amount=0,
        locked_amount=None,
        token_network_identifier=UNIT_TOKEN_NETWORK_ADDRESS,
        channel_identifier=UNIT_CHANNEL_ID,
        locksroot=None,
        token=UNIT_TOKEN_ADDRESS,
):

    secrethash = sha3(secret)
    lock = HashTimeLockState(
        amount,
        expiration,
        secrethash,
    )

    if locksroot is None:
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
        channel_address=channel_identifier,
        chain_id=UNIT_CHAIN_ID,
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
        payment_identifier=1,
        message_identifier=None,
        nonce=1,
        transferred_amount=0,
        locked_amount=None,
        locksroot=EMPTY_MERKLE_ROOT,
        recipient=UNIT_TRANSFER_TARGET,
        channel_identifier=UNIT_CHANNEL_ID,
        token=UNIT_TOKEN_ADDRESS,
        pkey=UNIT_TRANSFER_PKEY,
        sender=UNIT_TRANSFER_SENDER,
):

    if message_identifier is None:
        message_identifier = random.randint(0, UINT64_MAX)

    secrethash = sha3(secret)
    lock = Lock(
        amount,
        expiration,
        secrethash,
    )

    if locksroot == EMPTY_MERKLE_ROOT:
        locksroot = sha3(lock.as_bytes)

    if locked_amount is None:
        locked_amount = amount
    else:
        assert locked_amount >= amount

    transfer = LockedTransfer(
        chain_id=UNIT_CHAIN_ID,
        message_identifier=message_identifier,
        payment_identifier=payment_identifier,
        nonce=nonce,
        token_network_address=UNIT_TOKEN_NETWORK_ADDRESS,
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
        nonce,
        transferred_amount,
        locked_amount,
        token_network_address,
        channel_address,
        locksroot,
        extra_hash,
        private_key,
        sender_address,
):

    data_to_sign = balance_proof.signing_data(
        nonce,
        transferred_amount,
        locked_amount,
        channel_address,
        locksroot,
        extra_hash,
    )

    balance_hash = hash_balance_data(
        transferred_amount,
        locked_amount,
        locksroot,
    )
    data_to_sign = balance_proof.pack_signing_data(
        nonce=nonce,
        balance_hash=balance_hash,
        additional_hash=extra_hash,
        channel_identifier=channel_address,
        token_network_identifier=token_network_address,
        chain_id=UNIT_CHAIN_ID,
    )

    signature = signing.sign(data_to_sign, private_key)

    signed_balance_proof = BalanceProofSignedState(
        nonce,
        transferred_amount,
        locked_amount,
        locksroot,
        token_network_address,
        channel_address,
        extra_hash,
        signature,
        sender_address,
        UNIT_CHAIN_ID,
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
        sender=UNIT_TRANSFER_SENDER,
):

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
        payment_identifier=identifier,
        nonce=nonce,
        transferred_amount=transferred_amount,
        recipient=recipient,
        channel_identifier=channel_address,
        token=token_address,
        pkey=pkey,
        sender=sender,
    )

    # Do *not* register the transfer here
    is_valid, msg, _ = channel.is_valid_lockedtransfer(
        mediated_transfer,
        channel_state,
        channel_state.partner_state,
        channel_state.our_state,
    )
    assert is_valid, msg

    return mediated_transfer
