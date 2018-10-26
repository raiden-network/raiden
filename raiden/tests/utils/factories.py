# pylint: disable=too-many-arguments
import os
import random
import string

from coincurve import PrivateKey

from raiden.constants import UINT64_MAX, UINT256_MAX
from raiden.messages import Lock, LockedTransfer
from raiden.transfer import balance_proof, channel
from raiden.transfer.mediated_transfer import mediator
from raiden.transfer.mediated_transfer.state import (
    HashTimeLockState,
    LockedTransferUnsignedState,
    MediationPairState,
    TransferDescriptionWithSecretState,
    lockedtransfersigned_from_message,
)
from raiden.transfer.merkle_tree import merkleroot
from raiden.transfer.state import (
    EMPTY_MERKLE_ROOT,
    BalanceProofSignedState,
    BalanceProofUnsignedState,
    NettingChannelEndState,
    NettingChannelState,
    RouteState,
    TransactionExecutionStatus,
    message_identifier_from_prng,
)
from raiden.transfer.utils import hash_balance_data
from raiden.utils import privatekey_to_address, publickey_to_address, random_secret, sha3
from raiden_libs.utils.signing import eth_sign

# prefixing with UNIT_ to differ from the default globals
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


def make_transfer_description(
        payment_network_identifier=UNIT_PAYMENT_NETWORK_IDENTIFIER,
        payment_identifier=UNIT_TRANSFER_IDENTIFIER,
        amount=UNIT_TRANSFER_AMOUNT,
        token_network=UNIT_TOKEN_NETWORK_ADDRESS,
        initiator=UNIT_TRANSFER_INITIATOR,
        target=UNIT_TRANSFER_TARGET,
        secret=None,
):
    return TransferDescriptionWithSecretState(
        payment_network_identifier=payment_network_identifier,
        payment_identifier=payment_identifier,
        amount=amount,
        token_network_identifier=token_network,
        initiator=initiator,
        target=target,
        secret=secret or random_secret(),
    )


UNIT_TRANSFER_DESCRIPTION = make_transfer_description(secret=UNIT_SECRET)


def make_address():
    return bytes(''.join(random.choice(string.printable) for _ in range(20)), encoding='utf-8')


def make_channel_identifier():
    return random.randint(0, UINT256_MAX)


def make_payment_network_identifier():
    return bytes(''.join(random.choice(string.printable) for _ in range(20)), encoding='utf-8')


def make_transaction_hash():
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
        payment_network_identifier=None,
        token_network_identifier=None,
        channel_identifier=None,
        reveal_timeout=UNIT_REVEAL_TIMEOUT,
        settle_timeout=UNIT_SETTLE_TIMEOUT,
) -> NettingChannelState:

    our_address = our_address or make_address()
    partner_address = partner_address or make_address()
    token_address = token_address or make_address()
    payment_network_identifier = payment_network_identifier or make_payment_network_identifier()
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
        channel_identifier=channel_identifier,
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
        token_network_address=UNIT_TOKEN_NETWORK_ADDRESS,
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
        nonce,
        transferred_amount,
        locked_amount,
        token_network_address,
        channel_identifier,
        locksroot,
        extra_hash,
        private_key,
        sender_address,
):

    balance_hash = hash_balance_data(
        transferred_amount,
        locked_amount,
        locksroot,
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

    signed_balance_proof = BalanceProofSignedState(
        nonce,
        transferred_amount,
        locked_amount,
        locksroot,
        token_network_address,
        channel_identifier,
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
        locked_amount=None,
        pkey=UNIT_TRANSFER_PKEY,
        sender=UNIT_TRANSFER_SENDER,
        compute_locksroot=False,
        allow_invalid=False,
):

    if not allow_invalid:
        msg = 'expiration must be lower than settle_timeout'
        assert expiration < channel_state.settle_timeout, msg
        msg = 'expiration must be larger than settle_timeout'
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
        amount,
        initiator,
        target,
        expiration,
        secret,
        payment_identifier=identifier,
        nonce=nonce,
        transferred_amount=transferred_amount,
        locked_amount=locked_amount,
        recipient=recipient,
        channel_identifier=channel_identifier,
        token_network_address=channel_state.token_network_identifier,
        token=token_address,
        pkey=pkey,
        sender=sender,
        locksroot=locksroot,
    )

    # Do *not* register the transfer here
    if not allow_invalid:
        is_valid, msg, _ = channel.is_valid_lockedtransfer(
            mediated_transfer,
            channel_state,
            channel_state.partner_state,
            channel_state.our_state,
        )
        assert is_valid, msg

    return mediated_transfer


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
