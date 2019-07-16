""" Utilities to make and assert transfers. """
import random
from enum import Enum
from hashlib import sha256

import gevent
from eth_utils import to_checksum_address
from gevent.timeout import Timeout

from raiden.app import App
from raiden.constants import EMPTY_SIGNATURE, UINT64_MAX
from raiden.message_handler import MessageHandler
from raiden.messages.abstract import Message
from raiden.messages.decode import balanceproof_from_envelope
from raiden.messages.metadata import Metadata, RouteMetadata
from raiden.messages.transfers import LockedTransfer, LockExpired, Unlock
from raiden.tests.utils.factories import make_address, make_secret
from raiden.tests.utils.protocol import WaitForMessage
from raiden.transfer import channel, views
from raiden.transfer.architecture import TransitionResult
from raiden.transfer.channel import compute_locksroot
from raiden.transfer.mediated_transfer.events import SendSecretRequest
from raiden.transfer.mediated_transfer.state import LockedTransferSignedState
from raiden.transfer.mediated_transfer.state_change import ReceiveLockExpired
from raiden.transfer.state import (
    ChannelState,
    HashTimeLockState,
    NettingChannelState,
    PendingLocksState,
    make_empty_pending_locks_state,
)
from raiden.utils import random_secret
from raiden.utils.signer import LocalSigner, Signer
from raiden.utils.typing import (
    Any,
    Balance,
    Callable,
    ChainID,
    FeeAmount,
    Keccak256,
    List,
    LockedAmount,
    Nonce,
    Optional,
    PaymentAmount,
    PaymentID,
    TokenAddress,
    TokenAmount,
    TokenNetworkAddress,
    typecheck,
)


class TransferState(Enum):
    """ Represents the target state of a transfer. """

    UNLOCKED = "unlocked"
    EXPIRED = "expired"
    SECRET_NOT_REVEALED = "secret_not_revealed"
    SECRET_NOT_REQUESTED = "secret_not_requested"
    SECRET_REVEALED = "secret_revealed"


def sign_and_inject(message: Message, signer: Signer, app: App) -> None:
    """Sign the message with key and inject it directly in the app transport layer."""
    message.sign(signer)
    MessageHandler().on_message(app.raiden, message)


def get_channelstate(
    app0: App, app1: App, token_network_address: TokenNetworkAddress
) -> NettingChannelState:
    channel_state = views.get_channelstate_by_token_network_and_partner(
        views.state_from_app(app0), token_network_address, app1.raiden.address
    )
    return channel_state


def transfer(
    initiator_app: App,
    target_app: App,
    token_address: TokenAddress,
    amount: PaymentAmount,
    identifier: PaymentID,
    fee: FeeAmount = 0,
    timeout: Optional[float] = None,
    transfer_state: TransferState = TransferState.UNLOCKED,
) -> None:
    """ Nice to read shortcut to make successful mediated transfer.

    Note:
        Only the initiator and target are synched.
    """
    if transfer_state is TransferState.UNLOCKED:
        _transfer_unlocked(
            initiator_app=initiator_app,
            target_app=target_app,
            token_address=token_address,
            amount=amount,
            identifier=identifier,
            fee=fee,
            timeout=timeout,
        )
    elif transfer_state is TransferState.EXPIRED:
        _transfer_expired(
            initiator_app=initiator_app,
            target_app=target_app,
            token_address=token_address,
            amount=amount,
            identifier=identifier,
            fee=fee,
            timeout=timeout,
        )
    elif transfer_state is TransferState.SECRET_NOT_REQUESTED:
        _transfer_secret_not_requested(
            initiator_app=initiator_app,
            target_app=target_app,
            token_address=token_address,
            amount=amount,
            identifier=identifier,
            fee=fee,
            timeout=timeout,
        )
    else:
        raise RuntimeError("Type of transfer not implemented.")


def _transfer_unlocked(
    initiator_app: App,
    target_app: App,
    token_address: TokenAddress,
    amount: PaymentAmount,
    identifier: PaymentID,
    fee: FeeAmount = 0,
    timeout: Optional[float] = None,
) -> None:
    assert isinstance(target_app.raiden.message_handler, WaitForMessage)

    if timeout is None:
        timeout = 10

    wait_for_unlock = target_app.raiden.message_handler.wait_for_message(
        Unlock, {"payment_identifier": identifier}
    )

    payment_network_address = initiator_app.raiden.default_registry.address
    token_network_address = views.get_token_network_address_by_token_address(
        chain_state=views.state_from_app(initiator_app),
        payment_network_address=payment_network_address,
        token_address=token_address,
    )
    payment_status = initiator_app.raiden.mediated_transfer_async(
        token_network_address=token_network_address,
        amount=amount,
        target=target_app.raiden.address,
        identifier=identifier,
        fee=fee,
    )

    with Timeout(seconds=timeout):
        wait_for_unlock.get()
        msg = (
            f"transfer from {to_checksum_address(initiator_app.raiden.address)} "
            f"to {to_checksum_address(target_app.raiden.address)} failed."
        )
        assert payment_status.payment_done.get(), msg


def _transfer_expired(
    initiator_app: App,
    target_app: App,
    token_address: TokenAddress,
    amount: PaymentAmount,
    identifier: PaymentID,
    fee: FeeAmount = 0,
    timeout: Optional[float] = None,
) -> None:
    assert identifier is not None, "The identifier must be provided"
    assert isinstance(target_app.raiden.message_handler, WaitForMessage)

    # This timeout has to be larger then the lock expiration. The lock
    # expiration unit is block numbers, and its value is defined relative to
    # the node's reveal timeout configuration. For the integration tests the
    # reveal timeout is chosen proportionally to the number of nodes, 90
    # seconds is a rough default that should work with the standard
    # configuration.
    if timeout is None:
        timeout = 90

    secret = make_secret()
    secrethash = sha256(secret).digest()

    wait_for_remove_expired_lock = target_app.raiden.message_handler.wait_for_message(
        LockExpired, {"secrethash": secrethash}
    )

    payment_network_address = initiator_app.raiden.default_registry.address
    token_network_address = views.get_token_network_address_by_token_address(
        chain_state=views.state_from_app(initiator_app),
        payment_network_address=payment_network_address,
        token_address=token_address,
    )
    payment_status = initiator_app.raiden.start_mediated_transfer_with_secret(
        token_network_address=token_network_address,
        amount=amount,
        fee=fee,
        target=target_app.raiden.address,
        identifier=identifier,
        secret=secret,
        secrethash=secrethash,
    )

    with Timeout(seconds=timeout):
        wait_for_remove_expired_lock.get()
        msg = (
            f"transfer from {to_checksum_address(initiator_app.raiden.address)} "
            f"to {to_checksum_address(target_app.raiden.address)} did not expire."
        )
        assert payment_status.payment_done.get() is False, msg


def _transfer_secret_not_requested(
    initiator_app: App,
    target_app: App,
    token_address: TokenAddress,
    amount: PaymentAmount,
    identifier: PaymentID,
    fee: FeeAmount = 0,
    timeout: Optional[float] = None,
):
    if timeout is None:
        timeout = 10

    secret = make_secret()
    secrethash = sha256(secret).digest()

    hold_secret_request = target_app.raiden.raiden_event_handler.hold(
        SendSecretRequest, {"secrethash": secrethash}
    )

    payment_network_address = initiator_app.raiden.default_registry.address
    token_network_address = views.get_token_network_address_by_token_address(
        chain_state=views.state_from_app(initiator_app),
        payment_network_address=payment_network_address,
        token_address=token_address,
    )
    initiator_app.raiden.start_mediated_transfer_with_secret(
        token_network_address=token_network_address,
        amount=amount,
        fee=fee,
        target=target_app.raiden.address,
        identifier=identifier,
        secret=secret,
        secrethash=secrethash,
    )

    with Timeout(seconds=timeout):
        hold_secret_request.get()


def transfer_and_assert_path(
    path: List[App],
    token_address: TokenAddress,
    amount: PaymentAmount,
    identifier: PaymentID,
    fee: FeeAmount = 0,
    timeout: float = 10,
) -> None:
    """ Nice to read shortcut to make successful LockedTransfer.

    Note:
        This utility *does not enforce the path*, however it does check the
        provided path is used in totality. It's the responsability of the
        caller to ensure the path will be used. All nodes in `path` are
        synched.
    """
    assert identifier is not None, "The identifier must be provided"
    secret = random_secret()

    first_app = path[0]
    payment_network_address = first_app.raiden.default_registry.address
    token_network_address = views.get_token_network_address_by_token_address(
        chain_state=views.state_from_app(first_app),
        payment_network_address=payment_network_address,
        token_address=token_address,
    )

    for app in path:
        assert isinstance(app.raiden.message_handler, WaitForMessage)

        msg = "The apps must be on the same payment network"
        assert app.raiden.default_registry.address == payment_network_address, msg

        app_token_network_address = views.get_token_network_address_by_token_address(
            chain_state=views.state_from_app(app),
            payment_network_address=payment_network_address,
            token_address=token_address,
        )

        msg = "The apps must be synchronized with the blockchain"
        assert token_network_address == app_token_network_address, msg

    pairs = zip(path[:-1], path[1:])
    receiving = list()
    for from_app, to_app in pairs:
        from_channel_state = views.get_channelstate_by_token_network_and_partner(
            chain_state=views.state_from_app(from_app),
            token_network_address=token_network_address,
            partner_address=to_app.raiden.address,
        )
        to_channel_state = views.get_channelstate_by_token_network_and_partner(
            chain_state=views.state_from_app(to_app),
            token_network_address=token_network_address,
            partner_address=from_app.raiden.address,
        )

        msg = (
            f"{to_checksum_address(from_app.raiden.address)} does not have a channel with "
            f"{to_checksum_address(to_app.raiden.address)} needed to transfer through the "
            f"path {[to_checksum_address(app.raiden.address) for app in path]}."
        )
        assert from_channel_state, msg
        assert to_channel_state, msg

        msg = (
            f"channel among {to_checksum_address(from_app.raiden.address)} and "
            f"{to_checksum_address(to_app.raiden.address)} must be open to be used for a "
            f"transfer"
        )
        assert channel.get_status(from_channel_state) == ChannelState.STATE_OPENED, msg
        assert channel.get_status(to_channel_state) == ChannelState.STATE_OPENED, msg

        receiving.append((to_app, to_channel_state.identifier))

    results = [
        app.raiden.message_handler.wait_for_message(
            Unlock,
            {
                "channel_identifier": channel_identifier,
                "token_network_address": token_network_address,
                "payment_identifier": identifier,
                "secret": secret,
            },
        )
        for app, channel_identifier in receiving
    ]

    last_app = path[-1]
    payment_status = first_app.raiden.start_mediated_transfer_with_secret(
        token_network_address=token_network_address,
        amount=amount,
        fee=fee,
        target=last_app.raiden.address,
        identifier=identifier,
        secret=secret,
    )

    with Timeout(seconds=timeout):
        gevent.wait(results)
        msg = (
            f"transfer from {to_checksum_address(first_app.raiden.address)} "
            f"to {to_checksum_address(last_app.raiden.address)} failed."
        )
        assert payment_status.payment_done.get(), msg


def assert_synced_channel_state(
    token_network_address: TokenNetworkAddress,
    app0: App,
    balance0: Balance,
    pending_locks0: List[HashTimeLockState],
    app1: App,
    balance1: Balance,
    pending_locks1: List[HashTimeLockState],
) -> None:
    """ Assert the values of two synced channels.

    Note:
        This assert does not work for an intermediate state, where one message
        hasn't been delivered yet or has been completely lost."""
    # pylint: disable=too-many-arguments

    channel0 = get_channelstate(app0, app1, token_network_address)
    channel1 = get_channelstate(app1, app0, token_network_address)

    assert channel0.our_state.contract_balance == channel1.partner_state.contract_balance
    assert channel0.partner_state.contract_balance == channel1.our_state.contract_balance

    total_token = channel0.our_state.contract_balance + channel1.our_state.contract_balance

    our_balance0 = channel.get_balance(channel0.our_state, channel0.partner_state)
    partner_balance0 = channel.get_balance(channel0.partner_state, channel0.our_state)
    assert our_balance0 + partner_balance0 == total_token

    our_balance1 = channel.get_balance(channel1.our_state, channel1.partner_state)
    partner_balance1 = channel.get_balance(channel1.partner_state, channel1.our_state)
    assert our_balance1 + partner_balance1 == total_token

    locked_amount0 = sum(lock.amount for lock in pending_locks0)
    locked_amount1 = sum(lock.amount for lock in pending_locks1)

    assert_balance(channel0, balance0, locked_amount0)
    assert_balance(channel1, balance1, locked_amount1)

    # a participant's outstanding is the other's pending locks.
    assert_locked(channel0, pending_locks0)
    assert_locked(channel1, pending_locks1)

    assert_mirror(channel0, channel1)
    assert_mirror(channel1, channel0)


def wait_assert(func: Callable, *args, **kwargs) -> None:
    """ Utility to re-run `func` if it raises an assert. Return once `func`
    doesn't hit a failed assert anymore.

    This will loop forever unless a gevent.Timeout is used.
    """
    while True:
        try:
            func(*args, **kwargs)
        except AssertionError as e:
            try:
                gevent.sleep(0.5)
            except gevent.Timeout:
                raise e
        else:
            break


def assert_mirror(original: NettingChannelState, mirror: NettingChannelState) -> None:
    """ Assert that `mirror` has a correct `partner_state` to represent `original`."""
    original_locked_amount = channel.get_amount_locked(original.our_state)
    mirror_locked_amount = channel.get_amount_locked(mirror.partner_state)
    assert original_locked_amount == mirror_locked_amount

    balance0 = channel.get_balance(original.our_state, original.partner_state)
    balance1 = channel.get_balance(mirror.partner_state, mirror.our_state)
    assert balance0 == balance1

    balanceproof0 = channel.get_current_balanceproof(original.our_state)
    balanceproof1 = channel.get_current_balanceproof(mirror.partner_state)
    assert balanceproof0 == balanceproof1

    distributable0 = channel.get_distributable(original.our_state, original.partner_state)
    distributable1 = channel.get_distributable(mirror.partner_state, mirror.our_state)
    assert distributable0 == distributable1


def assert_locked(
    from_channel: NettingChannelState, pending_locks: List[HashTimeLockState]
) -> None:
    """ Assert the locks created from `from_channel`. """
    # a locked transfer is registered in the _partner_ state
    if pending_locks:
        locks = PendingLocksState(list(bytes(lock.encoded) for lock in pending_locks))
    else:
        locks = make_empty_pending_locks_state()

    assert from_channel.our_state.pending_locks == locks

    for lock in pending_locks:
        pending = lock.secrethash in from_channel.our_state.secrethashes_to_lockedlocks
        unclaimed = lock.secrethash in from_channel.our_state.secrethashes_to_unlockedlocks
        assert pending or unclaimed


def assert_balance(
    from_channel: NettingChannelState, balance: Balance, locked: LockedAmount
) -> None:
    """ Assert the from_channel overall token values. """
    assert balance >= 0
    assert locked >= 0

    distributable = balance - locked
    channel_distributable = channel.get_distributable(
        from_channel.our_state, from_channel.partner_state
    )
    channel_balance = channel.get_balance(from_channel.our_state, from_channel.partner_state)
    channel_locked_amount = channel.get_amount_locked(from_channel.our_state)

    msg = f"channel balance does not match. Expected: {balance} got: {channel_balance}"
    assert channel_balance == balance, msg

    msg = (
        f"channel distributable amount does not match. "
        f"Expected: {distributable} got: {channel_distributable}"
    )
    assert channel_distributable == distributable, msg

    msg = f"channel locked amount does not match. Expected: {locked} got: {channel_locked_amount}"
    assert channel_locked_amount == locked, msg

    msg = (
        f"locked_amount ({locked}) + distributable ({distributable}) "
        f"did not equal the balance ({balance})"
    )
    assert balance == locked + distributable, msg


def assert_dropped(iteration: TransitionResult, old_state: Any, reason: Optional[str] = None):
    msg = f"State change expected to be dropped ({reason or 'reason unknown'})."
    assert iteration.new_state is None or iteration.new_state == old_state, msg
    assert not iteration.events, msg


def make_receive_transfer_mediated(
    channel_state: NettingChannelState,
    privkey: bytes,
    nonce: Nonce,
    transferred_amount: TokenAmount,
    lock: HashTimeLockState,
    pending_locks: PendingLocksState = None,
    locked_amount: Optional[LockedAmount] = None,
    chain_id: Optional[ChainID] = None,
) -> LockedTransferSignedState:

    typecheck(lock, HashTimeLockState)

    signer = LocalSigner(privkey)
    address = signer.address
    if address not in (channel_state.our_state.address, channel_state.partner_state.address):
        raise ValueError("Private key does not match any of the participants.")

    if pending_locks is None:
        locks = make_empty_pending_locks_state()
        locks.locks.append(bytes(lock.encoded))
    else:
        assert bytes(lock.encoded) in pending_locks.locks
        locks = pending_locks

    if locked_amount is None:
        locked_amount = lock.amount

    assert locked_amount >= lock.amount

    locksroot = compute_locksroot(locks)

    payment_identifier = nonce
    transfer_target = make_address()
    transfer_initiator = make_address()
    chain_id = chain_id or channel_state.chain_id

    transfer_metadata = Metadata(
        routes=[RouteMetadata(route=[channel_state.our_state.address, transfer_target])]
    )

    mediated_transfer_msg = LockedTransfer(
        chain_id=chain_id,
        message_identifier=random.randint(0, UINT64_MAX),
        payment_identifier=payment_identifier,
        nonce=nonce,
        token_network_address=channel_state.token_network_address,
        token=channel_state.token_address,
        channel_identifier=channel_state.identifier,
        transferred_amount=transferred_amount,
        locked_amount=locked_amount,
        recipient=channel_state.partner_state.address,
        locksroot=locksroot,
        lock=lock,
        target=transfer_target,
        initiator=transfer_initiator,
        signature=EMPTY_SIGNATURE,
        fee=0,
        metadata=transfer_metadata,
    )
    mediated_transfer_msg.sign(signer)

    balance_proof = balanceproof_from_envelope(mediated_transfer_msg)

    receive_lockedtransfer = LockedTransferSignedState(
        payment_identifier=payment_identifier,
        token=channel_state.token_address,
        lock=lock,
        initiator=transfer_initiator,
        target=transfer_target,
        message_identifier=random.randint(0, UINT64_MAX),
        balance_proof=balance_proof,
        routes=transfer_metadata.routes,
    )

    return receive_lockedtransfer


def make_receive_expired_lock(
    channel_state: NettingChannelState,
    privkey: bytes,
    nonce: Nonce,
    transferred_amount: TokenAmount,
    lock: HashTimeLockState,
    pending_locks: List[Keccak256] = None,
    locked_amount: LockedAmount = None,
    chain_id: ChainID = None,
) -> ReceiveLockExpired:

    typecheck(lock, HashTimeLockState)

    signer = LocalSigner(privkey)
    address = signer.address
    if address not in (channel_state.our_state.address, channel_state.partner_state.address):
        raise ValueError("Private key does not match any of the participants.")

    if pending_locks is None:
        pending_locks = make_empty_pending_locks_state()
    else:
        assert bytes(lock.encoded) not in pending_locks

    locksroot = compute_locksroot(pending_locks)

    chain_id = chain_id or channel_state.chain_id
    lock_expired_msg = LockExpired(
        chain_id=chain_id,
        nonce=nonce,
        message_identifier=random.randint(0, UINT64_MAX),
        transferred_amount=transferred_amount,
        locked_amount=locked_amount,
        locksroot=locksroot,
        channel_identifier=channel_state.identifier,
        token_network_address=channel_state.token_network_address,
        recipient=channel_state.partner_state.address,
        secrethash=lock.secrethash,
        signature=EMPTY_SIGNATURE,
    )
    lock_expired_msg.sign(signer)

    balance_proof = balanceproof_from_envelope(lock_expired_msg)

    receive_lockedtransfer = ReceiveLockExpired(
        balance_proof=balance_proof,
        secrethash=lock.secrethash,
        message_identifier=random.randint(0, UINT64_MAX),
        sender=balance_proof.sender,
    )

    return receive_lockedtransfer
