""" Utilities to make and assert transfers. """
from contextlib import contextmanager
from enum import Enum

import gevent
from eth_utils import to_checksum_address
from gevent.timeout import Timeout

from raiden.app import App
from raiden.constants import EMPTY_SIGNATURE
from raiden.message_handler import MessageHandler
from raiden.messages.abstract import SignedMessage
from raiden.messages.decode import balanceproof_from_envelope
from raiden.messages.metadata import Metadata, RouteMetadata
from raiden.messages.transfers import Lock, LockedTransfer, LockExpired, Unlock
from raiden.raiden_service import RaidenService
from raiden.settings import (
    DEFAULT_MEDIATION_FEE_MARGIN,
    DEFAULT_RETRY_TIMEOUT,
    INTERNAL_ROUTING_DEFAULT_FEE_PERC,
)
from raiden.storage.restore import (
    get_event_with_balance_proof_by_balance_hash,
    get_state_change_with_balance_proof_by_locksroot,
    get_state_change_with_transfer_by_secrethash,
)
from raiden.storage.wal import SavedState, WriteAheadLog
from raiden.tests.utils.events import (
    count_unlock_failures,
    has_unlock_failure,
    raiden_state_changes_search_for_item,
)
from raiden.tests.utils.factories import (
    make_initiator_address,
    make_message_identifier,
    make_secret_with_hash,
    make_target_address,
)
from raiden.tests.utils.protocol import HoldRaidenEventHandler, WaitForMessage
from raiden.transfer import channel, views
from raiden.transfer.architecture import TransitionResult
from raiden.transfer.channel import compute_locksroot
from raiden.transfer.mediated_transfer.events import SendSecretRequest
from raiden.transfer.mediated_transfer.state import LockedTransferSignedState
from raiden.transfer.mediated_transfer.state_change import (
    ActionInitMediator,
    ActionInitTarget,
    ReceiveLockExpired,
    ReceiveTransferRefund,
)
from raiden.transfer.state import (
    BalanceProofSignedState,
    BalanceProofUnsignedState,
    ChannelState,
    HashTimeLockState,
    NettingChannelState,
    PendingLocksState,
    make_empty_pending_locks_state,
)
from raiden.transfer.state_change import ContractReceiveChannelDeposit, ReceiveUnlock
from raiden.utils.signer import LocalSigner, Signer
from raiden.utils.timeout import BlockTimeout
from raiden.utils.typing import (
    MYPY_ANNOTATION,
    Address,
    Any,
    Balance,
    BlockNumber,
    Callable,
    ChainID,
    FeeAmount,
    List,
    LockedAmount,
    Nonce,
    Optional,
    PaymentAmount,
    PaymentID,
    PaymentWithFeeAmount,
    SecretHash,
    TargetAddress,
    TokenAddress,
    TokenAmount,
    TokenNetworkAddress,
    cast,
    typecheck,
)

ZERO_FEE = FeeAmount(0)


class TransferState(Enum):
    """ Represents the target state of a transfer. """

    UNLOCKED = "unlocked"
    EXPIRED = "expired"
    SECRET_NOT_REVEALED = "secret_not_revealed"
    SECRET_NOT_REQUESTED = "secret_not_requested"
    SECRET_REVEALED = "secret_revealed"


def sign_and_inject(message: SignedMessage, signer: Signer, app: App) -> None:
    """Sign the message with key and inject it directly in the app transport layer."""
    message.sign(signer)
    MessageHandler().on_message(app.raiden, message)


def get_channelstate(
    app0: App, app1: App, token_network_address: TokenNetworkAddress
) -> NettingChannelState:
    channel_state = views.get_channelstate_by_token_network_and_partner(
        views.state_from_app(app0), token_network_address, app1.raiden.address
    )
    assert channel_state
    return channel_state


@contextmanager
def watch_for_unlock_failures(*apps, retry_timeout=DEFAULT_RETRY_TIMEOUT):
    """
    Context manager to assure there are no failing unlocks during transfers in integration tests.
    """

    def watcher_function():
        offset = {
            app.raiden.address: count_unlock_failures(app.raiden.wal.storage.get_events())
            for app in apps
        }
        while True:
            for app in apps:
                assert not has_unlock_failure(app.raiden, offset=offset[app.raiden.address])
            gevent.sleep(retry_timeout)

    watcher = gevent.spawn(watcher_function)
    try:
        yield
    finally:
        gevent.kill(watcher)


def transfer(
    initiator_app: App,
    target_app: App,
    token_address: TokenAddress,
    amount: PaymentAmount,
    identifier: PaymentID,
    timeout: Optional[float] = None,
    transfer_state: TransferState = TransferState.UNLOCKED,
) -> SecretHash:
    """ Nice to read shortcut to make successful mediated transfer.

    Note:
        Only the initiator and target are synched.
    """
    if transfer_state is TransferState.UNLOCKED:
        return _transfer_unlocked(
            initiator_app=initiator_app,
            target_app=target_app,
            token_address=token_address,
            amount=amount,
            identifier=identifier,
            timeout=timeout,
        )
    elif transfer_state is TransferState.EXPIRED:
        return _transfer_expired(
            initiator_app=initiator_app,
            target_app=target_app,
            token_address=token_address,
            amount=amount,
            identifier=identifier,
            timeout=timeout,
        )
    elif transfer_state is TransferState.SECRET_NOT_REQUESTED:
        return _transfer_secret_not_requested(
            initiator_app=initiator_app,
            target_app=target_app,
            token_address=token_address,
            amount=amount,
            identifier=identifier,
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
    timeout: Optional[float] = None,
) -> SecretHash:
    assert isinstance(target_app.raiden.message_handler, WaitForMessage)

    if timeout is None:
        timeout = 10

    wait_for_unlock = target_app.raiden.message_handler.wait_for_message(
        Unlock, {"payment_identifier": identifier}
    )

    token_network_registry_address = initiator_app.raiden.default_registry.address
    token_network_address = views.get_token_network_address_by_token_address(
        chain_state=views.state_from_app(initiator_app),
        token_network_registry_address=token_network_registry_address,
        token_address=token_address,
    )
    assert token_network_address
    secret, secrethash = make_secret_with_hash()
    payment_status = initiator_app.raiden.mediated_transfer_async(
        token_network_address=token_network_address,
        amount=amount,
        target=TargetAddress(target_app.raiden.address),
        identifier=identifier,
        secret=secret,
        secrethash=secrethash,
    )

    with watch_for_unlock_failures(initiator_app, target_app):
        with Timeout(seconds=timeout):
            wait_for_unlock.get()
            msg = (
                f"transfer from {to_checksum_address(initiator_app.raiden.address)} "
                f"to {to_checksum_address(target_app.raiden.address)} failed."
            )
            assert payment_status.payment_done.get(), msg

    return secrethash


def _transfer_expired(
    initiator_app: App,
    target_app: App,
    token_address: TokenAddress,
    amount: PaymentAmount,
    identifier: PaymentID,
    timeout: Optional[float] = None,
) -> SecretHash:
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

    secret, secrethash = make_secret_with_hash()
    wait_for_remove_expired_lock = target_app.raiden.message_handler.wait_for_message(
        LockExpired, {"secrethash": secrethash}
    )

    token_network_registry_address = initiator_app.raiden.default_registry.address
    token_network_address = views.get_token_network_address_by_token_address(
        chain_state=views.state_from_app(initiator_app),
        token_network_registry_address=token_network_registry_address,
        token_address=token_address,
    )
    assert token_network_address
    payment_status = initiator_app.raiden.start_mediated_transfer_with_secret(
        token_network_address=token_network_address,
        amount=amount,
        target=TargetAddress(target_app.raiden.address),
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

    return secrethash


def _transfer_secret_not_requested(
    initiator_app: App,
    target_app: App,
    token_address: TokenAddress,
    amount: PaymentAmount,
    identifier: PaymentID,
    timeout: Optional[float] = None,
) -> SecretHash:
    if timeout is None:
        timeout = 10

    secret, secrethash = make_secret_with_hash()

    assert isinstance(target_app.raiden.raiden_event_handler, HoldRaidenEventHandler)
    hold_secret_request = target_app.raiden.raiden_event_handler.hold(
        SendSecretRequest, {"secrethash": secrethash}
    )

    token_network_registry_address = initiator_app.raiden.default_registry.address
    token_network_address = views.get_token_network_address_by_token_address(
        chain_state=views.state_from_app(initiator_app),
        token_network_registry_address=token_network_registry_address,
        token_address=token_address,
    )
    assert token_network_address
    initiator_app.raiden.start_mediated_transfer_with_secret(
        token_network_address=token_network_address,
        amount=amount,
        target=TargetAddress(target_app.raiden.address),
        identifier=identifier,
        secret=secret,
        secrethash=secrethash,
    )

    with Timeout(seconds=timeout):
        hold_secret_request.get()

    return secrethash


def transfer_and_assert_path(
    path: List[App],
    token_address: TokenAddress,
    amount: PaymentAmount,
    identifier: PaymentID,
    timeout: float = 10,
) -> SecretHash:
    """ Nice to read shortcut to make successful LockedTransfer.

    Note:
        This utility *does not enforce the path*, however it does check the
        provided path is used in totality. It's the responsability of the
        caller to ensure the path will be used. All nodes in `path` are
        synched.
    """
    assert identifier is not None, "The identifier must be provided"
    secret, secrethash = make_secret_with_hash()

    first_app = path[0]
    token_network_registry_address = first_app.raiden.default_registry.address
    token_network_address = views.get_token_network_address_by_token_address(
        chain_state=views.state_from_app(first_app),
        token_network_registry_address=token_network_registry_address,
        token_address=token_address,
    )
    assert token_network_address

    for app in path:
        assert isinstance(app.raiden.message_handler, WaitForMessage)

        msg = "The apps must be on the same token network registry"
        assert app.raiden.default_registry.address == token_network_registry_address, msg

        app_token_network_address = views.get_token_network_address_by_token_address(
            chain_state=views.state_from_app(app),
            token_network_registry_address=token_network_registry_address,
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

    assert isinstance(app.raiden.message_handler, WaitForMessage)
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
        target=TargetAddress(last_app.raiden.address),
        identifier=identifier,
        secret=secret,
    )

    msg = (
        f"transfer from {to_checksum_address(first_app.raiden.address)} "
        f"to {to_checksum_address(last_app.raiden.address)} for amount "
        f"{amount} failed"
    )
    exception = RuntimeError(msg + " due to Timeout")
    with watch_for_unlock_failures(*path):
        with Timeout(seconds=timeout, exception=exception):
            gevent.wait(results)
            assert payment_status.payment_done.get(), msg

    return secrethash


def assert_deposit(
    token_network_address: TokenNetworkAddress,
    app0: App,
    app1: App,
    saved_state0: SavedState,
    saved_state1: SavedState,
) -> None:
    """Assert that app0 and app1 agree on app0's on-chain deposit.

    Notes:
        - This does not check the deposit from app1. It can be done with a
          second call to the function.
        - The two apps don't have to be at the same view of the blockchain, i.e. app1
          may have seen the latest block but app0 not.
        - It is important to do the validation on a fixed  state, that is why
          saved_state0 is used.
    """
    # Do not assert on the block number themselves, only useful to clarify the
    # error messages
    block_number0 = views.block_number(saved_state0.state)
    block_number1 = views.block_number(saved_state1.state)

    channel0 = views.get_channelstate_by_token_network_and_partner(
        saved_state0.state, token_network_address, app1.raiden.address
    )
    channel1 = views.get_channelstate_by_token_network_and_partner(
        saved_state1.state, token_network_address, app0.raiden.address
    )

    assert channel0
    assert channel1

    if channel0.our_state.contract_balance != channel1.partner_state.contract_balance:
        # TODO: Only consider the records up to saved state's state_change_id.
        # ATM this has a race condition where this utility could be called
        # before the alarm task fetches the corresponding event but while it
        # runs it does fetch it.

        # Any of the nodes may have seen the deposit first
        contract_balance = max(
            channel0.our_state.contract_balance, channel1.partner_state.contract_balance
        )

        deposit_description = {
            "canonical_identifier": {
                "chain_identifier": channel0.canonical_identifier.chain_identifier,
                "token_network_address": channel0.canonical_identifier.token_network_address,
                "channel_identifier": channel0.canonical_identifier.channel_identifier,
            },
            "deposit_transaction": {
                "participant_address": channel0.our_state.address,
                "contract_balance": contract_balance,
            },
        }
        node0_deposit_event = raiden_state_changes_search_for_item(
            app0.raiden, ContractReceiveChannelDeposit, deposit_description
        )
        node1_deposit_event = raiden_state_changes_search_for_item(
            app1.raiden, ContractReceiveChannelDeposit, deposit_description
        )

        is_partner_deposit_ignored = (
            node1_deposit_event is not None
            and channel1.partner_state.contract_balance != contract_balance
        )
        is_self_deposit_ignored = (
            node0_deposit_event is not None
            and channel0.partner_state.contract_balance != contract_balance
        )
        is_partner_deposit_missed = (
            node0_deposit_event
            and node0_deposit_event.deposit_transaction.deposit_block_number >= block_number1
        )
        is_self_deposit_missed = (
            node1_deposit_event
            and node1_deposit_event.deposit_transaction.deposit_block_number >= block_number1
        )

        if is_self_deposit_ignored:
            msg = "Node0 has fetched and ignored the its deposits, this is likely a bug."
        elif is_partner_deposit_ignored:
            msg = "Node1 has fetched and ignored the node0's deposits, this is likely a bug."
        elif is_self_deposit_missed:
            msg = (
                "Node0's has a problem with its blockchain event filters, it "
                "has not seen its deposit event even though it has seen a newer "
                "confirmed block"
            )
        elif is_partner_deposit_missed:
            msg = (
                "Node1's has a problem with its blockchain event filters, it "
                "missed node0's deposit event even though it has seen a newer "
                "confirmed block"
            )
        elif not app1.raiden.alarm:
            msg = (
                "Node1 has not seen the block at which node0's deposit happened "
                "and the alarm task is not running. Either the test stopped "
                "the node before it had time or the node got killed because of "
                "another error."
            )
        elif not app0.raiden.alarm:
            msg = (
                "Node0 has not seen the block at which node0's deposit happened "
                "and the alarm task is not running. Either the test stopped "
                "the node before it had time or the node got killed because of "
                "another error."
            )
        elif channel0.our_state.contract_balance > channel1.partner_state.contract_balance:
            msg = (
                "Node1 has not yet seen the block at which node0's deposit "
                "happened. The test is likely missing synchronization."
            )
        elif channel1.our_state.contract_balance > channel0.partner_state.contract_balance:
            msg = (
                "Node0 has not yet seen the block at which its deposit "
                "happened. The test is likely missing synchronization."
            )
        else:
            raise RuntimeError("This should never happen, the checks above are complementary")

        msg = (
            f"{msg}. "
            f"node1={to_checksum_address(app1.raiden.address)} "
            f"node0={to_checksum_address(app0.raiden.address)} "
            f"block_number0={block_number0} "
            f"block_number1={block_number1} "
            f"state_change_id0={saved_state0.state_change_id} "
            f"state_change_id1={saved_state1.state_change_id}."
        )

        raise AssertionError(msg)


def assert_balance_proof(
    token_network_address: TokenNetworkAddress,
    app0: App,
    app1: App,
    saved_state0: SavedState,
    saved_state1: SavedState,
) -> None:
    """Assert app0 and app1 agree on the latest balance proof from app0.

    Notes:
        - The other direction of the channel does not have to be synchronized,
          it can be checked with another call.
        - It is important to do the validation on a fixed  state, that is why
          saved_state0 is used.
    """
    assert app0.raiden.wal
    assert app1.raiden.wal

    assert app0.raiden.address == saved_state0.state.our_address
    assert app1.raiden.address == saved_state1.state.our_address

    channel0 = views.get_channelstate_by_token_network_and_partner(
        saved_state0.state, token_network_address, app1.raiden.address
    )
    channel1 = views.get_channelstate_by_token_network_and_partner(
        saved_state1.state, token_network_address, app0.raiden.address
    )

    assert channel0
    assert channel1

    balanceproof0 = cast(BalanceProofUnsignedState, channel0.our_state.balance_proof)
    balanceproof1 = cast(BalanceProofSignedState, channel1.partner_state.balance_proof)

    if balanceproof0 is None:
        msg = "Bug detected. The sender does not have a balance proof, but the recipient does."
        assert balanceproof1 is None, msg

        # nothing to compare
        return

    # Handle the case when the recipient didn't receive the message yet.
    if balanceproof1 is not None:
        nonce1 = balanceproof1.nonce
    else:
        nonce1 = 0

    if balanceproof0.nonce < nonce1:
        msg = (
            "This is a bug, it should never happen. The nonce updates **always**  "
            "start with the owner of the channel's end. This means for a channel "
            "A-B, only A can increase its nonce, same thing with B. At this "
            "point, the assertion is failling because this rule was broken, and "
            "the partner node has a larger nonce than the sending partner."
        )
        raise AssertionError(msg)

    if balanceproof0.nonce > nonce1:
        # TODO: Only consider the records up to saved state's state_change_id.
        # ATM this has a race condition where this utility could be called
        # before the alarm task fetches the corresponding event but while it
        # runs it does fetch it.
        sent_balance_proof = get_event_with_balance_proof_by_balance_hash(
            storage=app0.raiden.wal.storage,
            canonical_identifier=balanceproof0.canonical_identifier,
            balance_hash=balanceproof0.balance_hash,
            recipient=app1.raiden.address,
        )
        received_balance_proof = get_state_change_with_balance_proof_by_locksroot(
            storage=app1.raiden.wal.storage,
            canonical_identifier=balanceproof0.canonical_identifier,
            locksroot=balanceproof0.locksroot,
            sender=app0.raiden.address,
        )

        if received_balance_proof is not None:
            if type(received_balance_proof) == ReceiveTransferRefund:
                msg = (
                    f"Node1 received a refund from node0 and rejected it. This "
                    f"is likely a Raiden bug. state_change={received_balance_proof}"
                )
            elif type(received_balance_proof) in (
                ActionInitMediator,
                ActionInitTarget,
                ReceiveUnlock,
                ReceiveLockExpired,
            ):
                if type(received_balance_proof) == ReceiveUnlock:
                    assert isinstance(received_balance_proof, ReceiveUnlock), MYPY_ANNOTATION
                    is_valid, _, innermsg = channel.handle_unlock(
                        channel_state=channel1, unlock=received_balance_proof
                    )
                elif type(received_balance_proof) == ReceiveLockExpired:
                    assert isinstance(received_balance_proof, ReceiveLockExpired), MYPY_ANNOTATION
                    is_valid, innermsg, _ = channel.is_valid_lock_expired(
                        state_change=received_balance_proof,
                        channel_state=channel1,
                        sender_state=channel1.partner_state,
                        receiver_state=channel1.our_state,
                        block_number=saved_state1.state.block_number,
                    )
                else:
                    assert isinstance(
                        received_balance_proof, (ActionInitMediator, ActionInitTarget)
                    ), MYPY_ANNOTATION
                    is_valid, _, innermsg = channel.handle_receive_lockedtransfer(
                        channel_state=channel1,
                        mediated_transfer=received_balance_proof.from_transfer,
                    )

                if not is_valid:
                    msg = (
                        f"Node1 received the node0's message but rejected it. This "
                        f"is likely a Raiden bug. reason={innermsg} "
                        f"state_change={received_balance_proof}"
                    )
                else:
                    msg = (
                        f"Node1 received the node0's message at that time it "
                        f"was rejected, this is likely a race condition, node1 "
                        f"has to process the message again. reason={innermsg} "
                        f"state_change={received_balance_proof}"
                    )
            else:
                msg = (
                    f"Node1 received the node0's message but rejected it. This "
                    f"is likely a Raiden bug. state_change={received_balance_proof}"
                )

        elif sent_balance_proof is None:
            msg = (
                "Node0 did not send a message with the latest balanceproof, "
                "this is likely a Raiden bug."
            )
        else:
            msg = (
                "Node0 sent the latest balanceproof but Node1 didn't receive, "
                "likely the test is missing proper synchronization amongst the "
                "nodes."
            )

        msg = (
            f"{msg}. "
            f"node1={to_checksum_address(app1.raiden.address)} "
            f"node0={to_checksum_address(app0.raiden.address)} "
            f"state_change_id0={saved_state0.state_change_id} "
            f"state_change_id1={saved_state1.state_change_id}."
        )

        raise AssertionError(msg)

    is_equal = (
        balanceproof0.nonce == balanceproof1.nonce
        and balanceproof0.transferred_amount == balanceproof1.transferred_amount
        and balanceproof0.locked_amount == balanceproof1.locked_amount
        and balanceproof0.locksroot == balanceproof1.locksroot
        and balanceproof0.canonical_identifier == balanceproof1.canonical_identifier
        and balanceproof0.balance_hash == balanceproof1.balance_hash
    )

    if not is_equal:
        msg = (
            f"The balance proof seems corrupted, the recipient has different "
            f"values than the sender. "
            f"node1={to_checksum_address(app1.raiden.address)} "
            f"node0={to_checksum_address(app0.raiden.address)} "
            f"state_change_id0={saved_state0.state_change_id} "
            f"state_change_id1={saved_state1.state_change_id}."
        )

        raise AssertionError(msg)


def assert_channel_values(
    channel0: NettingChannelState,
    balance0: Balance,
    pending_locks0: List[HashTimeLockState],
    channel1: NettingChannelState,
    balance1: Balance,
    pending_locks1: List[HashTimeLockState],
) -> None:
    total_token = channel0.our_state.contract_balance + channel1.our_state.contract_balance

    our_balance0 = channel.get_balance(channel0.our_state, channel0.partner_state)
    partner_balance0 = channel.get_balance(channel0.partner_state, channel0.our_state)
    assert our_balance0 + partner_balance0 == total_token

    our_balance1 = channel.get_balance(channel1.our_state, channel1.partner_state)
    partner_balance1 = channel.get_balance(channel1.partner_state, channel1.our_state)
    assert our_balance1 + partner_balance1 == total_token

    locked_amount0 = LockedAmount(sum(lock.amount for lock in pending_locks0))
    locked_amount1 = LockedAmount(sum(lock.amount for lock in pending_locks1))

    assert_balance(channel0, balance0, locked_amount0)
    assert_balance(channel1, balance1, locked_amount1)

    # a participant's outstanding is the other's pending locks.
    assert_locked(channel0, pending_locks0)
    assert_locked(channel1, pending_locks1)

    assert_mirror(channel0, channel1)
    assert_mirror(channel1, channel0)


def assert_synced_channel_state(
    token_network_address: TokenNetworkAddress,
    app0: App,
    balance0: Balance,
    pending_locks0: List[HashTimeLockState],
    app1: App,
    balance1: Balance,
    pending_locks1: List[HashTimeLockState],
) -> None:
    """Compare channel's state from both nodes.

    Note:
        This assert does not work for an intermediate state, where one message
        hasn't been delivered yet or has been completely lost.
    """
    assert app0.raiden.wal
    assert app1.raiden.wal

    saved_state0 = app0.raiden.wal.saved_state
    saved_state1 = app1.raiden.wal.saved_state

    assert_deposit(token_network_address, app0, app1, saved_state0, saved_state1)
    assert_deposit(token_network_address, app1, app0, saved_state1, saved_state0)

    assert_balance_proof(token_network_address, app1, app0, saved_state1, saved_state0)
    assert_balance_proof(token_network_address, app0, app1, saved_state0, saved_state1)

    channel0 = views.get_channelstate_by_token_network_and_partner(
        saved_state0.state, token_network_address, app1.raiden.address
    )
    channel1 = views.get_channelstate_by_token_network_and_partner(
        saved_state1.state, token_network_address, app0.raiden.address
    )

    assert channel0
    assert channel1

    assert_channel_values(
        channel0=channel0,
        balance0=balance0,
        pending_locks0=pending_locks0,
        channel1=channel1,
        balance1=balance1,
        pending_locks1=pending_locks1,
    )


def assert_succeeding_transfer_invariants(
    token_network_address: TokenNetworkAddress,
    app0: App,
    balance0: Balance,
    pending_locks0: List[HashTimeLockState],
    app1: App,
    balance1: Balance,
    pending_locks1: List[HashTimeLockState],
) -> None:
    """ Channels are in synced states and no unlock failures have occurred. """
    assert not has_unlock_failure(app0.raiden)
    assert not has_unlock_failure(app1.raiden)

    assert_synced_channel_state(
        token_network_address, app0, balance0, pending_locks0, app1, balance1, pending_locks1
    )


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
        locks = PendingLocksState([lock.encoded for lock in pending_locks])
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
    locked_amount: Optional[PaymentWithFeeAmount] = None,
    chain_id: Optional[ChainID] = None,
) -> LockedTransferSignedState:

    typecheck(lock, HashTimeLockState)

    signer = LocalSigner(privkey)
    address = signer.address
    if address not in (channel_state.our_state.address, channel_state.partner_state.address):
        raise ValueError("Private key does not match any of the participants.")

    if pending_locks is None:
        locks = make_empty_pending_locks_state()
        locks.locks.append(lock.encoded)
    else:
        assert bytes(lock.encoded) in pending_locks.locks
        locks = pending_locks

    if locked_amount is None:
        locked_amount = lock.amount

    assert locked_amount >= lock.amount

    locksroot = compute_locksroot(locks)

    payment_identifier = PaymentID(nonce)
    transfer_target = make_target_address()
    transfer_initiator = make_initiator_address()
    chain_id = chain_id or channel_state.chain_id

    transfer_metadata = Metadata(
        routes=[RouteMetadata(route=[channel_state.our_state.address, Address(transfer_target)])]
    )

    mediated_transfer_msg = LockedTransfer(
        chain_id=chain_id,
        message_identifier=make_message_identifier(),
        payment_identifier=payment_identifier,
        nonce=nonce,
        token_network_address=channel_state.token_network_address,
        token=channel_state.token_address,
        channel_identifier=channel_state.identifier,
        transferred_amount=transferred_amount,
        locked_amount=TokenAmount(locked_amount),
        recipient=channel_state.partner_state.address,
        locksroot=locksroot,
        lock=Lock(amount=lock.amount, expiration=lock.expiration, secrethash=lock.secrethash),
        target=transfer_target,
        initiator=transfer_initiator,
        signature=EMPTY_SIGNATURE,
        metadata=transfer_metadata,
    )
    mediated_transfer_msg.sign(signer)

    receive_lockedtransfer = LockedTransferSignedState(
        payment_identifier=payment_identifier,
        token=channel_state.token_address,
        lock=lock,
        initiator=transfer_initiator,
        target=transfer_target,
        message_identifier=make_message_identifier(),
        balance_proof=balanceproof_from_envelope(mediated_transfer_msg),
        routes=[route_metadata.route for route_metadata in transfer_metadata.routes],
    )

    return receive_lockedtransfer


def make_receive_expired_lock(
    channel_state: NettingChannelState,
    privkey: bytes,
    nonce: Nonce,
    transferred_amount: TokenAmount,
    lock: HashTimeLockState,
    locked_amount: LockedAmount,
    pending_locks: PendingLocksState = None,
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
        assert lock.encoded not in pending_locks.locks

    locksroot = compute_locksroot(pending_locks)

    chain_id = chain_id or channel_state.chain_id
    lock_expired_msg = LockExpired(
        chain_id=chain_id,
        nonce=nonce,
        message_identifier=make_message_identifier(),
        transferred_amount=transferred_amount,
        locked_amount=TokenAmount(locked_amount),
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
        message_identifier=make_message_identifier(),
        sender=balance_proof.sender,
    )

    return receive_lockedtransfer


def block_timeout_for_transfer_by_secrethash(
    raiden: RaidenService, secrethash: SecretHash, error_message: str = None
) -> BlockTimeout:
    """
    Return a BlockTimeout to wait until the transfer identified by `secrethash` expires.
    """
    default_error_message = "Timeout due to transfer expiration."

    assert isinstance(raiden.wal, WriteAheadLog)
    state_change = get_state_change_with_transfer_by_secrethash(raiden.wal.storage, secrethash)
    assert state_change is not None, "Expected transfer not found in state changes."
    if isinstance(state_change.data, ActionInitMediator):
        expiration = state_change.data.from_transfer.lock.expiration
    elif isinstance(state_change.data, ActionInitTarget):
        expiration = state_change.data.transfer.lock.expiration
    else:
        assert False, "Unexpected state change found."

    return BlockTimeout(
        raiden=raiden,
        exception_to_throw=ValueError(error_message or default_error_message),
        block_number=BlockNumber(expiration),
        retry_timeout=DEFAULT_RETRY_TIMEOUT,
    )


def calculate_fee_for_amount(amount: int) -> FeeAmount:
    return FeeAmount(
        round((amount * INTERNAL_ROUTING_DEFAULT_FEE_PERC) * (1 + DEFAULT_MEDIATION_FEE_MARGIN))
    )
