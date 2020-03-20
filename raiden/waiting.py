import time
from enum import Enum
from typing import TYPE_CHECKING, List

import gevent
import structlog

from raiden.storage.restore import get_state_change_with_transfer_by_secrethash
from raiden.transfer import channel, views
from raiden.transfer.events import EventPaymentReceivedSuccess
from raiden.transfer.identifiers import CanonicalIdentifier
from raiden.transfer.mediated_transfer.events import EventUnlockClaimFailed
from raiden.transfer.mediated_transfer.state_change import ActionInitMediator, ActionInitTarget
from raiden.transfer.state import (
    CHANNEL_AFTER_CLOSE_STATES,
    ChannelState,
    NettingChannelEndState,
    NetworkState,
)
from raiden.transfer.state_change import (
    ContractReceiveChannelWithdraw,
    ContractReceiveSecretReveal,
)
from raiden.utils.formatting import to_checksum_address
from raiden.utils.typing import (
    Address,
    Any,
    BlockNumber,
    Callable,
    ChannelID,
    PaymentAmount,
    PaymentID,
    SecretHash,
    Sequence,
    TokenAddress,
    TokenAmount,
    TokenNetworkRegistryAddress,
    WithdrawAmount,
)

if TYPE_CHECKING:
    from raiden.raiden_service import RaidenService  # pylint: disable=unused-import
    from raiden.app import App

log = structlog.get_logger(__name__)

ALARM_TASK_ERROR_MSG = "Waiting relies on alarm task polling to update the node's internal state."
TRANSPORT_ERROR_MSG = "Waiting for protocol messages requires a running transport."


def wait_until(func: Callable, wait_for: float = None, sleep_for: float = 0.5) -> Any:
    """Test for a function and wait for it to return a truth value or to timeout.
    Returns the value or None if a timeout is given and the function didn't return
    inside time timeout
    Args:
        func: a function to be evaluated, use lambda if parameters are required
        wait_for: the maximum time to wait, or None for an infinite loop
        sleep_for: how much to gevent.sleep between calls
    Returns:
        func(): result of func, if truth value, or None"""
    res = func()

    if res:
        return res

    if wait_for:
        deadline = time.time() + wait_for
        while not res and time.time() <= deadline:
            gevent.sleep(sleep_for)
            res = func()

    else:
        while not res:
            gevent.sleep(sleep_for)
            res = func()

    return res


def wait_for_block(
    raiden: "RaidenService", block_number: BlockNumber, retry_timeout: float
) -> None:  # pragma: no unittest
    current = raiden.get_block_number()

    log_details = {
        "node": to_checksum_address(raiden.address),
        "target_block_number": block_number,
    }
    while current < block_number:
        assert raiden, ALARM_TASK_ERROR_MSG
        assert raiden.alarm, ALARM_TASK_ERROR_MSG

        log.debug("wait_for_block", current_block_number=current, **log_details)
        gevent.sleep(retry_timeout)
        current = raiden.get_block_number()


def wait_for_newchannel(
    raiden: "RaidenService",
    token_network_registry_address: TokenNetworkRegistryAddress,
    token_address: TokenAddress,
    partner_address: Address,
    retry_timeout: float,
) -> None:  # pragma: no unittest
    """Wait until the channel with partner_address is registered.

    Note:
        This does not time out, use gevent.Timeout.
    """
    channel_state = views.get_channelstate_for(
        views.state_from_raiden(raiden),
        token_network_registry_address,
        token_address,
        partner_address,
    )

    log_details = {
        "node": to_checksum_address(raiden.address),
        "token_network_registry_address": to_checksum_address(token_network_registry_address),
        "token_address": to_checksum_address(token_address),
        "partner_address": to_checksum_address(partner_address),
    }
    while channel_state is None:
        assert raiden, ALARM_TASK_ERROR_MSG
        assert raiden.alarm, ALARM_TASK_ERROR_MSG

        log.debug("wait_for_newchannel", **log_details)
        gevent.sleep(retry_timeout)
        channel_state = views.get_channelstate_for(
            views.state_from_raiden(raiden),
            token_network_registry_address,
            token_address,
            partner_address,
        )


def wait_for_participant_deposit(
    raiden: "RaidenService",
    token_network_registry_address: TokenNetworkRegistryAddress,
    token_address: TokenAddress,
    partner_address: Address,
    target_address: Address,
    target_balance: TokenAmount,
    retry_timeout: float,
) -> None:  # pragma: no unittest
    """Wait until a given channels balance exceeds the target balance.

    Note:
        This does not time out, use gevent.Timeout.
    """
    if target_address == raiden.address:
        balance = lambda channel_state: channel_state.our_state.contract_balance
    else:
        balance = lambda channel_state: channel_state.partner_state.contract_balance

    channel_state = views.get_channelstate_for(
        views.state_from_raiden(raiden),
        token_network_registry_address,
        token_address,
        partner_address,
    )
    if not channel_state:
        raise ValueError("no channel could be found between provided partner and target addresses")

    current_balance = balance(channel_state)

    log_details = {
        "node": to_checksum_address(raiden.address),
        "token_network_registry_address": to_checksum_address(token_network_registry_address),
        "token_address": to_checksum_address(token_address),
        "partner_address": to_checksum_address(partner_address),
        "target_address": to_checksum_address(target_address),
        "target_balance": target_balance,
    }
    while current_balance < target_balance:
        assert raiden, ALARM_TASK_ERROR_MSG
        assert raiden.alarm, ALARM_TASK_ERROR_MSG

        log.debug("wait_for_participant_deposit", current_balance=current_balance, **log_details)
        gevent.sleep(retry_timeout)
        channel_state = views.get_channelstate_for(
            views.state_from_raiden(raiden),
            token_network_registry_address,
            token_address,
            partner_address,
        )
        current_balance = balance(channel_state)


def wait_single_channel_deposit(
    app_deposit: "App",
    app_partner: "App",
    registry_address: TokenNetworkRegistryAddress,
    token_address: TokenAddress,
    total_deposit: TokenAmount,
    retry_timeout: float,
) -> None:
    """ Wait until a deposit of `total_deposit` for app_deposit is seen by both apps"""
    wait_for_participant_deposit(
        raiden=app_deposit.raiden,
        token_network_registry_address=registry_address,
        token_address=token_address,
        partner_address=app_partner.raiden.address,
        target_address=app_deposit.raiden.address,
        target_balance=total_deposit,
        retry_timeout=retry_timeout,
    )
    wait_for_participant_deposit(
        raiden=app_partner.raiden,
        token_network_registry_address=registry_address,
        token_address=token_address,
        partner_address=app_deposit.raiden.address,
        target_address=app_deposit.raiden.address,
        target_balance=total_deposit,
        retry_timeout=retry_timeout,
    )


def wait_both_channel_deposit(
    app_deposit: "App",
    app_partner: "App",
    registry_address: TokenNetworkRegistryAddress,
    token_address: TokenAddress,
    total_deposit: TokenAmount,
    retry_timeout: float,
) -> None:
    """ Wait until a deposit of `total_deposit` for both apps is seen by both apps"""
    wait_single_channel_deposit(
        app_deposit=app_deposit,
        app_partner=app_partner,
        registry_address=registry_address,
        token_address=token_address,
        total_deposit=total_deposit,
        retry_timeout=retry_timeout,
    )
    wait_single_channel_deposit(
        app_deposit=app_partner,
        app_partner=app_deposit,
        registry_address=registry_address,
        token_address=token_address,
        total_deposit=total_deposit,
        retry_timeout=retry_timeout,
    )


def wait_for_payment_balance(
    raiden: "RaidenService",
    token_network_registry_address: TokenNetworkRegistryAddress,
    token_address: TokenAddress,
    partner_address: Address,
    target_address: Address,
    target_balance: TokenAmount,
    retry_timeout: float,
) -> None:  # pragma: no unittest
    """Wait until a given channel's balance exceeds the target balance.

    Note:
        This does not time out, use gevent.Timeout.
    """

    def get_balance(end_state: NettingChannelEndState) -> TokenAmount:
        if end_state.balance_proof:
            return end_state.balance_proof.transferred_amount
        else:
            return TokenAmount(0)

    if target_address == raiden.address:
        balance = lambda channel_state: get_balance(channel_state.partner_state)
    elif target_address == partner_address:
        balance = lambda channel_state: get_balance(channel_state.our_state)
    else:
        raise ValueError("target_address must be one of the channel participants")

    channel_state = views.get_channelstate_for(
        views.state_from_raiden(raiden),
        token_network_registry_address,
        token_address,
        partner_address,
    )
    current_balance = balance(channel_state)

    log_details = {
        "token_network_registry_address": to_checksum_address(token_network_registry_address),
        "token_address": to_checksum_address(token_address),
        "partner_address": to_checksum_address(partner_address),
        "target_address": to_checksum_address(target_address),
        "target_balance": target_balance,
    }
    while current_balance < target_balance:
        assert raiden, ALARM_TASK_ERROR_MSG
        assert raiden.alarm, ALARM_TASK_ERROR_MSG

        log.critical("wait_for_payment_balance", current_balance=current_balance, **log_details)
        gevent.sleep(retry_timeout)
        channel_state = views.get_channelstate_for(
            views.state_from_raiden(raiden),
            token_network_registry_address,
            token_address,
            partner_address,
        )
        current_balance = balance(channel_state)


def wait_for_channel_in_states(
    raiden: "RaidenService",
    token_network_registry_address: TokenNetworkRegistryAddress,
    token_address: TokenAddress,
    channel_ids: List[ChannelID],
    retry_timeout: float,
    target_states: Sequence[ChannelState],
) -> None:
    """Wait until all channels are in `target_states`.

    Raises:
        ValueError: If the token_address is not registered in the
            token_network_registry.

    Note:
        This does not time out, use gevent.Timeout.
    """
    chain_state = views.state_from_raiden(raiden)
    token_network = views.get_token_network_by_token_address(
        chain_state=chain_state,
        token_network_registry_address=token_network_registry_address,
        token_address=token_address,
    )

    if token_network is None:
        raise ValueError(
            f"The token {to_checksum_address(token_address)} is not registered on "
            f"the network {to_checksum_address(token_network_registry_address)}."
        )

    token_network_address = token_network.address

    list_cannonical_ids = [
        CanonicalIdentifier(
            chain_identifier=chain_state.chain_id,
            token_network_address=token_network_address,
            channel_identifier=channel_identifier,
        )
        for channel_identifier in channel_ids
    ]

    log_details = {
        "token_network_registry_address": to_checksum_address(token_network_registry_address),
        "token_address": to_checksum_address(token_address),
        "list_cannonical_ids": list_cannonical_ids,
        "target_states": target_states,
    }

    while list_cannonical_ids:
        assert raiden, ALARM_TASK_ERROR_MSG
        assert raiden.alarm, ALARM_TASK_ERROR_MSG

        canonical_id = list_cannonical_ids[-1]
        chain_state = views.state_from_raiden(raiden)

        channel_state = views.get_channelstate_by_canonical_identifier(
            chain_state=chain_state, canonical_identifier=canonical_id
        )

        channel_is_settled = (
            channel_state is None or channel.get_status(channel_state) in target_states
        )

        if channel_is_settled:
            list_cannonical_ids.pop()
        else:
            log.debug("wait_for_channel_in_states", **log_details)
            gevent.sleep(retry_timeout)


def wait_for_close(
    raiden: "RaidenService",
    token_network_registry_address: TokenNetworkRegistryAddress,
    token_address: TokenAddress,
    channel_ids: List[ChannelID],
    retry_timeout: float,
) -> None:  # pragma: no unittest
    """Wait until all channels are closed.

    Note:
        This does not time out, use gevent.Timeout.
    """
    return wait_for_channel_in_states(
        raiden=raiden,
        token_network_registry_address=token_network_registry_address,
        token_address=token_address,
        channel_ids=channel_ids,
        retry_timeout=retry_timeout,
        target_states=CHANNEL_AFTER_CLOSE_STATES,
    )


def wait_for_token_network(
    raiden: "RaidenService",
    token_network_registry_address: TokenNetworkRegistryAddress,
    token_address: TokenAddress,
    retry_timeout: float,
) -> None:  # pragma: no unittest
    """Wait until the token network is visible to the RaidenService.

    Note:
        This does not time out, use gevent.Timeout.
    """
    token_network = views.get_token_network_by_token_address(
        views.state_from_raiden(raiden), token_network_registry_address, token_address
    )
    log_details = {
        "token_network_registry_address": to_checksum_address(token_network_registry_address),
        "token_address": to_checksum_address(token_address),
    }
    while token_network is None:
        assert raiden, ALARM_TASK_ERROR_MSG
        assert raiden.alarm, ALARM_TASK_ERROR_MSG

        log.debug("wait_for_token_network", **log_details)
        gevent.sleep(retry_timeout)
        token_network = views.get_token_network_by_token_address(
            views.state_from_raiden(raiden), token_network_registry_address, token_address
        )


def wait_for_settle(
    raiden: "RaidenService",
    token_network_registry_address: TokenNetworkRegistryAddress,
    token_address: TokenAddress,
    channel_ids: List[ChannelID],
    retry_timeout: float,
) -> None:  # pragma: no unittest
    """Wait until all channels are settled.

    Note:
        This does not time out, use gevent.Timeout.
    """
    return wait_for_channel_in_states(
        raiden=raiden,
        token_network_registry_address=token_network_registry_address,
        token_address=token_address,
        channel_ids=channel_ids,
        retry_timeout=retry_timeout,
        target_states=(ChannelState.STATE_SETTLED,),
    )


def wait_for_network_state(
    raiden: "RaidenService",
    node_address: Address,
    network_state: NetworkState,
    retry_timeout: float,
) -> None:  # pragma: no unittest
    """Wait until `node_address` becomes healthy.

    Note:
        This does not time out, use gevent.Timeout.
    """
    network_statuses = views.get_networkstatuses(views.state_from_raiden(raiden))
    current = network_statuses.get(node_address)

    log_details = {
        "node_address": to_checksum_address(node_address),
        "target_network_state": network_state,
    }
    while current != network_state:
        assert raiden, TRANSPORT_ERROR_MSG
        assert raiden.transport, TRANSPORT_ERROR_MSG

        log.debug("wait_for_network_state", current_network_state=current, **log_details)
        gevent.sleep(retry_timeout)
        network_statuses = views.get_networkstatuses(views.state_from_raiden(raiden))
        current = network_statuses.get(node_address)


def wait_for_healthy(
    raiden: "RaidenService", node_address: Address, retry_timeout: float
) -> None:  # pragma: no unittest
    """Wait until `node_address` becomes healthy.

    Note:
        This does not time out, use gevent.Timeout.
    """

    wait_for_network_state(raiden, node_address, NetworkState.REACHABLE, retry_timeout)


class TransferWaitResult(Enum):
    SECRET_REGISTERED_ONCHAIN = "secret registered onchain"
    UNLOCKED = "unlocked"
    UNLOCK_FAILED = "unlock_failed"


def wait_for_received_transfer_result(
    raiden: "RaidenService",
    payment_identifier: PaymentID,
    amount: PaymentAmount,
    retry_timeout: float,
    secrethash: SecretHash,
) -> TransferWaitResult:  # pragma: no unittest
    """Wait for the result of a transfer with the specified identifier
    and/or secrethash. Possible results are onchain secret registration,
    successful unlock and failed unlock. For a successful unlock, the
    amount is also checked.

    Note:
        This does not time out, use gevent.Timeout.
    """
    log_details = {"payment_identifier": payment_identifier, "amount": amount}

    assert raiden, TRANSPORT_ERROR_MSG
    assert raiden.wal, TRANSPORT_ERROR_MSG
    assert raiden.transport, TRANSPORT_ERROR_MSG
    stream = raiden.wal.storage.get_state_changes_stream(retry_timeout=retry_timeout)

    result = None
    while result is None:

        state_events = raiden.wal.storage.get_events()
        for event in state_events:
            unlocked = (
                isinstance(event, EventPaymentReceivedSuccess)
                and event.identifier == payment_identifier
                and PaymentAmount(event.amount) == amount
            )
            if unlocked:
                result = TransferWaitResult.UNLOCKED
                break
            claim_failed = (
                isinstance(event, EventUnlockClaimFailed)
                and event.identifier == payment_identifier
                and event.secrethash == secrethash
            )
            if claim_failed:
                result = TransferWaitResult.UNLOCK_FAILED
                break

        state_changes = next(stream)
        for state_change in state_changes:
            registered_onchain = (
                isinstance(state_change, ContractReceiveSecretReveal)
                and state_change.secrethash == secrethash
            )
            if registered_onchain:
                state_change_record = get_state_change_with_transfer_by_secrethash(
                    raiden.wal.storage, secrethash
                )
                assert state_change_record is not None, "Could not find state change for screthash"
                msg = "Expected ActionInitMediator/ActionInitTarget not found in state changes."
                expected_types = (ActionInitMediator, ActionInitTarget)
                assert isinstance(state_change_record.data, expected_types), msg

                transfer = None
                if isinstance(state_change_record.data, ActionInitMediator):
                    transfer = state_change_record.data.from_transfer
                if isinstance(state_change_record.data, ActionInitTarget):
                    transfer = state_change_record.data.transfer

                if transfer is not None and raiden.get_block_number() <= transfer.lock.expiration:
                    return TransferWaitResult.SECRET_REGISTERED_ONCHAIN

        log.debug("wait_for_transfer_result", **log_details)
        gevent.sleep(retry_timeout)

    return result  # type: ignore


def wait_for_withdraw_complete(
    raiden: "RaidenService",
    canonical_identifier: CanonicalIdentifier,
    total_withdraw: WithdrawAmount,
    retry_timeout: float,
) -> None:
    """Wait until a withdraw with a specific identifier and amount
    is seen in the WAL.

    Note:
        This does not time out, use gevent.Timeout.
    """
    log_details = {
        "canonical_identifier": canonical_identifier,
        "target_total_withdraw": total_withdraw,
    }
    assert raiden, TRANSPORT_ERROR_MSG
    assert raiden.wal, TRANSPORT_ERROR_MSG
    assert raiden.transport, TRANSPORT_ERROR_MSG
    stream = raiden.wal.storage.get_state_changes_stream(retry_timeout=retry_timeout)

    while True:
        state_changes = next(stream)

        for state_change in state_changes:
            found = (
                isinstance(state_change, ContractReceiveChannelWithdraw)
                and state_change.total_withdraw == total_withdraw
                and state_change.canonical_identifier == canonical_identifier
            )

            if found:
                return

        log.debug("wait_for_withdraw_complete", **log_details)
        gevent.sleep(retry_timeout)
