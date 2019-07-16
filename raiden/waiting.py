from typing import TYPE_CHECKING, List

import gevent
import structlog
from eth_utils import to_checksum_address

from raiden.transfer import channel, views
from raiden.transfer.events import EventPaymentReceivedSuccess
from raiden.transfer.identifiers import CanonicalIdentifier
from raiden.transfer.state import CHANNEL_AFTER_CLOSE_STATES, NODE_NETWORK_REACHABLE, ChannelState
from raiden.transfer.state_change import ContractReceiveChannelWithdraw
from raiden.utils.typing import (
    Address,
    BlockNumber,
    ChannelID,
    PaymentAmount,
    PaymentID,
    PaymentNetworkAddress,
    Sequence,
    TokenAddress,
    TokenAmount,
    WithdrawAmount,
)

if TYPE_CHECKING:
    from raiden.raiden_service import RaidenService  # pylint: disable=unused-import

log = structlog.get_logger(__name__)

ALARM_TASK_ERROR_MSG = "Waiting relies on alarm task polling to update the node's internal state."
TRANSPORT_ERROR_MSG = "Waiting for protocol messages requires a running transport."


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
    payment_network_address: PaymentNetworkAddress,
    token_address: TokenAddress,
    partner_address: Address,
    retry_timeout: float,
) -> None:  # pragma: no unittest
    """Wait until the channel with partner_address is registered.

    Note:
        This does not time out, use gevent.Timeout.
    """
    channel_state = views.get_channelstate_for(
        views.state_from_raiden(raiden), payment_network_address, token_address, partner_address
    )

    log_details = {
        "node": to_checksum_address(raiden.address),
        "payment_network_address": to_checksum_address(payment_network_address),
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
            payment_network_address,
            token_address,
            partner_address,
        )


def wait_for_participant_deposit(
    raiden: "RaidenService",
    payment_network_address: PaymentNetworkAddress,
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
    elif target_address == partner_address:
        balance = lambda channel_state: channel_state.partner_state.contract_balance
    else:
        raise ValueError("target_address must be one of the channel participants")

    channel_state = views.get_channelstate_for(
        views.state_from_raiden(raiden), payment_network_address, token_address, partner_address
    )
    current_balance = balance(channel_state)

    log_details = {
        "node": to_checksum_address(raiden.address),
        "payment_network_address": to_checksum_address(payment_network_address),
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
            payment_network_address,
            token_address,
            partner_address,
        )
        current_balance = balance(channel_state)


def wait_for_payment_balance(
    raiden: "RaidenService",
    payment_network_address: PaymentNetworkAddress,
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

    def get_balance(end_state):
        if end_state.balance_proof:
            return end_state.balance_proof.transferred_amount
        else:
            return 0

    if target_address == raiden.address:
        balance = lambda channel_state: get_balance(channel_state.partner_state)
    elif target_address == partner_address:
        balance = lambda channel_state: get_balance(channel_state.our_state)
    else:
        raise ValueError("target_address must be one of the channel participants")

    channel_state = views.get_channelstate_for(
        views.state_from_raiden(raiden), payment_network_address, token_address, partner_address
    )
    current_balance = balance(channel_state)

    log_details = {
        "payment_network_address": to_checksum_address(payment_network_address),
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
            payment_network_address,
            token_address,
            partner_address,
        )
        current_balance = balance(channel_state)


def wait_for_channel_in_states(
    raiden: "RaidenService",
    payment_network_address: PaymentNetworkAddress,
    token_address: TokenAddress,
    channel_ids: List[ChannelID],
    retry_timeout: float,
    target_states: Sequence[ChannelState],
) -> None:
    """Wait until all channels are in `target_states`.

    Raises:
        ValueError: If the token_address is not registered in the
            payment_network.

    Note:
        This does not time out, use gevent.Timeout.
    """
    chain_state = views.state_from_raiden(raiden)
    token_network = views.get_token_network_by_token_address(
        chain_state=chain_state,
        payment_network_address=payment_network_address,
        token_address=token_address,
    )

    if token_network is None:
        raise ValueError(
            f"The token {token_address} is not registered on "
            f"the network {payment_network_address}."
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
        "payment_network_address": to_checksum_address(payment_network_address),
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
    payment_network_address: PaymentNetworkAddress,
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
        payment_network_address=payment_network_address,
        token_address=token_address,
        channel_ids=channel_ids,
        retry_timeout=retry_timeout,
        target_states=CHANNEL_AFTER_CLOSE_STATES,
    )


def wait_for_payment_network(
    raiden: "RaidenService",
    payment_network_address: PaymentNetworkAddress,
    token_address: TokenAddress,
    retry_timeout: float,
) -> None:  # pragma: no unittest
    token_network = views.get_token_network_by_token_address(
        views.state_from_raiden(raiden), payment_network_address, token_address
    )
    log_details = {
        "payment_network_address": to_checksum_address(payment_network_address),
        "token_address": to_checksum_address(token_address),
    }
    while token_network is None:
        assert raiden, ALARM_TASK_ERROR_MSG
        assert raiden.alarm, ALARM_TASK_ERROR_MSG

        log.debug("wait_for_payment_network", **log_details)
        gevent.sleep(retry_timeout)
        token_network = views.get_token_network_by_token_address(
            views.state_from_raiden(raiden), payment_network_address, token_address
        )


def wait_for_settle(
    raiden: "RaidenService",
    payment_network_address: PaymentNetworkAddress,
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
        payment_network_address=payment_network_address,
        token_address=token_address,
        channel_ids=channel_ids,
        retry_timeout=retry_timeout,
        target_states=(ChannelState.STATE_SETTLED,),
    )


def wait_for_network_state(
    raiden: "RaidenService", node_address: Address, network_state: str, retry_timeout: float
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

    wait_for_network_state(raiden, node_address, NODE_NETWORK_REACHABLE, retry_timeout)


def wait_for_transfer_success(
    raiden: "RaidenService",
    payment_identifier: PaymentID,
    amount: PaymentAmount,
    retry_timeout: float,
) -> None:  # pragma: no unittest
    """Wait until a transfer with a specific identifier and amount
    is seen in the WAL.

    Note:
        This does not time out, use gevent.Timeout.
    """
    log_details = {"payment_identifier": payment_identifier, "amount": amount}
    found = False
    while not found:
        assert raiden, TRANSPORT_ERROR_MSG
        assert raiden.wal, TRANSPORT_ERROR_MSG
        assert raiden.transport, TRANSPORT_ERROR_MSG

        state_events = raiden.wal.storage.get_events()
        for event in state_events:
            found = (
                isinstance(event, EventPaymentReceivedSuccess)
                and event.identifier == payment_identifier
                and event.amount == amount
            )
            if found:
                break

        log.debug("wait_for_transfer_success", **log_details)
        gevent.sleep(retry_timeout)


def wait_for_withdraw_complete(
    raiden: "RaidenService",
    canonical_identifier: CanonicalIdentifier,
    total_withdraw: WithdrawAmount,
    retry_timeout: float,
) -> None:
    """Wait until a transfer with a specific identifier and amount
    is seen in the WAL.

    Note:
        This does not time out, use gevent.Timeout.
    """
    log_details = {
        "canonical_identifier": canonical_identifier,
        "target_total_withdraw": total_withdraw,
    }
    found = False
    while not found:
        assert raiden, TRANSPORT_ERROR_MSG
        assert raiden.wal, TRANSPORT_ERROR_MSG
        assert raiden.transport, TRANSPORT_ERROR_MSG

        state_changes = raiden.wal.storage.get_state_changes()
        for state_change in state_changes:
            found = (
                isinstance(state_change, ContractReceiveChannelWithdraw)
                and state_change.total_withdraw == total_withdraw
                and state_change.canonical_identifier == canonical_identifier
            )
            if found:
                break

        log.debug("wait_for_withdraw_complete", **log_details)
        gevent.sleep(retry_timeout)
