from typing import TYPE_CHECKING, List, cast

import gevent
import structlog

from raiden.transfer import channel, views
from raiden.transfer.events import EventPaymentReceivedSuccess
from raiden.transfer.identifiers import CanonicalIdentifier
from raiden.transfer.state import (
    CHANNEL_AFTER_CLOSE_STATES,
    CHANNEL_STATE_SETTLED,
    NODE_NETWORK_REACHABLE,
)
from raiden.utils.typing import (
    Address,
    BlockNumber,
    ChannelID,
    PaymentAmount,
    PaymentID,
    PaymentNetworkID,
    Sequence,
    TokenAddress,
    TokenAmount,
)

if TYPE_CHECKING:
    from raiden.raiden_service import RaidenService  # pylint: disable=unused-import

log = structlog.get_logger(__name__)  # pylint: disable=invalid-name

ALARM_TASK_ERROR_MSG = (
    "Waiting relies on alarm task polling to update the node's internal state."
)
TRANSPORT_ERROR_MSG = "Waiting for protocol messags requires a running transport."


def wait_for_block(
    raiden: "RaidenService", block_number: BlockNumber, retry_timeout: float
) -> None:
    while raiden.get_block_number() < block_number:
        assert raiden, ALARM_TASK_ERROR_MSG
        assert raiden.alarm, ALARM_TASK_ERROR_MSG

        gevent.sleep(retry_timeout)


def wait_for_newchannel(
    raiden: "RaidenService",
    payment_network_id: PaymentNetworkID,
    token_address: TokenAddress,
    partner_address: Address,
    retry_timeout: float,
) -> None:
    """Wait until the channel with partner_address is registered.

    Note:
        This does not time out, use gevent.Timeout.
    """
    channel_state = views.get_channelstate_for(
        views.state_from_raiden(raiden), payment_network_id, token_address, partner_address
    )

    while channel_state is None:
        assert raiden, ALARM_TASK_ERROR_MSG
        assert raiden.alarm, ALARM_TASK_ERROR_MSG

        gevent.sleep(retry_timeout)
        channel_state = views.get_channelstate_for(
            views.state_from_raiden(raiden), payment_network_id, token_address, partner_address
        )


def wait_for_participant_newbalance(
    raiden: "RaidenService",
    payment_network_id: PaymentNetworkID,
    token_address: TokenAddress,
    partner_address: Address,
    target_address: Address,
    target_balance: TokenAmount,
    retry_timeout: float,
) -> None:
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
        views.state_from_raiden(raiden), payment_network_id, token_address, partner_address
    )

    while balance(channel_state) < target_balance:
        assert raiden, ALARM_TASK_ERROR_MSG
        assert raiden.alarm, ALARM_TASK_ERROR_MSG

        gevent.sleep(retry_timeout)
        channel_state = views.get_channelstate_for(
            views.state_from_raiden(raiden), payment_network_id, token_address, partner_address
        )


def wait_for_payment_balance(
    raiden: "RaidenService",
    payment_network_id: PaymentNetworkID,
    token_address: TokenAddress,
    partner_address: Address,
    target_address: Address,
    target_balance: TokenAmount,
    retry_timeout: float,
) -> None:
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
        views.state_from_raiden(raiden), payment_network_id, token_address, partner_address
    )

    while balance(channel_state) < target_balance:
        assert raiden, ALARM_TASK_ERROR_MSG
        assert raiden.alarm, ALARM_TASK_ERROR_MSG

        log.critical("wait", b=balance(channel_state), t=target_balance)
        gevent.sleep(retry_timeout)
        channel_state = views.get_channelstate_for(
            views.state_from_raiden(raiden), payment_network_id, token_address, partner_address
        )


def wait_for_channel_in_states(
    raiden: "RaidenService",
    payment_network_id: PaymentNetworkID,
    token_address: TokenAddress,
    channel_ids: List[ChannelID],
    retry_timeout: float,
    target_states: Sequence[str],
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
        chain_state=chain_state, payment_network_id=payment_network_id, token_address=token_address
    )

    if token_network is None:
        raise ValueError(
            f"The token {token_address} is not registered on the network {payment_network_id}."
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
            gevent.sleep(retry_timeout)


def wait_for_close(
    raiden: "RaidenService",
    payment_network_id: PaymentNetworkID,
    token_address: TokenAddress,
    channel_ids: List[ChannelID],
    retry_timeout: float,
) -> None:
    """Wait until all channels are closed.

    Note:
        This does not time out, use gevent.Timeout.
    """
    return wait_for_channel_in_states(
        raiden=raiden,
        payment_network_id=payment_network_id,
        token_address=token_address,
        channel_ids=channel_ids,
        retry_timeout=retry_timeout,
        target_states=CHANNEL_AFTER_CLOSE_STATES,
    )


def wait_for_payment_network(
    raiden: "RaidenService",
    payment_network_id: PaymentNetworkID,
    token_address: TokenAddress,
    retry_timeout: float,
) -> None:
    token_network = views.get_token_network_by_token_address(
        views.state_from_raiden(raiden), payment_network_id, token_address
    )
    while token_network is None:
        assert raiden, ALARM_TASK_ERROR_MSG
        assert raiden.alarm, ALARM_TASK_ERROR_MSG

        gevent.sleep(retry_timeout)
        token_network = views.get_token_network_by_token_address(
            views.state_from_raiden(raiden), payment_network_id, token_address
        )


def wait_for_settle(
    raiden: "RaidenService",
    payment_network_id: PaymentNetworkID,
    token_address: TokenAddress,
    channel_ids: List[ChannelID],
    retry_timeout: float,
) -> None:
    """Wait until all channels are settled.

    Note:
        This does not time out, use gevent.Timeout.
    """
    return wait_for_channel_in_states(
        raiden=raiden,
        payment_network_id=payment_network_id,
        token_address=token_address,
        channel_ids=channel_ids,
        retry_timeout=retry_timeout,
        target_states=(CHANNEL_STATE_SETTLED,),
    )


def wait_for_settle_all_channels(raiden: "RaidenService", retry_timeout: float) -> None:
    """Wait until all channels are settled.

    Note:
        This does not time out, use gevent.Timeout.
    """
    chain_state = views.state_from_raiden(raiden)

    id_paymentnetworkstate = chain_state.identifiers_to_paymentnetworks.items()
    for payment_network_id, payment_network_state in id_paymentnetworkstate:

        id_tokennetworkstate = payment_network_state.tokenidentifiers_to_tokennetworks.items()
        for token_network_id, token_network_state in id_tokennetworkstate:
            channel_ids = cast(
                List[ChannelID], token_network_state.channelidentifiers_to_channels.keys()
            )

            wait_for_settle(
                raiden=raiden,
                payment_network_id=payment_network_id,
                token_address=TokenAddress(token_network_id),
                channel_ids=channel_ids,
                retry_timeout=retry_timeout,
            )


def wait_for_healthy(raiden: "RaidenService", node_address: Address, retry_timeout: float) -> None:
    """Wait until `node_address` becomes healthy.

    Note:
        This does not time out, use gevent.Timeout.
    """
    network_statuses = views.get_networkstatuses(views.state_from_raiden(raiden))

    while network_statuses.get(node_address) != NODE_NETWORK_REACHABLE:
        assert raiden, TRANSPORT_ERROR_MSG
        assert raiden.transport, TRANSPORT_ERROR_MSG

        gevent.sleep(retry_timeout)
        network_statuses = views.get_networkstatuses(views.state_from_raiden(raiden))


def wait_for_transfer_success(
    raiden: "RaidenService",
    payment_identifier: PaymentID,
    amount: PaymentAmount,
    retry_timeout: float,
) -> None:
    """Wait until a transfer with a specific identifier and amount
    is seen in the WAL.

    Note:
        This does not time out, use gevent.Timeout.
    """
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

        gevent.sleep(retry_timeout)
