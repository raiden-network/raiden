import gevent
import structlog

from raiden.transfer.state import NODE_NETWORK_REACHABLE
from raiden.transfer.state import (
    CHANNEL_STATE_SETTLED,
    CHANNEL_AFTER_CLOSE_STATES,
)
from raiden.transfer import channel, views
from raiden.transfer.events import EventTransferReceivedSuccess
from raiden.utils import typing
# type alias to avoid both circular dependencies and flake8 errors
RaidenService = 'RaidenService'

log = structlog.get_logger(__name__)  # pylint: disable=invalid-name


def wait_for_block(
        raiden: RaidenService,
        block_number: typing.BlockNumber,
        retry_timeout: float,
) -> None:
    current_block_number = views.block_number(
        views.state_from_raiden(raiden),
    )
    while current_block_number < block_number:
        gevent.sleep(retry_timeout)
        current_block_number = views.block_number(
            views.state_from_raiden(raiden),
        )


def wait_for_newchannel(
        raiden: RaidenService,
        payment_network_id: typing.PaymentNetworkID,
        token_address: typing.TokenAddress,
        partner_address: typing.Address,
        retry_timeout: float,
) -> None:
    """Wait until the channel with partner_address is registered.

    Note:
        This does not time out, use gevent.Timeout.
    """
    channel_state = views.get_channelstate_for(
        views.state_from_raiden(raiden),
        payment_network_id,
        token_address,
        partner_address,
    )

    while channel_state is None:
        gevent.sleep(retry_timeout)
        channel_state = views.get_channelstate_for(
            views.state_from_raiden(raiden),
            payment_network_id,
            token_address,
            partner_address,
        )


def wait_for_participant_newbalance(
        raiden: RaidenService,
        payment_network_id: typing.PaymentNetworkID,
        token_address: typing.TokenAddress,
        partner_address: typing.Address,
        target_address: typing.Address,
        target_balance: typing.TokenAmount,
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
        raise ValueError('target_address must be one of the channel participants')

    channel_state = views.get_channelstate_for(
        views.state_from_raiden(raiden),
        payment_network_id,
        token_address,
        partner_address,
    )

    while balance(channel_state) < target_balance:
        gevent.sleep(retry_timeout)
        channel_state = views.get_channelstate_for(
            views.state_from_raiden(raiden),
            payment_network_id,
            token_address,
            partner_address,
        )


def wait_for_close(
        raiden: RaidenService,
        payment_network_id: typing.PaymentNetworkID,
        token_address: typing.Address,
        channel_ids: typing.List[typing.ChannelID],
        retry_timeout: float,
) -> None:
    """Wait until all channels are closed.

    Note:
        This does not time out, use gevent.Timeout.
    """
    channel_ids = list(channel_ids)

    while channel_ids:
        first_id = channel_ids[0]
        channel_state = views.get_channelstate_by_id(
            views.state_from_raiden(raiden),
            payment_network_id,
            token_address,
            first_id,
        )

        channel_is_settled = (
            channel_state is None or
            channel.get_status(channel_state) in CHANNEL_AFTER_CLOSE_STATES
        )

        if channel_is_settled:
            channel_ids.pop()
        else:
            gevent.sleep(retry_timeout)


def wait_for_payment_network(
        raiden: RaidenService,
        payment_network_id: typing.PaymentNetworkID,
        token_address: typing.TokenAddress,
        retry_timeout: float,
) -> None:
    token_network = views.get_token_network_by_token_address(
        views.state_from_raiden(raiden),
        payment_network_id,
        token_address,
    )
    while token_network is None:
        gevent.sleep(retry_timeout)
        token_network = views.get_token_network_by_token_address(
            views.state_from_raiden(raiden),
            payment_network_id,
            token_address,
        )


def wait_for_settle(
        raiden: RaidenService,
        payment_network_id: typing.PaymentNetworkID,
        token_address: typing.TokenAddress,
        channel_ids: typing.List[typing.ChannelID],
        retry_timeout: float,
) -> None:
    """Wait until all channels are settled.

    Note:
        This does not time out, use gevent.Timeout.
    """
    if not isinstance(channel_ids, list):
        raise ValueError('channel_ids must be a list')

    channel_ids = list(channel_ids)

    while channel_ids:
        first_id = channel_ids[0]
        channel_state = views.get_channelstate_by_id(
            views.state_from_raiden(raiden),
            payment_network_id,
            token_address,
            first_id,
        )

        channel_is_settled = (
            channel_state is None or
            channel.get_status(channel_state) == CHANNEL_STATE_SETTLED
        )

        if channel_is_settled:
            channel_ids.pop()
        else:
            gevent.sleep(retry_timeout)


def wait_for_settle_all_channels(
        raiden: RaidenService,
        retry_timeout: float,
) -> None:
    """Wait until all channels are settled.

    Note:
        This does not time out, use gevent.Timeout.
    """
    chain_state = views.state_from_raiden(raiden)

    id_paymentnetworkstate = chain_state.identifiers_to_paymentnetworks.items()
    for payment_network_id, payment_network_state in id_paymentnetworkstate:

        id_tokennetworkstate = payment_network_state.tokenidentifiers_to_tokennetworks.items()
        for token_network_id, token_network_state in id_tokennetworkstate:
            channel_ids = token_network_state.channelidentifiers_to_channels.keys()

            wait_for_settle(
                raiden,
                payment_network_id,
                token_network_id,
                channel_ids,
                retry_timeout,
            )


def wait_for_healthy(
        raiden: RaidenService,
        node_address: typing.Address,
        retry_timeout: float,
) -> None:
    """Wait until `node_address` becomes healthy.

    Note:
        This does not time out, use gevent.Timeout.
    """
    network_statuses = views.get_networkstatuses(
        views.state_from_raiden(raiden),
    )

    while network_statuses.get(node_address) != NODE_NETWORK_REACHABLE:
        gevent.sleep(retry_timeout)
        network_statuses = views.get_networkstatuses(
            views.state_from_raiden(raiden),
        )


def wait_for_transfer_success(
        raiden: RaidenService,
        payment_identifier: typing.PaymentID,
        amount: typing.PaymentAmount,
        retry_timeout: float,
) -> None:
    """Wait until a direct transfer with a specific identifier and amount
    is seen in the WAL.

    Note:
        This does not time out, use gevent.Timeout.
    """
    found = False
    while not found:
        state_events = raiden.wal.storage.get_events_by_identifier(0, 'latest')
        for event_tuple in state_events:
            event = event_tuple[1]
            # if isinstance(event, EventTransferReceivedSuccess):
            found = (
                isinstance(event, EventTransferReceivedSuccess) and
                event.identifier == payment_identifier and
                event.amount == amount
            )
            if found:
                break

        gevent.sleep(retry_timeout)
