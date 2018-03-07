# -*- coding: utf-8 -*-
import gevent
from ethereum import slogging

from raiden.transfer.state import (
    CHANNEL_STATE_SETTLED,
    CHANNEL_AFTER_CLOSE_STATES,
)
from raiden.transfer import channel, views

log = slogging.get_logger(__name__)  # pylint: disable=invalid-name


def wait_for_newchannel(
        raiden,
        payment_network_id,
        token_network_id,
        partner_address,
        poll_timeout):
    """Wait until the channel with partner_address is registered.

    Note:
        This does not time out, use gevent.Timeout.
    """
    channel_state = views.get_channelstate_for(
        views.state_from_raiden(raiden),
        payment_network_id,
        token_network_id,
        partner_address,
    )

    while channel_state is None:
        gevent.sleep(poll_timeout)
        channel_state = views.get_channelstate_for(
            views.state_from_raiden(raiden),
            payment_network_id,
            token_network_id,
            partner_address,
        )


def wait_for_newbalance(
        raiden,
        payment_network_id,
        token_network_id,
        partner_address,
        target_balance,
        poll_timeout):
    """Wait until a given channels balance exceeds the target balance.

    Note:
        This does not time out, use gevent.Timeout.
    """
    channel_state = views.get_channelstate_for(
        views.state_from_raiden(raiden),
        payment_network_id,
        token_network_id,
        partner_address,
    )

    while channel_state.our_state.contract_balance < target_balance:
        gevent.sleep(poll_timeout)
        channel_state = views.get_channelstate_for(
            views.state_from_raiden(raiden),
            payment_network_id,
            token_network_id,
            partner_address,
        )


def wait_for_close(raiden, payment_network_id, token_network_id, channel_ids, poll_timeout):
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
            token_network_id,
            first_id,
        )

        channel_is_settled = (
            channel_state is None or
            channel.get_status(channel_state) in CHANNEL_AFTER_CLOSE_STATES
        )

        if channel_is_settled:
            channel_ids.pop()
        else:
            gevent.sleep(poll_timeout)


def wait_for_settle(raiden, payment_network_id, token_network_id, channel_ids, poll_timeout):
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
            token_network_id,
            first_id,
        )

        channel_is_settled = (
            channel_state is None or
            channel.get_status(channel_state) == CHANNEL_STATE_SETTLED
        )

        if channel_is_settled:
            channel_ids.pop()
        else:
            gevent.sleep(poll_timeout)


def wait_for_settle_all_channels(raiden, poll_timeout):
    """Wait until all channels are settled.

    Note:
        This does not time out, use gevent.Timeout.
    """
    node_state = views.state_from_raiden(raiden)

    id_paymentnetworkstate = node_state.identifiers_to_paymentnetworks.items()
    for payment_network_id, payment_network_state in id_paymentnetworkstate:

        id_tokennetworkstate = payment_network_state.tokenidentifiers_to_tokennetworks.items()
        for token_network_id, token_network_state in id_tokennetworkstate:
            channel_ids = token_network_state.channelidentifiers_to_channels.keys()

            wait_for_settle(
                raiden,
                payment_network_id,
                token_network_id,
                channel_ids,
                poll_timeout,
            )
