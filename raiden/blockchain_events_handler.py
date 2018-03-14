# -*- coding: utf-8 -*-
import logging

import gevent
from ethereum import slogging

from raiden.blockchain.events import get_channel_proxies
from raiden.blockchain.state import (
    get_channel_state,
    get_token_network_state_from_proxies,
)
from raiden.connection_manager import ConnectionManager
from raiden.transfer import views
from raiden.transfer.state_change import (
    ActionForTokenNetwork,
    ContractReceiveChannelNew,
    ContractReceiveRouteNew,
    ContractReceiveNewTokenNetwork,
)
from raiden.transfer.state_change import (
    ContractReceiveChannelNewBalance,
    ContractReceiveChannelClosed,
    ContractReceiveChannelSettled,
    ContractReceiveChannelWithdraw,
)
from raiden.utils import pex

log = slogging.get_logger(__name__)  # pylint: disable=invalid-name


def handle_tokennetwork_new(raiden, event):
    data = event.event_data
    manager_address = data['channel_manager_address']

    registry = raiden.default_registry
    manager_proxy = registry.manager(manager_address)
    netting_channel_proxies = get_channel_proxies(raiden.chain, raiden.address, manager_proxy)

    # Install the filters first to avoid missing changes, as a consequence
    # some events might be applied twice.
    raiden.blockchain_events.add_channel_manager_listener(manager_proxy)
    for channel_proxy in netting_channel_proxies:
        raiden.blockchain_events.add_netting_channel_listener(channel_proxy)

    token_network_state = get_token_network_state_from_proxies(
        raiden,
        manager_proxy,
        netting_channel_proxies,
    )

    new_payment_network = ContractReceiveNewTokenNetwork(
        event.originating_contract,
        token_network_state,
    )
    raiden.handle_state_change(new_payment_network)


def handle_channel_new(raiden, event):
    payment_network_identifier = raiden.default_registry.address

    data = event.event_data
    participant1 = data['participant1']
    participant2 = data['participant2']
    is_participant = raiden.address in (participant1, participant2)

    if is_participant:
        channel_proxy = raiden.chain.netting_channel(data['netting_channel'])
        token_address = channel_proxy.token_address()
        channel_state = get_channel_state(
            token_address,
            raiden.config['reveal_timeout'],
            channel_proxy,
        )

        new_channel = ContractReceiveChannelNew(channel_state)
        state_change = ActionForTokenNetwork(
            payment_network_identifier,
            token_address,
            new_channel,
        )
        raiden.handle_state_change(state_change)

        partner_address = channel_state.partner_state.address
        connection_manager = raiden.connection_manager_for_token(token_address)

        if ConnectionManager.BOOTSTRAP_ADDR != partner_address:
            raiden.start_health_check_for(partner_address)

        if connection_manager.wants_more_channels:
            gevent.spawn(connection_manager.retry_connect)

        # Start the listener *after* the channel is registered, to avoid None
        # exceptions (and not applying the event state change).
        #
        # TODO: install the filter on the same block or previous block in which
        # the channel state was queried
        raiden.blockchain_events.add_netting_channel_listener(channel_proxy)

    else:
        manager = raiden.chain.channel_manager(event.originating_contract)
        token_address = manager.token_address()

        new_route = ContractReceiveRouteNew(
            participant1,
            participant2,
        )
        state_change = ActionForTokenNetwork(
            payment_network_identifier,
            token_address,
            new_route,
        )
        raiden.handle_state_change(state_change)


def handle_channel_new_balance(raiden, event):
    data = event.event_data
    payment_network_identifier = raiden.default_registry.address
    channel_identifier = event.originating_contract
    token_address = data['token_address']
    participant_address = data['participant']
    new_balance = data['balance']

    previous_channel_state = views.get_channelstate_by_tokenaddress(
        views.state_from_raiden(raiden),
        payment_network_identifier,
        token_address,
        channel_identifier,
    )

    # Channels will only be registered if this node is a participant
    is_participant = previous_channel_state is not None

    if is_participant:
        previous_balance = previous_channel_state.our_state.contract_balance
        balance_was_zero = previous_balance == 0

        new_balance = ContractReceiveChannelNewBalance(
            channel_identifier,
            participant_address,
            new_balance,
        )
        state_change = ActionForTokenNetwork(
            payment_network_identifier,
            token_address,
            new_balance,
        )
        raiden.handle_state_change(state_change)

        if balance_was_zero:
            connection_manager = raiden.connection_manager_for_token(token_address)

            gevent.spawn(
                connection_manager.join_channel,
                participant_address,
                new_balance,
            )


def handle_channel_closed(raiden, event):
    payment_network_identifier = raiden.default_registry.address
    channel_identifier = event.originating_contract
    data = event.event_data

    channel_state = views.search_for_channel(
        views.state_from_raiden(raiden),
        payment_network_identifier,
        channel_identifier,
    )

    if channel_state:
        channel_closed = ContractReceiveChannelClosed(
            channel_identifier,
            data['closing_address'],
            data['block_number'],
        )
        state_change = ActionForTokenNetwork(
            payment_network_identifier,
            channel_state.token_address,
            channel_closed,
        )
        raiden.handle_state_change(state_change)


def handle_channel_settled(raiden, event):
    payment_network_identifier = raiden.default_registry.address
    data = event.event_data
    channel_identifier = event.originating_contract

    channel_state = views.search_for_channel(
        views.state_from_raiden(raiden),
        payment_network_identifier,
        channel_identifier,
    )

    if channel_state:
        channel_settled = ContractReceiveChannelSettled(
            channel_identifier,
            data['block_number'],
        )
        state_change = ActionForTokenNetwork(
            payment_network_identifier,
            channel_state.token_address,
            channel_settled,
        )
        raiden.handle_state_change(state_change)


def handle_channel_withdraw(raiden, event):
    channel_identifier = event.originating_contract
    data = event.event_data
    payment_network_identifier = raiden.default_registry.address

    channel_state = views.search_for_channel(
        views.state_from_raiden(raiden),
        payment_network_identifier,
        channel_identifier,
    )

    if channel_state:
        withdrawn_state_change = ContractReceiveChannelWithdraw(
            payment_network_identifier,
            channel_state.token_address,
            channel_identifier,
            data['secret'],
            data['receiver_address'],
        )

        raiden.handle_state_change(withdrawn_state_change)


def on_blockchain_event(raiden, event):
    if log.isEnabledFor(logging.DEBUG):
        log.debug('EVENT', node=pex(raiden.address), event=event)

    data = event.event_data
    assert isinstance(data['_event_type'], bytes)

    if data['_event_type'] == b'TokenAdded':
        handle_tokennetwork_new(raiden, event)

    elif data['_event_type'] == b'ChannelNew':
        handle_channel_new(raiden, event)

    elif data['_event_type'] == b'ChannelNewBalance':
        handle_channel_new_balance(raiden, event)

    elif data['_event_type'] == b'ChannelClosed':
        handle_channel_closed(raiden, event)

    elif data['_event_type'] == b'ChannelSettled':
        handle_channel_settled(raiden, event)

    elif data['_event_type'] == b'ChannelSecretRevealed':
        handle_channel_withdraw(raiden, event)

    elif log.isEnabledFor(logging.ERROR):
        log.error('Unknown event type', event=event)
