# -*- coding: utf-8 -*-
import gevent
import structlog

from raiden.blockchain.events import get_channel_proxies
from raiden.blockchain.state import (
    get_channel_state,
    get_token_network_state_from_proxies,
)
from raiden.connection_manager import ConnectionManager
from raiden.transfer import views
from raiden.transfer.state import TransactionChannelNewBalance
from raiden.transfer.state_change import (
    ContractReceiveChannelClosed,
    ContractReceiveChannelNew,
    ContractReceiveChannelNewBalance,
    ContractReceiveChannelSettled,
    ContractReceiveChannelWithdraw,
    ContractReceiveNewTokenNetwork,
    ContractReceiveRouteNew,
)
from raiden.utils import pex

log = structlog.get_logger(__name__)  # pylint: disable=invalid-name


def handle_tokennetwork_new(raiden, event):
    data = event.event_data
    manager_address = data['channel_manager_address']

    registry_address = data['registry_address']
    registry = raiden.chain.registry(registry_address)

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
    data = event.event_data
    registry_address = data['registry_address']
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

        new_channel = ContractReceiveChannelNew(
            registry_address,
            token_address,
            channel_state,
        )
        raiden.handle_state_change(new_channel)

        partner_address = channel_state.partner_state.address
        connection_manager = raiden.connection_manager_for_token(
            registry_address, token_address
        )

        if ConnectionManager.BOOTSTRAP_ADDR != partner_address:
            raiden.start_health_check_for(partner_address)

        gevent.spawn(connection_manager.retry_connect, registry_address)

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
            registry_address,
            token_address,
            participant1,
            participant2,
        )
        raiden.handle_state_change(new_route)


def handle_channel_new_balance(raiden, event):
    data = event.event_data
    registry_address = data['registry_address']
    channel_identifier = event.originating_contract
    token_address = data['token_address']
    participant_address = data['participant']
    new_balance = data['balance']
    deposit_block_number = data['block_number']

    previous_channel_state = views.get_channelstate_by_tokenaddress(
        views.state_from_raiden(raiden),
        registry_address,
        token_address,
        channel_identifier,
    )

    # Channels will only be registered if this node is a participant
    is_participant = previous_channel_state is not None

    if is_participant:
        previous_balance = previous_channel_state.our_state.contract_balance
        balance_was_zero = previous_balance == 0

        deposit_transaction = TransactionChannelNewBalance(
            participant_address,
            new_balance,
            deposit_block_number,
        )
        newbalance_statechange = ContractReceiveChannelNewBalance(
            registry_address,
            token_address,
            channel_identifier,
            deposit_transaction,
        )
        raiden.handle_state_change(newbalance_statechange)

        if balance_was_zero:
            connection_manager = raiden.connection_manager_for_token(
                registry_address, token_address
            )

            gevent.spawn(
                connection_manager.join_channel,
                registry_address,
                participant_address,
                new_balance,
            )


def handle_channel_closed(raiden, event):
    registry_address = event.event_data['registry_address']
    channel_identifier = event.originating_contract
    data = event.event_data

    channel_state = views.search_for_channel(
        views.state_from_raiden(raiden),
        registry_address,
        channel_identifier,
    )

    if channel_state:
        channel_closed = ContractReceiveChannelClosed(
            registry_address,
            channel_state.token_address,
            channel_identifier,
            data['closing_address'],
            data['block_number'],
        )
        raiden.handle_state_change(channel_closed)


def handle_channel_settled(raiden, event):
    registry_address = event.event_data['registry_address']
    data = event.event_data
    channel_identifier = event.originating_contract

    channel_state = views.search_for_channel(
        views.state_from_raiden(raiden),
        registry_address,
        channel_identifier,
    )

    if channel_state:
        channel_settled = ContractReceiveChannelSettled(
            registry_address,
            channel_state.token_address,
            channel_identifier,
            data['block_number'],
        )
        raiden.handle_state_change(channel_settled)


def handle_channel_withdraw(raiden, event):
    channel_identifier = event.originating_contract
    data = event.event_data
    registry_address = data['registry_address']

    channel_state = views.search_for_channel(
        views.state_from_raiden(raiden),
        registry_address,
        channel_identifier,
    )

    if channel_state:
        withdrawn_state_change = ContractReceiveChannelWithdraw(
            registry_address,
            channel_state.token_address,
            channel_identifier,
            data['secret'],
            data['receiver_address'],
        )

        raiden.handle_state_change(withdrawn_state_change)


def on_blockchain_event(raiden, event):
    log.debug('EVENT', node=pex(raiden.address), chain_event=event)

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

    else:
        log.error('Unknown event type', event=event)
