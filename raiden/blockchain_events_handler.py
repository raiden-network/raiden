# -*- coding: utf-8 -*-
import gevent
import structlog

from eth_utils import to_canonical_address

from raiden.blockchain.events import get_channel_proxies, decode_event_to_internal
from raiden.blockchain.state import (
    get_channel_state,
    get_token_network_state_from_proxies,
    create_new_token_network_state,
)
from raiden.connection_manager import ConnectionManager
from raiden.transfer import views
from raiden.utils import pex
from raiden.transfer.state import TransactionChannelNewBalance
from raiden.transfer.state_change import (
    ContractReceiveChannelClosed,
    ContractReceiveChannelNew,
    ContractReceiveChannelNewBalance,
    ContractReceiveChannelSettled,
    ContractReceiveChannelUnlock,
    ContractReceiveNewTokenNetwork,
    ContractReceiveRouteNew,
)
from raiden.blockchain.abi import (
    EVENT_TOKEN_ADDED,
    EVENT_TOKEN_ADDED2,
    EVENT_CHANNEL_NEW,
    EVENT_CHANNEL_NEW2,
    EVENT_CHANNEL_NEW_BALANCE,
    EVENT_CHANNEL_NEW_BALANCE2,
    EVENT_CHANNEL_WITHDRAW,
    EVENT_CHANNEL_UNLOCK,
    EVENT_BALANCE_PROOF_UPDATED,
    EVENT_TRANSFER_UPDATED,
    EVENT_CHANNEL_CLOSED,
    EVENT_CHANNEL_SETTLED,
    EVENT_CHANNEL_SECRET_REVEALED,
    EVENT_CHANNEL_SECRET_REVEALED2,
)

log = structlog.get_logger(__name__)  # pylint: disable=invalid-name


def handle_tokennetwork_new(raiden, event, current_block_number):
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
    raiden.handle_state_change(new_payment_network, current_block_number)


def handle_tokennetwork_new2(raiden, event, current_block_number):
    """ Handles a `TokenNetworkCreated` event. """
    data = event.event_data
    token_network_address = data['token_network_address']

    token_network_registry_address = event.originating_contract
    token_network_registry_proxy = raiden.chain.token_network_registry(
        token_network_registry_address
    )
    token_network_proxy = token_network_registry_proxy.token_network(token_network_address)

    raiden.blockchain_events.add_token_network_listener(token_network_proxy)
    token_network_state = create_new_token_network_state(
        raiden,
        token_network_proxy,
    )

    new_token_network = ContractReceiveNewTokenNetwork(
        event.originating_contract,
        token_network_state,
    )
    raiden.handle_state_change(new_token_network, current_block_number)


def handle_channel_new(raiden, event, current_block_number):
    data = event.event_data
    registry_address = data['registry_address']
    token_network_address = event.originating_contract
    participant1 = data['participant1']
    participant2 = data['participant2']
    is_participant = raiden.address in (participant1, participant2)

    if is_participant:
        channel_proxy = raiden.chain.netting_channel(data['netting_channel'])
        token_address = channel_proxy.token_address()
        channel_state = get_channel_state(
            token_address,
            token_network_address,
            raiden.config['reveal_timeout'],
            channel_proxy,
        )

        new_channel = ContractReceiveChannelNew(
            token_network_address,
            channel_state,
        )
        raiden.handle_state_change(new_channel, current_block_number)

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
        new_route = ContractReceiveRouteNew(
            token_network_address,
            participant1,
            participant2,
        )
        raiden.handle_state_change(new_route, current_block_number)


def handle_channel_new_balance(raiden, event, current_block_number):
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
        token_network_identifier = views.get_token_network_identifier_by_token_address(
            views.state_from_raiden(raiden),
            registry_address,
            token_address,
        )

        deposit_transaction = TransactionChannelNewBalance(
            participant_address,
            new_balance,
            deposit_block_number,
        )
        newbalance_statechange = ContractReceiveChannelNewBalance(
            token_network_identifier,
            channel_identifier,
            deposit_transaction,
        )
        raiden.handle_state_change(newbalance_statechange, current_block_number)

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


def handle_channel_closed(raiden, event, current_block_number):
    registry_address = event.event_data['registry_address']
    channel_identifier = event.originating_contract
    data = event.event_data

    channel_state = views.search_for_channel(
        views.state_from_raiden(raiden),
        registry_address,
        channel_identifier,
    )

    if channel_state:
        token_network_identifier = views.get_token_network_identifier_by_token_address(
            views.state_from_raiden(raiden),
            registry_address,
            channel_state.token_address,
        )

        channel_closed = ContractReceiveChannelClosed(
            token_network_identifier,
            channel_identifier,
            data['closing_address'],
            data['block_number'],
        )
        raiden.handle_state_change(channel_closed, current_block_number)


def handle_channel_settled(raiden, event, current_block_number):
    registry_address = event.event_data['registry_address']
    data = event.event_data
    channel_identifier = event.originating_contract

    channel_state = views.search_for_channel(
        views.state_from_raiden(raiden),
        registry_address,
        channel_identifier,
    )

    if channel_state:
        token_network_identifier = views.get_token_network_identifier_by_token_address(
            views.state_from_raiden(raiden),
            registry_address,
            channel_state.token_address,
        )

        channel_settled = ContractReceiveChannelSettled(
            token_network_identifier,
            channel_identifier,
            data['block_number'],
        )
        raiden.handle_state_change(channel_settled, current_block_number)


def handle_channel_unlock(raiden, event, current_block_number):
    channel_identifier = event.originating_contract
    data = event.event_data
    registry_address = data['registry_address']

    channel_state = views.search_for_channel(
        views.state_from_raiden(raiden),
        registry_address,
        channel_identifier,
    )

    if channel_state:
        unlock_state_change = ContractReceiveChannelUnlock(
            registry_address,
            channel_state.token_address,
            channel_identifier,
            data['secret'],
            data['receiver_address'],
        )

        raiden.handle_state_change(unlock_state_change, current_block_number)


def on_blockchain_event(raiden, event, current_block_number):
    log.debug(
        'EVENT',
        node=pex(raiden.address),
        chain_event=event,
        block_number=current_block_number,
    )

    data = event.event_data

    if data['event'] == EVENT_TOKEN_ADDED:
        data['registry_address'] = to_canonical_address(data['args']['registry_address'])
        data['channel_manager_address'] = to_canonical_address(
            data['args']['channel_manager_address']
        )
        handle_tokennetwork_new(raiden, event, current_block_number)

    elif data['event'] == EVENT_CHANNEL_NEW:
        data['registry_address'] = to_canonical_address(data['args']['registry_address'])
        data['participant1'] = to_canonical_address(data['args']['participant1'])
        data['participant2'] = to_canonical_address(data['args']['participant2'])
        handle_channel_new(raiden, event, current_block_number)

    elif data['event'] == EVENT_CHANNEL_NEW_BALANCE:
        data['registry_address'] = to_canonical_address(data['args']['registry_address'])
        data['token_address'] = to_canonical_address(data['args']['token_address'])
        data['participant'] = to_canonical_address(data['args']['participant'])
        data['balance'] = data['args']['balance']
        handle_channel_new_balance(raiden, event, current_block_number)

    elif data['event'] == EVENT_CHANNEL_CLOSED:
        data['registry_address'] = to_canonical_address(data['args']['registry_address'])
        data['closing_address'] = to_canonical_address(data['args']['closing_address'])
        handle_channel_closed(raiden, event, current_block_number)

    elif data['event'] == EVENT_CHANNEL_SETTLED:
        data['registry_address'] = to_canonical_address(data['args']['registry_address'])
        handle_channel_settled(raiden, event, current_block_number)

    elif data['event'] == EVENT_CHANNEL_SECRET_REVEALED:
        data['registry_address'] = to_canonical_address(data['args']['registry_address'])
        data['receiver_address'] = to_canonical_address(data['args']['receiver_address'])
        data['secret'] = data['args']['secret']
        handle_channel_unlock(raiden, event, current_block_number)

    # fix for https://github.com/raiden-network/raiden/issues/1508
    # balance proof updates are handled in the linked code, so no action is needed here
    # https://github.com/raiden-network/raiden/blob/da54ef4b20fb006c126fcb091b18269314c2003b/raiden/transfer/channel.py#L1337-L1344  # noqa
    elif data['event'] == EVENT_TRANSFER_UPDATED:
        pass

    else:
        log.error('Unknown event type', event_name=data['event'], raiden_event=event)


def on_blockchain_event2(raiden, event, current_block_number):
    log.debug('EVENT', node=pex(raiden.address), chain_event=event)

    event = decode_event_to_internal(event)
    data = event.event_data

    if data['args'].get('channel_identifier'):
        data['channel_identifier'] = data['args'].get('channel_identifier')

    if data['event'] == EVENT_TOKEN_ADDED2:
        handle_tokennetwork_new2(raiden, event, current_block_number)

    elif data['event'] == EVENT_CHANNEL_NEW2:
        data['settle_timeout'] = data['args']['settle_timeout']
        handle_channel_new(raiden, event, current_block_number)

    elif data['event'] == EVENT_CHANNEL_NEW_BALANCE2:
        data['deposit'] = data['args']['deposit']
        handle_channel_new_balance(raiden, event, current_block_number)

    elif data['event'] == EVENT_CHANNEL_WITHDRAW:
        data['withdrawn_amount'] = data['args']['withdrawn_amount']
        # handle_channel_withdraw(raiden, event)
        raise NotImplementedError('handle_channel_withdraw not implemented yet')

    elif data['event'] == EVENT_CHANNEL_UNLOCK:
        data['unlocked_amount'] = data['args']['unlocked_amount']
        data['returned_tokens'] = data['args']['returned_tokens']
        # handle_channel_unlock(raiden, event)
        raise NotImplementedError('handle_channel_unlock not implemented yet')

    elif data['event'] == EVENT_BALANCE_PROOF_UPDATED:
        # balance proof updates are handled in the linked code, so no action is needed here
        # https://github.com/raiden-network/raiden/blob/da54ef4b20fb006c126fcb091b18269314c2003b/raiden/transfer/channel.py#L1337-L1344  # noqa
        pass

    elif data['event'] == EVENT_CHANNEL_CLOSED:
        handle_channel_closed(raiden, event, current_block_number)

    elif data['event'] == EVENT_CHANNEL_SETTLED:
        data['participant1_amount'] = data['args']['participant1_amount']
        data['participant2_amount'] = data['args']['participant2_amount']
        handle_channel_settled(raiden, event, current_block_number)

    elif data['event'] == EVENT_CHANNEL_SECRET_REVEALED2:
        data['secrethash'] = data['args']['secrethash']
        # handle_secret_reveal(raiden, event, current_block_number)
        raise NotImplementedError('handle_secret_reveal not implemented yet')

    else:
        log.error('Unknown event type', event_name=data['event'], raiden_event=event)
