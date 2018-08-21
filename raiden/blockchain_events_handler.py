import gevent
import structlog

from raiden_contracts.constants import (
    ChannelEvent,
    EVENT_SECRET_REVEALED,
    EVENT_TOKEN_NETWORK_CREATED,
)

from raiden.blockchain.events import decode_event_to_internal
from raiden.blockchain.state import get_channel_state
from raiden.connection_manager import ConnectionManager
from raiden.transfer import views
from raiden.utils import pex, data_decoder
from raiden.transfer.state import (
    TransactionChannelNewBalance,
    TokenNetworkState,
)
from raiden.transfer.state_change import (
    ContractReceiveChannelClosed,
    ContractReceiveChannelNew,
    ContractReceiveChannelNewBalance,
    ContractReceiveChannelSettled,
    ContractReceiveChannelBatchUnlock,
    ContractReceiveNewTokenNetwork,
    ContractReceiveSecretReveal,
    ContractReceiveRouteNew,
    ContractReceiveRouteClosed,
    ContractReceiveUpdateTransfer,
)

log = structlog.get_logger(__name__)  # pylint: disable=invalid-name


def handle_tokennetwork_new(raiden, event, current_block_number):
    """ Handles a `TokenNetworkCreated` event. """
    data = event.event_data
    token_network_address = data['token_network_address']

    token_network_proxy = raiden.chain.token_network(token_network_address)
    raiden.blockchain_events.add_token_network_listener(
        token_network_proxy,
        from_block=data['blockNumber'],
    )

    token_address = data_decoder(event.event_data['args']['token_address'])

    token_network_state = TokenNetworkState(
        token_network_address,
        token_address,
    )

    transaction_hash = event.event_data['transactionHash']
    assert transaction_hash, 'A mined transaction must have the hash field'

    new_token_network = ContractReceiveNewTokenNetwork(
        transaction_hash,
        event.originating_contract,
        token_network_state,
    )
    raiden.handle_state_change(new_token_network, current_block_number)


def handle_channel_new(raiden, event, current_block_number):
    data = event.event_data
    token_network_identifier = event.originating_contract
    transaction_hash = event.event_data['transactionHash']
    assert transaction_hash, 'A mined transaction must have the hash field'
    channel_identifier = data['channel_identifier']
    participant1 = data['participant1']
    participant2 = data['participant2']
    is_participant = raiden.address in (participant1, participant2)

    # Raiden node is participant
    if is_participant:
        channel_proxy = raiden.chain.payment_channel(
            token_network_identifier,
            channel_identifier,
        )
        token_address = channel_proxy.token_address()
        channel_state = get_channel_state(
            token_address,
            raiden.default_registry.address,
            token_network_identifier,
            raiden.config['reveal_timeout'],
            channel_proxy,
            event.event_data['block_number'],
        )

        new_channel = ContractReceiveChannelNew(
            transaction_hash,
            token_network_identifier,
            channel_state,
        )
        raiden.handle_state_change(new_channel, current_block_number)
        partner_address = channel_state.partner_state.address

        if ConnectionManager.BOOTSTRAP_ADDR != partner_address:
            raiden.start_health_check_for(partner_address)

        # Start the listener *after* the channel is registered, to avoid None
        # exceptions (and not applying the event state change).
        #
        # TODO: install the filter on the same block or previous block in which
        # the channel state was queried
        raiden.blockchain_events.add_payment_channel_listener(
            channel_proxy,
            from_block=data['blockNumber'] + 1,
        )

    # Raiden node is not participant of channel
    else:
        new_route = ContractReceiveRouteNew(
            transaction_hash,
            token_network_identifier,
            channel_identifier,
            participant1,
            participant2,
        )
        raiden.handle_state_change(new_route, current_block_number)

    # A new channel is available, run the connection manager in case more
    # connections are needed
    connection_manager = raiden.connection_manager_for_token_network(token_network_identifier)
    gevent.spawn(connection_manager.retry_connect)


def handle_channel_new_balance(raiden, event, current_block_number):
    data = event.event_data
    channel_identifier = data['channel_identifier']
    token_network_identifier = event.originating_contract
    participant_address = data['participant']
    total_deposit = data['args']['total_deposit']
    deposit_block_number = data['block_number']
    transaction_hash = data['transactionHash']
    assert transaction_hash, 'A mined transaction must have the hash field'

    previous_channel_state = views.get_channelstate_by_token_network_identifier(
        views.state_from_raiden(raiden),
        token_network_identifier,
        channel_identifier,
    )

    # Channels will only be registered if this node is a participant
    is_participant = previous_channel_state is not None

    if is_participant:
        previous_balance = previous_channel_state.our_state.contract_balance
        balance_was_zero = previous_balance == 0

        deposit_transaction = TransactionChannelNewBalance(
            participant_address,
            total_deposit,
            deposit_block_number,
        )

        newbalance_statechange = ContractReceiveChannelNewBalance(
            transaction_hash,
            token_network_identifier,
            channel_identifier,
            deposit_transaction,
        )
        raiden.handle_state_change(newbalance_statechange, current_block_number)

        if balance_was_zero and participant_address != raiden.address:
            connection_manager = raiden.connection_manager_for_token_network(
                token_network_identifier,
            )

            gevent.spawn(
                connection_manager.join_channel,
                participant_address,
                total_deposit,
            )


def handle_channel_closed(raiden, event, current_block_number):
    token_network_identifier = event.originating_contract
    data = event.event_data
    channel_identifier = data['channel_identifier']
    transaction_hash = data['transactionHash']
    assert transaction_hash, 'A mined transaction must have the hash field'

    channel_state = views.get_channelstate_by_token_network_identifier(
        views.state_from_raiden(raiden),
        token_network_identifier,
        channel_identifier,
    )

    if channel_state:
        # The from address is included in the ChannelClosed event as the
        # closing_participant field
        channel_closed = ContractReceiveChannelClosed(
            transaction_hash=transaction_hash,
            transaction_from=data['closing_participant'],
            token_network_identifier=token_network_identifier,
            channel_identifier=channel_identifier,
            closed_block_number=data['block_number'],
        )
        raiden.handle_state_change(channel_closed, current_block_number)
    else:
        # This is a channel close event of a channel we're not a participant of
        channel_closed = ContractReceiveRouteClosed(
            transaction_hash=transaction_hash,
            token_network_identifier=token_network_identifier,
            channel_identifier=channel_identifier,
        )
        raiden.handle_state_change(channel_closed, current_block_number)


def handle_channel_update_transfer(raiden, event, current_block_number):
    token_network_identifier = event.originating_contract
    data = event.event_data
    channel_identifier = data['channel_identifier']

    channel_state = views.get_channelstate_by_token_network_identifier(
        views.state_from_raiden(raiden),
        token_network_identifier,
        channel_identifier,
    )

    if channel_state:
        channel_transfer_updated = ContractReceiveUpdateTransfer(
            transaction_from=data['closing_participant'],
            token_network_identifier=token_network_identifier,
            channel_identifier=channel_identifier,
            nonce=data['args']['nonce'],
        )
        raiden.handle_state_change(channel_transfer_updated, current_block_number)


def handle_channel_settled(raiden, event, current_block_number):
    data = event.event_data
    token_network_identifier = event.originating_contract
    channel_identifier = event.event_data['channel_identifier']

    transaction_hash = data['transactionHash']
    assert transaction_hash, 'A mined transaction must have the hash field'

    channel_state = views.get_channelstate_by_token_network_identifier(
        views.state_from_raiden(raiden),
        token_network_identifier,
        channel_identifier,
    )

    if channel_state:
        channel_settled = ContractReceiveChannelSettled(
            transaction_hash,
            token_network_identifier,
            channel_identifier,
            data['block_number'],
        )
        raiden.handle_state_change(channel_settled, current_block_number)


def handle_channel_batch_unlock(raiden, event, current_block_number):
    token_network_identifier = event.originating_contract
    data = event.event_data

    transaction_hash = data['transactionHash']
    assert transaction_hash, 'A mined transaction must have the hash field'

    unlock_state_change = ContractReceiveChannelBatchUnlock(
        transaction_hash,
        token_network_identifier,
        data['participant'],
        data['partner'],
        data['locksroot'],
        data['unlocked_amount'],
        data['returned_tokens'],
    )

    raiden.handle_state_change(unlock_state_change, current_block_number)


def handle_secret_revealed(raiden, event, current_block_number):
    secret_registry_address = event.originating_contract
    data = event.event_data

    transaction_hash = data['transactionHash']
    assert transaction_hash, 'A mined transaction must have the hash field'

    registeredsecret_state_change = ContractReceiveSecretReveal(
        transaction_hash,
        secret_registry_address,
        data['secrethash'],
        data['secret'],
    )

    raiden.handle_state_change(registeredsecret_state_change, current_block_number)


def on_blockchain_event(raiden, event, current_block_number, chain_id):
    log.debug('BLOCKCHAIN EVENT', node=pex(raiden.address), chain_event=event)

    event = decode_event_to_internal(event)
    data = event.event_data

    if data['event'] == EVENT_TOKEN_NETWORK_CREATED:
        handle_tokennetwork_new(raiden, event, current_block_number)

    elif data['event'] == ChannelEvent.OPENED:
        handle_channel_new(raiden, event, current_block_number)

    elif data['event'] == ChannelEvent.DEPOSIT:
        handle_channel_new_balance(raiden, event, current_block_number)

    elif data['event'] == ChannelEvent.WITHDRAW:
        # handle_channel_withdraw(raiden, event)
        raise NotImplementedError('handle_channel_withdraw not implemented yet')

    elif data['event'] == ChannelEvent.BALANCE_PROOF_UPDATED:
        handle_channel_update_transfer(raiden, event, current_block_number)

    elif data['event'] == ChannelEvent.CLOSED:
        handle_channel_closed(raiden, event, current_block_number)

    elif data['event'] == ChannelEvent.SETTLED:
        handle_channel_settled(raiden, event, current_block_number)

    elif data['event'] == EVENT_SECRET_REVEALED:
        handle_secret_revealed(raiden, event, current_block_number)

    elif data['event'] == ChannelEvent.UNLOCKED:
        handle_channel_batch_unlock(raiden, event, current_block_number)

    else:
        log.error('Unknown event type', event_name=data['event'], raiden_event=event)
