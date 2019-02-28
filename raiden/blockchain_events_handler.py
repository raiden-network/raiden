from typing import TYPE_CHECKING

import gevent
import structlog

from raiden.blockchain.events import Event
from raiden.blockchain.state import get_channel_state
from raiden.connection_manager import ConnectionManager
from raiden.network.proxies.utils import get_onchain_locksroots
from raiden.transfer import views
from raiden.transfer.architecture import StateChange
from raiden.transfer.state import TokenNetworkState, TransactionChannelNewBalance
from raiden.transfer.state_change import (
    ContractReceiveChannelBatchUnlock,
    ContractReceiveChannelClosed,
    ContractReceiveChannelNew,
    ContractReceiveChannelNewBalance,
    ContractReceiveChannelSettled,
    ContractReceiveNewTokenNetwork,
    ContractReceiveRouteClosed,
    ContractReceiveRouteNew,
    ContractReceiveSecretReveal,
    ContractReceiveUpdateTransfer,
)
from raiden.utils import CHANNEL_ID_UNSPECIFIED, CanonicalIdentifier, pex, typing
from raiden_contracts.constants import (
    EVENT_SECRET_REVEALED,
    EVENT_TOKEN_NETWORK_CREATED,
    ChannelEvent,
)

if TYPE_CHECKING:
    from raiden.raiden_service import RaidenService  # noqa: F401


log = structlog.get_logger(__name__)  # pylint: disable=invalid-name


def handle_tokennetwork_new(raiden: 'RaidenService', event: Event):
    """ Handles a `TokenNetworkCreated` event. """
    data = event.event_data
    args = data['args']
    block_number = data['block_number']
    token_network_address = args['token_network_address']
    token_address = typing.TokenAddress(args['token_address'])
    block_hash = data['block_hash']

    token_network_proxy = raiden.chain.token_network(token_network_address)
    raiden.blockchain_events.add_token_network_listener(
        token_network_proxy=token_network_proxy,
        contract_manager=raiden.contract_manager,
        from_block=block_number,
    )

    token_network_state = TokenNetworkState(
        token_network_address,
        token_address,
    )

    transaction_hash = event.event_data['transaction_hash']

    new_token_network = ContractReceiveNewTokenNetwork(
        transaction_hash=transaction_hash,
        payment_network_identifier=event.originating_contract,
        token_network=token_network_state,
        block_number=block_number,
        block_hash=block_hash,
    )
    raiden.handle_and_track_state_change(new_token_network)


def handle_channel_new(raiden: 'RaidenService', event: Event):
    data = event.event_data
    block_number = data['block_number']
    block_hash = data['block_hash']
    args = data['args']
    token_network_identifier = event.originating_contract
    transaction_hash = event.event_data['transaction_hash']
    channel_identifier = args['channel_identifier']
    participant1 = args['participant1']
    participant2 = args['participant2']
    is_participant = raiden.address in (participant1, participant2)

    # Raiden node is participant
    if is_participant:
        channel_proxy = raiden.chain.payment_channel(
            canonical_identifier=CanonicalIdentifier(
                chain_identifier=views.state_from_raiden(raiden).chain_id,
                token_network_address=token_network_identifier,
                channel_identifier=channel_identifier,
            ),
        )
        token_address = channel_proxy.token_address()
        channel_state = get_channel_state(
            token_address=typing.TokenAddress(token_address),
            payment_network_identifier=raiden.default_registry.address,
            token_network_address=token_network_identifier,
            reveal_timeout=raiden.config['reveal_timeout'],
            payment_channel_proxy=channel_proxy,
            opened_block_number=block_number,
        )

        new_channel = ContractReceiveChannelNew(
            transaction_hash=transaction_hash,
            channel_state=channel_state,
            block_number=block_number,
            block_hash=block_hash,
        )
        raiden.handle_and_track_state_change(new_channel)

        partner_address = channel_state.partner_state.address

        if ConnectionManager.BOOTSTRAP_ADDR != partner_address:
            raiden.start_health_check_for(partner_address)

    # Raiden node is not participant of channel
    else:
        new_route = ContractReceiveRouteNew(
            transaction_hash=transaction_hash,
            canonical_identifier=CanonicalIdentifier(
                chain_identifier=raiden.chain.network_id,
                token_network_address=token_network_identifier,
                channel_identifier=channel_identifier,
            ),
            participant1=participant1,
            participant2=participant2,
            block_number=block_number,
            block_hash=block_hash,
        )
        raiden.handle_and_track_state_change(new_route)

    # A new channel is available, run the connection manager in case more
    # connections are needed
    connection_manager = raiden.connection_manager_for_token_network(token_network_identifier)
    retry_connect = gevent.spawn(connection_manager.retry_connect)
    raiden.add_pending_greenlet(retry_connect)


def handle_channel_new_balance(raiden: 'RaidenService', event: Event):
    data = event.event_data
    args = data['args']
    block_number = data['block_number']
    block_hash = data['block_hash']
    channel_identifier = args['channel_identifier']
    token_network_identifier = event.originating_contract
    participant_address = args['participant']
    total_deposit = args['total_deposit']
    transaction_hash = data['transaction_hash']

    chain_state = views.state_from_raiden(raiden)
    previous_channel_state = views.get_channelstate_by_canonical_identifier(
        chain_state=chain_state,
        canonical_identifier=CanonicalIdentifier(
            chain_identifier=chain_state.chain_id,
            token_network_address=token_network_identifier,
            channel_identifier=channel_identifier,
        ),
    )

    # Channels will only be registered if this node is a participant
    if previous_channel_state is not None:
        previous_balance = previous_channel_state.our_state.contract_balance
        balance_was_zero = previous_balance == 0

        deposit_transaction = TransactionChannelNewBalance(
            participant_address,
            total_deposit,
            block_number,
        )

        newbalance_statechange = ContractReceiveChannelNewBalance(
            transaction_hash=transaction_hash,
            canonical_identifier=previous_channel_state.canonical_identifier,
            deposit_transaction=deposit_transaction,
            block_number=block_number,
            block_hash=block_hash,
        )
        raiden.handle_and_track_state_change(newbalance_statechange)

        if balance_was_zero and participant_address != raiden.address:
            connection_manager = raiden.connection_manager_for_token_network(
                token_network_identifier,
            )

            join_channel = gevent.spawn(
                connection_manager.join_channel,
                participant_address,
                total_deposit,
            )

            raiden.add_pending_greenlet(join_channel)


def handle_channel_closed(raiden: 'RaidenService', event: Event):
    token_network_identifier = event.originating_contract
    data = event.event_data
    block_number = data['block_number']
    args = data['args']
    channel_identifier = args['channel_identifier']
    transaction_hash = data['transaction_hash']
    block_hash = data['block_hash']

    chain_state = views.state_from_raiden(raiden)
    channel_state = views.get_channelstate_by_canonical_identifier(
        chain_state=chain_state,
        canonical_identifier=CanonicalIdentifier(
            chain_identifier=chain_state.chain_id,
            token_network_address=token_network_identifier,
            channel_identifier=channel_identifier,
        ),
    )

    channel_closed: StateChange
    if channel_state:
        # The from address is included in the ChannelClosed event as the
        # closing_participant field
        channel_closed = ContractReceiveChannelClosed(
            transaction_hash=transaction_hash,
            transaction_from=args['closing_participant'],
            canonical_identifier=channel_state.canonical_identifier,
            block_number=block_number,
            block_hash=block_hash,
        )
        raiden.handle_and_track_state_change(channel_closed)
    else:
        # This is a channel close event of a channel we're not a participant of
        route_closed = ContractReceiveRouteClosed(
            transaction_hash=transaction_hash,
            canonical_identifier=CanonicalIdentifier(
                chain_identifier=chain_state.chain_id,
                token_network_address=token_network_identifier,
                channel_identifier=channel_identifier,
            ),
            block_number=block_number,
            block_hash=block_hash,
        )
        raiden.handle_and_track_state_change(route_closed)


def handle_channel_update_transfer(raiden: 'RaidenService', event: Event):
    token_network_identifier = event.originating_contract
    data = event.event_data
    args = data['args']
    channel_identifier = args['channel_identifier']
    transaction_hash = data['transaction_hash']
    block_number = data['block_number']
    block_hash = data['block_hash']

    chain_state = views.state_from_raiden(raiden)
    channel_state = views.get_channelstate_by_canonical_identifier(
        chain_state=chain_state,
        canonical_identifier=CanonicalIdentifier(
            chain_identifier=chain_state.chain_id,
            token_network_address=token_network_identifier,
            channel_identifier=channel_identifier,
        ),
    )

    if channel_state:
        channel_transfer_updated = ContractReceiveUpdateTransfer(
            transaction_hash=transaction_hash,
            canonical_identifier=channel_state.canonical_identifier,
            nonce=args['nonce'],
            block_number=block_number,
            block_hash=block_hash,
        )
        raiden.handle_and_track_state_change(channel_transfer_updated)


def handle_channel_settled(raiden: 'RaidenService', event: Event):
    data = event.event_data
    token_network_identifier = event.originating_contract
    channel_identifier = data['args']['channel_identifier']
    block_number = data['block_number']
    block_hash = data['block_hash']
    transaction_hash = data['transaction_hash']

    chain_state = views.state_from_raiden(raiden)
    channel_state = views.get_channelstate_by_canonical_identifier(
        chain_state=chain_state,
        canonical_identifier=CanonicalIdentifier(
            chain_identifier=chain_state.chain_id,
            token_network_address=token_network_identifier,
            channel_identifier=channel_identifier,
        ),
    )

    if not channel_state:
        return

    """
    This is resolving a corner case where the current node view
    of the channel state does not reflect what the blockchain
    contains.
    The corner case goes as follows in a setup of nodes:
    A -> B:
    - A sends out a LockedTransfer to B
    - B sends a refund to A
    - B goes offline
    - A sends LockExpired to B
      Here:
      (1) the lock is removed from A's state
      (2) B never received the message
    - A closes the channel with B's refund
    - B comes back online and calls updateNonClosingBalanceProof
      with A's LockedTransfer (LockExpired was never processed).
    - When channel is settled, B unlocks it's refund transfer lock
      provided that it gains from doing so.
    - A does NOT try to unlock its lock because its side
      of the channel state is empty (lock expired and was removed).

    The above is resolved by providing the state machine with the
    onchain locksroots for both participants in the channel so that
    the channel state is updated to store these locksroots.
    In `raiden_event_handler:handle_contract_send_channelunlock`,
    those values are used to restore the channel state back to where
    the locksroots values existed and this channel state is used
    to calculate the gain and potentially perform unlocks in case
    there is value to be gained.
    """
    our_locksroot, partner_locksroot = get_onchain_locksroots(
        raiden=raiden,
        token_network_address=token_network_identifier,
        channel_identifier=channel_identifier,
        participant1=channel_state.our_state.address,
        participant2=channel_state.partner_state.address,
        block_identifier=block_hash,
    )

    channel_settled = ContractReceiveChannelSettled(
        transaction_hash=transaction_hash,
        canonical_identifier=channel_state.canonical_identifier,
        our_onchain_locksroot=our_locksroot,
        partner_onchain_locksroot=partner_locksroot,
        block_number=block_number,
        block_hash=block_hash,
    )
    raiden.handle_and_track_state_change(channel_settled)


def handle_channel_batch_unlock(raiden: 'RaidenService', event: Event):
    token_network_identifier = event.originating_contract
    data = event.event_data
    args = data['args']
    block_number = data['block_number']
    block_hash = data['block_hash']
    transaction_hash = data['transaction_hash']

    chain_state = views.state_from_raiden(raiden)
    unlock_state_change = ContractReceiveChannelBatchUnlock(
        transaction_hash=transaction_hash,
        canonical_identifier=CanonicalIdentifier(
            chain_identifier=chain_state.chain_id,
            token_network_address=token_network_identifier,
            # FIXME: we will resolve the channel identifier only further down in
            # raiden.transfer.token_network::handle_batch_unlock
            # can/should we do it here already?
            channel_identifier=CHANNEL_ID_UNSPECIFIED,
        ),
        participant=args['participant'],
        partner=args['partner'],
        locksroot=args['locksroot'],
        unlocked_amount=args['unlocked_amount'],
        returned_tokens=args['returned_tokens'],
        block_number=block_number,
        block_hash=block_hash,
    )

    raiden.handle_and_track_state_change(unlock_state_change)


def handle_secret_revealed(raiden: 'RaidenService', event: Event):
    secret_registry_address = event.originating_contract
    data = event.event_data
    args = data['args']
    block_number = data['block_number']
    block_hash = data['block_hash']
    transaction_hash = data['transaction_hash']
    registeredsecret_state_change = ContractReceiveSecretReveal(
        transaction_hash=transaction_hash,
        secret_registry_address=secret_registry_address,
        secrethash=args['secrethash'],
        secret=args['secret'],
        block_number=block_number,
        block_hash=block_hash,
    )

    raiden.handle_and_track_state_change(registeredsecret_state_change)


def on_blockchain_event(raiden: 'RaidenService', event: Event):
    data = event.event_data
    log.debug(
        'Blockchain event',
        node=pex(raiden.address),
        contract=pex(event.originating_contract),
        event_data=data,
    )

    event_name = data['event']
    if event_name == EVENT_TOKEN_NETWORK_CREATED:
        handle_tokennetwork_new(raiden, event)

    elif event_name == ChannelEvent.OPENED:
        handle_channel_new(raiden, event)

    elif event_name == ChannelEvent.DEPOSIT:
        handle_channel_new_balance(raiden, event)

    elif event_name == ChannelEvent.BALANCE_PROOF_UPDATED:
        handle_channel_update_transfer(raiden, event)

    elif event_name == ChannelEvent.CLOSED:
        handle_channel_closed(raiden, event)

    elif event_name == ChannelEvent.SETTLED:
        handle_channel_settled(raiden, event)

    elif event_name == EVENT_SECRET_REVEALED:
        handle_secret_revealed(raiden, event)

    elif event_name == ChannelEvent.UNLOCKED:
        handle_channel_batch_unlock(raiden, event)

    else:
        log.error('Unknown event type', event_name=data['event'], raiden_event=event)
