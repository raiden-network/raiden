from dataclasses import replace
from typing import TYPE_CHECKING

import gevent
import structlog
from eth_utils import to_checksum_address, to_hex

from raiden.blockchain.events import Event
from raiden.blockchain.state import get_channel_state
from raiden.connection_manager import ConnectionManager
from raiden.constants import EMPTY_HASH, LOCKSROOT_OF_NO_LOCKS
from raiden.messages import PFSFeeUpdate
from raiden.network.proxies.utils import get_onchain_locksroots
from raiden.services import send_pfs_update
from raiden.storage.restore import (
    get_event_with_balance_proof_by_locksroot,
    get_state_change_with_balance_proof_by_locksroot,
)
from raiden.transfer import views
from raiden.transfer.identifiers import CanonicalIdentifier
from raiden.transfer.state import (
    TokenNetworkGraphState,
    TokenNetworkState,
    TransactionChannelNewBalance,
)
from raiden.transfer.state_change import (
    ActionChannelUpdateFee,
    ContractReceiveChannelBatchUnlock,
    ContractReceiveChannelClosed,
    ContractReceiveChannelNew,
    ContractReceiveChannelNewBalance,
    ContractReceiveChannelSettled,
    ContractReceiveChannelWithdraw,
    ContractReceiveNewTokenNetwork,
    ContractReceiveRouteClosed,
    ContractReceiveRouteNew,
    ContractReceiveSecretReveal,
    ContractReceiveUpdateTransfer,
)
from raiden.utils.typing import (
    Address,
    BlockTimeout,
    ChainID,
    Optional,
    PaymentNetworkAddress,
    TokenAddress,
    Tuple,
    Union,
)
from raiden_contracts.constants import (
    EVENT_SECRET_REVEALED,
    EVENT_TOKEN_NETWORK_CREATED,
    ChannelEvent,
)

if TYPE_CHECKING:
    # pylint: disable=unused-import
    from raiden.network.blockchain_service import BlockChainService  # noqa: F401
    from raiden.raiden_service import RaidenService  # noqa: F401
    from raiden.storage.sqlite import SerializedSQLiteStorage  # noqa: F401
    from raiden.transfer.state import ChainState  # noqa: F401
    from raiden.transfer.mediated_transfer.mediation_fee import FeeScheduleState  # noqa: F401


log = structlog.get_logger(__name__)


def create_new_tokennetwork_state_change(event: Event) -> ContractReceiveNewTokenNetwork:
    data = event.event_data
    args = data["args"]
    block_number = data["block_number"]
    token_network_address = args["token_network_address"]
    token_address = TokenAddress(args["token_address"])
    block_hash = data["block_hash"]

    token_network_graph_state = TokenNetworkGraphState(token_network_address)
    token_network_state = TokenNetworkState(
        address=token_network_address,
        token_address=token_address,
        network_graph=token_network_graph_state,
    )

    transaction_hash = event.event_data["transaction_hash"]

    return ContractReceiveNewTokenNetwork(
        transaction_hash=transaction_hash,
        payment_network_address=event.originating_contract,
        token_network=token_network_state,
        block_number=block_number,
        block_hash=block_hash,
    )


def handle_tokennetwork_new(raiden: "RaidenService", event: Event):  # pragma: no unittest
    """ Handles a `TokenNetworkCreated` event. """
    data = event.event_data
    block_number = data["block_number"]
    token_network_address = data["args"]["token_network_address"]

    token_network_proxy = raiden.chain.token_network(token_network_address)
    raiden.blockchain_events.add_token_network_listener(
        token_network_proxy=token_network_proxy,
        contract_manager=raiden.contract_manager,
        from_block=block_number,
    )

    new_token_network = create_new_tokennetwork_state_change(event)
    raiden.handle_and_track_state_changes([new_token_network])


def create_channel_new_state_change(
    chain: "BlockChainService",
    chain_id: ChainID,
    our_address: Address,
    payment_network_address: PaymentNetworkAddress,
    reveal_timeout: BlockTimeout,
    fee_schedule: "FeeScheduleState",
    event: Event,
) -> Tuple[
    Union[ContractReceiveChannelNew, ContractReceiveRouteNew],
    Optional[Address],
    Optional[PFSFeeUpdate],
]:
    state_change: Union[ContractReceiveChannelNew, ContractReceiveRouteNew]

    data = event.event_data
    block_number = data["block_number"]
    block_hash = data["block_hash"]
    args = data["args"]
    token_network_address = event.originating_contract
    transaction_hash = event.event_data["transaction_hash"]
    channel_identifier = args["channel_identifier"]
    participant1 = args["participant1"]
    participant2 = args["participant2"]
    is_participant = our_address in (participant1, participant2)

    to_health_check = None
    fee_update = None

    # Raiden node is participant
    if is_participant:
        channel_proxy = chain.payment_channel(
            canonical_identifier=CanonicalIdentifier(
                chain_identifier=chain_id,
                token_network_address=token_network_address,
                channel_identifier=channel_identifier,
            )
        )
        token_address = channel_proxy.token_address()
        channel_state = get_channel_state(
            token_address=TokenAddress(token_address),
            payment_network_address=payment_network_address,
            token_network_address=token_network_address,
            reveal_timeout=reveal_timeout,
            payment_channel_proxy=channel_proxy,
            opened_block_number=block_number,
            fee_schedule=fee_schedule,
        )

        state_change = ContractReceiveChannelNew(
            transaction_hash=transaction_hash,
            channel_state=channel_state,
            block_number=block_number,
            block_hash=block_hash,
        )

        update_fee_statechange = ActionChannelUpdateFee(
            canonical_identifier=channel_state.canonical_identifier,
            flat_fee=channel_state.fee_schedule.flat,
            proportional_fee=channel_state.fee_schedule.proportional,
            use_imbalance_penalty=(channel_state.fee_schedule.imbalance_penalty is not None),
        )
        raiden.handle_and_track_state_change(update_fee_statechange)

        # Update PFS about changed fees for this channel
        send_pfs_update(
            raiden=raiden,
            canonical_identifier=channel_state.canonical_identifier,
            update_fee_schedule=True,
        )

        # pylint: disable=E1101
        partner_address = channel_state.partner_state.address

        if ConnectionManager.BOOTSTRAP_ADDR != partner_address:
            to_health_check = partner_address

        # Tell PFS about fees for this channel, when not in private mode
        fee_update = PFSFeeUpdate.from_channel_state(channel_state)

    # Raiden node is not participant of channel
    else:
        state_change = ContractReceiveRouteNew(
            transaction_hash=transaction_hash,
            canonical_identifier=CanonicalIdentifier(
                chain_identifier=chain_id,
                token_network_address=token_network_address,
                channel_identifier=channel_identifier,
            ),
            participant1=participant1,
            participant2=participant2,
            block_number=block_number,
            block_hash=block_hash,
        )

    return state_change, to_health_check, fee_update


def handle_channel_new(raiden: "RaidenService", event: Event):  # pragma: no unittest
    new_channel_or_route, to_health_check, fee_update = create_channel_new_state_change(
        chain=raiden.chain,
        chain_id=(views.state_from_raiden(raiden).chain_id),
        our_address=raiden.address,
        payment_network_address=raiden.default_registry.address,
        reveal_timeout=raiden.config["reveal_timeout"],
        fee_schedule=replace(raiden.config["default_fee_schedule"]),
        event=event,
    )

    raiden.handle_and_track_state_changes([new_channel_or_route])

    if to_health_check:
        raiden.start_health_check_for(to_health_check)

    if fee_update is not None and raiden.routing_mode != RoutingMode.PRIVATE:
        fee_update.sign(raiden.signer)
        # Appends message to queue, so it's not blocking
        raiden.transport.send_global(PATH_FINDING_BROADCASTING_ROOM, fee_update)

    # A new channel is available, run the connection manager in case more
    # connections are needed
    token_network_address = event.originating_contract
    connection_manager = raiden.connection_manager_for_token_network(token_network_address)
    retry_connect = gevent.spawn(connection_manager.retry_connect)
    raiden.add_pending_greenlet(retry_connect)


def create_new_balance_state_change(
    chain_state: "ChainState", event: Event
) -> Tuple[Optional[ContractReceiveChannelNewBalance], bool]:
    data = event.event_data
    args = data["args"]
    block_number = data["block_number"]
    block_hash = data["block_hash"]
    channel_identifier = args["channel_identifier"]
    token_network_address = event.originating_contract
    participant_address = args["participant"]
    total_deposit = args["total_deposit"]
    transaction_hash = data["transaction_hash"]

    previous_channel_state = views.get_channelstate_by_canonical_identifier(
        chain_state=chain_state,
        canonical_identifier=CanonicalIdentifier(
            chain_identifier=chain_state.chain_id,
            token_network_address=token_network_address,
            channel_identifier=channel_identifier,
        ),
    )

    # Channels will only be registered if this node is a participant
    if previous_channel_state is None:
        return None, False

    previous_balance = previous_channel_state.our_state.contract_balance
    balance_was_zero = previous_balance == 0

    deposit_transaction = TransactionChannelNewBalance(
        participant_address, total_deposit, block_number
    )

    state_change = ContractReceiveChannelNewBalance(
        transaction_hash=transaction_hash,
        canonical_identifier=previous_channel_state.canonical_identifier,
        deposit_transaction=deposit_transaction,
        block_number=block_number,
        block_hash=block_hash,
    )

    return state_change, balance_was_zero


def handle_channel_new_balance(raiden: "RaidenService", event: Event):  # pragma: no unittest
    channel_new_balance, balance_was_zero = create_new_balance_state_change(
        chain_state=views.state_from_raiden(raiden), event=event
    )

    if channel_new_balance:
        raiden.handle_and_track_state_changes([channel_new_balance])

        args = event.event_data["args"]
        token_network_address = event.originating_contract
        participant_address = args["participant"]
        total_deposit = args["total_deposit"]

        update_fee_statechange = ActionChannelUpdateFee(
            canonical_identifier=previous_channel_state.canonical_identifier,
            flat_fee=previous_channel_state.fee_schedule.flat,
            proportional_fee=previous_channel_state.fee_schedule.proportional,
            use_imbalance_penalty=(
                previous_channel_state.fee_schedule.imbalance_penalty is not None
            ),
        )
        raiden.handle_and_track_state_change(update_fee_statechange)

        # Update PFS about changed fees for this channel
        send_pfs_update(
            raiden=raiden,
            canonical_identifier=previous_channel_state.canonical_identifier,
            update_fee_schedule=True,
        )

        if balance_was_zero and participant_address != raiden.address:
            connection_manager = raiden.connection_manager_for_token_network(token_network_address)

            join_channel = gevent.spawn(
                connection_manager.join_channel, participant_address, total_deposit
            )

            raiden.add_pending_greenlet(join_channel)


def handle_channel_withdraw(raiden: "RaidenService", event: Event):
    data = event.event_data
    args = data["args"]
    block_number = data["block_number"]
    block_hash = data["block_hash"]
    channel_identifier = args["channel_identifier"]
    token_network_address = event.originating_contract
    participant = args["participant"]
    total_withdraw = args["total_withdraw"]
    transaction_hash = data["transaction_hash"]

    chain_state = views.state_from_raiden(raiden)
    canonical_identifier = CanonicalIdentifier(
        chain_identifier=chain_state.chain_id,
        token_network_address=token_network_address,
        channel_identifier=channel_identifier,
    )
    previous_channel_state = views.get_channelstate_by_canonical_identifier(
        chain_state=chain_state, canonical_identifier=canonical_identifier
    )

    # Channels will only be registered if this node is a participant
    if previous_channel_state is not None:
        channel_withdraw = ContractReceiveChannelWithdraw(
            transaction_hash=transaction_hash,
            canonical_identifier=canonical_identifier,
            total_withdraw=total_withdraw,
            participant=participant,
            block_number=block_number,
            block_hash=block_hash,
        )
        raiden.handle_and_track_state_changes([channel_withdraw])

        update_fee_statechange = ActionChannelUpdateFee(
            canonical_identifier=previous_channel_state.canonical_identifier,
            flat_fee=previous_channel_state.fee_schedule.flat,
            proportional_fee=previous_channel_state.fee_schedule.proportional,
            use_imbalance_penalty=(
                previous_channel_state.fee_schedule.imbalance_penalty is not None
            ),
        )
        raiden.handle_and_track_state_change(update_fee_statechange)

        # Update PFS about changed fees for this channel
        send_pfs_update(
            raiden=raiden,
            canonical_identifier=previous_channel_state.canonical_identifier,
            update_fee_schedule=True,
        )


def create_channel_closed_state_change(
    chain_state: "ChainState", event: Event
) -> Union[ContractReceiveChannelClosed, ContractReceiveRouteClosed]:
    token_network_address = event.originating_contract
    data = event.event_data
    block_number = data["block_number"]
    args = data["args"]
    channel_identifier = args["channel_identifier"]
    transaction_hash = data["transaction_hash"]
    block_hash = data["block_hash"]
    channel_state = views.get_channelstate_by_canonical_identifier(
        chain_state=chain_state,
        canonical_identifier=CanonicalIdentifier(
            chain_identifier=chain_state.chain_id,
            token_network_address=token_network_address,
            channel_identifier=channel_identifier,
        ),
    )

    if channel_state:
        # The from address is included in the ChannelClosed event as the
        # closing_participant field
        return ContractReceiveChannelClosed(
            transaction_hash=transaction_hash,
            transaction_from=args["closing_participant"],
            canonical_identifier=channel_state.canonical_identifier,
            block_number=block_number,
            block_hash=block_hash,
        )
    else:
        # This is a channel close event of a channel we're not a participant of
        return ContractReceiveRouteClosed(
            transaction_hash=transaction_hash,
            canonical_identifier=CanonicalIdentifier(
                chain_identifier=chain_state.chain_id,
                token_network_address=token_network_address,
                channel_identifier=channel_identifier,
            ),
            block_number=block_number,
            block_hash=block_hash,
        )


def handle_channel_closed(raiden: "RaidenService", event: Event):  # pragma: no unittest
    channel_or_route_closed = create_channel_closed_state_change(
        chain_state=views.state_from_raiden(raiden), event=event
    )
    raiden.handle_and_track_state_changes([channel_or_route_closed])


def create_update_transfer_state_change(
    chain_state: "ChainState", event: Event
) -> Optional[ContractReceiveUpdateTransfer]:
    token_network_address = event.originating_contract
    data = event.event_data
    args = data["args"]
    channel_identifier = args["channel_identifier"]
    transaction_hash = data["transaction_hash"]
    block_number = data["block_number"]
    block_hash = data["block_hash"]

    channel_state = views.get_channelstate_by_canonical_identifier(
        chain_state=chain_state,
        canonical_identifier=CanonicalIdentifier(
            chain_identifier=chain_state.chain_id,
            token_network_address=token_network_address,
            channel_identifier=channel_identifier,
        ),
    )

    if channel_state:
        return ContractReceiveUpdateTransfer(
            transaction_hash=transaction_hash,
            canonical_identifier=channel_state.canonical_identifier,
            nonce=args["nonce"],
            block_number=block_number,
            block_hash=block_hash,
        )

    return None


def handle_channel_update_transfer(raiden: "RaidenService", event: Event):  # pragma: no unittest
    update_transfer = create_update_transfer_state_change(
        chain_state=views.state_from_raiden(raiden), event=event
    )

    if update_transfer:
        raiden.handle_and_track_state_changes([update_transfer])


def handle_channel_settled(raiden: "RaidenService", event: Event):  # pragma: no unittest
    data = event.event_data
    token_network_address = event.originating_contract
    channel_identifier = data["args"]["channel_identifier"]
    block_number = data["block_number"]
    block_hash = data["block_hash"]
    transaction_hash = data["transaction_hash"]

    chain_state = views.state_from_raiden(raiden)
    channel_state = views.get_channelstate_by_canonical_identifier(
        chain_state=chain_state,
        canonical_identifier=CanonicalIdentifier(
            chain_identifier=chain_state.chain_id,
            token_network_address=token_network_address,
            channel_identifier=channel_identifier,
        ),
    )

    # This may happen for two reasons:
    # - This node is not a participant for the given channel (normal operation,
    #   the event should be ignored).
    # - Something went wrong in our code and the channel state was cleared
    #   before settle (a bug, this should raise an exception on development
    #   mode).
    # Because we cannot distinguish the two cases, assume the channel is not of
    # interest and ignore the event.
    if not channel_state:
        return

    # Recover the locksroot from the blockchain to fix data races. Check
    # get_onchain_locksroots for details.
    try:
        # First try to query the unblinded state. This way the
        # ContractReceiveChannelSettled's locksroots will  match the values
        # provided during settle.
        our_locksroot, partner_locksroot = get_onchain_locksroots(
            chain=raiden.chain,
            canonical_identifier=channel_state.canonical_identifier,
            participant1=channel_state.our_state.address,
            participant2=channel_state.partner_state.address,
            block_identifier=block_hash,
        )
    except ValueError:
        # State pruning handling. The block which generate the ChannelSettled
        # event may have been pruned, because of this the RPC call will raises
        # a ValueError.
        #
        # The solution is to query the channel's state from the latest block,
        # this /may/ create a ContractReceiveChannelSettled with the wrong
        # locksroot (i.e. not the locksroot used during the call to settle).
        # However this is fine, because at this point the channel is settled,
        # it is known that the locksroot can not be reverted without an unlock,
        # and because the unlocks are fare it doesn't matter who called it,
        # only if there are tokens locked in the settled channel.
        our_locksroot, partner_locksroot = get_onchain_locksroots(
            chain=raiden.chain,
            canonical_identifier=channel_state.canonical_identifier,
            participant1=channel_state.our_state.address,
            participant2=channel_state.partner_state.address,
            block_identifier="latest",
        )

    # For saving gas, LOCKSROOT_OF_NO_LOCKS is stored as EMPTY_HASH onchain
    if our_locksroot == EMPTY_HASH:
        our_locksroot = LOCKSROOT_OF_NO_LOCKS
    if partner_locksroot == EMPTY_HASH:
        partner_locksroot = LOCKSROOT_OF_NO_LOCKS

    channel_settled = ContractReceiveChannelSettled(
        transaction_hash=transaction_hash,
        canonical_identifier=channel_state.canonical_identifier,
        our_onchain_locksroot=our_locksroot,
        partner_onchain_locksroot=partner_locksroot,
        block_number=block_number,
        block_hash=block_hash,
    )
    raiden.handle_and_track_state_changes([channel_settled])


def create_batch_unlock_state_change(
    chain_state: "ChainState",
    our_address: Address,
    storage: "SerializedSQLiteStorage",
    event: Event,
) -> Optional[ContractReceiveChannelBatchUnlock]:
    token_network_address = event.originating_contract
    data = event.event_data
    args = data["args"]
    block_number = data["block_number"]
    block_hash = data["block_hash"]
    transaction_hash = data["transaction_hash"]
    participant1 = args["receiver"]
    participant2 = args["sender"]
    locksroot = args["locksroot"]

    token_network_state = views.get_token_network_by_address(chain_state, token_network_address)
    assert token_network_state is not None

    if participant1 == our_address:
        partner = participant2
    elif participant2 == our_address:
        partner = participant1
    else:
        log.debug(
            "Discarding unlock event, we're not part of it",
            participant1=to_checksum_address(participant1),
            participant2=to_checksum_address(participant2),
        )
        return None

    channel_identifiers = token_network_state.partneraddresses_to_channelidentifiers[partner]
    canonical_identifier = None

    for channel_identifier in channel_identifiers:
        if partner == args["sender"]:
            state_change_record = get_state_change_with_balance_proof_by_locksroot(
                storage=storage,
                canonical_identifier=CanonicalIdentifier(
                    chain_identifier=chain_state.chain_id,
                    token_network_address=token_network_address,
                    channel_identifier=channel_identifier,
                ),
                locksroot=locksroot,
                sender=partner,
            )
            if state_change_record is not None:
                canonical_identifier = (
                    state_change_record.data.balance_proof.canonical_identifier  # type: ignore
                )
                break
        elif partner == args["receiver"]:
            event_record = get_event_with_balance_proof_by_locksroot(
                storage=storage,
                canonical_identifier=CanonicalIdentifier(
                    chain_identifier=chain_state.chain_id,
                    token_network_address=token_network_address,
                    channel_identifier=channel_identifier,
                ),
                locksroot=locksroot,
                recipient=partner,
            )
            if event_record is not None:
                canonical_identifier = (
                    event_record.data.balance_proof.canonical_identifier  # type: ignore
                )
                break

    msg = (
        f"Can not resolve channel_id for unlock with locksroot {to_hex(locksroot)} and "
        f"partner {to_checksum_address(partner)}."
    )
    assert canonical_identifier is not None, msg

    return ContractReceiveChannelBatchUnlock(
        transaction_hash=transaction_hash,
        canonical_identifier=canonical_identifier,
        receiver=args["receiver"],
        sender=args["sender"],
        locksroot=args["locksroot"],
        unlocked_amount=args["unlocked_amount"],
        returned_tokens=args["returned_tokens"],
        block_number=block_number,
        block_hash=block_hash,
    )


def handle_channel_batch_unlock(raiden: "RaidenService", event: Event):  # pragma: no unittest
    assert raiden.wal, "The Raiden Service must be initialize to handle events"

    state_change = create_batch_unlock_state_change(
        chain_state=views.state_from_raiden(raiden),
        our_address=raiden.address,
        storage=raiden.wal.storage,
        event=event,
    )

    if state_change:
        raiden.handle_and_track_state_changes([state_change])


def handle_secret_revealed(raiden: "RaidenService", event: Event):  # pragma: no unittest
    secret_registry_address = event.originating_contract
    data = event.event_data
    args = data["args"]
    block_number = data["block_number"]
    block_hash = data["block_hash"]
    transaction_hash = data["transaction_hash"]
    registeredsecret_state_change = ContractReceiveSecretReveal(
        transaction_hash=transaction_hash,
        secret_registry_address=secret_registry_address,
        secrethash=args["secrethash"],
        secret=args["secret"],
        block_number=block_number,
        block_hash=block_hash,
    )

    raiden.handle_and_track_state_changes([registeredsecret_state_change])


def on_blockchain_event(raiden: "RaidenService", event: Event):  # pragma: no unittest
    data = event.event_data
    log.debug(
        "Blockchain event",
        node=to_checksum_address(raiden.address),
        contract=to_checksum_address(event.originating_contract),
        event_data=data,
    )

    event_name = data["event"]
    if event_name == EVENT_TOKEN_NETWORK_CREATED:
        handle_tokennetwork_new(raiden, event)

    elif event_name == ChannelEvent.OPENED:
        handle_channel_new(raiden, event)

    elif event_name == ChannelEvent.DEPOSIT:
        handle_channel_new_balance(raiden, event)

    elif event_name == ChannelEvent.WITHDRAW:
        handle_channel_withdraw(raiden, event)

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
        log.error("Unknown event type", event_name=data["event"], raiden_event=event)
