"""Module to map a blockchain event to a state change.

All fuctions that map an event to a state change must be side-effect free. If
any additional data is necessary, either from the database or the blockchain
itself, an utility should be added to `raiden.blockchain.state`, and then
called by `blockchainevent_to_statechange`.
"""
from dataclasses import dataclass
from typing import TYPE_CHECKING

import structlog

from raiden.blockchain.events import DecodedEvent
from raiden.blockchain.state import (
    ChannelSettleState,
    NewChannelDetails,
    get_contractreceivechannelbatchunlock_data_from_event,
    get_contractreceivechannelclosed_data_from_event,
    get_contractreceivechannelnew_data_from_event,
    get_contractreceivechannelsettled_data_from_event,
    get_contractreceiveupdatetransfer_data_from_event,
)
from raiden.constants import EMPTY_LOCKSROOT, LOCKSROOT_OF_NO_LOCKS
from raiden.settings import MediationFeeConfig
from raiden.transfer import views
from raiden.transfer.architecture import StateChange
from raiden.transfer.identifiers import CanonicalIdentifier
from raiden.transfer.state import (
    FeeScheduleState,
    NettingChannelEndState,
    NettingChannelState,
    SuccessfulTransactionState,
    TokenNetworkGraphState,
    TokenNetworkState,
    TransactionChannelDeposit,
    TransactionExecutionStatus,
)
from raiden.transfer.state_change import (
    ContractReceiveChannelBatchUnlock,
    ContractReceiveChannelClosed,
    ContractReceiveChannelDeposit,
    ContractReceiveChannelNew,
    ContractReceiveChannelSettled,
    ContractReceiveChannelWithdraw,
    ContractReceiveNewTokenNetwork,
    ContractReceiveRouteClosed,
    ContractReceiveRouteNew,
    ContractReceiveSecretReveal,
    ContractReceiveUpdateTransfer,
)
from raiden.utils.typing import (
    BlockNumber,
    BlockTimeout,
    Dict,
    List,
    Optional,
    SecretRegistryAddress,
    TokenAddress,
    TokenNetworkAddress,
    TokenNetworkRegistryAddress,
    Tuple,
)
from raiden_contracts.constants import (
    EVENT_SECRET_REVEALED,
    EVENT_TOKEN_NETWORK_CREATED,
    ChannelEvent,
)

if TYPE_CHECKING:
    from raiden.raiden_service import RaidenService

log = structlog.get_logger(__name__)


@dataclass(frozen=True)
class ChannelConfig:
    """Configuration options for a new channel."""

    reveal_timeout: BlockTimeout
    fee_schedule: FeeScheduleState


def contractreceivenewtokennetwork_from_event(
    event: DecodedEvent,
    pendingtokenregistration: Dict[
        TokenNetworkAddress, Tuple[TokenNetworkRegistryAddress, TokenAddress]
    ],
) -> ContractReceiveNewTokenNetwork:
    data = event.event_data
    args = data["args"]

    token_network_address = args["token_network_address"]
    token_address = TokenAddress(args["token_address"])
    token_network_registry_address = TokenNetworkRegistryAddress(event.originating_contract)

    pendingtokenregistration[token_network_address] = (
        token_network_registry_address,
        token_address,
    )

    return ContractReceiveNewTokenNetwork(
        token_network_registry_address=token_network_registry_address,
        token_network=TokenNetworkState(
            address=token_network_address,
            token_address=token_address,
            network_graph=TokenNetworkGraphState(token_network_address),
        ),
        transaction_hash=event.transaction_hash,
        block_number=event.block_number,
        block_hash=event.block_hash,
    )


def contractreceiveroutenew_from_event(event: DecodedEvent) -> ContractReceiveRouteNew:
    data = event.event_data
    args = data["args"]

    return ContractReceiveRouteNew(
        canonical_identifier=CanonicalIdentifier(
            chain_identifier=event.chain_id,
            token_network_address=TokenNetworkAddress(event.originating_contract),
            channel_identifier=args["channel_identifier"],
        ),
        participant1=args["participant1"],
        participant2=args["participant2"],
        transaction_hash=event.transaction_hash,
        block_number=event.block_number,
        block_hash=event.block_hash,
    )


def contractreceivechannelnew_from_event(
    new_channel_details: NewChannelDetails, channel_config: ChannelConfig, event: DecodedEvent
) -> ContractReceiveChannelNew:
    data = event.event_data
    args = data["args"]
    settle_timeout = args["settle_timeout"]

    block_number = event.block_number
    identifier = args["channel_identifier"]
    token_network_address = TokenNetworkAddress(event.originating_contract)

    our_state = NettingChannelEndState(new_channel_details.our_address)
    partner_state = NettingChannelEndState(new_channel_details.partner_address)

    open_transaction = SuccessfulTransactionState(block_number, None)

    # If the node was offline for a long period, the channel may have been
    # closed already, if that is the case during initialization the node will
    # process the other events and update the channel's state
    close_transaction: Optional[TransactionExecutionStatus] = None
    settle_transaction: Optional[TransactionExecutionStatus] = None

    channel_state = NettingChannelState(
        canonical_identifier=CanonicalIdentifier(
            chain_identifier=new_channel_details.chain_id,
            token_network_address=token_network_address,
            channel_identifier=identifier,
        ),
        token_address=new_channel_details.token_address,
        token_network_registry_address=new_channel_details.token_network_registry_address,
        reveal_timeout=channel_config.reveal_timeout,
        settle_timeout=settle_timeout,
        fee_schedule=channel_config.fee_schedule,
        our_state=our_state,
        partner_state=partner_state,
        open_transaction=open_transaction,
        close_transaction=close_transaction,
        settle_transaction=settle_transaction,
    )

    return ContractReceiveChannelNew(
        channel_state=channel_state,
        transaction_hash=event.transaction_hash,
        block_number=block_number,
        block_hash=event.block_hash,
    )


def contractreceivechanneldeposit_from_event(
    event: DecodedEvent, fee_config: MediationFeeConfig
) -> ContractReceiveChannelDeposit:
    data = event.event_data
    args = data["args"]
    block_number = event.block_number

    return ContractReceiveChannelDeposit(
        canonical_identifier=CanonicalIdentifier(
            chain_identifier=event.chain_id,
            token_network_address=TokenNetworkAddress(event.originating_contract),
            channel_identifier=args["channel_identifier"],
        ),
        deposit_transaction=TransactionChannelDeposit(
            args["participant"], args["total_deposit"], block_number
        ),
        transaction_hash=event.transaction_hash,
        block_number=block_number,
        block_hash=event.block_hash,
        fee_config=fee_config,
    )


def contractreceivechannelwithdraw_from_event(
    event: DecodedEvent, fee_config: MediationFeeConfig
) -> ContractReceiveChannelWithdraw:
    data = event.event_data
    args = data["args"]
    channel_identifier = args["channel_identifier"]
    participant = args["participant"]
    total_withdraw = args["total_withdraw"]

    return ContractReceiveChannelWithdraw(
        canonical_identifier=CanonicalIdentifier(
            chain_identifier=event.chain_id,
            token_network_address=TokenNetworkAddress(event.originating_contract),
            channel_identifier=channel_identifier,
        ),
        total_withdraw=total_withdraw,
        participant=participant,
        transaction_hash=event.transaction_hash,
        block_number=event.block_number,
        block_hash=event.block_hash,
        fee_config=fee_config,
    )


def contractreceivechannelclosed_from_event(
    canonical_identifier: CanonicalIdentifier, event: DecodedEvent
) -> ContractReceiveChannelClosed:
    data = event.event_data
    args = data["args"]

    # The from address is included in the ChannelClosed event as the
    # closing_participant field
    # `burn_amount` is only required for the monitoring service, ignore it here
    return ContractReceiveChannelClosed(
        transaction_from=args["closing_participant"],
        canonical_identifier=canonical_identifier,
        transaction_hash=event.transaction_hash,
        block_number=event.block_number,
        block_hash=event.block_hash,
    )


def contractreceiverouteclosed_from_event(event: DecodedEvent) -> ContractReceiveRouteClosed:
    data = event.event_data
    args = data["args"]
    channel_identifier = args["channel_identifier"]

    return ContractReceiveRouteClosed(
        canonical_identifier=CanonicalIdentifier(
            chain_identifier=event.chain_id,
            token_network_address=TokenNetworkAddress(event.originating_contract),
            channel_identifier=channel_identifier,
        ),
        transaction_hash=event.transaction_hash,
        block_number=event.block_number,
        block_hash=event.block_hash,
    )


def contractreceiveupdatetransfer_from_event(
    channel_state: NettingChannelState, event: DecodedEvent
) -> ContractReceiveUpdateTransfer:
    data = event.event_data
    args = data["args"]

    # `burn_amount` is only required for the monitoring service, ignore it here
    return ContractReceiveUpdateTransfer(
        canonical_identifier=channel_state.canonical_identifier,
        nonce=args["nonce"],
        transaction_hash=event.transaction_hash,
        block_number=event.block_number,
        block_hash=event.block_hash,
    )


def contractreceivechannelsettled_from_event(
    channel_settle_state: ChannelSettleState, event: DecodedEvent
) -> ContractReceiveChannelSettled:
    data = event.event_data
    block_number = data["block_number"]
    block_hash = data["block_hash"]
    transaction_hash = data["transaction_hash"]

    # For saving gas, LOCKSROOT_OF_NO_LOCKS is stored as EMPTY_HASH onchain
    if channel_settle_state.our_locksroot == EMPTY_LOCKSROOT:
        our_locksroot = LOCKSROOT_OF_NO_LOCKS
    else:
        our_locksroot = channel_settle_state.our_locksroot

    if channel_settle_state.partner_locksroot == EMPTY_LOCKSROOT:
        partner_locksroot = LOCKSROOT_OF_NO_LOCKS
    else:
        partner_locksroot = channel_settle_state.partner_locksroot

    return ContractReceiveChannelSettled(
        transaction_hash=transaction_hash,
        canonical_identifier=channel_settle_state.canonical_identifier,
        our_onchain_locksroot=our_locksroot,
        partner_onchain_locksroot=partner_locksroot,
        block_number=block_number,
        block_hash=block_hash,
    )


def contractreceivesecretreveal_from_event(event: DecodedEvent) -> ContractReceiveSecretReveal:
    secret_registry_address = event.originating_contract
    data = event.event_data
    args = data["args"]

    return ContractReceiveSecretReveal(
        secret_registry_address=SecretRegistryAddress(secret_registry_address),
        secrethash=args["secrethash"],
        secret=args["secret"],
        transaction_hash=event.transaction_hash,
        block_number=event.block_number,
        block_hash=event.block_hash,
    )


def contractreceivechannelbatchunlock_from_event(
    canonical_identifier: CanonicalIdentifier, event: DecodedEvent
) -> ContractReceiveChannelBatchUnlock:
    data = event.event_data
    args = data["args"]

    return ContractReceiveChannelBatchUnlock(
        canonical_identifier=canonical_identifier,
        receiver=args["receiver"],
        sender=args["sender"],
        locksroot=args["locksroot"],
        unlocked_amount=args["unlocked_amount"],
        returned_tokens=args["returned_tokens"],
        transaction_hash=event.transaction_hash,
        block_number=event.block_number,
        block_hash=event.block_hash,
    )


def blockchainevent_to_statechange(
    raiden: "RaidenService",
    event: DecodedEvent,
    current_confirmed_head: BlockNumber,
    pendingtokenregistration: Dict[
        TokenNetworkAddress, Tuple[TokenNetworkRegistryAddress, TokenAddress]
    ],
) -> List[StateChange]:  # pragma: no unittest
    msg = "The state of the node has to be primed before blockchain events can be processed."
    assert raiden.wal, msg

    event_name = event.event_data["event"]
    chain_state = views.state_from_raiden(raiden)
    proxy_manager = raiden.proxy_manager

    state_changes: List[StateChange] = []

    if event_name == EVENT_TOKEN_NETWORK_CREATED:
        state_changes.append(
            contractreceivenewtokennetwork_from_event(event, pendingtokenregistration)
        )

    elif event_name == ChannelEvent.OPENED:
        new_channel_details = get_contractreceivechannelnew_data_from_event(
            chain_state=chain_state, event=event, pendingtokenregistration=pendingtokenregistration
        )

        if new_channel_details is not None:
            fee_config: MediationFeeConfig = raiden.config.mediation_fees
            channel_config = ChannelConfig(
                reveal_timeout=raiden.config.reveal_timeout,
                fee_schedule=FeeScheduleState(
                    cap_fees=fee_config.cap_meditation_fees,
                    flat=fee_config.get_flat_fee(new_channel_details.token_address),
                    proportional=fee_config.get_proportional_fee(new_channel_details.token_address)
                    # no need to set the imbalance fee here, will be set during deposit
                ),
            )
            channel_new = contractreceivechannelnew_from_event(
                new_channel_details, channel_config, event
            )
            state_changes.append(channel_new)
        else:
            state_changes.append(contractreceiveroutenew_from_event(event))

    elif event_name == ChannelEvent.DEPOSIT:
        deposit = contractreceivechanneldeposit_from_event(event, raiden.config.mediation_fees)
        state_changes.append(deposit)

    elif event_name == ChannelEvent.WITHDRAW:
        withdraw = contractreceivechannelwithdraw_from_event(event, raiden.config.mediation_fees)
        state_changes.append(withdraw)

    elif event_name == ChannelEvent.BALANCE_PROOF_UPDATED:
        channel_state = get_contractreceiveupdatetransfer_data_from_event(chain_state, event)
        if channel_state:
            state_changes.append(contractreceiveupdatetransfer_from_event(channel_state, event))

    elif event_name == ChannelEvent.CLOSED:
        canonical_identifier = get_contractreceivechannelclosed_data_from_event(chain_state, event)

        if canonical_identifier is not None:
            state_changes.append(
                contractreceivechannelclosed_from_event(canonical_identifier, event)
            )
        else:
            state_changes.append(contractreceiverouteclosed_from_event(event))

    elif event_name == ChannelEvent.SETTLED:
        channel_settle_state = get_contractreceivechannelsettled_data_from_event(
            proxy_manager=proxy_manager,
            chain_state=chain_state,
            event=event,
            current_confirmed_head=current_confirmed_head,
        )

        if channel_settle_state:
            state_changes.append(
                contractreceivechannelsettled_from_event(channel_settle_state, event)
            )
        else:
            log.debug("Discarding settle event, we're not part of it", raiden_event=event)

    elif event_name == EVENT_SECRET_REVEALED:
        state_changes.append(contractreceivesecretreveal_from_event(event))

    elif event_name == ChannelEvent.UNLOCKED:
        canonical_identifier = get_contractreceivechannelbatchunlock_data_from_event(
            chain_state, raiden.wal.storage, event
        )

        if canonical_identifier is not None:
            state_changes.append(
                contractreceivechannelbatchunlock_from_event(canonical_identifier, event)
            )
        else:
            log.debug("Discarding unlock event, we're not part of it", raiden_event=event)

    else:
        log.error("Unknown event type", raiden_event=event)

    return state_changes
