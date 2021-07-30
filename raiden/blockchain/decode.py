"""Module to map a blockchain event to a state change.

All functions that map an event to a state change must be side-effect free. If
any additional data is necessary, either from the database or the blockchain
itself, an utility should be added to `raiden.blockchain.state`, and then
called by `blockchainevent_to_statechange`.
"""
from dataclasses import dataclass

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
from raiden.settings import MediationFeeConfig, RaidenConfig
from raiden.storage.sqlite import SerializedSQLiteStorage
from raiden.transfer.architecture import StateChange
from raiden.transfer.identifiers import CanonicalIdentifier
from raiden.transfer.state import (
    ChainState,
    FeeScheduleState,
    NettingChannelEndState,
    NettingChannelState,
    SuccessfulTransactionState,
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
    ContractReceiveRouteNew,
    ContractReceiveSecretReveal,
    ContractReceiveUpdateTransfer,
    UpdateServicesAddressesStateChange,
)
from raiden.utils.typing import (
    Balance,
    BlockTimeout,
    Optional,
    SecretRegistryAddress,
    TokenAddress,
    TokenNetworkAddress,
    TokenNetworkRegistryAddress,
)
from raiden_contracts.constants import (
    EVENT_REGISTERED_SERVICE,
    EVENT_SECRET_REVEALED,
    EVENT_TOKEN_NETWORK_CREATED,
    ChannelEvent,
)

log = structlog.get_logger(__name__)


@dataclass(frozen=True)
class ChannelConfig:
    """Configuration options for a new channel."""

    reveal_timeout: BlockTimeout
    fee_schedule: FeeScheduleState


def contractreceivenewtokennetwork_from_event(
    event: DecodedEvent,
) -> ContractReceiveNewTokenNetwork:
    data = event.event_data
    args = data["args"]

    token_network_address = args["token_network_address"]
    token_address = TokenAddress(args["token_address"])
    token_network_registry_address = TokenNetworkRegistryAddress(event.originating_contract)

    return ContractReceiveNewTokenNetwork(
        token_network_registry_address=token_network_registry_address,
        token_network=TokenNetworkState(
            address=token_network_address,
            token_address=token_address,
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

    our_state = NettingChannelEndState(new_channel_details.our_address, Balance(0))
    partner_state = NettingChannelEndState(new_channel_details.partner_address, Balance(0))

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
    return ContractReceiveChannelClosed(
        transaction_from=args["closing_participant"],
        canonical_identifier=canonical_identifier,
        transaction_hash=event.transaction_hash,
        block_number=event.block_number,
        block_hash=event.block_hash,
    )


def contractreceiveupdatetransfer_from_event(
    channel_state: NettingChannelState, event: DecodedEvent
) -> ContractReceiveUpdateTransfer:
    data = event.event_data
    args = data["args"]

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
        our_transferred_amount=channel_settle_state.our_transferred_amount,
        partner_onchain_locksroot=partner_locksroot,
        partner_transferred_amount=channel_settle_state.partner_transferred_amount,
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


def update_service_addresses_from_event(event: DecodedEvent) -> UpdateServicesAddressesStateChange:
    data = event.event_data
    args = data["args"]

    return UpdateServicesAddressesStateChange(
        service=args["service_address"], valid_till=args["valid_till"]
    )


def blockchainevent_to_statechange(
    raiden_config: RaidenConfig,
    raiden_storage: SerializedSQLiteStorage,
    chain_state: ChainState,
    event: DecodedEvent,
) -> Optional[StateChange]:  # pragma: no unittest
    event_name = event.event_data["event"]

    if event_name == EVENT_TOKEN_NETWORK_CREATED:
        return contractreceivenewtokennetwork_from_event(event)

    elif event_name == ChannelEvent.OPENED:
        new_channel_details = get_contractreceivechannelnew_data_from_event(chain_state, event)

        if new_channel_details is not None:
            fee_config = raiden_config.mediation_fees
            channel_config = ChannelConfig(
                reveal_timeout=raiden_config.reveal_timeout,
                fee_schedule=FeeScheduleState(
                    cap_fees=fee_config.cap_meditation_fees,
                    flat=fee_config.get_flat_fee(new_channel_details.token_address),
                    proportional=fee_config.get_proportional_fee(new_channel_details.token_address)
                    # no need to set the imbalance fee here, will be set during deposit
                ),
            )
            return contractreceivechannelnew_from_event(new_channel_details, channel_config, event)
        else:
            return contractreceiveroutenew_from_event(event)

    elif event_name == ChannelEvent.DEPOSIT:
        return contractreceivechanneldeposit_from_event(event, raiden_config.mediation_fees)

    elif event_name == ChannelEvent.WITHDRAW:
        return contractreceivechannelwithdraw_from_event(event, raiden_config.mediation_fees)

    elif event_name == ChannelEvent.BALANCE_PROOF_UPDATED:
        channel_state = get_contractreceiveupdatetransfer_data_from_event(chain_state, event)
        if channel_state:
            return contractreceiveupdatetransfer_from_event(channel_state, event)

    elif event_name == ChannelEvent.CLOSED:
        canonical_identifier = get_contractreceivechannelclosed_data_from_event(chain_state, event)

        if canonical_identifier is not None:
            return contractreceivechannelclosed_from_event(canonical_identifier, event)

    elif event_name == ChannelEvent.SETTLED:
        channel_settle_state = get_contractreceivechannelsettled_data_from_event(
            chain_state=chain_state,
            event=event,
        )

        if channel_settle_state:
            return contractreceivechannelsettled_from_event(channel_settle_state, event)
        else:
            log.debug("Discarding settle event, we're not part of it", raiden_event=event)

    elif event_name == EVENT_SECRET_REVEALED:
        return contractreceivesecretreveal_from_event(event)

    elif event_name == ChannelEvent.UNLOCKED:
        canonical_identifier = get_contractreceivechannelbatchunlock_data_from_event(
            chain_state, raiden_storage, event
        )

        if canonical_identifier is not None:
            return contractreceivechannelbatchunlock_from_event(canonical_identifier, event)

    elif event_name == EVENT_REGISTERED_SERVICE:
        return update_service_addresses_from_event(event)

    else:
        log.error("Unknown event type", raiden_event=event)

    return None
