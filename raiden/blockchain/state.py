"""Module for functions that load additional data necessary to instantiate the
ContractReceive* state changes, i.e. state changes for the blockchain events.

It is *very* important that every function here only fetches **confirmed** data,
otherwise the node will be susceptible to races due to reorgs. These races can
crash the client in the best case, or be an attack vector in the worst case.
Because of this, the event itself must already be confirmed.

If possible, the confirmed data should be retrieved from the same block at
which the event was emitted. However, because of state pruning this is not
always possible. If that block is pruned then the latest confirmed block must
be used.

Note that the latest confirmed block is *not necessarily* the same as the
current block number in the state machine. The current block number in the
ChainState is *a* confirmed block number, but not necessarily the latest. This
distinction is important during restarts, where the node's latest known block
is from the latest run, and is not up-to-date, this block may be pruned as
well.
"""
from dataclasses import dataclass

import structlog
from eth_utils import to_hex

from raiden.blockchain.events import DecodedEvent
from raiden.exceptions import RaidenUnrecoverableError
from raiden.storage.restore import (
    get_event_with_balance_proof_by_locksroot,
    get_state_change_with_balance_proof_by_locksroot,
)
from raiden.storage.sqlite import SerializedSQLiteStorage
from raiden.transfer import views
from raiden.transfer.identifiers import CanonicalIdentifier
from raiden.transfer.state import ChainState, NettingChannelState
from raiden.utils.formatting import to_checksum_address
from raiden.utils.typing import (
    Address,
    ChainID,
    Locksroot,
    Optional,
    TokenAddress,
    TokenAmount,
    TokenNetworkAddress,
    TokenNetworkRegistryAddress,
)

log = structlog.get_logger(__name__)


@dataclass(frozen=True)
class ChannelSettleState:
    """Recovered channel state that corresponds to the on-chain data."""

    canonical_identifier: CanonicalIdentifier
    our_transferred_amount: TokenAmount
    our_locksroot: Locksroot
    partner_transferred_amount: TokenAmount
    partner_locksroot: Locksroot


@dataclass(frozen=True)
class NewChannelDetails:
    chain_id: ChainID
    token_network_registry_address: TokenNetworkRegistryAddress
    token_address: TokenAddress
    token_network_address: TokenNetworkAddress
    our_address: Address
    partner_address: Address


def get_contractreceivechannelsettled_data_from_event(
    chain_state: ChainState,
    event: DecodedEvent,
) -> Optional[ChannelSettleState]:
    args = event.event_data["args"]
    token_network_address = TokenNetworkAddress(event.originating_contract)
    channel_identifier = args["channel_identifier"]
    participant1 = args["participant1"]
    participant2 = args["participant2"]
    locksroot_participant1 = args["participant1_locksroot"]
    amount_participant1 = args["participant1_amount"]
    locksroot_participant2 = args["participant2_locksroot"]
    amount_participant2 = args["participant2_amount"]

    canonical_identifier = CanonicalIdentifier(
        chain_identifier=chain_state.chain_id,
        token_network_address=token_network_address,
        channel_identifier=channel_identifier,
    )

    token_network_state = views.get_token_network_by_address(chain_state, token_network_address)
    msg = f"Could not find token network for address {to_checksum_address(token_network_address)}"
    assert token_network_state is not None, msg

    channel_state = views.get_channelstate_by_canonical_identifier(
        chain_state=chain_state, canonical_identifier=canonical_identifier
    )

    if not channel_state:
        return None

    if participant1 == to_checksum_address(chain_state.our_address):
        our_locksroot = locksroot_participant1
        our_amount = amount_participant1
        partner_locksroot = locksroot_participant2
        partner_amount = amount_participant2
    elif participant2 == to_checksum_address(chain_state.our_address):
        our_locksroot = locksroot_participant2
        our_amount = amount_participant2
        partner_locksroot = locksroot_participant1
        partner_amount = amount_participant1
    else:
        raise RaidenUnrecoverableError(
            "Received settle event that we're not a part of. "
            f"Settlement was between {participant1} and {participant2}",
        )

    return ChannelSettleState(
        canonical_identifier, our_amount, our_locksroot, partner_amount, partner_locksroot
    )


def get_contractreceiveupdatetransfer_data_from_event(
    chain_state: ChainState, event: DecodedEvent
) -> Optional[NettingChannelState]:
    data = event.event_data
    args = data["args"]
    channel_identifier = args["channel_identifier"]
    channel_state = views.get_channelstate_by_canonical_identifier(
        chain_state=chain_state,
        canonical_identifier=CanonicalIdentifier(
            chain_identifier=chain_state.chain_id,
            token_network_address=TokenNetworkAddress(event.originating_contract),
            channel_identifier=channel_identifier,
        ),
    )
    return channel_state


def get_contractreceivechannelbatchunlock_data_from_event(
    chain_state: ChainState, storage: SerializedSQLiteStorage, event: DecodedEvent
) -> Optional[CanonicalIdentifier]:
    token_network_address = TokenNetworkAddress(event.originating_contract)
    data = event.event_data
    args = data["args"]
    participant1 = args["receiver"]
    participant2 = args["sender"]
    locksroot = args["locksroot"]

    token_network_state = views.get_token_network_by_address(chain_state, token_network_address)
    msg = f"Could not find token network for address {to_checksum_address(token_network_address)}"
    assert token_network_state is not None, msg

    if participant1 == chain_state.our_address:
        partner = participant2
    elif participant2 == chain_state.our_address:
        partner = participant1
    else:
        log.debug("Discarding unlock event, we're not part of it")
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

    if canonical_identifier is None:
        log.warning(
            f"Can not resolve channel_id for unlock with locksroot {to_hex(locksroot)} and "
            f"partner {to_checksum_address(partner)}."
        )

    return canonical_identifier


def get_contractreceivechannelnew_data_from_event(
    chain_state: ChainState,
    event: DecodedEvent,
) -> Optional[NewChannelDetails]:
    token_network_address = TokenNetworkAddress(event.originating_contract)
    data = event.event_data
    args = data["args"]
    participant1 = args["participant1"]
    participant2 = args["participant2"]

    our_address = chain_state.our_address

    if our_address == participant1:
        partner_address = participant2
    elif our_address == participant2:
        partner_address = participant1
    else:
        # Not a channel which this node is a participant
        return None

    token_network_registry = views.get_token_network_registry_by_token_network_address(
        chain_state, token_network_address
    )
    assert token_network_registry is not None, "Token network registry missing"

    token_network = views.get_token_network_by_address(
        chain_state=chain_state, token_network_address=token_network_address
    )
    assert token_network is not None, "Token network missing"
    token_network_registry_address = token_network_registry.address
    token_address = token_network.token_address

    return NewChannelDetails(
        chain_id=event.chain_id,
        token_network_registry_address=token_network_registry_address,
        token_address=token_address,
        token_network_address=token_network_address,
        our_address=our_address,
        partner_address=partner_address,
    )


def get_contractreceivechannelclosed_data_from_event(
    chain_state: "ChainState", event: DecodedEvent
) -> Optional[CanonicalIdentifier]:
    token_network_address = TokenNetworkAddress(event.originating_contract)
    data = event.event_data
    args = data["args"]
    channel_identifier = args["channel_identifier"]

    channel_state = views.get_channelstate_by_canonical_identifier(
        chain_state=chain_state,
        canonical_identifier=CanonicalIdentifier(
            chain_identifier=chain_state.chain_id,
            token_network_address=token_network_address,
            channel_identifier=channel_identifier,
        ),
    )

    if channel_state:
        return channel_state.canonical_identifier

    return None
