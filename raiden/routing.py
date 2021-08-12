from uuid import UUID

import structlog
from eth_utils import to_canonical_address

from raiden.exceptions import ServiceRequestFailed
from raiden.network.pathfinding import PFSProxy
from raiden.transfer import channel, views
from raiden.transfer.state import ChainState, ChannelState, RouteState
from raiden.utils.formatting import to_checksum_address
from raiden.utils.typing import (
    Address,
    AddressMetadata,
    Any,
    BlockNumber,
    Dict,
    FeeAmount,
    InitiatorAddress,
    List,
    OneToNAddress,
    Optional,
    PaymentAmount,
    PaymentWithFeeAmount,
    PrivateKey,
    TargetAddress,
    TokenNetworkAddress,
    Tuple,
)

log = structlog.get_logger(__name__)


def get_best_routes(
    chain_state: ChainState,
    token_network_address: TokenNetworkAddress,
    one_to_n_address: Optional[OneToNAddress],
    from_address: InitiatorAddress,
    to_address: TargetAddress,
    amount: PaymentAmount,
    previous_address: Optional[Address],
    privkey: PrivateKey,
    our_address_metadata: AddressMetadata,
    pfs_proxy: PFSProxy,
) -> Tuple[Optional[str], List[RouteState], Optional[UUID]]:

    token_network = views.get_token_network_by_address(chain_state, token_network_address)
    assert token_network, "The token network must be validated and exist."

    # Always use a direct channel if available:
    # - There are no race conditions and the capacity is guaranteed to be
    #   available.
    # - There will be no mediation fees
    # - The transfer will be faster
    if Address(to_address) in token_network.partneraddresses_to_channelidentifiers.keys():
        for channel_id in token_network.partneraddresses_to_channelidentifiers[
            Address(to_address)
        ]:
            channel_state = token_network.channelidentifiers_to_channels[channel_id]

            # direct channels don't have fees
            payment_with_fee_amount = PaymentWithFeeAmount(amount)
            is_usable = channel.is_channel_usable_for_new_transfer(
                channel_state, payment_with_fee_amount, None
            )

            if is_usable is channel.ChannelUsability.USABLE:
                address_to_address_metadata = {Address(from_address): our_address_metadata}
                try:
                    address_metadata = pfs_proxy.query_address_metadata(to_address)
                except ServiceRequestFailed as ex:
                    msg = f"PFS returned an error while trying to fetch user information: \n{ex}"
                    log.error(msg)
                    return msg, [], None
                else:
                    address_to_address_metadata[Address(to_address)] = address_metadata

                try:
                    direct_route = RouteState(
                        route=[Address(from_address), Address(to_address)],
                        estimated_fee=FeeAmount(0),
                        address_to_metadata=address_to_address_metadata,
                    )
                    return None, [direct_route], None
                except ValueError as ex:
                    return str(ex), [], None

    if one_to_n_address is None:
        msg = "Pathfinding Service could not be used."
        log.warning(msg)
        return msg, [], None

    # Does any channel have sufficient capacity for the payment?
    channels = [
        token_network.channelidentifiers_to_channels[channel_id]
        for channels_to_partner in token_network.partneraddresses_to_channelidentifiers.values()
        for channel_id in channels_to_partner
    ]
    for channel_state in channels:
        payment_with_fee_amount = PaymentWithFeeAmount(amount)
        is_usable = channel.is_channel_usable_for_new_transfer(
            channel_state, payment_with_fee_amount, None
        )
        if is_usable is channel.ChannelUsability.USABLE:
            break
    else:
        return "You have no suitable channel to initiate this payment.", [], None

    # Make sure that the PFS knows about the last channel we opened
    latest_channel_opened_at = 0
    for channel_state in token_network.channelidentifiers_to_channels.values():
        latest_channel_opened_at = max(
            latest_channel_opened_at, channel_state.open_transaction.finished_block_number
        )

    pfs_error_msg, pfs_routes, pfs_feedback_token = get_best_routes_pfs(
        chain_state=chain_state,
        token_network_address=token_network_address,
        one_to_n_address=one_to_n_address,
        from_address=from_address,
        to_address=to_address,
        amount=amount,
        previous_address=previous_address,
        privkey=privkey,
        pfs_wait_for_block=BlockNumber(latest_channel_opened_at),
        pfs_proxy=pfs_proxy,
    )

    if pfs_error_msg:
        log.warning(
            "Request to Pathfinding Service was not successful. "
            "No routes to the target were found.",
            pfs_message=pfs_error_msg,
        )
        return pfs_error_msg, [], None

    if not pfs_routes:
        # As of version 0.5 it is possible for the PFS to return an empty
        # list of routes without an error message.
        return "PFS could not find any routes", [], None

    log.info("Received route(s) from PFS", routes=pfs_routes, feedback_token=pfs_feedback_token)
    return pfs_error_msg, pfs_routes, pfs_feedback_token


def get_best_routes_pfs(
    chain_state: ChainState,
    token_network_address: TokenNetworkAddress,
    one_to_n_address: OneToNAddress,
    from_address: InitiatorAddress,
    to_address: TargetAddress,
    amount: PaymentAmount,
    previous_address: Optional[Address],
    privkey: PrivateKey,
    pfs_wait_for_block: BlockNumber,
    pfs_proxy: PFSProxy,
) -> Tuple[Optional[str], List[RouteState], Optional[UUID]]:
    try:
        pfs_routes, feedback_token = pfs_proxy.query_paths(
            our_address=chain_state.our_address,
            privkey=privkey,
            current_block_number=chain_state.block_number,
            token_network_address=token_network_address,
            one_to_n_address=one_to_n_address,
            chain_id=chain_state.chain_id,
            route_from=from_address,
            route_to=to_address,
            value=amount,
            pfs_wait_for_block=pfs_wait_for_block,
        )
    except ServiceRequestFailed as e:
        log_message = ("PFS: " + e.args[0]) if e.args[0] else None
        log_info = e.args[1] if len(e.args) > 1 else {}
        log.warning("An error with the path request occurred", log_message=log_message, **log_info)
        return log_message, [], None

    paths = []
    for path_object in pfs_routes:
        route_state = make_route_state(
            path_object,
            previous_address,
            chain_state,
            token_network_address,
            Address(from_address),
        )
        if route_state is not None:
            paths.append(route_state)

    return None, paths, feedback_token


def make_route_state(
    path_object: Dict[str, Any],
    previous_address: Optional[Address],
    chain_state: ChainState,
    token_network_address: TokenNetworkAddress,
    from_address: Address,
) -> Optional[RouteState]:
    path = path_object["path"]
    address_to_metadata = path_object.get("address_metadata", {})
    if not address_to_metadata:
        log.warning("PFS didn't return path metadata.")
    elif set(path) != set(address_to_metadata.keys()):
        log.warning("PFS returned incorrect path metadata, skipping path.")

    estimated_fee = path_object["estimated_fee"]
    canonical_path = [to_canonical_address(node) for node in path]

    # get the second entry, as the first one is the node itself
    # also needs to be converted to canonical representation
    if len(canonical_path) < 2:
        log.warning("Route is invalid as it has less than 2 addresses")
        return None
    partner_address = canonical_path[1]

    # don't route back
    if partner_address == previous_address:
        return None

    channel_state = views.get_channelstate_by_token_network_and_partner(
        chain_state=chain_state,
        token_network_address=token_network_address,
        partner_address=partner_address,
    )

    if not channel_state:
        return None

    # check channel state
    if channel.get_status(channel_state) != ChannelState.STATE_OPENED:
        log.info(
            "Channel is not opened, ignoring",
            from_address=to_checksum_address(from_address),
            partner_address=to_checksum_address(partner_address),
            routing_source="Pathfinding Service",
        )
        return None

    canonical_address_metadata = {
        to_canonical_address(address): metadata
        for address, metadata in address_to_metadata.items()
    }

    try:
        return RouteState(
            route=canonical_path,
            address_to_metadata=canonical_address_metadata,
            estimated_fee=estimated_fee,
        )
    except ValueError as ex:
        log.warning("Invalid metadata in route", error=str(ex))
        return None
