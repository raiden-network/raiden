from heapq import heappop, heappush
from uuid import UUID

import networkx
import structlog
from eth_utils import to_canonical_address

from raiden.exceptions import ServiceRequestFailed
from raiden.messages.metadata import RouteMetadata
from raiden.network.pathfinding import PFSConfig, query_paths
from raiden.settings import INTERNAL_ROUTING_DEFAULT_FEE_PERC
from raiden.transfer import channel, views
from raiden.transfer.state import ChainState, ChannelState, NetworkState, RouteState
from raiden.utils.formatting import to_checksum_address
from raiden.utils.typing import (
    Address,
    BlockNumber,
    ChannelID,
    FeeAmount,
    InitiatorAddress,
    List,
    NamedTuple,
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
    pfs_config: Optional[PFSConfig],
    privkey: PrivateKey,
) -> Tuple[Optional[str], List[RouteState], Optional[UUID]]:

    token_network = views.get_token_network_by_address(chain_state, token_network_address)
    assert token_network, "The token network must be validated and exist."

    try:
        # networkx returns a generator, consume the result since it will be
        # iterated over multiple times.
        all_neighbors = list(
            networkx.all_neighbors(token_network.network_graph.network, from_address)
        )
    except networkx.NetworkXError:
        # If `our_address` is not in the graph, no channels opened with the
        # address.
        log.debug(
            "Node does not have a channel in the requested token network.",
            source=to_checksum_address(from_address),
            target=to_checksum_address(to_address),
            amount=amount,
        )
        return ("Node does not have a channel in the requested token network.", list(), None)

    error_closed = 0
    error_no_route = 0
    error_no_capacity = 0
    error_not_online = 0
    error_direct = None
    shortest_routes: List[Neighbour] = list()

    # Always use a direct channel if available:
    # - There are no race conditions and the capacity is guaranteed to be
    #   available.
    # - There will be no mediation fees
    # - The transfer will be faster
    if to_address in all_neighbors:
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
                direct_route = RouteState(
                    route=[Address(from_address), Address(to_address)],
                    forward_channel_id=channel_state.canonical_identifier.channel_identifier,
                    estimated_fee=FeeAmount(0),
                )
                return (None, [direct_route], None)

            error_direct = is_usable

    latest_channel_opened_at = BlockNumber(0)
    for partner_address in all_neighbors:
        for channel_id in token_network.partneraddresses_to_channelidentifiers[partner_address]:
            channel_state = token_network.channelidentifiers_to_channels[channel_id]

            if channel.get_status(channel_state) != ChannelState.STATE_OPENED:
                error_closed += 1
                continue

            latest_channel_opened_at = max(
                latest_channel_opened_at, channel_state.open_transaction.finished_block_number
            )

            try:
                route = networkx.shortest_path(  # pylint: disable=E1121
                    token_network.network_graph.network, partner_address, to_address
                )
            except (networkx.NetworkXNoPath, networkx.NodeNotFound):
                error_no_route += 1
            else:
                distributable = channel.get_distributable(
                    channel_state.our_state, channel_state.partner_state
                )

                network_status = views.get_node_network_status(
                    chain_state, channel_state.partner_state.address
                )

                if distributable < amount:
                    error_no_capacity += 1
                elif network_status != NetworkState.REACHABLE:
                    error_not_online += 1
                else:
                    nonrefundable = amount > channel.get_distributable(
                        channel_state.partner_state, channel_state.our_state
                    )

                    # The complete route includes the initiator, add it to the beginning
                    complete_route = [Address(from_address)] + route
                    neighbour = Neighbour(
                        length=len(route),
                        nonrefundable=nonrefundable,
                        partner_address=partner_address,
                        channelid=channel_state.identifier,
                        route=complete_route,
                    )
                    heappush(shortest_routes, neighbour)

    if not shortest_routes:
        qty_channels = sum(
            len(token_network.partneraddresses_to_channelidentifiers[partner_address])
            for partner_address in all_neighbors
        )
        error_msg = (
            f"None of the existing channels could be used to complete the "
            f"transfer. From the {qty_channels} existing channels. "
            f"{error_closed} are closed. {error_not_online} are not online. "
            f"{error_no_route} don't have a route to the target in the given "
            f"token network. {error_no_capacity} don't have enough capacity for "
            f"the requested transfer."
        )
        if error_direct is not None:
            error_msg += f"direct channel {error_direct}."

        log.warning(
            "None of the existing channels could be used to complete the transfer",
            from_address=to_checksum_address(from_address),
            to_address=to_checksum_address(to_address),
            error_closed=error_closed,
            error_no_route=error_no_route,
            error_no_capacity=error_no_capacity,
            error_direct=error_direct,
            error_not_online=error_not_online,
        )
        return (error_msg, list(), None)

    if pfs_config is not None and one_to_n_address is not None:
        pfs_error_msg, pfs_routes, pfs_feedback_token = get_best_routes_pfs(
            chain_state=chain_state,
            token_network_address=token_network_address,
            one_to_n_address=one_to_n_address,
            from_address=from_address,
            to_address=to_address,
            amount=amount,
            previous_address=previous_address,
            pfs_config=pfs_config,
            privkey=privkey,
            pfs_wait_for_block=latest_channel_opened_at,
        )

        if not pfs_error_msg:
            # As of version 0.5 it is possible for the PFS to return an empty
            # list of routes without an error message.
            if not pfs_routes:
                return ("PFS could not find any routes", list(), None)

            log.info(
                "Received route(s) from PFS", routes=pfs_routes, feedback_token=pfs_feedback_token
            )
            return (pfs_error_msg, pfs_routes, pfs_feedback_token)

        log.warning(
            "Request to Pathfinding Service was not successful. "
            "No routes to the target are found.",
            pfs_message=pfs_error_msg,
        )
        return (pfs_error_msg, list(), None)

    else:
        available_routes = list()

        while shortest_routes:
            neighbour = heappop(shortest_routes)

            # https://github.com/raiden-network/raiden/issues/4751
            # Internal routing doesn't know how much fees the initiator will be charged,
            # so it should set a percentage on top of the original amount
            # for the whole route.
            estimated_fee = FeeAmount(round(INTERNAL_ROUTING_DEFAULT_FEE_PERC * amount))
            if neighbour.length == 1:  # Target is our direct neighbour, pay no fees.
                estimated_fee = FeeAmount(0)

            available_routes.append(
                RouteState(
                    route=neighbour.route,
                    forward_channel_id=neighbour.channelid,
                    estimated_fee=estimated_fee,
                )
            )

        return (None, available_routes, None)


class Neighbour(NamedTuple):
    length: int  # first item used for ordering
    nonrefundable: bool
    partner_address: Address
    channelid: ChannelID
    route: List[Address]


def get_best_routes_pfs(
    chain_state: ChainState,
    token_network_address: TokenNetworkAddress,
    one_to_n_address: OneToNAddress,
    from_address: InitiatorAddress,
    to_address: TargetAddress,
    amount: PaymentAmount,
    previous_address: Optional[Address],
    pfs_config: PFSConfig,
    privkey: PrivateKey,
    pfs_wait_for_block: BlockNumber,
) -> Tuple[Optional[str], List[RouteState], Optional[UUID]]:
    try:
        pfs_routes, feedback_token = query_paths(
            pfs_config=pfs_config,
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
        path = path_object["path"]
        estimated_fee = path_object["estimated_fee"]
        canonical_path = [to_canonical_address(node) for node in path]

        # get the second entry, as the first one is the node itself
        # also needs to be converted to canonical representation
        partner_address = canonical_path[1]

        # don't route back
        if partner_address == previous_address:
            continue

        channel_state = views.get_channelstate_by_token_network_and_partner(
            chain_state=chain_state,
            token_network_address=token_network_address,
            partner_address=partner_address,
        )

        if not channel_state:
            continue

        # check channel state
        if channel.get_status(channel_state) != ChannelState.STATE_OPENED:
            log.info(
                "Channel is not opened, ignoring",
                from_address=to_checksum_address(from_address),
                partner_address=to_checksum_address(partner_address),
                routing_source="Pathfinding Service",
            )
            continue

        paths.append(
            RouteState(
                route=canonical_path,
                forward_channel_id=channel_state.identifier,
                estimated_fee=estimated_fee,
            )
        )

    return None, paths, feedback_token


def resolve_routes(
    routes: List[RouteMetadata],
    token_network_address: TokenNetworkAddress,
    chain_state: ChainState,
) -> List[RouteState]:
    """ resolve the forward_channel_id for a given route """

    resolvable = []
    for route_metadata in routes:
        if len(route_metadata.route) < 2:
            continue

        channel_state = views.get_channelstate_by_token_network_and_partner(
            chain_state=chain_state,
            token_network_address=token_network_address,
            partner_address=route_metadata.route[1],
        )

        if channel_state is not None:
            resolvable.append(
                RouteState(
                    route=route_metadata.route,
                    forward_channel_id=channel_state.canonical_identifier.channel_identifier,
                    # This is only used in the mediator, so fees are set to 0
                    estimated_fee=FeeAmount(0),
                )
            )
    return resolvable
