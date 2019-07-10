from heapq import heappop, heappush
from typing import Any, Dict, List, Tuple
from uuid import UUID

import networkx
import structlog
from eth_utils import to_canonical_address, to_checksum_address

from raiden.exceptions import ServiceRequestFailed
from raiden.messages.metadata import RouteMetadata
from raiden.network.pathfinding import PFSConfig, query_paths
from raiden.transfer import channel, views
from raiden.transfer.state import ChainState, ChannelState, RouteState
from raiden.utils.typing import (
    Address,
    ChannelID,
    InitiatorAddress,
    NamedTuple,
    Optional,
    PaymentAmount,
    TargetAddress,
    TokenNetworkAddress,
)

log = structlog.get_logger(__name__)


def get_best_routes(
    chain_state: ChainState,
    token_network_address: TokenNetworkAddress,
    one_to_n_address: Optional[Address],
    from_address: InitiatorAddress,
    to_address: TargetAddress,
    amount: PaymentAmount,
    previous_address: Optional[Address],
    config: Dict[str, Any],
    privkey: bytes,
) -> Tuple[List[RouteState], Optional[UUID]]:
    pfs_config = config.get("pfs_config", None)

    is_direct_partner = to_address in views.all_neighbour_nodes(chain_state)
    can_use_pfs = pfs_config and one_to_n_address is not None

    log.debug(
        "Getting route for payment",
        source=to_checksum_address(from_address),
        target=to_checksum_address(to_address),
        amount=amount,
        target_is_direct_partner=is_direct_partner,
        can_use_pfs=can_use_pfs,
    )

    # the pfs should not be requested when the target is linked via a direct channel
    if is_direct_partner:
        internal_routes = get_best_routes_internal(
            chain_state=chain_state,
            token_network_address=token_network_address,
            from_address=from_address,
            to_address=to_address,
            amount=amount,
            previous_address=previous_address,
        )
        channel_state = views.get_channelstate_by_token_network_and_partner(
            chain_state=chain_state,
            token_network_address=token_network_address,
            partner_address=Address(to_address),
        )

        for route_state in internal_routes:
            if to_address == route_state.next_hop_address and (
                channel_state
                # other conditions about e.g. channel state are checked in best routes internal
                and channel.get_distributable(
                    sender=channel_state.our_state, receiver=channel_state.partner_state
                )
                >= amount
            ):
                return [route_state], None

    if can_use_pfs:
        assert one_to_n_address  # mypy doesn't realize this has been checked above
        pfs_answer_ok, pfs_routes, pfs_feedback_token = get_best_routes_pfs(
            chain_state=chain_state,
            token_network_address=token_network_address,
            one_to_n_address=one_to_n_address,
            from_address=from_address,
            to_address=to_address,
            amount=amount,
            previous_address=previous_address,
            pfs_config=pfs_config,
            privkey=privkey,
        )

        if pfs_answer_ok:
            log.info(
                "Received route(s) from PFS", routes=pfs_routes, feedback_token=pfs_feedback_token
            )
            return pfs_routes, pfs_feedback_token
        else:
            log.warning(
                "Request to Pathfinding Service was not successful, "
                "falling back to internal routing."
            )

    return (
        get_best_routes_internal(
            chain_state=chain_state,
            token_network_address=token_network_address,
            from_address=from_address,
            to_address=to_address,
            amount=amount,
            previous_address=previous_address,
        ),
        None,
    )


class Neighbour(NamedTuple):
    length: int  # first item used for ordering
    nonrefundable: bool
    partner_address: Address
    channelid: ChannelID
    route: List[Address]


def get_best_routes_internal(
    chain_state: ChainState,
    token_network_address: TokenNetworkAddress,
    from_address: InitiatorAddress,
    to_address: TargetAddress,
    amount: int,
    previous_address: Optional[Address],
) -> List[RouteState]:
    """ Returns a list of channels that can be used to make a transfer.

    This will filter out channels that are not open and don't have enough
    capacity.
    """
    # TODO: Route ranking.
    # Rate each route to optimize the fee price/quality of each route and add a
    # rate from in the range [0.0,1.0].

    available_routes = list()

    token_network = views.get_token_network_by_address(chain_state, token_network_address)

    if not token_network:
        return list()

    neighbors_heap: List[Neighbour] = list()
    try:
        all_neighbors = networkx.all_neighbors(token_network.network_graph.network, from_address)
    except networkx.NetworkXError:
        # If `our_address` is not in the graph, no channels opened with the
        # address
        return list()

    for partner_address in all_neighbors:
        # don't send the message backwards
        if partner_address == previous_address:
            continue

        channel_state = views.get_channelstate_by_token_network_and_partner(
            chain_state, token_network_address, partner_address
        )

        if not channel_state:
            continue

        if channel.get_status(channel_state) != ChannelState.STATE_OPENED:
            log.info(
                "Channel is not opened, ignoring",
                from_address=to_checksum_address(from_address),
                partner_address=to_checksum_address(partner_address),
                routing_source="Internal Routing",
            )
            continue

        nonrefundable = amount > channel.get_distributable(
            channel_state.partner_state, channel_state.our_state
        )

        try:
            route = networkx.shortest_path(
                token_network.network_graph.network, partner_address, to_address
            )
            neighbour = Neighbour(
                length=len(route),
                nonrefundable=nonrefundable,
                partner_address=partner_address,
                channelid=channel_state.identifier,
                route=route,
            )
            heappush(neighbors_heap, neighbour)
        except (networkx.NetworkXNoPath, networkx.NodeNotFound):
            pass

    if not neighbors_heap:
        log.warning(
            "No routes available",
            from_address=to_checksum_address(from_address),
            to_address=to_checksum_address(to_address),
        )
        return list()

    while neighbors_heap:
        neighbour = heappop(neighbors_heap)
        # The complete route includes the initiator, add it to the beginning
        complete_route = [Address(from_address)] + neighbour.route

        available_routes.append(RouteState(complete_route, neighbour.channelid))

    return available_routes


def get_best_routes_pfs(
    chain_state: ChainState,
    token_network_address: TokenNetworkAddress,
    one_to_n_address: Address,
    from_address: InitiatorAddress,
    to_address: TargetAddress,
    amount: PaymentAmount,
    previous_address: Optional[Address],
    pfs_config: PFSConfig,
    privkey: bytes,
) -> Tuple[bool, List[RouteState], Optional[UUID]]:
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
        )
    except ServiceRequestFailed as e:
        log_message = e.args[0]
        log_info = e.args[1] if len(e.args) > 1 else {}
        log.warning(log_message, **log_info)
        return False, [], None

    paths = []
    for path_object in pfs_routes:
        path = path_object["path"]
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

        paths.append(RouteState(canonical_path, channel_state.identifier))

    return True, paths, feedback_token


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
                )
            )
    return resolvable
