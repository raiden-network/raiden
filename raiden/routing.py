from heapq import heappop, heappush
from typing import Any, Dict, List, Tuple
from uuid import UUID

import networkx
import structlog
from eth_utils import to_canonical_address, to_checksum_address

from raiden.exceptions import ServiceRequestFailed
from raiden.network.pathfinding import query_paths
from raiden.transfer import channel, views
from raiden.transfer.state import CHANNEL_STATE_OPENED, ChainState, RouteState
from raiden.utils.typing import (
    Address,
    ChannelID,
    InitiatorAddress,
    NamedTuple,
    Optional,
    PaymentAmount,
    TargetAddress,
    TokenNetworkID,
)

log = structlog.get_logger(__name__)  # pylint: disable=invalid-name


def get_best_routes(
    chain_state: ChainState,
    token_network_id: TokenNetworkID,
    one_to_n_address: Optional[Address],
    from_address: InitiatorAddress,
    to_address: TargetAddress,
    amount: PaymentAmount,
    previous_address: Optional[Address],
    config: Dict[str, Any],
    privkey: bytes,
) -> Tuple[List[RouteState], Optional[UUID]]:
    services_config = config.get("services", None)

    # the pfs should not be requested when the target is linked via a direct channel
    if to_address in views.all_neighbour_nodes(chain_state):
        neighbours = get_best_routes_internal(
            chain_state=chain_state,
            token_network_id=token_network_id,
            from_address=from_address,
            to_address=to_address,
            amount=amount,
            previous_address=previous_address,
        )
        channel_state = views.get_channelstate_by_token_network_and_partner(
            chain_state=chain_state,
            token_network_id=token_network_id,
            partner_address=Address(to_address),
        )

        for route_state in neighbours:
            if to_address == route_state.node_address and (
                channel_state
                # other conditions about e.g. channel state are checked in best routes internal
                and channel.get_distributable(
                    sender=channel_state.our_state, receiver=channel_state.partner_state
                )
                >= amount
            ):
                return [route_state], None

    if (
        services_config
        and services_config["pathfinding_service_address"] is not None
        and one_to_n_address is not None
    ):
        pfs_answer_ok, pfs_routes, pfs_feedback_token = get_best_routes_pfs(
            chain_state=chain_state,
            token_network_id=token_network_id,
            one_to_n_address=one_to_n_address,
            from_address=from_address,
            to_address=to_address,
            amount=amount,
            previous_address=previous_address,
            config=services_config,
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
            token_network_id=token_network_id,
            from_address=from_address,
            to_address=to_address,
            amount=amount,
            previous_address=previous_address,
        ),
        None,
    )


class Neighbour(NamedTuple):
    length: int
    nonrefundable: bool
    partner_address: Address
    channelid: ChannelID


def get_best_routes_internal(
    chain_state: ChainState,
    token_network_id: TokenNetworkID,
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

    token_network = views.get_token_network_by_identifier(chain_state, token_network_id)

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
            chain_state, token_network_id, partner_address
        )

        if not channel_state:
            continue

        if channel.get_status(channel_state) != CHANNEL_STATE_OPENED:
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
            length = networkx.shortest_path_length(
                token_network.network_graph.network, partner_address, to_address
            )
            neighbour = Neighbour(
                length=length,
                nonrefundable=nonrefundable,
                partner_address=partner_address,
                channelid=channel_state.identifier,
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
        route_state = RouteState(
            node_address=neighbour.partner_address, channel_identifier=neighbour.channelid
        )
        available_routes.append(route_state)
    return available_routes


def get_best_routes_pfs(
    chain_state: ChainState,
    token_network_id: TokenNetworkID,
    one_to_n_address: Address,
    from_address: InitiatorAddress,
    to_address: TargetAddress,
    amount: PaymentAmount,
    previous_address: Optional[Address],
    config: Dict[str, Any],
    privkey: bytes,
) -> Tuple[bool, List[RouteState], Optional[UUID]]:
    try:
        pfs_routes, feedback_token = query_paths(
            service_config=config,
            our_address=chain_state.our_address,
            privkey=privkey,
            current_block_number=chain_state.block_number,
            token_network_address=token_network_id,
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

        # get the second entry, as the first one is the node itself
        # also needs to be converted to canonical representation
        partner_address = to_canonical_address(path[1])

        # don't route back
        if partner_address == previous_address:
            continue

        channel_state = views.get_channelstate_by_token_network_and_partner(
            chain_state=chain_state,
            token_network_id=token_network_id,
            partner_address=partner_address,
        )

        if not channel_state:
            continue

        # check channel state
        if channel.get_status(channel_state) != CHANNEL_STATE_OPENED:
            log.info(
                "Channel is not opened, ignoring",
                from_address=to_checksum_address(from_address),
                partner_address=to_checksum_address(partner_address),
                routing_source="Pathfinding Service",
            )
            continue

        paths.append(
            RouteState(node_address=partner_address, channel_identifier=channel_state.identifier)
        )

    return True, paths, feedback_token
