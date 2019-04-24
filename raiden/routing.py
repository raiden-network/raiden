from heapq import heappop, heappush
from typing import Any, Dict, List, Tuple

import networkx
import structlog
from eth_utils import to_canonical_address, to_checksum_address

from raiden.exceptions import ServiceRequestFailed
from raiden.network.pathfinding import query_paths
from raiden.transfer import channel, views
from raiden.transfer.state import CHANNEL_STATE_OPENED, ChainState, RouteState
from raiden.utils import pex, typing
from raiden.utils.typing import PaymentAmount, TokenAmount

log = structlog.get_logger(__name__)  # pylint: disable=invalid-name


def get_best_routes(
        chain_state: ChainState,
        token_network_id: typing.TokenNetworkID,
        from_address: typing.InitiatorAddress,
        to_address: typing.TargetAddress,
        amount: PaymentAmount,
        previous_address: typing.Optional[typing.Address],
        config: Dict[str, Any],
        privkey: bytes,
) -> List[RouteState]:
    services_config = config.get('services', None)

    if services_config and services_config['pathfinding_service_address'] is not None:
        pfs_answer_ok, pfs_routes = get_best_routes_pfs(
            chain_state=chain_state,
            token_network_id=token_network_id,
            from_address=from_address,
            to_address=to_address,
            amount=amount,
            previous_address=previous_address,
            config=services_config,
            privkey=privkey,
        )

        if pfs_answer_ok:
            log.info(
                'Received route(s) from PFS',
                routes=pfs_routes,
            )
            return pfs_routes
        else:
            log.warning(
                'Request to Pathfinding Service was not successful, '
                'falling back to internal routing.',
            )

    return get_best_routes_internal(
        chain_state=chain_state,
        token_network_id=token_network_id,
        from_address=from_address,
        to_address=to_address,
        amount=amount,
        previous_address=previous_address,
    )


def get_best_routes_internal(
        chain_state: ChainState,
        token_network_id: typing.TokenNetworkID,
        from_address: typing.InitiatorAddress,
        to_address: typing.TargetAddress,
        amount: int,
        previous_address: typing.Optional[typing.Address],
) -> List[RouteState]:
    """ Returns a list of channels that can be used to make a transfer.

    This will filter out channels that are not open and don't have enough
    capacity.
    """
    # TODO: Route ranking.
    # Rate each route to optimize the fee price/quality of each route and add a
    # rate from in the range [0.0,1.0].

    available_routes = list()

    token_network = views.get_token_network_by_identifier(
        chain_state,
        token_network_id,
    )

    if not token_network:
        return list()

    neighbors_heap = list()
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
            chain_state,
            token_network_id,
            partner_address,
        )

        if not channel_state:
            continue

        if channel.get_status(channel_state) != CHANNEL_STATE_OPENED:
            log.info(
                'Channel is not opened, ignoring',
                from_address=pex(from_address),
                partner_address=pex(partner_address),
                routing_source='Internal Routing',
            )
            continue

        nonrefundable = amount > channel.get_distributable(
            channel_state.partner_state,
            channel_state.our_state,
        )

        try:
            length = networkx.shortest_path_length(
                token_network.network_graph.network,
                partner_address,
                to_address,
            )
            heappush(
                neighbors_heap,
                (length, nonrefundable, partner_address, channel_state.identifier),
            )
        except (networkx.NetworkXNoPath, networkx.NodeNotFound):
            pass

    if not neighbors_heap:
        log.warning(
            'No routes available',
            from_address=pex(from_address),
            to_address=pex(to_address),
        )
        return list()

    while neighbors_heap:
        *_, partner_address, channel_state_id = heappop(neighbors_heap)
        route_state = RouteState(partner_address, channel_state_id)
        available_routes.append(route_state)
    return available_routes


def get_best_routes_pfs(
        chain_state: ChainState,
        token_network_id: typing.TokenNetworkID,
        from_address: typing.InitiatorAddress,
        to_address: typing.TargetAddress,
        amount: TokenAmount,
        previous_address: typing.Optional[typing.Address],
        config: Dict[str, Any],
        privkey: bytes,
) -> Tuple[bool, List[RouteState]]:

    try:
        result = query_paths(
            service_config=config,
            our_address=to_checksum_address(chain_state.our_address),
            privkey=privkey,
            current_block_number=chain_state.block_number,
            token_network_address=token_network_id,
            route_from=from_address,
            route_to=to_address,
            value=amount,
        )
    except ServiceRequestFailed as e:
        log_message = e.args[0]
        log_info = e.args[1] if len(e.args) > 1 else {}
        log.warning(log_message, **log_info)
        return False, []

    paths = []
    for path_object in result:
        path = path_object['path']

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
                'Channel is not opened, ignoring',
                from_address=pex(from_address),
                partner_address=pex(partner_address),
                routing_source='Pathfinding Service',
            )
            continue

        paths.append(
            RouteState(
                node_address=partner_address,
                channel_identifier=channel_state.identifier,
            ),
        )

    return True, paths
