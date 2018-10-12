from heapq import heappop, heappush
from typing import List

import networkx
import structlog

from raiden.transfer import channel, views
from raiden.transfer.state import (
    CHANNEL_STATE_OPENED,
    NODE_NETWORK_REACHABLE,
    NODE_NETWORK_UNKNOWN,
    ChainState,
    RouteState,
)
from raiden.utils import pex, typing

log = structlog.get_logger(__name__)  # pylint: disable=invalid-name


def get_best_routes(
        chain_state: ChainState,
        token_network_id: typing.Address,
        from_address: typing.Address,
        to_address: typing.Address,
        amount: int,
        previous_address: typing.Address,
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

    network_statuses = views.get_networkstatuses(chain_state)

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

        assert channel_state is not None

        if channel.get_status(channel_state) != CHANNEL_STATE_OPENED:
            log.info(
                'channel is not opened, ignoring',
                from_address=pex(from_address),
                partner_address=pex(partner_address),
            )
            continue

        distributable = channel.get_distributable(
            channel_state.our_state,
            channel_state.partner_state,
        )

        if amount > distributable:
            log.info(
                'channel doesnt have enough funds, ignoring',
                from_address=pex(from_address),
                partner_address=pex(partner_address),
                amount=amount,
                distributable=distributable,
            )
            continue

        network_state = network_statuses.get(partner_address, NODE_NETWORK_UNKNOWN)

        if network_state != NODE_NETWORK_REACHABLE:
            log.info(
                'partner for channel state isn\'t reachable, ignoring',
                from_address=pex(from_address),
                partner_address=pex(partner_address),
                status=network_state,
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
