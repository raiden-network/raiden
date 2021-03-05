from typing import Dict, Tuple

from raiden.transfer.state import NettingChannelState, NetworkState, RouteState
from raiden.utils.typing import (
    Address,
    ChannelID,
    InitiatorAddress,
    List,
    NodeNetworkStateMap,
    TokenNetworkAddress,
)


def filter_reachable_routes(
    route_states: List[RouteState], nodeaddresses_to_networkstates: NodeNetworkStateMap
) -> List[RouteState]:
    """ This function makes sure we use reachable routes only. """

    return [
        route
        for route in route_states
        if nodeaddresses_to_networkstates.get(route.next_hop_address) == NetworkState.REACHABLE
    ]


# TODO: change function for swaps
#       * use token network address in route state
#       * check if token_network_address parameter is still needed
#         * if yes, check that the right one is passed by all callers
#       * change blacklisted_channel_ids to contain the TN, too
def filter_acceptable_routes(
    route_states: List[RouteState],
    blacklisted_channel_ids: List[ChannelID],
    addresses_to_channel: Dict[Tuple[TokenNetworkAddress, Address], NettingChannelState],
    token_network_address: TokenNetworkAddress,
) -> List[RouteState]:
    """ Keeps only routes whose forward_channel is not in the list of blacklisted channels """

    return [
        route
        for route in route_states
        if addresses_to_channel[(token_network_address, route.route[1])].identifier
        not in blacklisted_channel_ids
    ]


def prune_route_table(
    route_states: List[RouteState],
    selected_route: RouteState,
    initiator_address: InitiatorAddress,
) -> List[RouteState]:
    """Given a selected route, returns a filtered route table that
    contains only routes using the same forward channel and removes our own
    address in the process.
    Our address is also removed from the address metadata, if we are not the initiator
    """

    pruned_routes = list()
    for route_state in route_states:
        # the condition will only forward relevant routes that involve the next hop
        if route_state.next_hop == selected_route.next_hop:
            # remove the head address from the route
            route = route_state.route[1:]

            address_metadata = route_state.address_metadata.copy()
            route_head_address = route_state.route[0]
            if route_head_address != initiator_address:
                #  the target needs to receive the initiator's metadata,
                #  so only remove the metadate when this is a hop
                del address_metadata[route_head_address]
            pruned_routes.append(RouteState(route=route, address_metadata=address_metadata))
    return pruned_routes
