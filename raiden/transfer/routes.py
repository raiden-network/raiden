from typing import Dict, Tuple

from raiden.transfer.state import NettingChannelState, NetworkState, RouteState
from raiden.utils.typing import Address, ChannelID, List, NodeNetworkStateMap, TokenNetworkAddress


def filter_reachable_routes(
    route_states: List[RouteState],
    nodeaddresses_to_networkstates: NodeNetworkStateMap,
    our_address: Address,
) -> List[RouteState]:
    """This function makes sure we use reachable routes only."""
    # TODO this function is not used anymore (only in tests), probably can be removed

    filtered_routes = list()
    for route in route_states:
        next_hop = route.hop_after(our_address)
        if not next_hop:
            continue
        if nodeaddresses_to_networkstates.get(next_hop) == NetworkState.REACHABLE:
            filtered_routes.append(route)
    return filtered_routes


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
    our_address: Address,
) -> List[RouteState]:
    """Keeps only routes whose forward_channel is not in the list of blacklisted channels"""

    acceptable_routes = list()
    for route in route_states:
        next_hop = route.hop_after(our_address)
        if not next_hop:
            continue
        channel = addresses_to_channel.get((token_network_address, next_hop))
        if channel is None:
            continue
        if channel.identifier not in blacklisted_channel_ids:
            acceptable_routes.append(route)
    return acceptable_routes


def prune_route_table(
    route_states: List[RouteState], selected_route: RouteState, our_address: Address
) -> List[RouteState]:
    """Given a selected route, returns a filtered route table that
    contains only routes using the same forward channel and removes our own
    address in the process.
    Note that address metadata are kept complete for the whole route.

    Also note that we don't need to handle ``ValueError``s here since the new
    ``RouteState``s are built from existing ones, which means the metadata have
    already been validated.
    """

    pruned_route_states = list()
    for rs in route_states:
        next_hop = rs.hop_after(our_address)
        if not next_hop:
            continue
        selected_next_hop = selected_route.hop_after(our_address)
        if not selected_next_hop:
            # This shouldn't happen, since we shouldn't select a route that has no next hop
            continue
        if next_hop == selected_next_hop:
            idx = rs.route.index(our_address)
            pruned_route = rs.route[idx + 1 :]
            if pruned_route:
                pruned_route_states.append(
                    RouteState(route=pruned_route, address_to_metadata=rs.address_to_metadata)
                )
    return pruned_route_states
