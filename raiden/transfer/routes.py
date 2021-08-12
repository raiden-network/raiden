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

    filtered_routes = []
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

    acceptable_routes = []
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
