from typing import Dict, Tuple

from raiden.transfer.state import NettingChannelState, NetworkState, RouteState
from raiden.utils.typing import Address, ChannelID, List, NodeNetworkStateMap, TokenNetworkAddress


def filter_reachable_routes(
    route_states: List[RouteState], nodeaddress_to_networkstate: NodeNetworkStateMap
) -> List[RouteState]:
    """ This function makes sure we use reachable routes only. """

    return [
        route
        for route in route_states
        if nodeaddress_to_networkstate.get(route.next_hop_address) == NetworkState.REACHABLE
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
    route_states: List[RouteState], selected_route: RouteState
) -> List[RouteState]:
    """ Given a selected route, returns a filtered route table that
    contains only routes using the same forward channel and removes our own
    address in the process.
    """
    return [
        RouteState(route=rs.route[1:])
        for rs in route_states
        if rs.next_hop == selected_route.next_hop
    ]
