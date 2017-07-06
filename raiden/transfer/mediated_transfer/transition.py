# -*- coding: utf-8 -*-
from raiden.transfer.state import CHANNEL_STATE_OPENED


def update_route(next_state, route_state_change):
    new_route = route_state_change.route

    available_idx = None
    available_routes = list(next_state.routes.available_routes)
    for available_idx, old_route in enumerate(available_routes):
        if new_route.node_address == old_route.node_address:
            break

    # TODO: what if the route that changed is the current route?

    if new_route.state != CHANNEL_STATE_OPENED:
        available_routes.pop(available_idx)

    elif new_route.state == CHANNEL_STATE_OPENED:
        if available_idx:
            # overwrite it, balance might have changed
            available_routes[available_idx] = new_route

        else:
            # TODO: re-add the new_route into the available_routes list if it can be used.
            ignored = any(
                route.node_address == new_route.node_address
                for route in next_state.routes.ignored_routes
            )

            canceled = any(
                route.node_address == new_route.node_address
                for route in next_state.routes.canceled_routes
            )

            if not canceled and not ignored:
                # new channel opened, add the route for use
                available_routes.append(new_route)

    next_state.routes.available_routes = available_routes
