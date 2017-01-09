# -*- coding: utf-8 -*-


def update_route(next_state, route_state_change):
    new_route = route_state_change.route

    available_idx = None
    available_routes = list(next_state.routes.available_routes)
    for available_idx, old_route in enumerate(available_routes):
        if new_route.next_hop == old_route.next_hop:
            break

    # TODO: what if the route that changed is the current route?

    if new_route.state == 'unavailable':
        available_routes.pop(available_idx)

    elif new_route.state == 'avaiable':
        if available_idx:
            # overwrite it, balance might have changed
            available_routes[available_idx] = new_route

        else:
            # TODO: re-add the new_route into the available_routes list if it can be used.
            ignored = any(
                route.next_hop == route.next_hop
                for route in next_state.routes.ignored_routes
            )

            canceled = any(
                route.next_hop == route.next_hop
                for route in next_state.routes.canceled_routes
            )

            if not canceled and not ignored:
                # new channel openned, add the route for use
                available_routes.append(new_route)

    next_state.routes.available_routes = available_routes
