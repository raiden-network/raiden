# -*- coding: utf-8 -*-


def update_route(next_state, route):
    available_routes = list(next_state.routes.available_routes)

    available_idx = None
    for available_idx, route in enumerate(available_routes):
        if route.next_hop == route.next_hop:
            break

    if route.state == 'unavailable':
        available_routes.pop(available_idx)

    elif route.state == 'avaiable':
        if available_idx:
            available_routes[available_idx] = route

        else:
            ignored = any(
                route.next_hop == route.next_hop
                for route in next_state.routes.ignored_routes
            )
            canceled = any(
                route.next_hop == route.next_hop
                for route in next_state.routes.canceled_routes
            )

            if not canceled and not ignored:
                available_routes.append(route)

    next_state.routes.available_routes = available_routes
