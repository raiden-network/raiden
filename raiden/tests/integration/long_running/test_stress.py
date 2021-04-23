import time
from http import HTTPStatus
from itertools import count
from typing import Sequence

import gevent
import grequests
import pytest
import structlog
from eth_utils import to_canonical_address
from flask import url_for

from raiden.api.python import RaidenAPI
from raiden.api.rest import APIServer, RestAPI
from raiden.constants import RoutingMode
from raiden.message_handler import MessageHandler
from raiden.network.transport import MatrixTransport
from raiden.raiden_event_handler import RaidenEventHandler
from raiden.raiden_service import RaidenService
from raiden.settings import RestApiConfig
from raiden.tests.integration.api.utils import wait_for_listening_port
from raiden.tests.integration.fixtures.raiden_network import RestartNode
from raiden.tests.utils.detect_failure import raise_on_failure
from raiden.tests.utils.protocol import HoldRaidenEventHandler
from raiden.tests.utils.transfer import (
    assert_synced_channel_state,
    wait_assert,
    watch_for_unlock_failures,
)
from raiden.transfer import views
from raiden.ui.startup import RaidenBundle
from raiden.utils.formatting import to_checksum_address
from raiden.utils.typing import (
    Address,
    BlockNumber,
    Host,
    Iterator,
    List,
    Port,
    TokenAddress,
    TokenAmount,
    TokenNetworkAddress,
    Tuple,
)

log = structlog.get_logger(__name__)


def iwait_and_get(items: Sequence[gevent.Greenlet]) -> None:
    """Iteratively wait and get on passed greenlets.

    This ensures exceptions in the greenlets are re-raised as soon as possible.
    """
    for item in gevent.iwait(items):
        item.get()


def _url_for(apiserver: APIServer, endpoint: str, **kwargs) -> str:
    # url_for() expects binary address so we have to convert here
    for key, val in kwargs.items():
        if isinstance(val, str) and val.startswith("0x"):
            kwargs[key] = to_canonical_address(val)

    with apiserver.flask_app.app_context():
        return url_for(f"v1_resources.{endpoint}", **kwargs)


def start_apiserver(raiden_app: RaidenService, rest_api_port_number: Port) -> APIServer:
    raiden_api = RaidenAPI(raiden_app)
    rest_api = RestAPI(raiden_api)
    api_server = APIServer(
        rest_api, config=RestApiConfig(host=Host("localhost"), port=rest_api_port_number)
    )

    # required for url_for
    api_server.flask_app.config["SERVER_NAME"] = f"localhost:{rest_api_port_number}"

    api_server.start()

    wait_for_listening_port(rest_api_port_number)

    return api_server


def start_apiserver_for_network(
    raiden_network: List[RaidenService], port_generator: Iterator[Port]
) -> List[APIServer]:
    return [start_apiserver(app, next(port_generator)) for app in raiden_network]


def restart_app(app: RaidenService, restart_node: RestartNode) -> RaidenService:
    new_transport = MatrixTransport(
        config=app.config.transport, environment=app.config.environment_type
    )
    raiden_event_handler = RaidenEventHandler()
    hold_handler = HoldRaidenEventHandler(raiden_event_handler)

    app = RaidenService(
        config=app.config,
        rpc_client=app.rpc_client,
        proxy_manager=app.proxy_manager,
        query_start_block=BlockNumber(0),
        raiden_bundle=RaidenBundle(
            app.default_registry,
            app.default_secret_registry,
        ),
        services_bundle=app.default_services_bundle,
        transport=new_transport,
        raiden_event_handler=hold_handler,
        message_handler=MessageHandler(),
        routing_mode=RoutingMode.PRIVATE,
    )

    restart_node(app)

    return app


def restart_network(
    raiden_network: List[RaidenService], restart_node: RestartNode
) -> List[RaidenService]:
    for app in raiden_network:
        app.stop()

    wait_network = (gevent.spawn(restart_app, app, restart_node) for app in raiden_network)

    gevent.joinall(set(wait_network), raise_error=True)

    new_network = [greenlet.get() for greenlet in wait_network]

    return new_network


def restart_network_and_apiservers(
    raiden_network: List[RaidenService],
    restart_node: RestartNode,
    api_servers: List[APIServer],
    port_generator: Iterator[Port],
) -> Tuple[List[RaidenService], List[APIServer]]:
    """Stop an app and start it back"""
    for rest_api in api_servers:
        rest_api.stop()

    new_network = restart_network(raiden_network, restart_node)
    new_servers = start_apiserver_for_network(new_network, port_generator)

    return (new_network, new_servers)


def address_from_apiserver(apiserver: APIServer) -> Address:
    return apiserver.rest_api.raiden_api.address


def transfer_and_assert(
    server_from: APIServer,
    server_to: APIServer,
    token_address: TokenAddress,
    identifier: int,
    amount: TokenAmount,
) -> None:
    url = _url_for(
        server_from,
        "token_target_paymentresource",
        token_address=to_checksum_address(token_address),
        target_address=to_checksum_address(address_from_apiserver(server_to)),
    )
    json = {"amount": amount, "identifier": identifier}

    log.debug("PAYMENT REQUEST", url=url, json=json)

    request = grequests.post(url, json=json)

    start = time.monotonic()
    response = request.send().response
    duration = time.monotonic() - start

    log.debug("PAYMENT RESPONSE", url=url, json=json, response=response, duration=duration)

    assert getattr(request, "exception", None) is None
    assert response is not None
    assert response.status_code == HTTPStatus.OK, f"Payment failed, reason: {response.content}"
    assert response.headers["Content-Type"] == "application/json"


def sequential_transfers(
    server_from: APIServer,
    server_to: APIServer,
    number_of_transfers: int,
    token_address: TokenAddress,
    identifier_generator: Iterator[int],
) -> None:
    for _ in range(number_of_transfers):
        transfer_and_assert(
            server_from=server_from,
            server_to=server_to,
            token_address=token_address,
            identifier=next(identifier_generator),
            amount=TokenAmount(1),
        )


def stress_send_serial_transfers(
    rest_apis: List[APIServer],
    token_address: TokenAddress,
    identifier_generator: Iterator[int],
    deposit: TokenAmount,
) -> None:
    """Send `deposit` transfers of value `1` one at a time, without changing
    the initial capacity.
    """
    pairs = list(zip(rest_apis, rest_apis[1:] + [rest_apis[0]]))

    # deplete the channels in one direction
    for server_from, server_to in pairs:
        sequential_transfers(
            server_from=server_from,
            server_to=server_to,
            number_of_transfers=deposit,
            token_address=token_address,
            identifier_generator=identifier_generator,
        )

    # deplete the channels in the backwards direction
    for server_to, server_from in pairs:
        sequential_transfers(
            server_from=server_from,
            server_to=server_to,
            number_of_transfers=deposit * 2,
            token_address=token_address,
            identifier_generator=identifier_generator,
        )

    # reset the balances balances by sending the "extra" deposit forward
    for server_from, server_to in pairs:
        sequential_transfers(
            server_from=server_from,
            server_to=server_to,
            number_of_transfers=deposit,
            token_address=token_address,
            identifier_generator=identifier_generator,
        )


def stress_send_parallel_transfers(
    rest_apis: List[APIServer],
    token_address: TokenAddress,
    identifier_generator: Iterator[int],
    deposit: TokenAmount,
) -> None:
    """Send `deposit` transfers in parallel, without changing the initial capacity."""
    pairs = list(zip(rest_apis, rest_apis[1:] + [rest_apis[0]]))

    # deplete the channels in one direction
    iwait_and_get(
        [
            gevent.spawn(
                sequential_transfers,
                server_from=server_from,
                server_to=server_to,
                number_of_transfers=deposit,
                token_address=token_address,
                identifier_generator=identifier_generator,
            )
            for server_from, server_to in pairs
        ]
    )

    # deplete the channels in the backwards direction
    iwait_and_get(
        [
            gevent.spawn(
                sequential_transfers,
                server_from=server_from,
                server_to=server_to,
                number_of_transfers=deposit * 2,
                token_address=token_address,
                identifier_generator=identifier_generator,
            )
            for server_to, server_from in pairs
        ]
    )

    # reset the balances balances by sending the "extra" deposit forward
    iwait_and_get(
        [
            gevent.spawn(
                sequential_transfers,
                server_from=server_from,
                server_to=server_to,
                number_of_transfers=deposit,
                token_address=token_address,
                identifier_generator=identifier_generator,
            )
            for server_from, server_to in pairs
        ]
    )


def stress_send_and_receive_parallel_transfers(
    rest_apis: List[APIServer],
    token_address: TokenAddress,
    identifier_generator: Iterator[int],
    deposit: TokenAmount,
) -> None:
    """Send transfers of value one in parallel"""
    pairs = list(zip(rest_apis, rest_apis[1:] + [rest_apis[0]]))

    forward_transfers = [
        gevent.spawn(
            sequential_transfers,
            server_from=server_from,
            server_to=server_to,
            number_of_transfers=deposit,
            token_address=token_address,
            identifier_generator=identifier_generator,
        )
        for server_from, server_to in pairs
    ]

    backwards_transfers = [
        gevent.spawn(
            sequential_transfers,
            server_from=server_from,
            server_to=server_to,
            number_of_transfers=deposit,
            token_address=token_address,
            identifier_generator=identifier_generator,
        )
        for server_to, server_from in pairs
    ]

    iwait_and_get(forward_transfers + backwards_transfers)


def assert_channels(
    raiden_network: List[RaidenService],
    token_network_address: TokenNetworkAddress,
    deposit: TokenAmount,
) -> None:
    pairs = list(zip(raiden_network, raiden_network[1:] + [raiden_network[0]]))

    for first, second in pairs:
        wait_assert(
            assert_synced_channel_state,
            token_network_address,
            first,
            deposit,
            [],
            second,
            deposit,
            [],
        )


@pytest.mark.skip(reason="flaky, see https://github.com/raiden-network/raiden/issues/4803")
@raise_on_failure
@pytest.mark.parametrize("number_of_nodes", [3])
@pytest.mark.parametrize("number_of_tokens", [1])
@pytest.mark.parametrize("channels_per_node", [2])
@pytest.mark.parametrize("deposit", [2])
@pytest.mark.parametrize("reveal_timeout", [15])
@pytest.mark.parametrize("settle_timeout", [120])
def test_stress(
    raiden_network: List[RaidenService],
    restart_node: RestartNode,
    deposit: TokenAmount,
    token_addresses: List[TokenAddress],
    port_generator: Iterator[Port],
) -> None:
    token_address = token_addresses[0]
    rest_apis = start_apiserver_for_network(raiden_network, port_generator)
    identifier_generator = count(start=1)

    token_network_address = views.get_token_network_address_by_token_address(
        views.state_from_raiden(raiden_network[0]),
        raiden_network[0].default_registry.address,
        token_address,
    )
    assert token_network_address

    for _ in range(2):
        assert_channels(raiden_network, token_network_address, deposit)

        with watch_for_unlock_failures(*raiden_network):
            stress_send_serial_transfers(rest_apis, token_address, identifier_generator, deposit)

        raiden_network, rest_apis = restart_network_and_apiservers(
            raiden_network, restart_node, rest_apis, port_generator
        )

        assert_channels(raiden_network, token_network_address, deposit)

        with watch_for_unlock_failures(*raiden_network):
            stress_send_parallel_transfers(rest_apis, token_address, identifier_generator, deposit)

        raiden_network, rest_apis = restart_network_and_apiservers(
            raiden_network, restart_node, rest_apis, port_generator
        )

        assert_channels(raiden_network, token_network_address, deposit)

        with watch_for_unlock_failures(*raiden_network):
            stress_send_and_receive_parallel_transfers(
                rest_apis, token_address, identifier_generator, deposit
            )

        raiden_network, rest_apis = restart_network_and_apiservers(
            raiden_network, restart_node, rest_apis, port_generator
        )

    restart_network(raiden_network, restart_node)
