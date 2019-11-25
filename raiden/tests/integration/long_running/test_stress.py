import time
from http import HTTPStatus
from itertools import combinations, count
from typing import Sequence

import gevent
import grequests
import pytest
import structlog
from eth_utils import to_canonical_address, to_checksum_address
from flask import url_for

from raiden import waiting
from raiden.api.python import RaidenAPI
from raiden.api.rest import APIServer, RestAPI
from raiden.app import App
from raiden.constants import RoutingMode
from raiden.message_handler import MessageHandler
from raiden.network.transport import MatrixTransport
from raiden.raiden_event_handler import RaidenEventHandler
from raiden.tests.integration.api.utils import wait_for_listening_port
from raiden.tests.utils.transfer import (
    assert_synced_channel_state,
    wait_assert,
    watch_for_unlock_failures,
)
from raiden.transfer import views
from raiden.utils.typing import (
    Address,
    BlockNumber,
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
    """ Iteratively wait and get on passed greenlets.

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


def start_apiserver(raiden_app: App, rest_api_port_number: Port) -> APIServer:
    raiden_api = RaidenAPI(raiden_app.raiden)
    rest_api = RestAPI(raiden_api)
    api_server = APIServer(rest_api, config={"host": "localhost", "port": rest_api_port_number})

    # required for url_for
    api_server.flask_app.config["SERVER_NAME"] = f"localhost:{rest_api_port_number}"

    api_server.start()

    wait_for_listening_port(rest_api_port_number)

    return api_server


def start_apiserver_for_network(
    raiden_network: List[App], port_generator: Iterator[Port]
) -> List[APIServer]:
    return [start_apiserver(app, next(port_generator)) for app in raiden_network]


def restart_app(app: App) -> App:
    new_transport = MatrixTransport(app.raiden.config["transport"]["matrix"])
    app = App(
        config=app.config,
        rpc_client=app.raiden.rpc_client,
        proxy_manager=app.raiden.proxy_manager,
        query_start_block=BlockNumber(0),
        default_one_to_n_address=app.raiden.default_one_to_n_address,
        default_registry=app.raiden.default_registry,
        default_secret_registry=app.raiden.default_secret_registry,
        default_service_registry=app.raiden.default_service_registry,
        default_msc_address=app.raiden.default_msc_address,
        transport=new_transport,
        raiden_event_handler=RaidenEventHandler(),
        message_handler=MessageHandler(),
        routing_mode=RoutingMode.PRIVATE,
    )

    app.start()

    return app


def restart_network(raiden_network: List[App], retry_timeout: float) -> List[App]:
    for app in raiden_network:
        app.stop()

    wait_network = [gevent.spawn(restart_app, app) for app in raiden_network]

    gevent.wait(wait_network)

    new_network = [greenlet.get() for greenlet in wait_network]

    # The tests assume the nodes are available to transfer
    for app0, app1 in combinations(new_network, 2):
        waiting.wait_for_healthy(app0.raiden, app1.raiden.address, retry_timeout)

    return new_network


def restart_network_and_apiservers(
    raiden_network: List[App],
    api_servers: List[APIServer],
    port_generator: Iterator[Port],
    retry_timeout: float,
) -> Tuple[List[App], List[APIServer]]:
    """Stop an app and start it back"""
    for rest_api in api_servers:
        rest_api.stop()

    new_network = restart_network(raiden_network, retry_timeout)
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
    assert response.status_code == HTTPStatus.OK
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
    """Send `deposit` transfers in parallel, without changing the initial capacity.
    """
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
    raiden_network: List[App], token_network_address: TokenNetworkAddress, deposit: TokenAmount
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
@pytest.mark.parametrize("number_of_nodes", [3])
@pytest.mark.parametrize("number_of_tokens", [1])
@pytest.mark.parametrize("channels_per_node", [2])
@pytest.mark.parametrize("deposit", [2])
@pytest.mark.parametrize("reveal_timeout", [15])
@pytest.mark.parametrize("settle_timeout", [120])
def test_stress(
    raiden_network: List[App],
    deposit: TokenAmount,
    retry_timeout: float,
    token_addresses: List[TokenAddress],
    port_generator: Iterator[Port],
) -> None:
    token_address = token_addresses[0]
    rest_apis = start_apiserver_for_network(raiden_network, port_generator)
    identifier_generator = count()

    token_network_address = views.get_token_network_address_by_token_address(
        views.state_from_app(raiden_network[0]),
        raiden_network[0].raiden.default_registry.address,
        token_address,
    )
    assert token_network_address

    for _ in range(2):
        assert_channels(raiden_network, token_network_address, deposit)

        with watch_for_unlock_failures(*raiden_network):
            stress_send_serial_transfers(rest_apis, token_address, identifier_generator, deposit)

        raiden_network, rest_apis = restart_network_and_apiservers(
            raiden_network, rest_apis, port_generator, retry_timeout
        )

        assert_channels(raiden_network, token_network_address, deposit)

        with watch_for_unlock_failures(*raiden_network):
            stress_send_parallel_transfers(rest_apis, token_address, identifier_generator, deposit)

        raiden_network, rest_apis = restart_network_and_apiservers(
            raiden_network, rest_apis, port_generator, retry_timeout
        )

        assert_channels(raiden_network, token_network_address, deposit)

        with watch_for_unlock_failures(*raiden_network):
            stress_send_and_receive_parallel_transfers(
                rest_apis, token_address, identifier_generator, deposit
            )

        raiden_network, rest_apis = restart_network_and_apiservers(
            raiden_network, rest_apis, port_generator, retry_timeout
        )

    restart_network(raiden_network, retry_timeout)
