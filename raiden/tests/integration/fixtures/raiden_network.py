import gevent
import pytest
import structlog

from raiden.tests.utils.tests import shutdown_apps_and_cleanup_tasks
from raiden.tests.utils.network import (
    CHAIN,
    create_apps,
    create_network_channels,
    create_sequential_channels,
    netting_channel_open_and_deposit,
    wait_for_channels,
    wait_for_alarm_start,
)

log = structlog.get_logger(__name__)  # pylint: disable=invalid-name


@pytest.fixture
def raiden_chain(
        request,
        token_addresses,
        channels_per_node,
        deposit,
        settle_timeout,
        blockchain_services,
        endpoint_discovery_services,
        raiden_udp_ports,
        reveal_timeout,
        database_paths,
        retry_interval,
        retries_before_backoff,
        throttle_capacity,
        throttle_fill_rate,
        nat_invitation_timeout,
        nat_keepalive_retries,
        nat_keepalive_timeout,
        local_matrix_server,
):

    if len(token_addresses) != 1:
        raise ValueError('raiden_chain only works with a single token')

    assert channels_per_node in (0, 1, 2, CHAIN), (
        'deployed_network uses create_sequential_network that can only work '
        'with 0, 1 or 2 channels'
    )

    raiden_apps = create_apps(
        blockchain_services.blockchain_services,
        endpoint_discovery_services,
        blockchain_services.deploy_registry.address,
        blockchain_services.secret_registry.address,
        raiden_udp_ports,
        reveal_timeout,
        settle_timeout,
        database_paths,
        retry_interval,
        retries_before_backoff,
        throttle_capacity,
        throttle_fill_rate,
        nat_invitation_timeout,
        nat_keepalive_retries,
        nat_keepalive_timeout,
        local_matrix_server,
    )

    for app in raiden_apps:
        app.raiden.install_and_query_payment_network_filters(app.raiden.default_registry.address)

    app_channels = create_sequential_channels(
        raiden_apps,
        channels_per_node,
    )

    greenlets = []
    for token_address in token_addresses:
        for app_pair in app_channels:
            greenlets.append(gevent.spawn(
                netting_channel_open_and_deposit,
                app_pair[0],
                app_pair[1],
                token_address,
                deposit,
                settle_timeout,
            ))
    gevent.wait(greenlets)

    exception = RuntimeError('`raiden_chain` fixture setup failed, nodes are unreachable')
    with gevent.Timeout(seconds=30, exception=exception):
        wait_for_channels(
            app_channels,
            blockchain_services.deploy_registry.address,
            token_addresses,
            deposit,
        )

    yield raiden_apps

    shutdown_apps_and_cleanup_tasks(raiden_apps)


@pytest.fixture
def raiden_network(
        request,
        token_addresses,
        channels_per_node,
        deposit,
        settle_timeout,
        blockchain_services,
        endpoint_discovery_services,
        raiden_udp_ports,
        reveal_timeout,
        database_paths,
        retry_interval,
        retries_before_backoff,
        throttle_capacity,
        throttle_fill_rate,
        nat_invitation_timeout,
        nat_keepalive_retries,
        nat_keepalive_timeout,
        local_matrix_server,
):

    raiden_apps = create_apps(
        blockchain_services.blockchain_services,
        endpoint_discovery_services,
        blockchain_services.deploy_registry.address,
        blockchain_services.secret_registry.address,
        raiden_udp_ports,
        reveal_timeout,
        settle_timeout,
        database_paths,
        retry_interval,
        retries_before_backoff,
        throttle_capacity,
        throttle_fill_rate,
        nat_invitation_timeout,
        nat_keepalive_retries,
        nat_keepalive_timeout,
        local_matrix_server,
    )

    app_channels = create_network_channels(
        raiden_apps,
        channels_per_node,
    )

    greenlets = []
    for token_address in token_addresses:
        for app_pair in app_channels:
            greenlets.append(gevent.spawn(
                netting_channel_open_and_deposit,
                app_pair[0],
                app_pair[1],
                token_address,
                deposit,
                settle_timeout,
            ))
    gevent.wait(greenlets)

    exception = RuntimeError('`raiden_network` fixture setup failed, nodes are unreachable')
    with gevent.Timeout(seconds=30, exception=exception):
        wait_for_channels(
            app_channels,
            blockchain_services.deploy_registry.address,
            token_addresses,
            deposit,
        )

    # Force blocknumber update
    exception = RuntimeError('Alarm failed to start and set up start_block correctly')

    with gevent.Timeout(seconds=5, exception=exception):
        wait_for_alarm_start(raiden_apps)

    for app in raiden_apps:
        app.raiden.alarm.poll_for_new_block()

    yield raiden_apps

    shutdown_apps_and_cleanup_tasks(raiden_apps)
