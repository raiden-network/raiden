import gevent
import pytest
import structlog

from raiden.tests.utils.tests import shutdown_apps_and_cleanup_tasks
from raiden.tests.utils.network import (
    CHAIN,
    create_apps,
    create_network_channels,
    create_sequential_channels,
    payment_channel_open_and_deposit,
    wait_for_channels,
    wait_for_alarm_start,
)

log = structlog.get_logger(__name__)  # pylint: disable=invalid-name


@pytest.fixture
def raiden_chain(
        token_addresses,
        token_network_registry_address,
        channels_per_node,
        deposit,
        settle_timeout,
        chain_id,
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
        chain_id,
        blockchain_services.blockchain_services,
        endpoint_discovery_services,
        token_network_registry_address,
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

    from_block = 0
    for app in raiden_apps:
        app.raiden.install_all_blockchain_filters(
            app.raiden.default_registry,
            app.raiden.default_secret_registry,
            from_block,
        )

    app_channels = create_sequential_channels(
        raiden_apps,
        channels_per_node,
    )

    greenlets = []
    for token_address in token_addresses:
        for app_pair in app_channels:
            greenlets.append(gevent.spawn(
                payment_channel_open_and_deposit,
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
        token_addresses,
        token_network_registry_address,
        channels_per_node,
        deposit,
        settle_timeout,
        chain_id,
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
        chain_id,
        blockchain_services.blockchain_services,
        endpoint_discovery_services,
        token_network_registry_address,
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
                payment_channel_open_and_deposit,
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

    yield raiden_apps

    shutdown_apps_and_cleanup_tasks(raiden_apps)
