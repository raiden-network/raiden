import gevent
import pytest

from raiden.constants import GENESIS_BLOCK_NUMBER
from raiden.tests.utils.network import (
    CHAIN,
    create_all_channels_for_network,
    create_apps,
    create_network_channels,
    create_sequential_channels,
    parallel_start_apps,
    wait_for_alarm_start,
    wait_for_channels,
    wait_for_token_networks,
)
from raiden.tests.utils.tests import shutdown_apps_and_cleanup_tasks


def wait_for_min_blocks(raiden, web3):
    """Wait until the block height exceeds confirmation_blocks, so the
    computation of the last confirmed block in tests will not yield a
    negative block number.
    """
    while web3.eth.blockNumber <= raiden.confirmation_blocks:
        gevent.sleep(.5)


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
        environment_type,
        unrecoverable_error_should_crash,
        local_matrix_servers,
        private_rooms,
        retry_timeout,
        blockchain_type,
):

    if len(token_addresses) != 1:
        raise ValueError('raiden_chain only works with a single token')

    assert channels_per_node in (0, 1, 2, CHAIN), (
        'deployed_network uses create_sequential_network that can only work '
        'with 0, 1 or 2 channels'
    )

    raiden_apps = create_apps(
        chain_id=chain_id,
        blockchain_services=blockchain_services.blockchain_services,
        endpoint_discovery_services=endpoint_discovery_services,
        token_network_registry_address=token_network_registry_address,
        secret_registry_address=blockchain_services.secret_registry.address,
        raiden_udp_ports=raiden_udp_ports,
        reveal_timeout=reveal_timeout,
        settle_timeout=settle_timeout,
        database_paths=database_paths,
        retry_interval=retry_interval,
        retries_before_backoff=retries_before_backoff,
        throttle_capacity=throttle_capacity,
        throttle_fill_rate=throttle_fill_rate,
        nat_invitation_timeout=nat_invitation_timeout,
        nat_keepalive_retries=nat_keepalive_retries,
        nat_keepalive_timeout=nat_keepalive_timeout,
        environment_type=environment_type,
        unrecoverable_error_should_crash=unrecoverable_error_should_crash,
        local_matrix_url=local_matrix_servers[0],
        private_rooms=private_rooms,
    )

    wait_for_min_blocks(raiden_apps[0].raiden, blockchain_services[2].client.web3)
    parallel_start_apps(raiden_apps)

    from_block = GENESIS_BLOCK_NUMBER
    for app in raiden_apps:
        app.raiden.install_all_blockchain_filters(
            app.raiden.default_registry,
            app.raiden.default_secret_registry,
            from_block,
        )

    exception = RuntimeError('`raiden_chain` fixture setup failed, token networks unavailable')
    timeout = 120 if blockchain_type == 'parity' else 30
    with gevent.Timeout(seconds=timeout, exception=exception):
        wait_for_token_networks(
            raiden_apps=raiden_apps,
            token_network_registry_address=token_network_registry_address,
            token_addresses=token_addresses,
        )

    app_channels = create_sequential_channels(
        raiden_apps,
        channels_per_node,
    )

    create_all_channels_for_network(
        app_channels=app_channels,
        token_addresses=token_addresses,
        channel_individual_deposit=deposit,
        channel_settle_timeout=settle_timeout,
        token_network_registry_address=token_network_registry_address,
        retry_timeout=retry_timeout,
    )

    exception = RuntimeError('`raiden_chain` fixture setup failed, nodes are unreachable')
    timeout = 120 if blockchain_type == 'parity' else 30
    with gevent.Timeout(seconds=timeout, exception=exception):
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
        environment_type,
        unrecoverable_error_should_crash,
        local_matrix_servers,
        private_rooms,
        retry_timeout,
        blockchain_type,
):
    raiden_apps = create_apps(
        chain_id=chain_id,
        blockchain_services=blockchain_services.blockchain_services,
        endpoint_discovery_services=endpoint_discovery_services,
        token_network_registry_address=token_network_registry_address,
        secret_registry_address=blockchain_services.secret_registry.address,
        raiden_udp_ports=raiden_udp_ports,
        reveal_timeout=reveal_timeout,
        settle_timeout=settle_timeout,
        database_paths=database_paths,
        retry_interval=retry_interval,
        retries_before_backoff=retries_before_backoff,
        throttle_capacity=throttle_capacity,
        throttle_fill_rate=throttle_fill_rate,
        nat_invitation_timeout=nat_invitation_timeout,
        nat_keepalive_retries=nat_keepalive_retries,
        nat_keepalive_timeout=nat_keepalive_timeout,
        environment_type=environment_type,
        unrecoverable_error_should_crash=unrecoverable_error_should_crash,
        local_matrix_url=local_matrix_servers[0],
        private_rooms=private_rooms,
    )

    wait_for_min_blocks(raiden_apps[0].raiden, blockchain_services[2].client.web3)
    parallel_start_apps(raiden_apps)

    exception = RuntimeError('`raiden_chain` fixture setup failed, token networks unavailable')
    timeout = 120 if blockchain_type == 'parity' else 30
    with gevent.Timeout(seconds=timeout, exception=exception):
        wait_for_token_networks(
            raiden_apps=raiden_apps,
            token_network_registry_address=token_network_registry_address,
            token_addresses=token_addresses,
        )

    app_channels = create_network_channels(
        raiden_apps,
        channels_per_node,
    )

    create_all_channels_for_network(
        app_channels=app_channels,
        token_addresses=token_addresses,
        channel_individual_deposit=deposit,
        channel_settle_timeout=settle_timeout,
        token_network_registry_address=token_network_registry_address,
        retry_timeout=retry_timeout,
    )

    exception = RuntimeError('`raiden_network` fixture setup failed, nodes are unreachable')
    timeout = 120 if blockchain_type == 'parity' else 30
    with gevent.Timeout(seconds=timeout, exception=exception):
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
