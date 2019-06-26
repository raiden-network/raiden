import os

import gevent
import pytest

from raiden.constants import GENESIS_BLOCK_NUMBER
from raiden.tests.utils.ci import get_artifacts_storage
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


def timeout(blockchain_type: str):
    """As parity nodes are slower, we need to set a longer timeout when
    waiting for onchain events to complete."""
    return 120 if blockchain_type == "parity" else 30


@pytest.fixture
def raiden_chain(
    token_addresses,
    token_network_registry_address,
    one_to_n_address,
    channels_per_node,
    deposit,
    settle_timeout,
    chain_id,
    blockchain_services,
    reveal_timeout,
    retry_interval,
    retries_before_backoff,
    environment_type,
    unrecoverable_error_should_crash,
    local_matrix_servers,
    private_rooms,
    blockchain_type,
    contracts_path,
    user_deposit_address,
    monitoring_service_contract_address,
    global_rooms,
    tmpdir,
    request,
):

    if len(token_addresses) != 1:
        raise ValueError("raiden_chain only works with a single token")

    assert channels_per_node in (0, 1, 2, CHAIN), (
        "deployed_network uses create_sequential_network that can only work "
        "with 0, 1 or 2 channels"
    )

    base_datadir = os.path.join(
        get_artifacts_storage(request.node.name) or str(tmpdir), "raiden_nodes"
    )

    service_registry_address = None
    if blockchain_services.service_registry:
        service_registry_address = blockchain_services.service_registry.address
    raiden_apps = create_apps(
        chain_id=chain_id,
        blockchain_services=blockchain_services.blockchain_services,
        token_network_registry_address=token_network_registry_address,
        one_to_n_address=one_to_n_address,
        secret_registry_address=blockchain_services.secret_registry.address,
        service_registry_address=service_registry_address,
        user_deposit_address=user_deposit_address,
        monitoring_service_contract_address=monitoring_service_contract_address,
        reveal_timeout=reveal_timeout,
        settle_timeout=settle_timeout,
        database_basedir=base_datadir,
        retry_interval=retry_interval,
        retries_before_backoff=retries_before_backoff,
        environment_type=environment_type,
        unrecoverable_error_should_crash=unrecoverable_error_should_crash,
        local_matrix_url=local_matrix_servers[0],
        private_rooms=private_rooms,
        contracts_path=contracts_path,
        global_rooms=global_rooms,
    )

    confirmed_block = raiden_apps[0].raiden.confirmation_blocks + 1
    blockchain_services.deploy_service.wait_until_block(target_block_number=confirmed_block)

    parallel_start_apps(raiden_apps)

    from_block = GENESIS_BLOCK_NUMBER
    for app in raiden_apps:
        app.raiden.install_all_blockchain_filters(
            app.raiden.default_registry, app.raiden.default_secret_registry, from_block
        )

    exception = RuntimeError("`raiden_chain` fixture setup failed, token networks unavailable")
    with gevent.Timeout(seconds=timeout(blockchain_type), exception=exception):
        wait_for_token_networks(
            raiden_apps=raiden_apps,
            token_network_registry_address=token_network_registry_address,
            token_addresses=token_addresses,
        )

    app_channels = create_sequential_channels(raiden_apps, channels_per_node)

    create_all_channels_for_network(
        app_channels=app_channels,
        token_addresses=token_addresses,
        channel_individual_deposit=deposit,
        channel_settle_timeout=settle_timeout,
    )

    exception = RuntimeError("`raiden_chain` fixture setup failed, nodes are unreachable")
    with gevent.Timeout(seconds=timeout(blockchain_type), exception=exception):
        wait_for_channels(
            app_channels, blockchain_services.deploy_registry.address, token_addresses, deposit
        )

    yield raiden_apps

    shutdown_apps_and_cleanup_tasks(raiden_apps)


@pytest.fixture
def monitoring_service_contract_address():
    return bytes([1] * 20)


@pytest.fixture
def raiden_network(
    token_addresses,
    token_network_registry_address,
    one_to_n_address,
    channels_per_node,
    deposit,
    settle_timeout,
    chain_id,
    blockchain_services,
    reveal_timeout,
    retry_interval,
    retries_before_backoff,
    environment_type,
    unrecoverable_error_should_crash,
    local_matrix_servers,
    private_rooms,
    blockchain_type,
    contracts_path,
    user_deposit_address,
    monitoring_service_contract_address,
    global_rooms,
    tmpdir,
    request,
):
    service_registry_address = None
    if blockchain_services.service_registry:
        service_registry_address = blockchain_services.service_registry.address

    base_datadir = os.path.join(
        get_artifacts_storage(request.node.name) or str(tmpdir), "raiden_nodes"
    )

    raiden_apps = create_apps(
        chain_id=chain_id,
        contracts_path=contracts_path,
        blockchain_services=blockchain_services.blockchain_services,
        token_network_registry_address=token_network_registry_address,
        secret_registry_address=blockchain_services.secret_registry.address,
        service_registry_address=service_registry_address,
        one_to_n_address=one_to_n_address,
        user_deposit_address=user_deposit_address,
        monitoring_service_contract_address=monitoring_service_contract_address,
        reveal_timeout=reveal_timeout,
        settle_timeout=settle_timeout,
        database_basedir=base_datadir,
        retry_interval=retry_interval,
        retries_before_backoff=retries_before_backoff,
        environment_type=environment_type,
        unrecoverable_error_should_crash=unrecoverable_error_should_crash,
        local_matrix_url=local_matrix_servers[0],
        private_rooms=private_rooms,
        global_rooms=global_rooms,
    )

    confirmed_block = raiden_apps[0].raiden.confirmation_blocks + 1
    blockchain_services.deploy_service.wait_until_block(target_block_number=confirmed_block)

    parallel_start_apps(raiden_apps)

    exception = RuntimeError("`raiden_chain` fixture setup failed, token networks unavailable")
    with gevent.Timeout(seconds=timeout(blockchain_type), exception=exception):
        wait_for_token_networks(
            raiden_apps=raiden_apps,
            token_network_registry_address=token_network_registry_address,
            token_addresses=token_addresses,
        )

    app_channels = create_network_channels(raiden_apps, channels_per_node)

    create_all_channels_for_network(
        app_channels=app_channels,
        token_addresses=token_addresses,
        channel_individual_deposit=deposit,
        channel_settle_timeout=settle_timeout,
    )

    exception = RuntimeError("`raiden_network` fixture setup failed, nodes are unreachable")
    with gevent.Timeout(seconds=timeout(blockchain_type), exception=exception):
        wait_for_channels(
            app_channels, blockchain_services.deploy_registry.address, token_addresses, deposit
        )

    # Force blocknumber update
    exception = RuntimeError("Alarm failed to start and set up start_block correctly")

    with gevent.Timeout(seconds=5, exception=exception):
        wait_for_alarm_start(raiden_apps)

    yield raiden_apps

    shutdown_apps_and_cleanup_tasks(raiden_apps)
