# -*- coding: utf-8 -*-
import pytest
from ethereum import slogging

from raiden.tests.utils.tests import cleanup_tasks
from raiden.tests.utils.network import (
    CHAIN,
    create_apps,
    create_network_channels,
    create_sequential_channels,
)

log = slogging.getLogger(__name__)  # pylint: disable=invalid-name


def _raiden_cleanup(request, raiden_apps):
    """ Helper to do cleanup a Raiden App. """
    def _cleanup():
        for app in raiden_apps:
            app.stop(leave_channels=False)

        # Two tests in sequence could run a UDP server on the same port, a hanging
        # greenlet from the previous tests could send packet to the new server and
        # mess things up. Kill all greenlets to make sure that no left-over state
        # from a previous test interferes with a new one.
        cleanup_tasks()
    request.addfinalizer(_cleanup)


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
        transport_class,
        cached_genesis,
        reveal_timeout,
        database_paths,
        retry_interval,
        retries_before_backoff,
        throttle_capacity,
        throttle_fill_rate,
        nat_invitation_timeout,
        nat_keepalive_retries,
        nat_keepalive_timeout):

    if len(token_addresses) > 1:
        raise ValueError('raiden_chain only works with a single token')

    assert channels_per_node in (0, 1, 2, CHAIN), (
        'deployed_network uses create_sequential_network that can only work '
        'with 0, 1 or 2 channels'
    )

    raiden_apps = create_apps(
        blockchain_services.blockchain_services,
        endpoint_discovery_services,
        blockchain_services.deploy_registry.address,
        raiden_udp_ports,
        transport_class,
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
    )

    if not cached_genesis:
        create_sequential_channels(
            raiden_apps,
            token_addresses[0],
            channels_per_node,
            deposit,
            settle_timeout,
        )

    for app in raiden_apps:
        app.raiden.register_registry(app.raiden.default_registry.address)

    _raiden_cleanup(request, raiden_apps)

    return raiden_apps


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
        transport_class,
        cached_genesis,
        reveal_timeout,
        database_paths,
        retry_interval,
        retries_before_backoff,
        throttle_capacity,
        throttle_fill_rate,
        nat_invitation_timeout,
        nat_keepalive_retries,
        nat_keepalive_timeout):

    raiden_apps = create_apps(
        blockchain_services.blockchain_services,
        endpoint_discovery_services,
        blockchain_services.deploy_registry.address,
        raiden_udp_ports,
        transport_class,
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
    )

    if not cached_genesis:
        create_network_channels(
            raiden_apps,
            token_addresses,
            channels_per_node,
            deposit,
            settle_timeout
        )

    _raiden_cleanup(request, raiden_apps)

    # The block_number is primed on the app creation, but after the app is
    # created all the channels are deployed, for the tester implementation this
    # will advance the block_number with synchronous execution, making the
    # apps' block_number to greatly fall behind.
    if not cached_genesis:
        for app in raiden_apps:
            app.raiden.alarm.poll_for_new_block()

    return raiden_apps
