# -*- coding: utf-8 -*-
import gevent
import pytest
from ethereum import slogging

from raiden import waiting
from raiden.exceptions import RaidenShuttingDown
from raiden.tests.utils.tests import cleanup_tasks
from raiden.tests.utils.network import (
    CHAIN,
    create_apps,
    create_network_channels,
    create_sequential_channels,
    netting_channel_open_and_deposit,
)

log = slogging.getLogger(__name__)  # pylint: disable=invalid-name


def _raiden_cleanup(request, raiden_apps):
    """ Helper to do cleanup a Raiden App. """
    def _cleanup():
        for app in raiden_apps:
            try:
                app.stop(leave_channels=False)
            except RaidenShuttingDown:
                pass

        # Two tests in sequence could run a UDP server on the same port, a hanging
        # greenlet from the previous tests could send packet to the new server and
        # mess things up. Kill all greenlets to make sure that no left-over state
        # from a previous test interferes with a new one.
        cleanup_tasks()
    request.addfinalizer(_cleanup)


def wait_for_usable_channel(
        app0,
        app1,
        registry_address,
        token_address,
        our_deposit,
        partner_deposit,
        events_poll_timeout=0.5,
):
    """ Wait until the channel from app0 to app1 is usable.

    The channel and the deposits are registered, and the partner network state
    is reachable.
    """
    waiting.wait_for_newchannel(
        app0.raiden,
        registry_address,
        token_address,
        app1.raiden.address,
        events_poll_timeout,
    )

    waiting.wait_for_participant_newbalance(
        app0.raiden,
        registry_address,
        token_address,
        app1.raiden.address,
        app0.raiden.address,
        our_deposit,
        events_poll_timeout,
    )

    waiting.wait_for_participant_newbalance(
        app0.raiden,
        registry_address,
        token_address,
        app1.raiden.address,
        app1.raiden.address,
        partner_deposit,
        events_poll_timeout,
    )

    waiting.wait_for_healthy(
        app0.raiden,
        app1.raiden.address,
        events_poll_timeout,
    )


def wait_for_channels(
        app_channels,
        registry_address,
        token_addresses,
        deposit,
        events_poll_timeout=0.5,
):
    """ Wait until all channels are usable from both directions. """
    for app0, app1 in app_channels:
        for token_address in token_addresses:
            wait_for_usable_channel(
                app0,
                app1,
                registry_address,
                token_address,
                deposit,
                deposit,
                events_poll_timeout,
            )
            wait_for_usable_channel(
                app1,
                app0,
                registry_address,
                token_address,
                deposit,
                deposit,
                events_poll_timeout,
            )


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

    for app in raiden_apps:
        app.raiden.register_payment_network(app.raiden.default_registry.address)

    app_channels = create_sequential_channels(
        raiden_apps,
        channels_per_node,
    )

    if not cached_genesis:
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

    exception = RuntimeError('fixture setup failed, nodes are unreachable')
    with gevent.Timeout(seconds=30, exception=exception):
        wait_for_channels(
            app_channels,
            blockchain_services.deploy_registry.address,
            token_addresses,
            deposit,
        )

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

    app_channels = create_network_channels(
        raiden_apps,
        channels_per_node,
    )

    if not cached_genesis:
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

    exception = RuntimeError('fixture setup failed, nodes are unreachable')
    with gevent.Timeout(seconds=30, exception=exception):
        wait_for_channels(
            app_channels,
            blockchain_services.deploy_registry.address,
            token_addresses,
            deposit,
        )

    _raiden_cleanup(request, raiden_apps)

    # Force blocknumber update for the tester backend
    if not cached_genesis:
        for app in raiden_apps:
            app.raiden.alarm.poll_for_new_block()

    return raiden_apps
