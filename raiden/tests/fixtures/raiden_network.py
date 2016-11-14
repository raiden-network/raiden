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
            app.stop()

        # Two tests in sequence could run a UDP server on the same port, a hanging
        # greenlet from the previous tests could send packet to the new server and
        # mess things up. Kill all greenlets to make sure that no left-over state
        # from a previous test interferes with a new one.
        cleanup_tasks()
    request.addfinalizer(_cleanup)


@pytest.fixture
def raiden_chain(
        request,
        assets_addresses,
        channels_per_node,
        deposit,
        settle_timeout,
        blockchain_services,
        transport_class,
        cached_genesis):

    if len(assets_addresses) > 1:
        raise ValueError('raiden_chain only works with a single asset')

    assert channels_per_node in (0, 1, 2, CHAIN), (
        'deployed_network uses create_sequential_network that can only work '
        'with 0, 1 or 2 channels'
    )

    verbosity = request.config.option.verbose

    raiden_apps = create_apps(
        blockchain_services.blockchain_services,
        transport_class,
        verbosity,
    )

    if not cached_genesis:
        create_sequential_channels(
            raiden_apps,
            assets_addresses[0],
            channels_per_node,
            deposit,
            settle_timeout,
        )

    for app in raiden_apps:
        app.raiden.register_registry(app.raiden.chain.default_registry)

    _raiden_cleanup(request, raiden_apps)

    return raiden_apps


@pytest.fixture
def raiden_network(
        request,
        assets_addresses,
        channels_per_node,
        deposit,
        settle_timeout,
        blockchain_services,
        transport_class,
        cached_genesis):

    verbosity = request.config.option.verbose

    raiden_apps = create_apps(
        blockchain_services.blockchain_services,
        transport_class,
        verbosity,
    )

    if not cached_genesis:
        create_network_channels(
            raiden_apps,
            assets_addresses,
            channels_per_node,
            deposit,
            settle_timeout,
        )

    for app in raiden_apps:
        app.raiden.register_registry(app.raiden.chain.default_registry)

    _raiden_cleanup(request, raiden_apps)

    return raiden_apps
