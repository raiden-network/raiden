# -*- coding: utf-8 -*-
import logging

import pytest
from ethereum.utils import sha3
from ethereum import slogging

from raiden.app import DEFAULT_SETTLE_TIMEOUT
from raiden.network.transport import UDPTransport
from raiden.tests.utils.messages import setup_messages_cb
from raiden.tests.utils.network import create_apps, create_network_channels
from raiden.tests.utils.mock_client import BlockChainServiceMock, MOCK_REGISTRY_ADDRESS
from raiden.api.wamp_server import WAMPRouter


# Start:
# 1) `python test_webui.py`
# 2) interact in browser on 'localhost:8080'
# 3) copy availabe addresses from terminal to browser for interaction
# -) it is not guaranteed that a channel to a specific address exists
# -) TODO: DirectTransfers will stay in the 'requesting' state because callbacks aren't handled yet


@pytest.mark.skipif(True, reason='UI has to be tested manually')
def test_webui():  # pylint: disable=too-many-locals
    num_assets = 3
    num_nodes = 10
    verbose = 0
    settle_timeout = DEFAULT_SETTLE_TIMEOUT

    assets_addresses = [
        sha3('webui:asset:{}'.format(number))[:20]
        for number in range(num_assets)
    ]

    private_keys = [
        sha3('webui:{}'.format(position))
        for position in range(num_nodes)
    ]

    BlockChainServiceMock.reset()
    blockchain_service = BlockChainServiceMock(None, MOCK_REGISTRY_ADDRESS)
    registry = blockchain_service.registry(MOCK_REGISTRY_ADDRESS)

    for asset in assets_addresses:
        registry.add_asset(asset)

    channels_per_node = 2
    deposit = 100

    blockchain_services = [
        BlockChainServiceMock(privkey, MOCK_REGISTRY_ADDRESS)
        for privkey in private_keys
    ]

    app_list = create_apps(
        blockchain_services,
        UDPTransport,
        verbose,
    )

    create_network_channels(
        app_list,
        assets_addresses,
        channels_per_node,
        deposit,
        settle_timeout,
    )

    app0 = app_list[0]

    addresses = [
        app.raiden.address.encode('hex')
        for app in app_list
        if app != app_list[0]
    ]

    print '\nCreated nodes: \n',
    for node in addresses:
        print node

    setup_messages_cb()

    app0_assets = getattr(app0.raiden.api, 'assets')
    print '\nAvailable assets:'
    for asset in app0_assets:
        print asset.encode('hex')
    print '\n'

    wamp = WAMPRouter(app0.raiden, 8080, ['channel', 'test'])
    wamp.run()

    BlockChainServiceMock.reset()


def main():
    slogging.configure(':DEBUG')
    logging.basicConfig(level=logging.DEBUG)

    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG)
    test_webui()


if __name__ == '__main__':
    main()
