# -*- coding: utf8 -*-
import pytest
from ethereum.utils import sha3

from raiden.app import DEFAULT_SETTLE_TIMEOUT
from raiden.network.rpc.client import BlockChainServiceMock, MOCK_REGISTRY_ADDRESS
from raiden.network.transport import UDPTransport
from raiden.tests.utils.messages import setup_messages_cb
from raiden.tests.utils.network import create_network
from raiden.web_ui import WebUI, UIHandler

# Start:
# 1) `python test_webui.py`
# 2) interact in browser on 'localhost:8080'
# 3) copy availabe addresses from terminal to browser for interaction
# 4) it is not guaranteed that a channel to a specific address exists


@pytest.mark.skipif(True, reason='UI has to be tested manually')
def test_webui():  # pylint: disable=too-many-locals
    num_assets = 3
    num_nodes = 10

    assets_addresses = [
        sha3('webui:asset:{}'.format(number))[:20]
        for number in range(num_assets)
    ]

    private_keys = [
        sha3('webui:{}'.format(position))
        for position in range(num_nodes)
    ]

    channels_per_node = 2
    deposit = 100
    app_list = create_network(
        private_keys,
        assets_addresses,
        MOCK_REGISTRY_ADDRESS,
        channels_per_node,
        deposit,
        DEFAULT_SETTLE_TIMEOUT,
        UDPTransport,
        BlockChainServiceMock
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

    am0 = app0.raiden.assetmanagers.values()[0]

    # search for a path of length=2 A > B > C
    num_hops = 2
    source = app0.raiden.address

    path_list = am0.channelgraph.get_paths_of_length(source, num_hops)
    assert len(path_list)

    for path in path_list:
        assert len(path) == num_hops + 1
        assert path[0] == source

    path = path_list[0]
    target = path[-1]
    assert path in am0.channelgraph.get_shortest_paths(source, target)
    assert min(len(p) for p in am0.channelgraph.get_shortest_paths(source, target)) == num_hops + 1

    app0_assets = getattr(app0.raiden.api, 'assets')
    print '\nAvailable assets:'
    for asset in app0_assets:
        print asset.encode('hex')
    print '\n'

    handler = UIHandler(app0.raiden)
    WebUI(handler).run()


if __name__ == '__main__':
    test_webui()
