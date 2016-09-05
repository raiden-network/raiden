# -*- coding: utf8 -*-
from __future__ import print_function

import time

import gevent
from ethereum import slogging
from ethereum.utils import sha3

from raiden.app import DEFAULT_SETTLE_TIMEOUT
from raiden.network.rpc.client import (
    BlockChainServiceMock,
    DEFAULT_POLL_TIMEOUT,
    MOCK_REGISTRY_ADDRESS,
)
from raiden.network.transport import UDPTransport
from raiden.tests.utils.network import create_network
from raiden.benchmark.utils import (
    print_serialization,
    print_slow_function,
    print_slow_path,
)

log = slogging.getLogger('test.speed')  # pylint: disable=invalid-name
slogging.configure(':debug')


def test_mediated_transfer(num_transfers=100, num_nodes=10, num_assets=1,
                           channels_per_node=2, deposit=100):
    # pylint: disable=too-many-locals

    assert num_assets <= num_nodes

    private_keys = [
        sha3('mediated_transfer:{}'.format(position))
        for position in range(num_nodes)
    ]

    assets = [
        sha3('asset:{}'.format(number))[:20]
        for number in range(num_assets)
    ]

    BlockChainServiceMock._instance = True
    blockchain_service = BlockChainServiceMock(None, MOCK_REGISTRY_ADDRESS)
    BlockChainServiceMock._instance = blockchain_service  # pylint: disable=redefined-variable-type

    registry = blockchain_service.registry(MOCK_REGISTRY_ADDRESS)
    for asset in assets:
        registry.add_asset(asset)

    apps = create_network(
        private_keys,
        assets,
        MOCK_REGISTRY_ADDRESS,
        channels_per_node,
        deposit,
        DEFAULT_SETTLE_TIMEOUT,
        DEFAULT_POLL_TIMEOUT,
        UDPTransport,
        BlockChainServiceMock
    )

    def start_transfers(idx, curr_asset, num_transfers):
        amount = 10
        curr_app = apps[idx]
        asset_manager = curr_app.raiden.get_manager_by_asset_address(curr_asset)

        all_paths = asset_manager.channelgraph.get_paths_of_length(
            source=curr_app.raiden.address,
            num_hops=2,
        )
        path = all_paths[0]
        target = path[-1]

        finished = gevent.event.Event()

        def _completion_cb(task, success):
            _completion_cb.num_transfers -= 1
            if _completion_cb.num_transfers > 0:
                curr_app.raiden.api.transfer_async(curr_asset, amount, target)
            else:
                finished.set()

        _completion_cb.num_transfers = num_transfers
        assetmanagers_by_address = {
            node.raiden.address: node.raiden.managers_by_asset_address
            for node in apps
        }

        next_hop = path[1]
        next_assetmanager = assetmanagers_by_address[next_hop][curr_asset]
        next_assetmanager.transfermanager.on_task_completed_callbacks.append(_completion_cb)

        curr_app.raiden.api.transfer_async(curr_asset, amount, target)
        return finished

    finished_events = []

    # Start all transfers
    start_time = time.time()
    for idx, curr_asset in enumerate(assets):
        print('finished {}'.format(idx))
        finished = start_transfers(idx, curr_asset, num_transfers)
        finished_events.append(finished)

    # Wait until all transfers are done
    gevent.wait(finished_events)
    elapsed = time.time() - start_time

    completed_transfers = num_transfers * num_assets
    tps = completed_transfers / elapsed
    print('Completed {} transfers at {} tps / {:.7}s'.format(completed_transfers, tps, elapsed))


def main():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('--transfers', default=100, type=int)
    parser.add_argument('--nodes', default=10, type=int)
    parser.add_argument('--assets', default=1, type=int)
    parser.add_argument('--channels-per-node', default=2, type=int)
    parser.add_argument('-p', '--profile', default=False, action='store_true')
    args = parser.parse_args()

    if args.profile:
        import GreenletProfiler
        GreenletProfiler.set_clock_type('cpu')
        GreenletProfiler.start()

    test_mediated_transfer(
        num_transfers=args.transfers,
        num_nodes=args.nodes,
        num_assets=args.assets,
        channels_per_node=args.channels_per_node,
    )

    if args.profile:
        GreenletProfiler.stop()
        stats = GreenletProfiler.get_func_stats()
        pstats = GreenletProfiler.convert2pstats(stats)

        print_serialization(pstats)
        print_slow_path(pstats)
        print_slow_function(pstats)

        pstats.sort_stats('time').print_stats()
        # stats.save('profile.callgrind', type='callgrind')


if __name__ == '__main__':
    main()
