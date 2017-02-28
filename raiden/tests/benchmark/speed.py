# -*- coding: utf-8 -*-
from __future__ import print_function, division

import time

import gevent
from ethereum import slogging
from ethereum.utils import sha3

from raiden.settings import DEFAULT_SETTLE_TIMEOUT
from raiden.tests.utils.mock_client import (
    BlockChainServiceMock,
    MOCK_REGISTRY_ADDRESS,
)
from raiden.network.transport import UDPTransport
from raiden.tests.utils.network import create_network
from raiden.tests.benchmark.utils import (
    print_serialization,
    print_slow_function,
    print_slow_path,
)

log = slogging.getLogger('test.speed')  # pylint: disable=invalid-name


def setup_apps(amount, tokens, num_transfers, num_nodes, channels_per_node):
    assert len(tokens) <= num_nodes

    deposit = amount * num_transfers

    private_keys = [
        sha3('mediated_transfer:{}'.format(position))
        for position in range(num_nodes)
    ]

    BlockChainServiceMock.reset()
    blockchain_services = list()
    for privkey in private_keys:
        blockchain = BlockChainServiceMock(
            privkey,
            MOCK_REGISTRY_ADDRESS,
        )
        blockchain_services.append(blockchain)

    registry = blockchain_services[0].registry(MOCK_REGISTRY_ADDRESS)
    for token in tokens:
        registry.add_token(token)

    verbosity = 3
    apps = create_network(
        blockchain_services,
        tokens,
        channels_per_node,
        deposit,
        DEFAULT_SETTLE_TIMEOUT,
        UDPTransport,
        verbosity,
    )

    return apps


def test_throughput(apps, tokens, num_transfers, amount):
    def start_transfers(curr_app, curr_token, num_transfers):
        graph = curr_app.raiden.channelgraphs[curr_token]

        all_paths = graph.get_paths_of_length(
            source=curr_app.raiden.address,
            num_hops=2,
        )
        path = all_paths[0]
        target = path[-1]

        api = curr_app.raiden.api
        events = list()

        for i in range(num_transfers):
            async_result = api.transfer_async(
                curr_token,
                amount,
                target,
                1)  # TODO: fill in identifier
            events.append(async_result)

        return events

    finished_events = []

    # Start all transfers
    start_time = time.time()
    for idx, curr_token in enumerate(tokens):
        curr_app = apps[idx]
        finished = start_transfers(curr_app, curr_token, num_transfers)
        finished_events.extend(finished)

    # Wait until the transfers for all tokens are done
    gevent.wait(finished_events)
    elapsed = time.time() - start_time

    completed_transfers = num_transfers * len(tokens)
    tps = completed_transfers / elapsed
    print('Completed {} transfers {:.5} tps / {:.5}s'.format(completed_transfers, tps, elapsed))


def test_latency(apps, tokens, num_transfers, amount):
    def start_transfers(idx, curr_token, num_transfers):
        curr_app = apps[idx]
        graph = curr_app.raiden.channelgraphs[curr_token]

        all_paths = graph.get_paths_of_length(
            source=curr_app.raiden.address,
            num_hops=2,
        )
        path = all_paths[0]
        target = path[-1]

        finished = gevent.event.Event()

        def _transfer():
            api = curr_app.raiden.api
            for i in range(num_transfers):
                async_result = api.transfer_async(
                    curr_token,
                    amount,
                    target,
                    1  # TODO: fill in identifier
                )
                async_result.wait()

            finished.set()

        gevent.spawn(_transfer)
        return finished

    finished_events = []

    # Start all transfers
    start_time = time.time()
    for idx, curr_token in enumerate(tokens):
        finished = start_transfers(idx, curr_token, num_transfers)
        finished_events.append(finished)

    # Wait until the transfers for all tokens are done
    gevent.wait(finished_events)
    elapsed = time.time() - start_time
    completed_transfers = num_transfers * len(tokens)

    tps = completed_transfers / elapsed
    print('Completed {} transfers. tps:{:.5} latency:{:.5} time:{:.5}s'.format(
        completed_transfers,
        tps,
        elapsed / completed_transfers,
        elapsed,
    ))


def main():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('--transfers', default=100, type=int)
    parser.add_argument('--nodes', default=10, type=int)
    parser.add_argument('--tokens', default=1, type=int)
    parser.add_argument('--channels-per-node', default=2, type=int)
    parser.add_argument('-p', '--profile', default=False, action='store_true')
    parser.add_argument('--pdb', default=False, action='store_true')
    parser.add_argument('--throughput', dest='throughput', action='store_true', default=True)
    parser.add_argument('--latency', dest='throughput', action='store_false')
    parser.add_argument('--log', action='store_true', default=False)
    args = parser.parse_args()

    if args.log:
        slogging.configure(':DEBUG')

    if args.profile:
        import GreenletProfiler
        GreenletProfiler.set_clock_type('cpu')
        GreenletProfiler.start()

    tokens = [
        sha3('token:{}'.format(number))[:20]
        for number in range(args.tokens)
    ]

    amount = 10
    apps = setup_apps(
        amount,
        tokens,
        args.transfers,
        args.nodes,
        args.channels_per_node,
    )

    if args.pdb:
        from pyethapp.utils import enable_greenlet_debugger
        enable_greenlet_debugger()

        try:
            if args.throughput:
                test_throughput(apps, tokens, args.transfers, amount)
            else:
                test_latency(apps, tokens, args.transfers, amount)
        except:
            import pdb
            pdb.xpm()
    else:
        if args.throughput:
            test_throughput(apps, tokens, args.transfers, amount)
        else:
            test_latency(apps, tokens, args.transfers, amount)

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
