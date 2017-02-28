# -*- coding: utf-8 -*-
from __future__ import print_function

import time

from raiden.settings import (
    DEFAULT_SETTLE_TIMEOUT,
    DEFAULT_POLL_TIMEOUT,
    DEFAULT_REVEAL_TIMEOUT,
)
from raiden.network.rpc.client import (
    BlockChainServiceMock,
    MOCK_REGISTRY_ADDRESS,
)
from raiden.network.transport import UDPTransport
from raiden.tests.utils.network import create_network
from raiden.utils import sha3
from raiden.tests.benchmark.utils import (
    print_serialization,
    print_slow_function,
    print_slow_path,
)


def transfer_speed(num_transfers=100, max_locked=100):  # pylint: disable=too-many-locals
    channels_per_node = 1
    num_nodes = 2
    num_tokens = 1

    private_keys = [
        sha3('speed:{}'.format(position))
        for position in range(num_nodes)
    ]

    tokens = [
        sha3('token:{}'.format(number))[:20]
        for number in range(num_tokens)
    ]

    amounts = [
        a % 100 + 1
        for a in range(1, num_transfers + 1)
    ]

    deposit = sum(amounts)

    secrets = [
        str(i)
        for i in range(num_transfers)
    ]

    BlockChainServiceMock._instance = True
    blockchain_service = BlockChainServiceMock(None, MOCK_REGISTRY_ADDRESS)
    BlockChainServiceMock._instance = blockchain_service  # pylint: disable=redefined-variable-type

    registry = blockchain_service.registry(MOCK_REGISTRY_ADDRESS)
    for token in tokens:
        registry.add_token(token)

    apps = create_network(
        private_keys,
        tokens,
        MOCK_REGISTRY_ADDRESS,
        channels_per_node,
        deposit,
        DEFAULT_SETTLE_TIMEOUT,
        DEFAULT_POLL_TIMEOUT,
        UDPTransport,
        BlockChainServiceMock
    )

    app0, app1 = apps  # pylint: disable=unbalanced-tuple-unpacking
    channel0 = app0.raiden.channelgraphs[tokens[0]].address_channel.values()[0]
    channel1 = app1.raiden.channelgraphs[tokens[0]].address_channel.values()[0]

    expiration = app0.raiden.chain.block_number() + DEFAULT_REVEAL_TIMEOUT + 3

    start = time.time()

    for i, amount in enumerate(amounts):
        hashlock = sha3(secrets[i])
        locked_transfer = channel0.create_lockedtransfer(
            amount=amount,
            identifier=1,  # TODO: fill in identifier
            expiration=expiration,
            hashlock=hashlock,
        )
        app0.raiden.sign(locked_transfer)
        channel0.register_transfer(locked_transfer)
        channel1.register_transfer(locked_transfer)

        if i > max_locked:
            idx = i - max_locked
            secret = secrets[idx]
            channel0.register_secret(secret)
            channel1.register_secret(secret)

    elapsed = time.time() - start
    print('%d transfers per second' % (num_transfers / elapsed))


def main():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('--transfers', default=10000, type=int)
    parser.add_argument('--max-locked', default=100, type=int)
    parser.add_argument('-p', '--profile', default=False, action='store_true')
    args = parser.parse_args()

    if args.profile:
        import GreenletProfiler
        GreenletProfiler.set_clock_type('cpu')
        GreenletProfiler.start()

    transfer_speed(
        num_transfers=args.transfers,
        max_locked=args.max_locked,
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
