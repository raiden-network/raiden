# -*- coding: utf-8 -*-

import time

from raiden.settings import (
    DEFAULT_SETTLE_TIMEOUT,
    DEFAULT_POLL_TIMEOUT,
    DEFAULT_REVEAL_TIMEOUT,
)
from raiden.tests.utils.tester_client import (
    BlockChainServiceTesterMock,
)
from raiden.tests.fixtures.tester import (
    tester_blockgas_limit,
    tester_channelmanager_library_address,
    tester_nettingchannel_library_address,
    tester_registry_address,
    tester_chain,
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
        sha3('speed:{}'.format(position).encode())
        for position in range(num_nodes)
    ]

    tokens = [
        sha3('token:{}'.format(number).encode())[:20]
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

    blockchain_services = list()
    tester = tester_chain(
        private_keys[0],
        private_keys,
        tester_blockgas_limit(),
    )
    nettingchannel_library_address = tester_nettingchannel_library_address(
        tester_chain,
    )
    channelmanager_library_address = tester_channelmanager_library_address(
        tester_chain,
        nettingchannel_library_address,
    )
    registry_address = tester_registry_address(
        tester_chain,
        channelmanager_library_address,
    )
    for privkey in private_keys:
        blockchain = BlockChainServiceTesterMock(
            privkey,
            tester,
        )
        blockchain_services.append(blockchain)

    registry = blockchain_services[0].registry(registry_address)

    for token in tokens:
        registry.add_token(token)

    apps = create_network(
        private_keys,
        tokens,
        registry_address,
        channels_per_node,
        deposit,
        DEFAULT_SETTLE_TIMEOUT,
        DEFAULT_POLL_TIMEOUT,
        UDPTransport,
        BlockChainServiceTesterMock,
    )

    app0, app1 = apps  # pylint: disable=unbalanced-tuple-unpacking
    channel0 = list(app0.raiden.token_to_channelgraph[tokens[0]].address_to_channel.values())[0]
    channel1 = list(app1.raiden.token_to_channelgraph[tokens[0]].address_to_channel.values())[0]

    expiration = app0.raiden.chain.block_number() + DEFAULT_REVEAL_TIMEOUT + 3

    start = time.time()

    for i, amount in enumerate(amounts):
        hashlock = sha3(secrets[i].encode())
        locked_transfer = channel0.create_lockedtransfer(
            amount=amount,
            identifier=1,  # TODO: fill in identifier
            expiration=expiration,
            hashlock=hashlock,
        )
        app0.raiden.sign(locked_transfer)

        channel0.register_transfer(
            app0.raiden.get_block_number(),
            locked_transfer,
        )
        channel1.register_transfer(
            app0.raiden.get_block_number(),
            locked_transfer,
        )

        if i > max_locked:
            idx = i - max_locked
            secret = secrets[idx]
            channel0.register_secret(secret)
            channel1.register_secret(secret)

    elapsed = time.time() - start
    print('{} transfers per second'.format(num_transfers / elapsed))


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
