# -*- coding: utf8 -*-
from __future__ import print_function

import time

from raiden.tests.utils.network import create_network
from raiden.utils import sha3


def transfer_speed(num_transfers=100, max_locked=100):  # pylint: disable=too-many-locals
    num_nodes = 2
    num_assets = 1

    private_keys = [
        sha3('speed:{}'.format(position))
        for position in range(num_nodes)
    ]

    assets = [
        sha3('asset:{}'.format(number))[:20]
        for number in range(num_assets)
    ]

    apps = create_network(
        private_keys,
        assets,
        channels_per_node=1,
    )

    app0, app1 = apps  # pylint: disable=unbalanced-tuple-unpacking
    channel0 = app0.raiden.assetmanagers.values()[0].channels.values()[0]
    channel1 = app1.raiden.assetmanagers.values()[0].channels.values()[0]

    amounts = [a % 100 + 1 for a in range(1, num_transfers + 1)]
    secrets = [str(i) for i in range(num_transfers)]
    expiration = app0.raiden.chain.block_number + 100

    start = time.time()

    for i, amount in enumerate(amounts):
        hashlock = sha3(secrets[i])
        locked_transfer = channel0.create_lockedtransfer(
            amount=amount,
            expiration=expiration,
            hashlock=hashlock,
        )
        app0.raiden.sign(locked_transfer)
        channel0.register_transfer(locked_transfer)
        channel1.register_transfer(locked_transfer)

        if i > max_locked:
            idx = i - max_locked
            secret = secrets[idx]
            channel0.claim_locked(secret)
            channel1.claim_locked(secret)

    elapsed = time.time() - start
    print('%d transfers per second' % (num_transfers / elapsed))


if __name__ == '__main__':
    transfer_speed(10000, 100)
