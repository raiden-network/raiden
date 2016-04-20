# -*- coding: utf8 -*-
from __future__ import print_function

import contextlib
import timeit

from raiden.utils import privtoaddr, sha3
from raiden.messages import (
    Ack, Ping, SecretRequest, Secret, Transfer, Lock, LockedTransfer,
    MediatedTransfer, CancelTransfer, TransferTimeout, ConfirmTransfer, decode,
)


PRIVKEY = 'x' * 32
ADDRESS = privtoaddr(PRIVKEY)
HASH = sha3(PRIVKEY)
ITERATIONS = 1000000  # timeit default


def run_timeit(message_name, message, iterations=ITERATIONS):
    data = message.encode()

    def test_encode():
        message.encode()

    def test_decode():
        decode(data)

    encode_time = timeit.timeit(test_encode, number=iterations)
    decode_time = timeit.timeit(test_decode, number=iterations)

    print('{}: encode {} decode {}'.format(message_name, encode_time, decode_time))


def test_ack(iterations=ITERATIONS):
    msg = Ack(ADDRESS, HASH)
    run_timeit('Ack', msg, iterations=iterations)


def test_ping(iterations=ITERATIONS):
    msg = Ping(nonce=0).sign(PRIVKEY)
    run_timeit('Ping', msg, iterations=iterations)


# def test_rejected(iterations=ITERATIONS):
#     msg = Rejected(HASH, 1, []).sign(PRIVKEY)
#     run_timeit('Rejected', msg, iterations=iterations)
# def test_rejected_with_args(iterations=ITERATIONS):
#     msg = Rejected(HASH, 1, [1, 2, 3])
#     run_timeit('Rejected with args', msg, iterations=iterations)


def test_secret_request(iterations=ITERATIONS):
    hashlock = HASH
    msg = SecretRequest(hashlock).sign(PRIVKEY)
    run_timeit('SecretRequest', msg, iterations=iterations)


def test_secret(iterations=ITERATIONS):
    secret = HASH
    msg = Secret(secret).sign(PRIVKEY)
    run_timeit('Secret', msg, iterations=iterations)


def test_transfer(iterations=ITERATIONS):
    nonce = 1
    asset = ADDRESS
    balance = 1
    recipient = ADDRESS
    locksroot = HASH

    msg = Transfer(nonce, asset, balance, recipient, locksroot).sign(PRIVKEY)
    run_timeit('Transfer', msg, iterations=iterations)


def test_locked_transfer(iterations=ITERATIONS):
    amount = 1
    expiration = 1
    hashlock = sha3(ADDRESS)
    lock = Lock(amount, expiration, hashlock)

    nonce = 1
    asset = ADDRESS
    balance = 1
    recipient = ADDRESS
    locksroot = sha3(ADDRESS)
    msg = LockedTransfer(nonce, asset, balance, recipient, locksroot, lock).sign(PRIVKEY)
    run_timeit('LockedTransfer', msg, iterations=iterations)


def test_mediated_transfer(iterations=ITERATIONS):
    amount = 1
    expiration = 1
    hashlock = sha3(ADDRESS)
    lock = Lock(amount, expiration, hashlock)

    nonce = 1
    asset = ADDRESS
    balance = 1
    recipient = ADDRESS
    locksroot = sha3(ADDRESS)
    target = ADDRESS
    initiator = ADDRESS
    msg = MediatedTransfer(nonce, asset, balance, recipient, locksroot,
                           lock, target, initiator, fee=0)
    msg.sign(PRIVKEY)

    run_timeit('MediatedTranfer', msg, iterations=iterations)


def test_cancel_transfer(iterations=ITERATIONS):
    amount = 1
    expiration = 1
    hashlock = sha3(ADDRESS)
    lock = Lock(amount, expiration, hashlock)

    nonce = 1
    asset = ADDRESS
    balance = 1
    recipient = ADDRESS
    locksroot = sha3(ADDRESS)
    msg = CancelTransfer(nonce, asset, balance, recipient, locksroot, lock).sign(PRIVKEY)
    run_timeit('CancelTransfer', msg, iterations=iterations)


def test_transfer_timeout(iterations=ITERATIONS):
    echo = HASH
    hashlock = HASH
    msg = TransferTimeout(echo, hashlock).sign(PRIVKEY)
    run_timeit('TransferTimeout', msg, iterations=iterations)


def test_confirm_transfer(iterations=ITERATIONS):
    hashlock = HASH
    msg = ConfirmTransfer(hashlock).sign(PRIVKEY)
    run_timeit('ConfirmTransfer', msg, iterations=iterations)


def test_all(iterations=ITERATIONS):
    test_ack(iterations=iterations)
    test_ping(iterations=iterations)
    # needs the args type
    # test_reject(iterations=iterations)
    # test_reject_with_args(iterations=iterations)
    test_secret_request(iterations=iterations)
    test_transfer(iterations=iterations)
    test_locked_transfer(iterations=iterations)
    test_mediated_transfer(iterations=iterations)
    test_cancel_transfer(iterations=iterations)
    test_transfer_timeout(iterations=iterations)
    test_confirm_transfer(iterations=iterations)


@contextlib.contextmanager
def profile_session(bias=None):
    # we are not running more than one greenlet in this test, so it's fine to
    # use python's standard profiler
    import cProfile
    import profile
    import pstats

    if bias is None:
        bias_profiler = profile.Profile()
        runs = [bias_profiler.calibrate(100000) for __ in range(5)]
        bias = min(runs)

        # the bias should be consistent, otherwise we need to increase the number of iterations
        msg = 'Bias calculations: {}, used bias: {}'.format(runs, bias)
        print(msg)

    profiler = cProfile.Profile()
    profiler.bias = bias
    profiler.enable()

    yield

    profiler.create_stats()
    stats = pstats.Stats(profiler)
    stats.strip_dirs().sort_stats('cumulative').print_stats(15)
    stats.strip_dirs().sort_stats('time').print_stats(15)


def main():
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument('name', default='test_all', nargs='?')
    parser.add_argument('-i', '--iterations', default=ITERATIONS, type=int)
    parser.add_argument('-p', '--profile', default=False, action='store_true')
    parser.add_argument('--bias', default=None, action='store', type=float)

    args = parser.parse_args()

    test_name = args.name
    iterations = args.iterations
    do_profile = args.profile
    bias = args.bias

    if test_name not in globals():
        raise ValueError('unknow test name: {}'.format(test_name))

    test_function = globals()[test_name]

    if do_profile or bias is not None:
        with profile_session(bias=bias):
            test_function(iterations=iterations)
    else:
        test_function(iterations=iterations)


if __name__ == '__main__':
    main()
