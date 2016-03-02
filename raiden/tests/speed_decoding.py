# -*- coding: utf8 -*-
import timeit

from raiden.utils import privtoaddr, sha3
from raiden.encoding import Decoder
from raiden.messages import (
    Ack, Ping, Rejected, SecretRequest, Secret, Transfer, Lock, LockedTransfer,
    MediatedTransfer, CancelTransfer, TransferTimeout, ConfirmTransfer,
)


privkey = 'x' * 32
address = privtoaddr(privkey)
hash_ = sha3(privkey)
decode = Decoder(extra_klasses=[MediatedTransfer, CancelTransfer]).decode


def run_timeit(message_name, message):
    data = message.encode()

    def test_encode():
        message.encode()

    def test_decode():
        decode(data)

    encode_time = timeit.timeit(test_encode)
    decode_time = timeit.timeit(test_decode)

    print('{}: encode {} decode {}'.format(message_name, encode_time, decode_time))


def test_ack():
    msg = Ack(address, hash_)
    run_timeit('Ack', msg)


def test_ping():
    msg = Ping(nonce=0).sign(privkey)
    run_timeit('Ping', msg)


# FIXME:
def test_rejected():
    msg = Rejected(hash_, 1, []).sign(privkey)
    run_timeit('Rejected', msg)


# FIXME:
def test_rejected_with_args():
    msg = Rejected(hash_, 1, [1, 2, 3])
    run_timeit('Rejected with args', msg)


def test_secret_request():
    hashlock = hash_
    msg = SecretRequest(hashlock).sign(privkey)
    run_timeit('SecretRequest', msg)


def test_secret():
    secret = hash_
    msg = Secret(secret).sign(privkey)
    run_timeit('Secret', msg)


def test_transfer():
    nonce = 1
    asset = hash_
    balance = 1
    recipient = hash_
    locksroot = hash_

    msg = Transfer(nonce, asset, balance, recipient, locksroot).sign(privkey)
    run_timeit('Transfer', msg)


def test_locked_transfer():
    amount = 1
    expiration = 1
    hashlock = sha3(address)
    lock = Lock(amount, expiration, hashlock)

    nonce = 1
    asset = hash_
    balance = 1
    recipient = hash_
    locksroot = sha3(address)
    msg = LockedTransfer(nonce, asset, balance, recipient, locksroot, lock).sign(privkey)
    run_timeit('LockedTransfer', msg)


def test_mediated_transfer():
    amount = 1
    expiration = 1
    hashlock = sha3(address)
    lock = Lock(amount, expiration, hashlock)

    nonce = 1
    asset = hash_
    balance = 1
    recipient = hash_
    locksroot = sha3(address)
    target = hash_
    initiator = hash_
    msg = MediatedTransfer(nonce, asset, balance, recipient, locksroot,
                           lock, target, initiator, fee=0)
    msg.sign(privkey)

    run_timeit('MediateTranfer', msg)


def test_cancel_transfer():
    amount = 1
    expiration = 1
    hashlock = sha3(address)
    lock = Lock(amount, expiration, hashlock)

    nonce = 1
    asset = hash_
    balance = 1
    recipient = hash_
    locksroot = sha3(address)
    msg = CancelTransfer(nonce, asset, balance, recipient, locksroot, lock).sign(privkey)
    run_timeit('CancelTransfer', msg)


def test_transfer_timeout():
    echo = hash_
    hashlock = hash_
    msg = TransferTimeout(echo, hashlock).sign(privkey)
    run_timeit('TransferTimeout', msg)


def test_confirm_transfer():
    hashlock = hash_
    msg = ConfirmTransfer(hashlock).sign(privkey)
    run_timeit('ConfirmTransfer', msg)


def test_all():
    test_ack()
    test_ping()
    # needs the args type
    # test_reject()
    # test_reject_with_args()
    test_secret_request()
    test_transfer()
    test_locked_transfer()
    test_mediated_transfer()
    test_cancel_transfer()
    test_transfer_timeout()
    test_confirm_transfer()


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('name', default='test_all', nargs='?')
    args = parser.parse_args()
    name = args.name

    if name not in globals():
        raise ValueError('unknow test name: {}'.format(name))

    globals()[name]()
