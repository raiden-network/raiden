# -*- coding: utf-8 -*-
from pathfinder.model.lock import Lock


def test_lock_packing():
    lock = Lock(100, 1000, b'a' * 32)

    assert lock.pack() == (
        b'\x00\x00\x00\x00\x00\x00\x03\xe8\x00\x00\x00\x00\x00\x00\x00\x00\x00'
        b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
        b'\x00\x00\x00\x00\x00daaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
    )


def test_lock_hashing():
    lock = Lock(100, 1000, b'a' * 32)

    assert lock.compute_hash() == (
        b'\x02S\xd3\x028 \t0B\x853\\\xe7f\xcc:\x068>\x84J\x0e\xe2\x0c\xdc\xc3Q\xca\x0f\x94,"'
    )
