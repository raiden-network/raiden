# -*- coding: utf8 -*-
import pytest

from raiden.mtree import merkleroot, check_proof, get_proof, NoHash32Error
from raiden.utils import keccak


def test_small():
    values = [x * 32 for x in 'a']
    proof_for = values[-1]
    proof = [proof_for]
    r = merkleroot(values, proof)
    assert check_proof(proof, r, proof_for)


def test_empy():
    r = merkleroot('')
    assert r == ''


def test_multiple_empty():
    r = merkleroot(['', ''])
    assert r == ''


def test_non_hash():
    with pytest.raises(NoHash32Error):
        merkleroot(['not32bytes', 'neither'])


def test_single():
    h = keccak('x')
    assert merkleroot([h]) == h


def test_duplicates():
    h = keccak('x')
    h1 = keccak('y')
    assert merkleroot([h, h]) == h
    assert merkleroot([h, h1, h]) == merkleroot([h, h1])


def test_basic():
    values = [x * 32 for x in 'ab']
    proof_for = values[-1]
    proof = [proof_for]
    r = merkleroot(values, proof)
    # print pex(r)
    # print 'proof', proof
    assert check_proof(proof, r, proof_for)

    proof_for = values[-1]
    proof = [proof_for]
    r = merkleroot(values, proof)
    # print pex(r)
    # print 'proof', proof
    assert check_proof(proof, r, proof_for)


def test_get_proof():
    values = [x * 32 for x in 'ab']
    proof_for = values[-1]
    proof = [proof_for]
    r = merkleroot(values, proof)
    # print pex(r)
    # print 'proof', proof
    assert check_proof(proof, r, proof_for)

    proof_for = values[-1]
    proof = get_proof(values, proof_for, r)
    assert check_proof(proof, r, proof_for)


def test_basic3():
    values = [x * 32 for x in 'abc']
    proof_for = values[-1]
    proof = [proof_for]
    r = merkleroot(values, proof)
    # print pex(r)
    # print 'proof', pexl(proof)
    assert check_proof(proof, r, proof_for)
    proof_for = values[0]
    proof = [proof_for]
    r = merkleroot(values, proof)
    # print pex(r)
    # print 'proof', pexl(proof)
    assert check_proof(proof, r, proof_for)


def do_test_many(values):
    for i, v in enumerate(values):
        proof = [v]
        r = merkleroot(values, proof)
        assert check_proof(proof, r, v)
        proof = get_proof(values, v, r)
        assert check_proof(proof, r, v)


def test_many(num=10):
    for nummi in range(1, num + 1):
        values = [keccak(str(i)) for i in range(nummi)]
        rvalues = list(reversed(values))
        r = do_test_many(values)
        r0 = do_test_many(rvalues)
        assert r == r0


def do_test_speed(rounds=100, num_hashes=1000):
    import time
    values = [keccak(str(i)) for i in range(num_hashes)]
    st = time.time()
    for i in range(rounds):
        merkleroot(values)
    elapsed = time.time() - st
    print '%d additions per second' % (num_hashes * rounds / elapsed)

if __name__ == '__main__':
    do_test_speed()
