import pytest
from raiden.utils import sha3
from raiden.mtree import merkleroot, check_proof


def test_small():
    values = [x * 32 for x in 'a']
    proof_for = values[-1]
    proof = [proof_for]
    r = merkleroot(list(values), proof)
    assert check_proof(proof, r, proof_for)

    r = merkleroot('')
    assert r == ''


def test_basic():
    values = [x * 32 for x in 'ab']
    proof_for = values[-1]
    proof = [proof_for]
    r = merkleroot(list(values), proof)
    # print pex(r)
    # print 'proof', proof
    assert check_proof(proof, r, proof_for)

    proof_for = values[-1]
    proof = [proof_for]
    r = merkleroot(list(values), proof)
    # print pex(r)
    # print 'proof', proof
    assert check_proof(proof, r, proof_for)


def test_basic3():
    values = [x * 32 for x in 'abc']
    proof_for = values[-1]
    proof = [proof_for]
    r = merkleroot(list(values), proof)
    # print pex(r)
    # print 'proof', pexl(proof)
    assert check_proof(proof, r, proof_for)
    proof_for = values[0]
    proof = [proof_for]
    r = merkleroot(list(values), proof)
    # print pex(r)
    # print 'proof', pexl(proof)
    assert check_proof(proof, r, proof_for)


def test_multiple():
    values = [x * 32 for x in 'abada']
    proof_for = values[-1]
    proof = [proof_for]
    with pytest.raises(AssertionError):
        r = merkleroot(list(values), proof)
        assert check_proof(proof, r, proof_for)


def do_test_many(values):
    for i, v in enumerate(values):
        proof = [v]
        r = merkleroot(list(values), proof)
        assert check_proof(proof, r, v)


def test_many(num=10):
    for nummi in range(1, num + 1):
        values = [sha3(str(i)) for i in range(nummi)]
        rvalues = list(reversed(values))
        r = do_test_many(values)
        r0 = do_test_many(rvalues)
        assert r == r0


def do_test_speed(rounds=100, num_hashes=1000):
    import time
    values = [sha3(str(i)) for i in range(num_hashes)]
    st = time.time()
    for i in range(rounds):
        merkleroot(list(values))
    elapsed = time.time() - st
    print '%d additions per second' % (num_hashes * rounds / elapsed)

if __name__ == '__main__':
    do_test_speed()
