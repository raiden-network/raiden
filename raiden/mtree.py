from utils import pex, sha3


def xorsha3(s1, s2):
    return sha3(''.join(chr(ord(a) ^ ord(b)) for a, b in zip(s1, s2)))


def merkleroot(lst, proof=[], first=True):
    """
    lst: list of hashes
    proof: empty or with the element for which a proof shall be built, proof will be in proof

    the proof contains all elements between `element` and `root`.
    if on all of [element] + proof is recursively xorsha applied one gets the root.

    returns: merkleroot
    """
    if not lst:
        return ''
    if first:
        lst.sort()
    proof = proof or [None]
    searching = proof.pop()
    assert searching is None or searching in lst
    out = []
    while len(lst) > 1:
        a, b = lst.pop(0), lst.pop(0)
        h = xorsha3(a, b)
        if a == searching:
            proof.extend((b, h))
        elif b == searching:
            proof.extend((a, h))
        out.append(h)
    if lst:
        h = lst.pop()
        out.append(h)
        if h == searching:
            proof.append(h)
        assert not lst
    if len(out) > 1:
        return merkleroot(out, proof, False)
    else:
        if searching:
            proof.pop()  # pop root
        return out[0]


def check_proof(proof, root, h):
    while len(proof):
        e = proof.pop(0)
        h = xorsha3(h, e)
    return h == root


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
    values = [x * 32 for x in 'abaacac']
    proof_for = values[-1]
    proof = [proof_for]
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


def test_speed(rounds=100, num_hashes=1000):
    import time
    values = [sha3(str(i)) for i in range(num_hashes)]
    st = time.time()
    for i in range(rounds):
        merkleroot(list(values))
    elapsed = time.time() - st
    print '%d additions per second' % (num_hashes * rounds / elapsed)

if __name__ == '__main__':
    test_small()
    test_basic()
    test_multiple()
    test_basic3()
    test_many(100)
    test_speed()
