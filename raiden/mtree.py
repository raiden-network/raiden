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
        assert len(lst) == len(set(lst)), 'no duplicates allowed'
        lst = list(lst)
        lst.sort()
    proof = proof or [None]
    searching = proof.pop()
    assert searching is None or searching in lst
    out = []
    for i in range(len(lst) / 2):
#        a, b = lst.pop(0), lst.pop(0)
        a, b = lst[i * 2], lst[i * 2 + 1]
        h = xorsha3(a, b)
        if a == searching:
            proof.extend((b, h))
        elif b == searching:
            proof.extend((a, h))
        out.append(h)
    if len(lst) % 2:
        h = lst[-1]
        out.append(h)
        if h == searching:
            proof.append(h)
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


def get_proof(lst, proof_for, root=None):
    proof = [proof_for]
    r = merkleroot(lst, proof)
    if root:
        assert root == r
    return proof
