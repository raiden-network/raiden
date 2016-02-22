from utils import keccak


def hash_pair(s1, s2):
    if s1 > s2:
        s2, s1 = s1, s2
    return keccak(s1 + s2)


class NoHash32Error(Exception):
    pass


def merkleroot(lst, proof=[], first=True):
    """
    lst: list of hashes
    proof: empty or with the element for which a proof shall be built, proof will be in proof

    the proof contains all elements between `element` and `root`.
    if on all of [element] + proof is recursively hash_pair applied one gets the root.

    returns: merkleroot
    """
    if first:
        lst = build_lst(lst)
    if not lst:
        return ''
    proof = proof or [None]
    searching = proof.pop()
    assert searching is None or searching in lst
    out = []
    for i in range(len(lst) / 2):
        # a, b = lst.pop(0), lst.pop(0)
        a, b = lst[i * 2], lst[i * 2 + 1]
        h = hash_pair(a, b)
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


def build_lst(lst):
    _lst = set()
    for e in lst:
        if e and len(e) != 32:
            raise NoHash32Error()
        elif e:
            _lst.add(e)
    lst = list(_lst)
    lst.sort()
    return lst


def check_proof(proof, root, h):
    while len(proof):
        e = proof.pop(0)
        h = hash_pair(h, e)
    return h == root


def get_proof(lst, proof_for, root=None):
    proof = [proof_for]
    r = merkleroot(lst, proof)
    if root:
        assert root == r
    return proof
