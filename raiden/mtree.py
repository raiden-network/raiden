from utils import pex, sha3, big_endian_to_int, ishash

bi = lambda x: big_endian_to_int(str(x))
bisorted = lambda *ab: sorted(ab, cmp=lambda a, b: cmp(bi(a), bi(b)))


class MTree(object):

    """
    Simple Merkle Tree implementation
    """

    hash = ''
    r = ''
    l = ''

    def __init__(self, l='', r='', parent=None):
        self.parent = parent
        if parent:
            self.node_by_hash = parent.node_by_hash
        else:
            self.node_by_hash = dict()
        for h in (l, r):
            if h:
                self._add(h)

    def add(self, h):
        self._add(h)
        self.node_by_hash[h]._update_hash()
        # for h, n in self.node_by_hash.items():
        #     assert h in (n.l, n.r)

    def remove(self, h):
        assert ishash(h)
        self.node_by_hash[h]._remove(h)

    def get_proof(self, h):
        """
        returns the path of hashes, that when recursively hashed proves inclusion of `hash`.
        """
        assert not self.parent  # is root
        return self.node_by_hash[h]._to_root(h)

    def _add(self, h):
        assert h not in (self.l, self.r)
        if isinstance(h, MTree):
            h.parent = self
        hbi = bi(h)
        if not self.l:  # special case init
            self.l = h
            self.node_by_hash[h] = self
        elif not self.r:
            self.r = h
            self.node_by_hash[h] = self
        elif hbi < bi(self.l):  # add left
            self.l = MTree(h, self.l, self)
        elif hbi > bi(self.r):  # add right
            self.r = MTree(self.r, h, self)
        elif hbi % 2:  # add any
            assert self.r and self.l
            self.r = MTree(h, self.r, self)
        else:
            self.l = MTree(self.l, h, self)

    def _to_root(self, h):
        # print '_to_root', pex(self), pex(h)
        assert h and isinstance(h, bytes)
        cs = [c for c in (str(self.l), str(self.r)) if c]
        assert str(h) in cs, (cs, self.l, self.r, str(h))
        cs.remove(str(h))
        if self.parent:
            return self.parent._to_root(str(self)) + cs
        return [self.hash] + cs

    def _update_hash(self):
        self.l, self.r = bisorted(self.l, self.r)
        self.hash = sha3(str(self.l) + str(self.r))
        if self.parent:
            self.parent._update_hash()

    def __str__(self):
        assert self.hash
        return self.hash

    def __cmp__(self, other):
        return cmp(bi(self), bi(other))

    def _remove(self, h):
        # print 'removing in', pex(self)
        if h == self.l:
            v = self.r
            self.l = ''
        else:
            v = self.l
            self.r = ''
        del self.node_by_hash[h]
        if self.parent:
            # print 'has parent', pex(self.parent)
            # print 'has value', pex(v)
            assert v
            if self.parent.l == self:
                self.parent.l = v
            else:
                assert self.parent.r == self
                self.parent.r = v

            if ishash(v):
                self.node_by_hash[v] = self.parent
            else:
                assert isinstance(v, MTree)
                v.parent = self.parent
            self.parent._update_hash()
        else:
            # print 'has no parent', pex(self)
            # special handling for root node
            for v in (self.l, self.r):
                if isinstance(v, MTree):
                    self.l, self.r = v.l, v.r
            for v in (self.l, self.r):
                if ishash(v):
                    self.node_by_hash[v] = self
                elif v:
                    assert isinstance(v, MTree)
                    v.parent = self
            self._update_hash()

    @property
    def depth(self):
        return 1 + (self.parent.depth if self.parent else 0)

    def dump(self):
        d = self.depth
        print '\t' * d + 'T:' + pex(self)
        if isinstance(self.l, bytes):
            print '\t' * (d + 1) + pex(self.l)
        else:
            self.l.dump()
        if isinstance(self.r, bytes):
            print '\t' * (d + 1) + pex(self.r)
        else:
            self.r.dump()


def check_proof(roothash, p, h):
    # print 'check proof', [pex(_) for _ in p]
    assert p[0] == roothash, pex(roothash)
    if len(p) < 2:
        h = sha3(h)
    for n in reversed(p[1:]):
        h = sha3(''.join(bisorted(n, h)))
    assert h == roothash, pex(h)


def test_basic():
    values = [sha3(str(i)) for i in range(20)]
    svalues = sorted(values, cmp=lambda a, b: cmp(bi(a), bi(b)))

    t = MTree()
    t._update_hash()
    assert t.hash == sha3('')

    v1 = svalues[1]
    t.add(v1)
    assert t.l == ''
    assert t.r == v1

    assert t.hash == sha3(v1)
    p = t.get_proof(v1)
    assert len(p) == 1
    assert p[0] == t.hash

    v0 = svalues[0]
    assert bi(v1) > bi(v0)
    t.add(v0)
    assert t.l == v0
    assert t.r == v1

    assert t.hash == sha3(v0 + v1)
    p = t.get_proof(v1)
    assert len(p) == 2
    assert p[0] == t.hash
    assert p[1] == v0
    p = t.get_proof(v0)
    assert len(p) == 2
    assert p[0] == t.hash
    assert p[1] == v1
    check_proof(t.hash, p, v0)

    v2 = svalues[2]
    assert bi(v1) < bi(v2)

    t.add(v2)
    assert t.l == v0
    assert isinstance(t.r, MTree)
    assert t.r.l == v1
    assert t.r.r == v2

    assert bi(t.r.hash) > bi(t.l)
    assert bi(t.r.l) < bi(t.r.r)
    assert t.r.hash == sha3(v1 + v2)
    th = t.hash
    t._update_hash()
    assert th == t.hash
    assert t.hash == sha3(v0 + sha3(v1 + v2))
    p = t.get_proof(v2)
    assert len(p) == 3
    assert p[0] == t.hash
    assert p[1] == v0
    assert p[2] == v1

    p = t.get_proof(v1)
    assert len(p) == 3
    assert p[0] == t.hash
    assert p[1] == v0
    assert p[2] == v2

    p = t.get_proof(v0)
    assert len(p) == 2
    assert p[0] == t.hash
    assert p[1] == sha3(v1 + v2)


def do_test_many(add_values, del_values=None):
    del_values = del_values or add_values

    t = MTree()
    for i, v in enumerate(add_values):
        t.add(v)
        for vv in add_values[:i + 1]:
            p = t.get_proof(vv)
            check_proof(t.hash, p, vv)

    for i, v in enumerate(del_values):
        # print 'removing', pex(v)
        t.remove(v)
        # t.dump()
        for vv in del_values[i + 1:]:
            p = t.get_proof(vv)
            check_proof(t.hash, p, vv)


def test_many(num=100):
    values = [sha3(str(i)) for i in range(num)]
    rvalues = list(reversed(values))
    svalues = sorted(values, cmp=lambda a, b: cmp(bi(a), bi(b)))
    rsvalues = list(reversed(svalues))
    do_test_many(values)
    do_test_many(rvalues)
    do_test_many(values, rvalues)
    do_test_many(svalues)
    do_test_many(values, svalues)
    do_test_many(svalues, values)
    do_test_many(rsvalues)
    do_test_many(svalues, rsvalues)


def test_speed(rounds=1000, num_hashes=100):
    import time
    values = [sha3(str(i)) for i in range(num_hashes)]
    st = time.time()
    for i in range(rounds):
        t = MTree()
        for v in values:
            t.add(v)
    elapsed = time.time() - st
    print '%d additions per second' % (num_hashes * rounds / elapsed)


if __name__ == '__main__':
    test_basic()
    test_speed()
    test_many()
