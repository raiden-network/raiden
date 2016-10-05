# from __future__ import division
import random
import sys
random.seed(42)
# sys.setrecursionlimit(2000)
print "use pypy"
DEBUG = False


def _get_closest_node_id(target_id, nodeids):
    # this is very slow
    for node_id in nodeids:
        if node_id > target_id:
            return node_id
    return nodeids[0]


def get_closest_node_id(target_id, nodeids):
    return nodeids[get_closest_node_idx(target_id, nodeids)]


def get_closest_node_idx(target_id, nodeids):
    start, end = 0, len(nodeids) - 1
    while end - start > 1:
        idx = start + (end - start) / 2
        if nodeids[idx] > target_id:
            end = idx
        else:
            start = idx
    assert end - start <= 1, (end, start)
    ds = abs(nodeids[start] - target_id)
    de = abs(nodeids[end] - target_id)
    idx = min((ds, start), (de, end))[1]
    return idx


class Node(object):
    """
    a node with `num_channels` actively opens half of them with other nodes
    and has `deposit`.
    The other half is reserved for other nodes connecting.
    """

    def __init__(self, sim, id, num_channels, capacity_per_channel):
        self.sim = sim
        self.id = id
        assert num_channels % 2 == 0
        self.num_channels = num_channels
        self.num_initiated_channels = num_channels // 2
        self.capacity_per_channel = capacity_per_channel
        self.channels = dict()  # nodeid => capacity

    def __repr__(self):
        return '<Node:%d>' % self.id

    @property
    def targets(self):
        """
        connect to closest node larger than self!
        """
        distances = [self.sim.max_id / 2**i for i in range(self.num_initiated_channels)]
        return [(self.id + d) % self.sim.max_id for d in distances]

    def initiate_channels(self):

        # connected nodes should have the same order of magnitude capacity
        if sim.capacity_groups is True:
            max_capacity = self.capacity_per_channel / (1. - self.sim.max_capacity_deviation)
            min_capacity = (1 - self.sim.max_capacity_deviation) * self.capacity_per_channel

        for target_id in self.targets:
            assert target_id != self.targets
            if sim.capacity_groups is True:
                # stuff to optimize
                node_id = None
                idx = get_closest_node_idx(target_id, self.sim.nodeids)
                offset = 0
                max_idx = len(self.sim.node_by_id) - 1
                while offset > -1:  # find next matching
                    for idx2 in (max(0, idx - offset), min(idx + offset, max_idx)):
                        node_id = self.sim.nodeids[idx2]
                        capa = self.sim.node_by_id[node_id].capacity_per_channel
                        if min_capacity < capa < max_capacity:
                            offset = -2
                            break  # found
                    offset += 1
            else:
                node_id = get_closest_node_id(target_id, self.sim.nodeids)
            self.connect(node_id)
            # connect other
            self.sim.node_by_id[node_id].connect(self.id)

            if sim.capacity_groups:
                capa = self.sim.node_by_id[node_id].capacity_per_channel
                assert min_capacity < capa < max_capacity

    def connect(self, other_id):
        assert other_id
        assert other_id in self.sim.node_by_id
        if other_id in self.channels:
            return
        node = self.sim.node_by_id[other_id]
        self.channels[node.id] = self.capacity_per_channel

    def randomize_capacity(self):
        for n, c in self.channels.items():
            c *= 2 * random.random()
            self.channels[n] = c

    def _channels_by_distance(self, target_id, amount):
        def _distance(node_id):
            d = target_id - node_id
            if d < 0:
                d += self.sim.max_id
            return d
        nodeids = sorted(self.channels.keys(), lambda a, b: cmp(_distance(a), _distance(b)))
        assert len(nodeids) < 2 or _distance(nodeids[0]) <= _distance(nodeids[1])
        return [nid for nid in nodeids if self.channels[nid] >= amount]

    def _channels_by_distance_plus(self, target_id, amount):
        """
        sort nodes by their shortest distance to target_id
        """
        def _distance(node_id):
            d = target_id - node_id
            if d < 0:
                d += self.sim.max_id
            return d

        distance_channel = []
        for nodeid, capacity in self.channels.items():
            if capacity < amount:
                continue
            res = self.sim.node_by_id[nodeid]._channels_by_distance(target_id, amount)
            assert len(res) < 2 or _distance(res[0]) <= _distance(res[1])
            if res and _distance(res[0]) < _distance(nodeid):
                distance_channel.append((_distance(res[0]), nodeid))
            else:
                distance_channel.append((_distance(nodeid), nodeid))
        distance_channel.sort()
        if DEBUG:
            print 'closest d,nodeid', distance_channel[0]
        return [n for d, n in distance_channel]

    def transfer(self, transfer, proactive_routing=False):
        """
        try to transfer along a channel with a node that has a lower id than target.
        closest node first
        """
        # print 'in transfer', self, transfer.receiver
        if self in transfer.tried:
            return False
        transfer.tried.append(self)
        transfer.path.append(self)

        # sort connections by distance to target
        target_id = transfer.receiver

        if target_id == self.id:
            return True

        if len(transfer.tried) > self.sim.max_tried:
            if DEBUG:
                print target_id
                print [n.id for n in transfer.path]
                print [n.id for n in transfer.tried]
            return False

        if not proactive_routing:
            candidates = self._channels_by_distance(target_id, transfer.amount)
        else:
            candidates = self._channels_by_distance_plus(target_id, transfer.amount)
            if DEBUG:
                candidates2 = self._channels_by_distance(target_id, transfer.amount)
                print
                print "node:", self.id, "target", target_id
                print candidates
                print candidates2
                assert len(candidates2) >= len(candidates)
            # candidates = candidates2
        res = False
        for node_id in candidates:
            assert node_id not in transfer.tried
            if node_id > target_id:
                if len(transfer.path) > 1:  # not first
                    break
            assert self.channels[node_id] >= transfer.amount
            node = self.sim.node_by_id[node_id]
            res = node.transfer(transfer, proactive_routing)
            if res:
                break

        if not res:
            transfer.path.pop()
            return False
        return True


class Transfer(object):

    def __init__(self, sender, receiver, amount):
        self.sender = sender
        self.receiver = receiver
        self.amount = amount
        self.tried = []
        self.path = []
        self.success = False
        # print self

    def __repr__(self):
        return '<Transfer v=%d t=%s>' % (self.amount, self.receiver)


def mk_linear_distribution_func(v_min, v_max):
    def f(x):
        return v_min + (v_max - v_min) * x
    return f


def mk_power_distribution_func(v_min, v_max):
    assert v_min > 0
    v_min /= float(v_max)  # express as fraction
    c = 1 / v_min - 1

    def f(x):
        return v_max / (c * x + 1)
    return f


# p = mk_power_distribution_func(0.03, 1)
# p = mk_power_distribution_func(1, 128)

# vals = [p(i * 0.1) for i in range(10)]
# ivals = [sum(vals[0:i + 1]) for i in range(10)]
# tot = max(ivals)
# fvals = [ivals[i] / tot for i in range(10)]
# print tot
# for i in range(10):
#     print i * 0.1, vals[i], ivals[i], fvals[i]
# assert False


class Simulation(object):
    num_nodes = 10000
    max_id = 2**32
    num_channels = 32
    max_capacity = 128
    min_capacity = 1
    randomize_capacity = False
    proactive_routing = False
    capacity_groups = False
    max_capacity_deviation = .3
    max_tried = 1000

    capacity_distribution = 'power'
    assert capacity_distribution in ('power', 'linear')

    def __init__(self):
        self.node_by_id = dict()
        self.nodeids = []

        if self.capacity_distribution == 'power':
            _f = mk_power_distribution_func(self.min_capacity, self.max_capacity)
        elif self.capacity_distribution == 'linear':
            _f = mk_linear_distribution_func(self.min_capacity, self.max_capacity)
        else:
            raise Exception
        self._capacity_dist_func = _f

    def _capacity_distribution(self, x):
        assert isinstance(x, float)
        assert 0 <= x <= 1
        return self._capacity_dist_func(x)

    def _iteredges(self):
        for node in self.node_by_id.values():
            for nid, c in node.channels.items():
                yield nid, c

    def setup_network(self):
        print 'setting up nodes'
        for i in range(self.num_nodes):
            node_id = random.randrange(self.max_id)
            if node_id in self.node_by_id:
                continue  # id space collision
            capacity = self._capacity_distribution(i / float(self.num_nodes))
            node = Node(self, node_id, self.num_channels, capacity)
            self.node_by_id[node.id] = node
        self.nodeids = sorted(self.node_by_id.keys())
        print 'num_nodes', len(self.nodeids)

        print 'setting up channels'

        for node_id in self.nodeids:  # sorted by capacity dec
            node = self.node_by_id[node_id]
            node.initiate_channels()
            if self.randomize_capacity:
                node.randomize_capacity()

        capacities = [c for nid, c in self._iteredges()]
        num_edges = len(capacities)
        median_num_edges_per_node = sorted(len(n.channels)
                                           for n in self.node_by_id.values())[self.num_nodes / 2]
        avg_capacity = sum(capacities) / float(len(capacities))
        median_capacity = sorted(capacities)[len(capacities) / 2]

        fmt = 'num_edges:{} per node:{:.1f} median per node:{:.1f}'
        print fmt.format(num_edges, num_edges / float(len(self.nodeids)),
                         median_num_edges_per_node)
        print 'avg_capacity:{} median capacity:{}'.format(avg_capacity, median_capacity)

    def dump_nodes(self, num=4):
        # dump some nodes and their channels
        for nodeid in self.nodeids[:num]:
            print
            node = self.node_by_id[nodeid]
            assert len(node.targets) < len(node.channels)
            # print node, zip(sorted(node.channels.keys()), sorted(node.targets))
            print 'targets:', sorted(node.targets)
            print 'edges:', sorted(node.channels.keys())
            print 'capacities:', sorted(node.channels.values())

    def rand_transfer(self, amount):
        candidates = [n for n in self.node_by_id.values() if n.capacity_per_channel >= amount]
        assert len(candidates) >= 2
        sender = random.choice(candidates)
        receiver = sender
        while receiver is sender:
            receiver = random.choice(candidates)
        if DEBUG:
            print
            print "new transfer", receiver
        t = Transfer(sender.id, receiver.id, amount)
        res = sender.transfer(t, self.proactive_routing)
        t.success = res
        return t

    def run(self, steps=4, samples=100):
        random.seed(42)

        total_successful = 0

        for i in range(steps):
            value = self._capacity_distribution(i / float(steps)) / 2
            usable_nodes = len([n for n in self.node_by_id.values()
                                if n.capacity_per_channel >= value]) / float(len(self.nodeids))
            transfers = []
            for i in range(samples):
                _ = self.rand_transfer(value)
                transfers.append(_)

            successful = [t for t in transfers if t.success]
            num_successful = len(successful)
            total_successful += num_successful
            pct_successful = num_successful / float(len(transfers))

            if num_successful > 0:
                avg_path_len = sum([len(t.path) for t in successful]) / float(num_successful)
                median_path_len = sorted([len(t.path) for t in successful])[num_successful // 2]
                max_path_len = max([len(t.path) for t in successful])
            else:
                avg_path_len = median_path_len = max_path_len = 0
            avg_tried_len = sum([len(t.tried) for t in transfers]) / float(len(transfers))
            median_tried_len = sorted([len(t.tried) for t in transfers])[len(transfers) // 2]
            max_tried_len = max([len(t.tried) for t in transfers])

            fmt = 'value:{:-5.2f}{:-5.2f} success:{:.2f} p_len:{:-4.0f} {:-4.0f} {:-4.0f} ' + \
                'tried:{:-4.0f} {:-4.0f} {:-4.0f}'
            print fmt.format(value, usable_nodes, pct_successful, avg_path_len,
                             median_path_len, max_path_len, avg_tried_len,
                             median_tried_len, max_tried_len)
        num_transfers = steps * samples
        pct_successful = (100 * total_successful) / num_transfers
        print 'Of {} transfers {}% successful'.format(num_transfers, pct_successful)


if __name__ == '__main__':
    sim = Simulation()

    # config
    sim.num_nodes = 100000
    sim.num_channels = 32
    sim.max_capacity = 128
    sim.min_capacity = 1
    sim.randomize_capacity = False
    sim.proactive_routing = False
    sim.capacity_groups = True
    sim.max_capacity_deviation = 0.3
    sim.capacity_distribution = 'power'  # or 'linear'

    sim.max_tried = 500

    # setup
    sim.setup_network()
#    sim.dump_nodes(4)

    # run sim
    # print "running simulation w/proactive routing"
    sim.run(steps=10, samples=100)
    # sim.proactive_routing = True
    # print "running simulation"
    # sim.run(steps=10, samples=100)
    # # sim.rand_transfer(1.5)

    """
    Done: Model that nodes preferably connect nodes of similar capacity!!!

    Thoughts: The less value one has, the less valuable he is as a mediator
              therefore the less channels he should have open.

              The other way round for nodes with high values.


              Q: Does it make sense to have different capacity based on the distance?

                 Being able to transfer to neighbours is essential
                 so transfers can be facillitated at all

                 While having a short path is secondary.
    """
