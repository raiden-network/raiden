import random
random.seed(42)
num_nodes = 10000
max_id = 2**32
max_id = num_nodes * 100
num_channels = 4

node_by_id = dict()
nodeids = []

print "use pypy"


def get_closest_node_id(target_id):
    for node_id in nodeids:
        if node_id > target_id:
            return node_id
    return nodeids[0]


class Node(object):

    def __init__(self, id, num_channels, deposit):
        self.id = id
        assert num_channels % 2 == 0
        self.num_channels = num_channels
        self.num_initiated_channels = num_channels / 2
        self.deposit = deposit
        self.channels = dict()  # nodeid => capacity

    def __repr__(self):
        return '<Node:%d>' % self.id

    @property
    def targets(self):
        """
        connect to closest node larger than self!
        """
        distances = [max_id / 2**i for i in range(self.num_initiated_channels)]
        return [(self.id + d) % max_id for d in distances]

    def initiate_channels(self):
        assert self.id in self.targets
        for target_id in self.targets:
            node_id = get_closest_node_id(target_id)
            self.connect(node_id)

    def connect(self, other_id):
        assert other_id
        assert other_id in node_by_id
        node = node_by_id[other_id]
        # self.channels[node.id] = self.deposit / self.num_channels
        self.channels[node.id] = self.deposit
        # node.channels[self.id] = node.deposit / node.num_channels

    def transfer(self, transfer):
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

        def _distance(cid):
            d = target_id - cid
            if d < 0:
                d += max_id
            return d

        res = False
        channels = sorted(self.channels.keys(), lambda a, b: cmp(_distance(a), _distance(b)))
        # print target_id, channels
        for cid in channels:
            if cid > target_id:
                if len(transfer.path) > 1:  # not first
                    # print 'breaking'
                    break
            capacity = self.channels[cid]
            # print cid, capacity, transfer.amount
            if capacity < transfer.amount:
                continue
            node = node_by_id[cid]
            try:
                res = node.transfer(transfer)
            except RuntimeError:
                continue
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

deposit_distribution = [100 * 2**i for i in range(5)]
print deposit_distribution


print 'setting up nodes'
for i in range(num_nodes):
    node_id = random.randrange(max_id)
    deposit = random.choice(deposit_distribution)
    node = Node(node_id, num_channels, deposit)
    node_by_id[node.id] = node
nodeids = sorted(node_by_id.keys())

print 'setting up channels'
for node in node_by_id.values():
    node.initiate_channels()

num_edges = sum([len(n.channels) for n in node_by_id.values()]) / 2
print 'num_nodes', len(nodeids)
print 'num_edges', num_edges

# dump some nodes and their channels
# for nodeid in nodeids[:4]:
#     node = node_by_id[nodeid]
#     print node, sorted(node.channels.keys()), node.targets


def rand_transfer(amount):
    sender = random.choice(nodeids)
    receiver = sender
    while receiver == sender:
        receiver = random.choice(nodeids)
    t = Transfer(sender, receiver, amount)
    res = node_by_id[sender].transfer(t)
    t.success = res
    return t


for value in deposit_distribution:
    transfers = []
    value /= 2
    for i in range(100):
        t = rand_transfer(value)
        transfers.append(t)

    avg_path_len = sum([len(t.path) for t in transfers]) / float(len(transfers))
    avg_tried_len = sum([len(t.tried) for t in transfers]) / float(len(transfers))
    median_tried_len = sorted([len(t.tried) for t in transfers])[len(transfers) / 2]
    max_tried_len = max([len(t.tried) for t in transfers])
    num_successful = sum(1 for t in transfers if t.success)

    print 'value', value, deposit_distribution
    print 'avg_path_len', avg_path_len
    print 'avg_tried_len', avg_tried_len, median_tried_len, max_tried_len
    print 'num_successful', num_successful, num_successful / float(len(transfers))
