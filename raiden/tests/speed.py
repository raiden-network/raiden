import time
from raiden.messages import Ack,  Transfer
from raiden.app import create_network
from utils import setup_messages_cb, dump_messages
from raiden.tasks import TransferTask
import gevent


def test_mediated_transfer(num_transfers=100):

    apps = create_network(num_nodes=10, num_assets=1, channels_per_node=2)
    a0 = apps[0]
    messages = setup_messages_cb(a0.transport)

    # channels
    am0 = a0.raiden.assetmanagers.values()[0]

    # search for a path of length=2 A > B > C
    num_hops = 2
    source = a0.raiden.address
    paths = am0.channelgraph.get_paths_of_length(source, num_hops)
    assert len(paths)
    for p in paths:
        assert len(p) == num_hops + 1
        assert p[0] == source
    path = paths[0]
    target = path[-1]
    assert path in am0.channelgraph.get_paths(source, target)
    assert min(len(p) for p in am0.channelgraph.get_paths(source, target)) == num_hops + 1

    assetmanagers_by_address = dict((a.raiden.address, a.raiden.assetmanagers) for a in apps)

    # addresses
    a, b, c = path

    # asset
    asset_address = am0.asset_address

    amount = 10
    # set shorter timeout for testing
    TransferTask.timeout_per_hop = 0.1

    st = time.time()
    finished = gevent.event.Event()

    def _completion_cb(task, success):
        print
        print 'task completed', task, success, _completion_cb.num_transfers
        _completion_cb.num_transfers -= 1
        if _completion_cb.num_transfers > 0:
            a0.raiden.api.transfer(asset_address, amount, target)
        else:
            finished.set()

    _completion_cb.num_transfers = num_transfers

    am1 = assetmanagers_by_address[b][asset_address]
    am1.transfermanager.on_task_completed_callbacks.append(_completion_cb)

    a0.raiden.api.transfer(asset_address, amount, target)
    finished.wait()

    elapsed = time.time() - st
    completed_transfers = num_transfers - _completion_cb.num_transfers
    tps = completed_transfers / elapsed
    print 'transfers completed:{} per second:{}'.format(completed_transfers, tps)

if __name__ == '__main__':
    test_mediated_transfer(num_transfers=1000)
