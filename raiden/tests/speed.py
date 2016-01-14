import time
from raiden.transport import UDPTransport
from raiden.app import create_network
from raiden.tasks import TransferTask
import gevent


def test_mediated_transfer(num_transfers=100, num_nodes=10, num_assets=1, channels_per_node=2):

    apps = create_network(
        num_nodes=num_nodes,
        num_assets=num_assets,
        channels_per_node=channels_per_node,
        transport_class=UDPTransport)

    def start_transfers(idx, num_transfers):
        a0 = apps[idx]

        # channels
        assets = sorted(a0.raiden.assetmanagers.keys())
        asset = assets[idx]
        am0 = a0.raiden.assetmanagers[asset]

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
        return finished

    # Start timer to report elapsed time
    st = time.time()
    finished_events = []
    assert num_assets <= num_nodes

    # Start all transfers
    for i in range(num_assets):
        f = start_transfers(i, num_transfers)
        finished_events.append(f)

    # Wait until all transfers are done
    gevent.wait(finished_events)

    elapsed = time.time() - st
    completed_transfers = num_transfers * num_assets
    tps = completed_transfers / elapsed
    print 'transfers completed:{} per second:{}'.format(completed_transfers, tps)

if __name__ == '__main__':
    test_mediated_transfer()
    test_mediated_transfer(num_transfers=1000)
    #test_mediated_transfer(num_transfers=1000, num_nodes=10, num_assets=10, channels_per_node=3)
