from raiden.messages import Ack, decode, Transfer
from raiden.app import create_network
from raiden.tests.utils import setup_messages_cb, MessageLogger
from raiden.tasks import TransferTask
import gevent
from raiden.web_ui import WebUI






def test_transfer():
    apps = create_network(num_nodes=2, num_assets=1, channels_per_node=1)
    a0, a1 = apps
    messages = setup_messages_cb()
    mlogger = MessageLogger()
    web_ui_a0 = WebUI(a0.raiden.api)

    # channels
    am0 = a0.raiden.assetmanagers.values()[0]
    am1 = a1.raiden.assetmanagers.values()[0]

    assert am0.asset_address == am1.asset_address

    c0 = am0.channels[a1.raiden.address]
    c1 = am1.channels[a0.raiden.address]

    b0 = c0.balance
    b1 = c1.balance

    amount = 10
    target = a1.raiden.address
    assert target in am0.channels
    # a0.raiden.api.transfer(am0.asset_address, amount, target=target)
    web_ui_a0.transfer(am0.asset_address, amount, target,1)

    gevent.sleep(1)
    # callback handler

    print web_ui_a0.published
    # assert web_ui_a0.published[1] ==

    assert len(messages) == 2  # Transfer, Ack
    mt = decode(messages[0])
    assert isinstance(mt, Transfer)
    assert mt.balance == b1 + amount

    # success for first transfer is True
    # print a0.raiden.api.open_requests
    # assert a0.raiden.api.sent_success[0] == True


    ma = decode(messages[1])
    assert isinstance(ma, Ack)
    assert ma.echo == mt.hash

    assert b1 + amount == c1.balance
    assert b0 - amount == c0.balance

    assert c0.locked.root == c1.partner.locked.root == c1.locked.root == ''

    a0_messages = mlogger.get_node_messages(a0)
    assert len(a0_messages) == 2
    assert isinstance(a0_messages[0], Transfer)
    assert isinstance(a0_messages[1], Ack)

    a0_sent_messages = mlogger.get_node_messages(a0, only_sent=True)
    assert len(a0_sent_messages) == 1
    assert isinstance(a0_sent_messages[0], Transfer)

    a0_recv_messages = mlogger.get_node_messages(a0, only_recv=True)
    assert len(a0_recv_messages) == 1
    assert isinstance(a0_recv_messages[0], Ack)

    a1_messages = mlogger.get_node_messages(a1)
    assert len(a1_messages) == 2
    assert isinstance(a1_messages[0], Transfer)
    assert isinstance(a1_messages[1], Ack)

    a1_sent_messages = mlogger.get_node_messages(a1, only_sent=True)
    assert len(a1_sent_messages) == 1
    assert isinstance(a1_sent_messages[0], Ack)

    a1_recv_messages = mlogger.get_node_messages(a1, only_recv=True)
    assert len(a1_recv_messages) == 1
    assert isinstance(a1_recv_messages[0], Transfer)


def test_mediated_transfer():

    apps = create_network(num_nodes=10, num_assets=1, channels_per_node=2)
    a0 = apps[0]
    setup_messages_cb()
    web_ui_a0 = WebUI(a0.raiden.api)

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

    ams_by_address = dict((a.raiden.address, a.raiden.assetmanagers) for a in apps)

    # addresses
    a, b, c = path

    # asset
    asset_address = am0.asset_address

    # channels
    c_ab = ams_by_address[a][asset_address].channels[b]
    c_ba = ams_by_address[b][asset_address].channels[a]
    c_bc = ams_by_address[b][asset_address].channels[c]
    c_cb = ams_by_address[c][asset_address].channels[b]

    # initial channel balances
    b_ab = c_ab.balance
    b_ba = c_ba.balance
    b_bc = c_bc.balance
    b_cb = c_cb.balance

    amount = 10
    # set shorter timeout for testing
    TransferTask.timeout_per_hop = 0.1

    # a0.raiden.api.transfer(asset_address, amount, target)
    web_ui_a0.transfer(asset_address, amount, target,2)


    gevent.sleep(1.)

    # callback returned 'success = True' and publish_WAMP was called:
    # assert web_ui_a0.published[2] == True
    print web_ui_a0.published
    # check
    assert b_ab - amount == c_ab.balance
    assert b_ba + amount == c_ba.balance
    assert b_bc - amount == c_bc.balance
    assert b_cb + amount == c_cb.balance


if __name__ == '__main__':
    test_transfer()
    test_mediated_transfer()
