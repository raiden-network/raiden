import gevent
from raiden.messages import decode
from raiden.utils import pex
gevent.get_hub().SYSTEM_ERROR = BaseException
from raiden.transport import DummyTransport


def setup_messages_cb():
    messages = []

    def cb(sender_raiden, host_port, msg):
        messages.append(msg)
    DummyTransport.network.on_send_cbs.extend([cb])
    return messages


def dump_messages(messages):
    print 'dumping {} messages'.format(len(messages))
    for m in messages:
        print m


class MessageLogger(object):

    """Register callbacks to collect all messages. Messages can be queried"""

    def __init__(self):
        self.messages_by_node = {}

        def sent_msg_cb(sender_raiden, host_port, msg):
            key = pex(sender_raiden.address)
            self.collect_message(key, '>', msg)
            #print 'sent_msg_cb', pex(sender_raiden.address), time.time()
        DummyTransport.network.on_send_cbs.extend([sent_msg_cb])

        def recv_msg_cb(receiver_raiden, host_port, msg):
            key = pex(receiver_raiden.address)
            self.collect_message(key, '<', msg)
            #print 'recv_msg_cb', pex(receiver_raiden.address), time.time()
        DummyTransport.on_recv_cbs.extend([recv_msg_cb])

    def collect_message(self, key, direction, msg):
        self.messages_by_node.setdefault(key, [])
        self.messages_by_node[key].append((direction, msg))

    def get_node_messages(self, node, decoded=False, only_sent=False, only_recv=False):
        """ Return list of node's messages. """
        assert not (only_sent and only_recv)

        key = pex(node.raiden.address)
        if only_sent:
            filter_ = lambda t: t == '>'
        elif only_recv:
            filter_ = lambda t: t == '<'
        else:
            filter_ = lambda t: True

        ret = filter(filter_, [msg for t, msg in self.messages_by_node.get(key, [])])
        if decoded:
            ret = [decode(msg) for msg in ret]

        return ret
