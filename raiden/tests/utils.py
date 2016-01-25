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


class MessageLog(object):

    SENT = '>'
    RECV = '<'

    def __init__(self, address, msg, direction):
        self.address = address
        self.msg = msg
        self.direction = direction
        self.is_decoded = False

    def is_recv(self):
        return self.direction == self.RECV

    def is_sent(self):
        return self.direction == self.SENT

    @property
    def decoded(self):
        if self.is_decoded:
            return self.msg
        self.is_decoded = True
        self.msg = decode(self.msg)
        return self.msg


class MessageLogger(object):

    """Register callbacks to collect all messages. Messages can be queried"""

    def __init__(self):
        self.messages_by_node = {}

        def sent_msg_cb(sender_raiden, host_port, msg):
            self.collect_message(sender_raiden.address, msg, MessageLog.SENT)
            #print 'sent_msg_cb', pex(sender_raiden.address)
        DummyTransport.network.on_send_cbs.extend([sent_msg_cb])

        def recv_msg_cb(receiver_raiden, host_port, msg):
            self.collect_message(receiver_raiden.address, msg, MessageLog.RECV)
            #print 'recv_msg_cb', pex(receiver_raiden.address)
        DummyTransport.on_recv_cbs.extend([recv_msg_cb])

    def collect_message(self, address, msg, direction):
        msglog = MessageLog(address, msg, direction)
        key = pex(address)
        self.messages_by_node.setdefault(key, [])
        self.messages_by_node[key].append(msglog)

    def get_node_messages(self, node, only_sent=False, only_recv=False):
        """ Return list of node's messages. """
        assert not (only_sent and only_recv)

        key = pex(node.raiden.address)
        if only_sent:
            filter_ = lambda t: t.is_sent()
        elif only_recv:
            filter_ = lambda t: t.is_recv()
        else:
            filter_ = lambda t: True

        ret = filter(filter_, self.messages_by_node.get(key, []))
        return [msglog.decoded for msglog in ret]
