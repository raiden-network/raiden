import gevent
gevent.get_hub().SYSTEM_ERROR = BaseException
from raiden.transport import DummyTransport


def setup_messages_cb():
    messages = []

    def cb(sender_raiden, host_port, msg):
        messages.append(msg)
    DummyTransport.network.on_send_cbs = [cb]
    return messages


def dump_messages(messages):
    print 'dumping {} messages'.format(len(messages))
    for m in messages:
        print m
