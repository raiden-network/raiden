import gevent
gevent.get_hub().SYSTEM_ERROR = BaseException


def setup_messages_cb(transport):
    messages = []

    def cb(sender_raiden, host_port, msg):
        messages.append(msg)
    transport.on_send_cbs = [cb]
    return messages


def dump_messages(messages):
    print 'dumping {} messages'.format(len(messages))
    for m in messages:
        print m
