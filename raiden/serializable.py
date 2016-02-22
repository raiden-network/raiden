from raiden.utils import big_endian_to_int, sha3
import umsgpack
__all__ = (
    'deserialize',
    'Message1',
    'Message2',
    'Message3'
)


# Pluggable binary codecs
binary_encoder = umsgpack.packb
binary_decoder = umsgpack.unpackb


class MessageBase(object):
    """
      Serializable message. Example:

      class ACK(MessageBase):
        cmdid = 1
        def __init__(self):
          pass

      msg = ACK()
      msg_bin = msg.serialize()
      msg_as_object = deserialize(msg_bin)
    """

    def __iter__(self):
        yield ('cmdid', self.cmdid)
        for k, v in self.__dict__.iteritems():
            if hasattr(v, 'cmdid'):
                yield (k, dict(v))
            else:
                yield (k, v)

    def serialize(self):
        return binary_encoder(dict(self))

    def json(self):
        return dict(self)

    @property
    def hash(self):
            # warnings.warn('Expensive comparison called')
        return sha3(self.serialize())

    def __eq__(self, other):
        return isinstance(other, self.__class__) and self.hash == other.hash

    def __hash__(self):
        return big_endian_to_int(self.hash)


def deserialize(d, binary=True):
    if binary:
        d = binary_decoder(d)

    klasses = MessageBase.__subclasses__()
    message_class_by_id = dict((c.cmdid, c) for c in klasses)

    cls = message_class_by_id[d['cmdid']]()
    for k, v in d.items():
        if isinstance(v, dict) and 'cmdid' in v:
            setattr(cls, k, deserialize(v, binary=False))
        else:
            setattr(cls, k, v)

    return cls


class Message1(MessageBase):
    cmdid = 1

    def __init__(self):
        self.field = 'some field 1'


class Message2(MessageBase):
    cmdid = 11

    def __init__(self):
        self.field = 'some field 2'
        self.msg1 = Message1()


class Message3(MessageBase):
    cmdid = 12

    def __init__(self):
        self.msg1 = Message1()
        self.msg2 = Message2()


msg = Message3()
assert isinstance(msg.json(), dict)

msg_bin = msg.serialize()
assert isinstance(msg_bin, str)

msg_dec = deserialize(msg_bin)
assert isinstance(msg_dec, Message3)

assert isinstance(msg_dec.msg1, Message1)
assert isinstance(msg_dec.msg2, Message2)
assert isinstance(msg_dec.msg2.msg1, Message1)
assert msg_dec.msg2.field == 'some field 2'
assert msg_dec.msg2.msg1.field == 'some field 1'

assert msg_dec == msg
