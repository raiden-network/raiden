# Copyright (c) 2015 Heiko Hees
from utils import big_endian_to_int, sha3, isaddress, ishash, int_to_big_endian, pex
from rlp.codec import consume_item, consume_length_prefix
from rlp import DecodingError
from c_secp256k1 import ecdsa_recover_compact as c_ecdsa_recover_compact
from c_secp256k1 import ecdsa_sign_compact as c_ecdsa_sign_compact
import warnings
from rlp.sedes import Binary
from rlp.sedes import big_endian_int as t_int
t_address = Binary.fixed_length(20, allow_empty=False)
t_hash = Binary.fixed_length(32, allow_empty=False)
t_hash_optional = Binary.fixed_length(32, allow_empty=True)


class ByteSerializer(object):

    @classmethod
    def serialize(cls, s):
        return s

    deserialize = serialize


class IntSerializer(object):

    @classmethod
    def serialize(cls, i):
        return int_to_big_endian(i)

    @classmethod
    def deserialize(cls, s):
        return big_endian_to_int(s)

t_int = IntSerializer
t_address = t_hash = t_hash_optional = ByteSerializer


def _encode_optimized(item):
    """RLP encode (a nested sequence of) bytes"""
    if isinstance(item, bytes):
        if len(item) == 1 and ord(item) < 128:
            return item
        prefix = length_prefix(len(item), 128)
    else:
        item = b''.join([_encode_optimized(x) for x in item])
        prefix = length_prefix(len(item), 192)
    return prefix + item


def length_prefix(length, offset):
    """Construct the prefix to lists or strings denoting their length.

    :param length: the length of the item in bytes
    :param offset: ``0x80`` when encoding raw bytes, ``0xc0`` when encoding a
                   list
    """
    if length < 56:
        return chr(offset + length)
    else:
        length_string = int_to_big_endian(length)
        return chr(offset + 56 - 1 + len(length_string)) + length_string


def decoderlp(rlpdata):
    """Decode an RLP encoded object."""
    try:
        item, end = consume_item(rlpdata, 0)
    except IndexError:
        raise DecodingError('RLP string to short', rlpdata)
    return item


class RLPHashable(object):

    fields = []

    @property
    def hash(self):
        warnings.warn('Expensive comparison called')
        return sha3(self.encode())

    def __eq__(self, other):
        return isinstance(other, self.__class__) and self.hash == other.hash

    def __hash__(self):
        return big_endian_to_int(self.hash)

    def __ne__(self, other):
        return not self.__eq__(other)

    def encode(self):
        return _encode_optimized(self.serialize())

    def serialize(self):
        "return object as a list of bytestrings"
        return [t.serialize(getattr(self, n)) for n, t in self.fields]

    @classmethod
    def deserialize(cls, byte_args):
        args = [t.deserialize(b) for (n, t), b in zip(cls.fields, byte_args)]
        return cls(*args)

    @classmethod
    def decode(cls, msg):
        """
        decode msg to an instance of the class
        set sender if it is a SignedMessage

        rlpdata(N) | signature(65)
        """
        byte_args = decoderlp(msg)
        return cls.deserialize(byte_args)


class Message(RLPHashable):

    """
    Message also has a sender property, so that Acks can be sent
    """

    cmdid = 0
    sender = ''

    fields = [('cmdid', t_int), ('sender', t_address)]

    def __repr__(self):
        return '<{}>'.format(self.__class__.__name__)

    # def __len__(self):
    #     return len(self.encode())

    @classmethod
    def deserialize(cls, byte_args):
        args = [t.deserialize(b) for (n, t), b in zip(cls.fields, byte_args)]
        return cls(*args[1:])


class SignatureMissingError(Exception):
    pass


class SignedMessage(Message):

    """
    Base Message, dispatching is decided based on the cmdid.
    Future protocol versions can be distinguished by using a different cmdid range
    """

    fields = [('cmdid', t_int)]
    signature = ''
    _sender = ''

    def encode(self):
        if not self.signature:
            raise SignatureMissingError()
        return _encode_optimized(self.serialize()) + self.signature

    @classmethod
    def decode(cls, msg):
        """
        decode msg to an instance of the class
        set sender if it is a SignedMessage

        rlpdata(N) | signature(65)
        """
        rlpdata = msg[:-65]
        byte_args = decoderlp(rlpdata)
        o = cls.deserialize(byte_args)
        o.signature = msg[-65:]
        o._recover_sender(rlpdata)
        return o

    def sign(self, privkey):
        assert not self.signature
        assert isinstance(privkey, bytes) and len(privkey) == 32
        h = sha3(_encode_optimized(self.serialize()))
        self.signature = c_ecdsa_sign_compact(h, privkey)
        assert len(self.signature) == 65
        return self

    def _recover_sender(self, msg):
        if not self.signature:
            raise SignatureMissingError()
        pub = c_ecdsa_recover_compact(sha3(msg), self.signature)
        self._sender = sha3(pub[1:])[-20:]

    @property
    def sender(self):
        if not self._sender:
            self._recover_sender(self.encode()[:-65])
        return self._sender


class Decoder(object):

    def __init__(self, extra_klasses=None):
        # infrastructure to deserialize messages into a Message instance
        klasses = Message.__subclasses__() + SignedMessage.__subclasses__()
        if extra_klasses:
            klasses.extend(extra_klasses)
        self.message_class_by_id = dict((c.cmdid, c) for c in klasses if c != SignedMessage)
        assert max(self.message_class_by_id.keys()) < 128  # assure we have 1 byte only cmdids

    def decode(self, data):
        # cmdid = rlp.peek(data, 0, sedes=t_int)  # cmdid is first element
        t, l, pos = consume_length_prefix(data, 0)
        cmdid = t_int.deserialize(consume_item(data[pos], 0)[0])
        cls = self.message_class_by_id[cmdid]
        print 'DECODING', cls
        return cls.decode(data)
