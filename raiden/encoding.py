# -*- coding: utf8 -*-
# Copyright (c) 2015 Heiko Hees
import warnings
import struct

import umsgpack
from c_secp256k1 import ecdsa_recover_compact as c_ecdsa_recover_compact
from c_secp256k1 import ecdsa_sign_compact as c_ecdsa_sign_compact
from ethereum import slogging

from raiden.utils import big_endian_to_int, sha3, int_to_big_endian

log = slogging.get_logger('encoding')


def encode_msg(serializable_data):
    """Encode a data via msgpack"""
    return umsgpack.packb(serializable_data)


def decode_msg(binary_data):
    """Decode a msgpack encoded object"""
    return umsgpack.unpackb(binary_data)


def _pack_map(obj, fp):
    if len(obj) <= 15:
        fp.write(struct.pack("B", 0x80 | len(obj)))
    elif len(obj) <= 2**16 - 1:
        fp.write(b"\xde" + struct.pack(">H", len(obj)))
    elif len(obj) <= 2**32 - 1:
        fp.write(b"\xdf" + struct.pack(">I", len(obj)))
    else:
        raise umsgpack.UnsupportedTypeException("huge array")

    for k in sorted(obj.iterkeys()):
        umsgpack.pack(k, fp)
        umsgpack.pack(obj[k], fp)


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
umsgpack._pack_map = _pack_map


class MessageHashable(object):

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
        return encode_msg(self.serialize())

    def serialize(self):
        "return object as a list of bytestrings"
        return [t.serialize(getattr(self, n)) for n, t in self.fields]

    @classmethod
    def deserialize(cls, byte_args):
        args = [t.deserialize(b) for (n, t), b in zip(cls.fields, byte_args)]
        return cls(*args)

    @classmethod
    def decode(cls, msg):
        byte_args = decode_msg(msg)
        return cls.deserialize(byte_args)


class Message(MessageHashable):
    """ Message also has a sender property, so that Acks can be sent. """

    cmdid = None  # this class cannot be serialized
    sender = ''

    fields = [('cmdid', t_int), ('sender', t_address)]

    def __repr__(self):
        return '<{}>'.format(self.__class__.__name__)

    def encode(self):
        """ cmdid(1) | msgpack_data(N) """
        return struct.pack("B", self.cmdid) + encode_msg(self.serialize())

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

    cmdid = None  # this class cannot be serialized
    fields = [('cmdid', t_int)]
    signature = ''
    _sender = ''

    def encode(self):
        """
        cmdid(1) | msgpack_data(N) | signature(65)
        """

        if not self.signature:
            raise SignatureMissingError()
        return struct.pack("B", self.cmdid) + encode_msg(self.serialize()) + self.signature

    @classmethod
    def decode(cls, msg):
        """
        decode msg to an instance of the class
        set sender if it is a SignedMessage

        msgpack_data(N) | signature(65)
        """
        msgpack_data = msg[:-65]
        byte_args = decode_msg(msgpack_data)
        o = cls.deserialize(byte_args)
        o.signature = msg[-65:]
        o._recover_sender(msgpack_data)
        return o

    def sign(self, privkey):
        assert not self.signature
        assert isinstance(privkey, bytes) and len(privkey) == 32
        h = sha3(encode_msg(self.serialize()))
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
            self._recover_sender(self.encode()[1:-65])
        return self._sender


class Decoder(object):
    ''' An automatic registry for Message subclasses. '''

    def __init__(self, extra_klasses=None):
        classes = set([Message])

        extra_klasses = extra_klasses or []
        for klass in extra_klasses:
            classes.add(klass)

            if not issubclass(klass, Message):
                raise ValueError('{} is not a subclass of Message'.format(klass))

        cmdid_class = dict()
        seen = set(classes)
        while classes:
            klass = classes.pop()

            if klass.cmdid is not None:  # 0 is a valid value
                cmdid = klass.cmdid
                if not (0 <= cmdid <= 255):
                    msg = '{}: Invalid cmdid {}, needs to be in the [0, 255] range.'.format(
                        klass,
                        cmdid,
                    )
                    raise ValueError(msg)

                if cmdid in cmdid_class:
                    msg = 'Conflicting cmdid among {} and {}'.format(
                        klass,
                        cmdid_class[cmdid]
                    )
                    raise ValueError(msg)

                cmdid_class[cmdid] = klass

            for subclass in klass.__subclasses__():
                if subclass not in seen:
                    seen.add(subclass)
                    classes.add(subclass)

        self.message_class_by_id = cmdid_class

    def decode(self, data):
        # cmdid is a first byte
        cmdid = struct.unpack('B', data[0])[0]
        cls = self.message_class_by_id[cmdid]
        log.debug('DECODING', cls=cls)
        return cls.decode(data[1:])
