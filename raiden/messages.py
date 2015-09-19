# Copyright (c) 2015 Heiko Hees
from utils import big_endian_to_int, sha3, isaddress, ishash, int_to_big_endian, pex
import rlp
from rlp.sedes import Binary

from rlp.sedes import big_endian_int as t_int
from rlp.sedes import binary as t_binary
from rlp.sedes import List as t_list

t_address = Binary.fixed_length(20, allow_empty=False)
t_hash = Binary.fixed_length(32, allow_empty=False)
t_hash_optional = Binary.fixed_length(32, allow_empty=True)


class RLPHashable(rlp.Serializable):
    rlp_ = None

    @property
    def hash(self):
        return sha3(getattr(self, 'rlp_', None) or rlp.encode(self))

    def __eq__(self, other):
        return isinstance(other, self.__class__) and self.hash == other.hash

    def __hash__(self):
        return big_endian_to_int(self.hash)

    def __ne__(self, other):
        return not self.__eq__(other)

    def __repr__(self):
        try:
            h = self.hash
        except Exception:
            h = ''
        return '<%s(%s)>' % (self.__class__.__name__, pex(h))


class Signed(RLPHashable):

    fields = [('sender', t_address)]  # FIMXE this is a dummy

    def __init__(self, sender=''):
        assert not sender or isaddress(sender)
        super(Signed, self).__init__(sender=sender)

    def __len__(self):
        return len(rlp.encode(self)) + 1 + 32  # fixme dummy

    def sign(self, sender):  # fixme dummy
        assert isaddress(sender)
        self.sender = sender
        return self


class Message(RLPHashable):

    """
    Message also has a sender property, so that Acks can be sent
    """

    cmdid = 0
    sender = ''

    fields = [('cmdid', t_int), ('sender', t_address)]

    def __repr__(self):
        return '<{} {}>'.format(self.__class__.__name__, pex(self.hash))


class SignedMessage(Signed, Message):

    """
    Base Message, dispatching is decided based on the cmdid.
    Future protocol versions can be distinguished by using a different cmdid range
    """

    fields = [('cmdid', t_int), ('sender', t_address)]


class Ack(Message):

    """
    All accepted messages should be confirmed by an `Ack`
    which echoes the orginals Message hash

    We don't sign Acks because attack vector can be mitigated and to speed up things
    """

    cmdid = 0

    fields = Message.fields + [('echo', t_hash)]

    def __init__(self, echo, sender=''):
        self.echo = echo
        self.sender = sender


class Ping(SignedMessage):

    """
    Ping, should be responded by an Ack message
    """
    cmdid = 1

    fields = SignedMessage.fields + [('nonce', t_int)]

    def __init__(self, nonce):
        self.nonce = nonce


class BaseError(Exception):
    errorid = 0
    echo = ''
    error_map = dict()

    def __init__(self, msg_or_echo, *args):
        if isinstance(msg_or_echo, SignedMessage):
            self.echo = msg_or_echo.hash
        else:
            assert ishash(msg_or_echo)
            self.echo = msg_or_echo
        super(BaseError, self).__init__(*args)

    def asmessage(self):
        return Rejected(self.echo, self.errorid, *self.args)

    @classmethod
    def register(cls):
        assert issubclass(cls, BaseError)
        BaseError.error_map[cls.errorid] = cls

BaseError.register()


class Rejected(SignedMessage):

    """
    All rejected messages should be confirmed by a `Rejected`
    which echoes the orginals Message hash.
    """

    cmdid = 2

    fields = SignedMessage.fields + \
        [
            ('echo', t_hash),
            ('errorid', t_int),
            ('args', t_list)
        ]

    def __init__(self, echo, errorid, *args):
        self.echo = echo
        self.errorid = errorid
        self.args = args

    def aserror(self):
        cls = BaseError[self.errorid]
        return cls(self.echo, *self.args)


class SecretRequest(SignedMessage):

    """
    Requests the secret which unlocks a hashlock
    """
    cmdid = 3

    fields = SignedMessage.fields + \
        [
            ('hashlock', t_hash),
        ]

    def __init__(self, hashlock):
        self.hashlock = hashlock


class Secret(SignedMessage):

    """
    Provides the secret to a hashlock
    """
    cmdid = 4

    fields = SignedMessage.fields + \
        [
            ('secret', t_hash)
        ]

    def __init__(self, secret):
        self.secret = secret
        self.hashlock = sha3(secret)


class Transfer(SignedMessage):

    """
    Signs the unidirectional settled `balance` of `asset` to `recipient` plus locked transfers.
        Settled refers to the inclusion of formerly locked amounts.
        Locked amounts are not included in the balance yet, but represented by the `locksroot`.

    `locksroot` is the root of a merkle tree which records the outstanding
    locked_amounts with their hashlocks.
    this allows to keep transfering, although the there are locks outstanding.
    this is because the recipient knwows that haslocked transfers can be settled
    once the secret becomes available even, when the peer fails and the balance
    could not be netted.


    If `secret` is provided, this allows to settle a formerly locked transfer,
    the given secret is already reflected in the locksroot.
    """

    cmdid = 5
    fields = SignedMessage.fields + \
        [
            ('nonce', t_int),
            ('asset', t_address),
            ('balance', t_int),
            ('recipient', t_address),
            ('locksroot', t_hash_optional),
            ('secret', t_hash_optional),
        ]

    def __init__(self, nonce, asset, balance, recipient, locksroot, secret=None):
        self.nonce = nonce
        self.asset = asset
        self.balance = balance
        self.recipient = recipient
        self.locksroot = locksroot
        self.secret = secret or ''  # secret for settling a locked amount: hashlock = sha3(secret)


class Lock(rlp.Serializable):

    """
    Data describing a locked `amount`.

    `expiration` is the highest block_number until which the transfer can be settled
    `hashlock` is the hashed secret, necessary to release the funds
    """
    fields =  \
        [
            ('amount', t_int),
            ('expiration', t_int),
            ('hashlock', t_hash),
        ]

    _cached_asstring = None

    def __init__(self,  amount, expiration, hashlock):
        assert amount > 0
        assert ishash(hashlock)
        self.amount = amount
        self.expiration = expiration
        self.hashlock = hashlock

    @property
    def asstring(self):
        if not self._cached_asstring:
            # return ''.join(self.__class__.exclude(['cmdid', 'sender']).serialize(self)) # slow
            self._cached_asstring = rlp.encode([self.amount, self.expiration, self.hashlock])
        return self._cached_asstring


# class StateLock(rlp.Serializable):

#     """
#     NotImplemented

#     A Lock which depends on a certain state on the associated chain.

#     Therefore it comes with `data` which when passed to the `ChannelsContract`
#     will call a contract at address data[:20] with data[20:].
#     """
#     fields =  \
#         [
#             ('amount', t_int),
#             ('expiration', t_int),
#             ('data', t_hash),
#         ]

#     def __init__(self,  amount, expiration, data):
#         assert amount > 0
#         self.amount = amount
#         self.expiration = expiration
#         self.data = data

#     @property
#     def hashlock(self):
#         return sha3(''.join(self.__class__.exclude('cmdid', 'sender').serialize(self)))


class LockedTransfer(SignedMessage):

    """
    `LockedTransfer` which signs, that recipient can claim `locked_amount`
    if she knows the secret to `hashlock`.

    The `locked_amount` is not part of the `balance` but implicit in the `locksroot`.

    Bob sends Carol a hashlocked Transfer:
        balance is not updated
        locksroot is updated with [nonce, asset, locked_amount, recipient, hashlock]

    This signs Carol, that she can claim locked_amount from Bob if she knows the secret to hashlock

    If the secret to hashlock becomes public, but Bob fails to sign Carol a netted balance,
    with an updated rootlock which reflects the deletion of the lock, then
        Carol can request settlement on chain by providing:
            any signed [nonce, asset, balance, recipient, locksroot, ...]
            along a merkle proof from locksroot to the not yet netted formerly locked amount
    """
    cmdid = 6
    fields = SignedMessage.fields + \
        [
            ('nonce', t_int),
            ('asset', t_address),
            ('balance', t_int),
            ('recipient', t_address),
            ('locksroot', t_hash),
            ('lock', Lock),
        ]

    def __init__(self, nonce, asset, balance, recipient, locksroot, lock):
        self.nonce = nonce
        self.asset = asset
        self.balance = balance
        self.recipient = recipient
        self.locksroot = locksroot
        self.lock = lock

    def to_mediatedtransfer(self, target, fee=0, initiator=''):
        assert not self.sender  # must not yet be signed
        self.__class__ = MediatedTransfer
        self.target = target
        self.fee = fee
        self.initiator = initiator

    def to_canceltransfer(self):
        self.__class__ = CancelTransfer


class MediatedTransfer(LockedTransfer):

    """
    A MediatedTransfer has a `target` address to which a chain of transfers shall be established.
    Here the `haslock` is mandatory.

    `fee` is the remaining fee a recipient shall use to complete the mediated transfer.
    The recipient can deduct his own fee from the amount and lower `fee` to the remaining fee.
    Just as the recipient can fail to forward at all, or the assumed amount,
    it can deduct a too high fee, but this would render completion of the transfer unlikely.

    The initiator of a mediated transfer will calculate fees based on the likely fees along the
    path. Note, it can not determin the path, as it does not know which nodes are available.

    Initial `amount` should be expected received amount + fees.

    Fees are always payable by the initiator.

    `initiator` is the party that knows the secret to the `hashlock`
    """
    cmdid = 7
    fields = LockedTransfer.fields + \
        [
            ('target', t_address),
            ('fee', t_int),
            ('initiator', t_address)
        ]

    def __init__(self, nonce, asset, balance, recipient, locksroot,
                 lock, target, initiator, fee=0):
        super(MediatedTransfer, self).__init__(nonce, asset, balance, recipient,
                                               locksroot, lock)
        self.target = target
        self.fee = fee
        self.initiator = initiator


class CancelTransfer(LockedTransfer):

    """
    gracefully cancels a transfer by reversing it
    indicates that no route could be found
    """
    cmdid = 8


class TransferTimeout(SignedMessage):
    cmdid = 9

    fields = SignedMessage.fields + [('echo', t_hash), ('hashlock', t_hash)]

    def __init__(self, echo, hashlock):
        self.echo = echo
        self.hashlock = hashlock


# class TransferRequest(SignedMessage):

#     """
#     Requests the transfer of an asset.

#     If the recipient agrees, it replies with an `Ack` message and
#     initiates a (Mediated)Transfer.
#     """
#     cmdid = 10

#     fields = SignedMessage.fields + \
#         [
#             ('asset', t_address),
#             ('amount', t_int),
#             ('haslock', t_hash),
#             ('reference', t_hash_optional),
#         ]

#     def __init__(self, asset, amount, hashlock, reference=''):
#         self.asset = asset
#         self.amount = amount
#         self.hashlock = hashlock
#         self.reference = reference


# class ExchangeRequest(SignedMessage):

#     """
#     Requests the exchange of an asset pair
#     `bid_asset`: address of the offered asset
#     `ask_asset`: address of the wanted asset
#     `bid_amount`: amount bid of the offered asset, can be zero for market orders
#     `ask_amount`: amount asked of the wanted asset, can be zero for market orders

#     Any of `bid_amount` , `ask_amount` must be non zero.

#     `ExchangeRequests` are broadcasted : TBD

#     Any party interested in an exchange can send a TransferRequest to the initiator.
#     They are free to only partially match the exchange offer.


#     Case `bid_amount=0`: Buy market order
#     Responder must announce, which `amount` of `bit_asset` it requests.
#         Responder sends:
#             Opening MediatedTransfer which specifies the `ask_amount`.
#             TransferRequest which specifies the `bid_amount`.
#         If the initiator agrees, it sends:
#             Acks
#             MediatedTransfer matching the TransferRequest
#         It sends a Reject message otherwise.


#     Case `ask_amount=0`: Sell market order
#     Responder must announce, which `amount` of `ask_asset` it requests.

#     Case `ask_amount & bid_amount`: Limit Order
#     """
#     cmdid = 11

#     fields = SignedMessage.fields + \
#         [
#             ('bid_asset', t_address),
#             ('ask_asset', t_address),
#             ('bid_amount', t_int),
#             ('ask_amount', t_int)
#         ]

#     def __init__(self, bid_asset, ask_asset,  bid_amount=0, ask_amount=0):
#         self.bid_asset = bid_asset
#         self.ask_asset = ask_asset
#         self.bid_amount = bid_amount
#         self.ask_amount = ask_amount


# infrastructure to deserialize messages into a Message instance
message_class_by_id = dict((c.cmdid, c) for c in
                           Message.__subclasses__() + SignedMessage.__subclasses__())
message_class_by_id[MediatedTransfer.cmdid] = MediatedTransfer
cmdid_pos = [_[0] for _ in Message.fields].index('cmdid')
sender_pos = [_[0] for _ in SignedMessage.fields].index('sender')
for cls in message_class_by_id.values():
    assert cls.fields[cmdid_pos][0] == 'cmdid'


def deserialize(data):
    # cmdid, sender are deserialized separately
    # cmdid to match the class
    # sender, so we don't have it in the signatures
    cmdid = rlp.peek(data, cmdid_pos, sedes=t_int)
    sender = rlp.peek(data, sender_pos, sedes=t_address)
    assert cmdid < 256
    cls = message_class_by_id[cmdid]
    m = cls.deserialize(rlp.decode(data), exclude=['sender', 'cmdid'])
    m.mutable_ = True
    m.sender = sender
    m.mutable_ = False
    return m
