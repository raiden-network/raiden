# Copyright (c) 2015 Heiko Hees
from utils import big_endian_to_int, sha3, isaddress, ishash
import rlp
from rlp.sedes import Binary
from rlp.utils import encode_hex

from rlp.sedes import big_endian_int as t_int
from rlp.sedes import binary as t_binary
from rlp.sedes import List as t_list

t_address = Binary.fixed_length(20, allow_empty=False)
t_hash = Binary.fixed_length(32, allow_empty=False)
t_hash_optional = Binary.fixed_length(32, allow_empty=True)


class RLPHashable(rlp.Serializable):
    _rlp_data = None  # deserialized message should not be changed

    @property
    def hash(self):
        return sha3(self._rlp_data or rlp.encode(self))

    def __eq__(self, other):
        return isinstance(other, self.__class__) and self.hash == other.hash

    def __hash__(self):
        return big_endian_to_int(self.hash)

    def __ne__(self, other):
        return not self.__eq__(other)

    def __repr__(self):
        return '<%s(%s)>' % (self.__class__.__name__, encode_hex(self.hash)[:4])


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


class SignedMessage(Signed):

    """
    Base Message, dispatching is decided based on the cmdid.
    Future protocol versions can be distinguished by using a different cmdid range
    """
    cmdid = 0

    fields = Signed.fields + [('cmdid', t_int)]


class Ping(SignedMessage):

    """
    Ping, should be responded by an Ack message
    """
    cmdid = 0

    fields = SignedMessage.fields + [('nonce', t_int)]

    def __init__(self, nonce):
        self.nonce = nonce


class Ack(SignedMessage):

    """
    All accepted messages should be confirmed by an `Ack`
    which echoes the orginals Message hash
    """

    cmdid = 1

    fields = SignedMessage.fields + [('echo', t_hash)]

    def __init__(self, echo):
        self.echo = echo


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


class HashLockRequest(SignedMessage):

    """
    Requests the secret which unlocks a hashlock
    proof can be empty or
        an rlp encoded `Transfer` which is expected to unlock
    """
    cmdid = 3

    fields = SignedMessage.fields + \
        [
            ('hashlock', t_hash),
            ('proof', t_binary)
        ]

    def __init__(self, hashlock, proof=''):
        self.hashlock = hashlock
        self.proof = proof


class HashLock(SignedMessage):

    """
    Provides the secret to a hashlock
    """
    cmdid = 4

    fields = SignedMessage.fields + \
        [
            ('hashlock', t_hash),
            ('secret', t_hash)
        ]

    def __init__(self, hashlock, secret):
        self.hashlock = hashlock
        self.secret = secret


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
            ('locksroot', t_hash),
            ('secret', t_hash_optional),
        ]

    def __init__(self, nonce, asset, balance, recipient, locksroot, hashlock='', secret=''):
        self.nonce = nonce
        self.asset = asset
        self.balance = balance
        self.recipient = recipient
        self.secret = secret  # secret for settling a locked amount: hashlock = sha3(secret)


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

    Note:


    """
    cmdid = 6
    fields = SignedMessage.fields + \
        [
            ('nonce', t_int),
            ('asset', t_address),
            ('balance', t_int),
            ('recipient', t_address),
            ('locksroot', t_hash),
            ('locked_amount', t_int),
            ('lock_expiration', t_int),
            ('hashlock', t_hash),
            # ('scriptlock', t_binary),  # Future: evm bytecode which must return true
        ]

    def __init__(self, nonce, asset, balance, recipient, locksroot,
                 locked_amount, lock_expiration, hashlock):
        self.nonce = nonce
        self.asset = asset
        self.balance = balance
        self.recipient = recipient
        self.locked_amount = locked_amount
        self.hashlock = hashlock


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


    `initiator_signature` is optional and signs H(asset, amount, target, hashlock)
    It can be provided to prove and accumulate reputation.
    """
    cmdid = 7
    fields = Transfer.fields + \
        [
            ('target', t_address),
            ('fee', t_int),
            ('initiator_signature', t_binary)
        ]

    def __init__(self, nonce, asset, balance, recipient, locksroot,
                 locked_amount, hashlock, target, fee=0, initiator_signature=''):
        super(MediatedTransfer, self).__init(self, nonce, asset, balance, recipient, locksroot,
                                             locked_amount, hashlock)
        self.target = target
        self.fee = fee
        self.initiator_signature = initiator_signature


class TransferRequest(SignedMessage):

    """
    Requests the transfer of an asset.

    If the recipient agrees, it replies with an `Ack` message and
    initiates a (Mediated)Transfer.
    """
    cmdid = 8

    fields = SignedMessage.fields + \
        [
            ('asset', t_address),
            ('amount', t_int),
            ('reference', t_hash_optional),
        ]

    def __init__(self, asset, amount, reference=''):
        self.asset = asset
        self.amount = amount
        self.reference = reference


class ExchangeRequest(SignedMessage):

    """
    Requests the exchange of an asset pair
    `bid_asset`: address of the offered asset
    `ask_asset`: address of the wanted asset
    `bid_amount`: amount bid of the offered asset, can be zero for market orders
    `ask_amount`: amount asked of the wanted asset, can be zero for market orders

    Any of `bid_amount` , `ask_amount` must be non zero.

    `ExchangeRequests` are broadcasted : TBD

    Any party interested in an exchange can send a TransferRequest to the initiator.
    They are free to only partially match the exchange offer.


    Case `bid_amount=0`: Buy market order
    Responder must announce, which `amount` of `bit_asset` it requests.
        Responder sends:
            Opening MediatedTransfer which specifies the `ask_amount`.
            TransferRequest which specifies the `bid_amount`.
        If the initiator agrees, it sends:
            Acks
            MediatedTransfer matching the TransferRequest
        It sends a Reject message otherwise.


    Case `ask_amount=0`: Sell market order
    Responder must announce, which `amount` of `ask_asset` it requests.

    Case `ask_amount & bid_amount`: Limit Order
    """
    cmdid = 9

    fields = SignedMessage.fields + \
        [
            ('bid_asset', t_address),
            ('ask_asset', t_address),
            ('bid_amount', t_int),
            ('ask_amount', t_int)
        ]

    def __init__(self, bid_asset, ask_asset,  bid_amount=0, ask_amount=0):
        self.bid_asset = bid_asset
        self.ask_asset = ask_asset
        self.bid_amount = bid_amount
        self.ask_amount = ask_amount

# infrastructure to deserialize messages into a SignedMessage instance
message_class_by_id = dict((c.cmdid, c) for c in SignedMessage.__subclasses__())
message_class_by_id[MediatedTransfer.cmdid] = MediatedTransfer
cmdid_pos = [_[0] for _ in SignedMessage.fields].index('cmdid')
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
    m._rlp_data = data
    m.sender = sender
    return m
