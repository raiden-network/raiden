from messages import Secret, BaseError, CancelTransfer, TransferTimeout
from messages import TransferRequest, SecretRequest
from utils import sha3
import gevent
from gevent.event import AsyncResult
import random


class TransferTask(gevent.Greenlet):

    """
    Normal Operation (Transfer A > C)
    A: Initiator Creates Secret
    A: MediatedTransfer > B
    B: MediatedTransfer > C
    C: SecretRequest > A (implicitly signs, that valid transfer was received)
    A: Secret > C
    C: Secret > B

    Timeout (Transfer A > C)
    A: Initiator Creates Secret
    A: MediatedTransfer > B
    B: MediatedTransfer > C
    Failure: No Ack from C
    B: TransferTimeout > A
    Resolution: A won't reveal the secret, tries new transfer, B bans C

    CancelTransfer (Transfer A > D)
    A: Initiator Creates Secret
    A: MediatedTransfer > B
    B: MediatedTransfer > C
    Failure: C can not establish path to D (e.g. insufficient distributable, no active node)
    C: CancelTransfer > B (levels out balance)
    B: MediatedTransfer > C2
    C2: MediatedTransfer > D
    ...

    """

    block_expiration = 120  # FIXME, this needs to timeout on block expiration
    timeout_per_hop = 10

    def __init__(self, transfermanager, amount, target, hashlock,
                 expiration=None, originating_transfer=None, secret=None):  # fee!
        self.transfermanager = transfermanager
        self.assetmanager = transfermanager.assetmanager
        self.raiden = transfermanager.assetmanager.raiden
        self.amount = amount
        self.target = target
        self.hashlock = hashlock
        self.expiration = None or 10  # fixme
        assert secret or originating_transfer
        self.originating_transfer = originating_transfer  # no sender == self initiated transfer
        self.secret = secret

    @property
    def isinitiator(self):
        "whether this node initiated the transfer"
        return not self.originating_transfer

    def _run(self):
        if self.isinitiator:
            initiator = self.raiden.address
        else:
            initiator = self.originating_transfer.initiator

        # look for shortest path
        for path in self.assetmanager.channelgraph.get_paths(self.raiden.address, self.target):
            assert path[0] == self.raiden.address
            assert path[1] in self.assetmanager.channels
            assert path[-1] == self.target
            recipient = path[1]
            # check if channel is active
            if not self.assetmanager.channel_isactive(recipient):
                continue
            channel = self.assetmanager.channels[recipient]
            # check if we have enough funds ,fixme add limit per transfer
            if self.amount > channel.distributable:
                continue
            # calculate fee, calc expiration
            t = channel.create_lockedtransfer(self.amount, self.expiration, self.hashlock)

            t.to_mediatedtransfer(self.target, initiator=initiator, fee=0)  # fixme fee
            channel.register_transfer(t)
            # send mediated transfer
            msg = self.send_transfer(t, path)
            if isinstance(msg, CancelTransfer):
                continue  # try with next path
            elif isinstance(msg, TransferTimeout):
                # stale hashlock
                self.raiden.send(channel.partner.address, msg)
                return False
            elif isinstance(msg, Secret):
                assert self.originating_transfer
                self.raiden.protocol.send(self.originating_transfer, msg)
                return True
            elif isinstance(msg, SecretRequest):
                assert self.isinitiator
                assert msg.sender == self.target
                self.raiden.send(channel.partner.address, Secret(self.secret))
                return True
        # we did not find a path, send CancelTransfer
        if self.originating_transfer:
            channel = self.assetmanager.channels[self.originating_transfer.sender]
            t = channel.create_canceltransfer(self.originating_transfer)
            channel.register_transfer(t)
            self.raiden.send(self.originating_transfer.sender, t)
        return False

    def on_event(self, msg):
        assert self.event and not self.event.ready()
        self.event.add(msg)

    def send_transfer(self, transfer, path):
        self.event = AsyncResult()  # http://www.gevent.org/gevent.event.html
        self.raiden.protocol.send(transfer)
        timeout = self.timeout_per_hop * (len(path) - 1)  # fixme, consider no found paths
        msg = self.event.wait(timeout)
        if msg is None:  # timeout
            return TransferTimeout(echo=transfer.hash, hashlock=transfer.hashlock)
        assert msg.hashlock == transfer.hashlock
        channel = self.assetmanager.channels[msg.recipient]
        if isinstance(msg, CancelTransfer):
            assert msg.amount == transfer.amount
            assert msg.recipient == transfer.sender == self.raiden.address
            channel.register_transfer(msg)
            return msg
            # try with next path
        elif isinstance(msg, TransferTimeout):
            assert msg.echo == transfer.hash
            return msg
            # send back StaleHashLock, we need new hashlock
        elif isinstance(msg, Secret):
            # done exit
            assert msg.hashlock == self.hashlock
            channel.claim_locked(msg.secret)
            return msg
        elif isinstance(msg, SecretRequest):
            # reveal secret
            assert msg.sender == self.target
            return msg
        assert False, "Not Implemented"
