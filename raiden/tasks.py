from messages import Secret, CancelTransfer, TransferTimeout
from messages import SecretRequest
from utils import lpex, pex
import gevent
from gevent.event import AsyncResult
from ethereum import slogging
__all__ = (
    'Task',
    'TransferTask',
    'ForwardSecretTask',
)
log = slogging.get_logger('tasks')


class Task(gevent.Greenlet):

    def on_completion(self, success):
        self.transfermanager.on_task_completed(self, success)
        return success

    def on_event(self, msg):
        log.debug("SET EVENT {} {} {}".format(self, id(self.event), msg))
        if self.event.ready():
            log.debug("ALREADY HAD EVENT {} {} now {}".format(self, self.event.get(), msg))
        assert self.event and not self.event.ready()
        self.event.set(msg)


class TransferTask(Task):

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
        import transfermanager as transfermanagermodule
        assert isinstance(transfermanager, transfermanagermodule.TransferManager)
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
        super(TransferTask, self).__init__()
        log.info("INIT", task=self)
        self.transfermanager.on_task_started(self)

    def __repr__(self):
        return '<{} {}>'.format(self.__class__.__name__, pex(self.raiden.address))

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
            log.info("TRYING {} with path {}".format(self, lpex(path)))
            assert path[0] == self.raiden.address
            assert path[1] in self.assetmanager.channels
            assert path[-1] == self.target
            recipient = path[1]
            # check if channel is active
            if not self.assetmanager.channel_isactive(recipient):
                continue
            channel = self.assetmanager.channels[recipient]
            # check if we have enough funds, fixme add limit per transfer
            if self.amount > channel.distributable:
                continue
            # calculate fee, calc expiration
            t = channel.create_lockedtransfer(self.amount, self.expiration, self.hashlock)
            t = t.to_mediatedtransfer(self.target, initiator=initiator, fee=0)  # fixme fee
            self.raiden.sign(t)
            channel.register_transfer(t)

            # send mediated transfer
            msg = self.send_transfer(recipient, t, path)
            log.debug("SEND RETURNED {}  {}".format(self, msg))

            success = self.check_path(msg, channel)
            if success is None:
                continue  # try with next path
            else:
                return self.on_completion(success)
        # we did not find a path, send CancelTransfer
        if self.originating_transfer:
            channel = self.assetmanager.channels[self.originating_transfer.sender]
            t = channel.create_canceltransfer(self.originating_transfer)
            channel.register_transfer(t)
            self.raiden.sign(t)
            self.raiden.send(self.originating_transfer.sender, t)
        return self.on_completion(False)

    def check_path(self, msg, channel):
        if isinstance(msg, CancelTransfer):
            return None  # try with next path
        elif isinstance(msg, TransferTimeout):
            # stale hashlock
            if not self.isinitiator:
                self.raiden.send(self.originating_transfer.sender, msg)
            return False
        elif isinstance(msg, Secret):
            assert self.originating_transfer
            assert msg.hashlock == self.hashlock
            if self.originating_transfer.sender != self.originating_transfer.initiator:
                fwd = Secret(msg.secret)
                self.raiden.sign(fwd)
                self.raiden.send(self.originating_transfer.sender, fwd)
            else:
                log.warning("NOT FORWARDING SECRET TO ININTIATOR")
            return True
        elif isinstance(msg, SecretRequest):
            assert self.isinitiator
            assert msg.sender == self.target
            msg = Secret(self.secret)
            self.raiden.sign(msg)
            self.raiden.send(self.target, msg)
            # apply secret to own channel
            channel.claim_locked(self.secret)
            return True
        return None

    def send_transfer(self, recipient, transfer, path):
        self.event = AsyncResult()  # http://www.gevent.org/gevent.event.html
        self.raiden.send(recipient, transfer)
        timeout = self.timeout_per_hop * (len(path) - 1)  # fixme, consider no found paths
        msg = self.event.wait(timeout)

        log.debug("HAVE EVENT {} {}".format(self, msg))

        if msg is None:  # timeout
            log.error("TIMEOUT! " * 5)
            msg = TransferTimeout(echo=transfer.hash, hashlock=transfer.lock.hashlock)
            self.raiden.sign(msg)
            return msg

        if isinstance(msg, CancelTransfer):
            assert msg.hashlock == transfer.lock.hashlock
            assert msg.amount == transfer.lock.amount
            assert msg.recipient == transfer.sender == self.raiden.address
            channel = self.assetmanager.channels[msg.recipient]
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
            # channel = self.assetmanager.channels[msg.recipient]
            # channel.claim_locked(msg.secret)  # fixme this is also done by assetmanager
            return msg
        elif isinstance(msg, SecretRequest):
            # reveal secret
            log.info("SECRETREQUEST RECEIVED {}".format(msg))
            assert msg.sender == self.target
            return msg
        assert False, "Not Implemented"


class ForwardSecretTask(Task):

    timeout = TransferTask.timeout_per_hop

    def __init__(self, transfermanager, hashlock, recipient):
        self.transfermanager = transfermanager
        self.recipient = recipient
        self.hashlock = hashlock
        self.raiden = transfermanager.assetmanager.raiden
        super(ForwardSecretTask, self).__init__()
        log.info("INIT", task=self)
        self.transfermanager.on_task_started(self)

    def __repr__(self):
        return '<{} {}>'.format(self.__class__.__name__, pex(self.raiden.address))

    def _run(self):
        self.event = AsyncResult()  # http://www.gevent.org/gevent.event.html
        timeout = self.timeout
        msg = self.event.wait(timeout)
        if not msg:
            log.error("TIMEOUT! " * 5)
            # TransferTimeout is of no use, SecretRequest was for sender
            return self.on_completion(False)
        assert isinstance(msg, Secret)
        assert msg.hashlock == self.hashlock
        fwd = Secret(msg.secret)
        self.raiden.sign(fwd)
        self.raiden.send(self.recipient, fwd)
        return self.on_completion(True)
