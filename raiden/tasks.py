# -*- coding: utf8 -*-
import gevent
from gevent.event import AsyncResult

from ethereum import slogging

from raiden.messages import Secret, CancelTransfer, TransferTimeout, LockedTransfer
from raiden.messages import SecretRequest
from raiden.utils import lpex, pex

__all__ = (
    'Task',
    'MediatedTransferTask',
    'ForwardSecretTask',
)

log = slogging.get_logger(__name__)  # pylint: disable=invalid-name


class Task(gevent.Greenlet):

    def on_completion(self, success):
        self.transfermanager.on_task_completed(self, success)
        return success

    def on_event(self, msg):
        # we might have timed out before
        if self.event.ready():
            log.debug('ALREADY HAD EVENT {task_repr} {event_value} now {raiden_message}'.format(
                task_repr=self,
                event_value=self.event.get(),
                raiden_message=msg,
            ))
        else:
            log.debug('SET EVENT {task_repr} {event_id} {raiden_message}'.format(
                task_repr=repr(self),
                event_id=id(self.event),
                raiden_message=msg,
            ))

            self.event.set(msg)


class MediatedTransferTask(Task):
    # Normal Operation (Transfer A > C)
    # A: Initiator Creates Secret
    # A: MediatedTransfer > B
    # B: MediatedTransfer > C
    # C: SecretRequest > A (implicitly signs, that valid transfer was received)
    # A: Secret > C
    # C: Secret > B

    # Timeout (Transfer A > C)
    # A: Initiator Creates Secret
    # A: MediatedTransfer > B
    # B: MediatedTransfer > C
    # Failure: No Ack from C
    # B: TransferTimeout > A
    # Resolution: A won't reveal the secret, tries new transfer, B bans C

    # CancelTransfer (Transfer A > D)
    # A: Initiator Creates Secret
    # A: MediatedTransfer > B
    # B: MediatedTransfer > C
    # Failure: C can not establish path to D (e.g. insufficient distributable, no active node)
    # C: CancelTransfer > B (levels out balance)
    # B: MediatedTransfer > C2
    # C2: MediatedTransfer > D

    def __init__(self, transfermanager, amount, target, hashlock,
                 lock_expiration=None, originating_transfer=None, secret=None):  # fee!
        self.amount = amount
        self.assetmanager = transfermanager.assetmanager
        self.event = None
        self.fee = 0  # FIXME: calculate fee
        self.hashlock = hashlock
        self.originating_transfer = originating_transfer
        self.raiden = transfermanager.raiden
        self.secret = secret
        self.target = target
        self.transfermanager = transfermanager
        self.isinitiator = bool(secret)

        if originating_transfer and secret:
            raise ValueError('Cannot set both secret and originating_transfer')

        if not (originating_transfer or secret):
            raise ValueError('Either originating_transfer or secret needs to be informed')

        if originating_transfer and not isinstance(originating_transfer, LockedTransfer):
            raise ValueError('originating_transfer needs to be a LockedTransfer')

        if self.isinitiator:
            self.initiator = self.raiden.address
            self.lock_expiration = self.raiden.chain.block_number + 18
        else:
            self.initiator = originating_transfer.initiator
            self.lock_expiration = originating_transfer.lock.expiration - 1

        super(MediatedTransferTask, self).__init__()
        self.transfermanager.on_task_started(self)

    def __repr__(self):
        return '<{} {}>'.format(self.__class__.__name__, pex(self.raiden.address))

    def _run(self):  # pylint: disable=method-hidden

        for path, channel in self.get_best_routes():
            next_hop = path[1]

            mediated_transfer = channel.create_mediatedtransfer(
                self.initiator,
                self.target,
                self.fee,
                self.amount,
                # HOTFIX: you cannot know channel.settle_timeout beforehand,since path is not yet defined
                # FIXME: implement expiration adjustment in different task (e.g. 'InitMediatedTransferTask')
                self.lock_expiration if self.lock_expiration is not None else channel.settle_timeout - 1,
                self.hashlock,
            )
            self.raiden.sign(mediated_transfer)
            channel.register_transfer(mediated_transfer)

            log.debug('MEDIATED TRANSFER initiator={} {}'.format(
                pex(mediated_transfer.initiator),
                lpex(path),
            ))

            msg_timeout = self.raiden.config['msg_timeout']

            # timeout not dependent on expiration (canceltransfer/transfertimeout msgs),
            # but should be set shorter than the expiration
            msg = self.send_transfer_and_wait(next_hop, mediated_transfer, path, msg_timeout)

            log.debug('MEDIATED TRANSFER RETURNED {} {}'.format(
                pex(self.raiden.address),
                msg,
            ))

            result = self.check_path(msg, channel)

            # `next_hop` didn't get a response from any of it's, let's try the
            # next path
            if isinstance(result, TransferTimeout):
                continue

            # `next_hop` doesn't have any path with a valid channel to proceed,
            # try the next path
            if isinstance(result, CancelTransfer):
                continue

            # `check_path` failed, try next path
            if result is None:
                continue

            return self.on_completion(result)

        # No suitable path avaiable (e.g. insufficient distributable, no active node)
        # Send CancelTransfer to the originating node, this has the effect of
        # backtracking in the graph search of the raiden network.
        if self.originating_transfer:
            from_address = self.originating_transfer.sender
            from_transfer = self.originating_transfer
            from_channel = self.assetmanager.channels[from_address]

            log.debug('CANCEL MEDIATED TRANSFER from={} {}'.format(
                pex(from_address),
                pex(self.raiden.address),
            ))

            cancel_transfer = from_channel.create_canceltransfer_for(from_transfer)
            self.raiden.sign(cancel_transfer)
            from_channel.register_transfer(cancel_transfer)
            self.raiden.send(from_address, cancel_transfer)
        else:
            log.error('UNABLE TO COMPLETE MEDIATED TRANSFER target={} amount={}'.format(
                pex(self.target),
                self.amount,
            ))

        return self.on_completion(False)

    def get_best_routes(self):
        """ Yield a two-tuple (path, channel) that can be used to mediate the
        transfer. The result is ordered from the best to worst path.
        """
        available_paths = self.assetmanager.channelgraph.get_shortest_paths(
            self.raiden.address,
            self.target,
        )

        for path in available_paths:
            assert path[0] == self.raiden.address
            assert path[1] in self.assetmanager.channels
            assert path[-1] == self.target

            partner = path[1]
            channel = self.assetmanager.channels[partner]

            if not channel.isopen:
                continue

            # we can't intermediate the transfer if we don't have enough funds
            if self.amount > channel.distributable:
                continue

            # Our partner won't accept a locked transfer that can expire after
            # the settlement period, otherwise the secret could be revealed
            # after channel is settled and he would lose the asset, or before
            # the minimum required.

            # FIXME Hotfix, see self._run()
            if not self.lock_expiration:
                lock_expiration = channel.settle_timeout - 1
            else:
                lock_expiration = self.lock_expiration

            reveal_expiration = self.raiden.chain.block_number + channel.reveal_timeout
            settle_expiration = self.raiden.chain.block_number + channel.settle_timeout
            if not reveal_expiration <= lock_expiration < settle_expiration:
                log.debug(
                    'lock_expiration is too large, channel/path cannot be used',
                    lock_expiration=lock_expiration,
                    channel_locktime=settle_expiration,
                    nodeid=pex(path[0]),
                    partner=pex(path[1]),
                )
                continue

            yield (path, channel)

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
                log.warning('NOT FORWARDING SECRET TO ININTIATOR')
            return True
        elif isinstance(msg, SecretRequest):
            assert self.isinitiator

            # lock.target can easilly be tampered, ensure that we are receiving
            # the SecretRequest from the correct node
            if msg.sender != self.target:
                log.error('Tampered SecretRequest', secret_request=msg)
                return None  # try the next available path

            # TODO: the lock.amount can easily be tampered, check the `target`
            # locked transfer has the correct `amount`
            msg = Secret(self.secret)
            self.raiden.sign(msg)
            self.raiden.send(self.target, msg)

            # TODO: Guarantee that `target` received the secret, otherwise we
            # updated the channel and the first hop will receive the asset, but
            # none of the other channels will make the transfer
            channel.claim_locked(self.secret)
            return True
        return None

    def send_transfer_and_wait(self, recipient, transfer, path, msg_timeout):
        """ Send `transfer` to `recipient` and wait for the response.

        Args:
            recipient (address): The address of the node that will receive the
                message.
            transfer: The transfer message.
            path: The current path that is being tried.
            msg_timeout: How long should we wait for a response from `recipient`.

        Returns:
            TransferTimeout: If the other end didn't respond
        """
        self.event = AsyncResult()
        self.raiden.send(recipient, transfer)

        # The event is set either when a relevant message is received or we
        # reach the timeout.
        #
        # The relevant messages are: CancelTransfer, TransferTimeout,
        # SecretRequest, or Secret
        msg = self.event.wait(msg_timeout)

        # Timed out
        if msg is None:
            log.error('TIMEOUT [{}]! recipient={} didnt respond path={}'.format(
                msg_timeout,
                pex(recipient),
                lpex(path),
            ))

            transfer_timeout = TransferTimeout(
                echo=transfer.hash,
                hashlock=transfer.lock.hashlock,
            )
            self.raiden.sign(transfer_timeout)
            return transfer_timeout

        log.debug(
            'HAVE EVENT {} {}'.format(self, msg),
            node=pex(self.raiden.address),
        )

        if isinstance(msg, CancelTransfer):
            assert msg.lock.hashlock == transfer.lock.hashlock
            assert msg.lock.amount == transfer.lock.amount
            assert msg.recipient == transfer.sender == self.raiden.address
            channel = self.assetmanager.channels[msg.sender]
            channel.register_transfer(msg)
            return msg
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
            log.info('SECRETREQUEST RECEIVED {}'.format(msg))
            assert msg.sender == self.target
            return msg

        raise NotImplementedError()

class InitMediatedTransferTask(Task):  # TODO
    """
    optimum initial expiration time:
        "expiration = self.raiden.chain.block_number + channel.settle_timeout - config['reveal_timeout']"
    PROBLEM:  we dont know yet which channel to use! channel.settle_timeout not known
    -> create InitMediatedTransferTask, that spawns MediatedTransfers and waits for timeout/success.
    on timeout, it alters timeout/expiration arguments, handles locks and lock forwarding
    """
    def __init__(self):
        raise NotImplementedError


class ForwardSecretTask(Task):

    def __init__(self, transfermanager, hashlock, recipient, msg_timeout):
        self.transfermanager = transfermanager
        self.recipient = recipient
        self.hashlock = hashlock
        self.msg_timeout = msg_timeout
        self.raiden = transfermanager.raiden
        self.event = None

        super(ForwardSecretTask, self).__init__()
        self.transfermanager.on_task_started(self)

        log.info('INIT', task=self)

    def __repr__(self):
        return '<{} {}>'.format(self.__class__.__name__, pex(self.raiden.address))

    def _run(self):  # pylint: disable=method-hidden
        self.event = AsyncResult()  # http://www.gevent.org/gevent.event.html
        msg = self.event.wait(self.msg_timeout)
        # returns None if msg_timeout is reached and event-value wasn't set()
        if not msg:
            log.error('TIMEOUT! ' * 5)
            # TransferTimeout is of no use, SecretRequest was for sender
            return self.on_completion(False)
        assert isinstance(msg, Secret)
        assert msg.hashlock == self.hashlock
        fwd = Secret(msg.secret)
        self.raiden.sign(fwd)
        self.raiden.send(self.recipient, fwd)
        return self.on_completion(True)
