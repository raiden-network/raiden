# -*- coding: utf8 -*-
import random

from ethereum import slogging

from raiden.messages import DirectTransfer, MediatedTransfer, LockedTransfer, SecretRequest
from raiden.tasks import Task, MediatedTransferTask, ForwardSecretTask
from raiden.utils import sha3, pex

log = slogging.get_logger(__name__)  # pylint: disable=invalid-name


class TransferManager(object):
    """ Mediates transfers for a fee. """

    def __init__(self, assetmanager, raiden):
        import raiden.assetmanager as assetmanager_mod
        assert isinstance(assetmanager, assetmanager_mod.AssetManager)

        self.raiden = raiden
        self.assetmanager = assetmanager
        self.transfertasks = dict()  # hashlock > MediatedTransferTask
        self.on_task_completed_callbacks = []

    def on_task_started(self, task):
        assert isinstance(task, Task)
        self.transfertasks[task.hashlock] = task

    def on_task_completed(self, task, success):
        assert isinstance(task, Task)
        del self.transfertasks[task.hashlock]
        for callback in self.on_task_completed_callbacks:
            callback(task, success)

    def transfer(self, amount, target, hashlock=None, secret=None):
        """ Transfer `amount` between this node and `target`.

        This method will start a asyncronous transfer, the transfer might fail
        or succeed depending on a couple of factors:
            - Existence of a path that can be used, through the usage of direct
            or intermediary channels.
            - Network speed, making the transfer suficiently fast so it doesn't
            timeout.
        """

        # either we have a direct channel with `target`
        if target in self.assetmanager.channels and not hashlock:
            channel = self.assetmanager.channels[target]
            direct_transfer = channel.create_directtransfer(amount, secret=secret)
            self.raiden.sign(direct_transfer)
            channel.register_transfer(direct_transfer)

            task = self.raiden.protocol.send(direct_transfer.recipient, direct_transfer)
            task.join()

        # or we need to use the network to mediate the transfer
        else:
            if not (hashlock or secret):
                secret = sha3(hex(random.getrandbits(256)))
                hashlock = sha3(secret)

            task = MediatedTransferTask(
                self,
                amount,
                target,
                hashlock,
                lock_expiration=None,
                originating_transfer=None,
                secret=secret,
            )
            task.start()
            task.join()

    def request_transfer(self, amount, target):
        pass

    def on_transferrequest(self, request):
        # FIXME: Dummy, we accept any request
        self.transfer(self, request.amount, request.sender, request.hashlock)

    def on_mediatedtransfer(self, transfer):
        assert isinstance(transfer, MediatedTransfer)
        log.debug('ON MEDIATED TRANSFER', address=pex(self.raiden.address))

        channel = self.assetmanager.channels[transfer.sender]

        channel.register_transfer(transfer)  # this raises if the transfer is invalid

        # either we are the target of the transfer, so we need to send a
        # SecretRequest
        if transfer.target == self.raiden.address:
            secret_request = SecretRequest(transfer.lock.hashlock)
            self.raiden.sign(secret_request)
            self.raiden.send(transfer.initiator, secret_request)

            secret_request_task = ForwardSecretTask(
                self,
                transfer.lock.hashlock,
                recipient=transfer.sender,
            )
            secret_request_task.start()

        # or we are a participating node in the network and need to keep
        # forwarding the MediatedTransfer
        else:
            transfer_task = MediatedTransferTask(
                self,
                transfer.lock.amount,
                transfer.target,
                transfer.lock.hashlock,
                originating_transfer=transfer,
            )
            transfer_task.start()

    def on_transfer(self, transfer):
        assert isinstance(transfer, (DirectTransfer, LockedTransfer))
        channel = self.assetmanager.channels[transfer.sender]
        channel.register_transfer(transfer)

    def on_exchangerequest(self, message):
        # if matches any own order
        # if signed for me and fee:
            # broadcast
        pass
