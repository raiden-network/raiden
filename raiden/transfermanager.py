# -*- coding: utf8 -*-
import logging

from gevent.event import AsyncResult
from ethereum import slogging

from raiden.tasks import StartMediatedTransferTask, MediateTransferTask, EndMediatedTransferTask
from raiden.utils import pex

log = slogging.get_logger(__name__)  # pylint: disable=invalid-name


class TransferManager(object):
    """ Manages all transfers done through this node. """

    def __init__(self, assetmanager):
        self.assetmanager = assetmanager

        self.transfertasks = dict()
        self.on_task_completed_callbacks = []

    def register_task_for_hashlock(self, task, hashlock):
        self.transfertasks[hashlock] = task

    def on_hashlock_result(self, hashlock, success):
        task = self.transfertasks[hashlock]
        del self.transfertasks[hashlock]

        for callback in self.on_task_completed_callbacks:
            result = callback(task, success)

            if result is True:
                self.on_task_completed_callbacks.remove(callback)

    def transfer_async(self, amount, target, callback=None):
        """ Transfer `amount` between this node and `target`.

        This method will start a asyncronous transfer, the transfer might fail
        or succeed depending on a couple of factors:
            - Existence of a path that can be used, through the usage of direct
            or intermediary channels.
            - Network speed, making the transfer suficiently fast so it doesn't
            timeout.
        """

        if target in self.assetmanager.partneraddress_channel:
            channel = self.assetmanager.partneraddress_channel[target]
            direct_transfer = channel.create_directtransfer(amount)
            self.assetmanager.raiden.sign(direct_transfer)
            channel.register_transfer(direct_transfer, callback=callback)

            return self.assetmanager.raiden.protocol.send_async(
                target,
                direct_transfer,
            )

        else:
            result = AsyncResult()
            task = StartMediatedTransferTask(
                self,
                amount,
                target,
                result,
            )
            task.start()

            if callback:
                self.on_task_completed_callbacks.append(callback)

            return result

    def on_mediatedtransfer_message(self, transfer):
        if transfer.sender not in self.assetmanager.partneraddress_channel:
            raise RuntimeError('Received message for inexisting channel.')

        if log.isEnabledFor(logging.DEBUG):
            log.debug(
                'MEDIATED TRANSFER RECEIVED node:%s %s > %s hashlock:%s [%s]',
                pex(self.assetmanager.raiden.address),
                pex(transfer.sender),
                pex(self.assetmanager.raiden.address),
                pex(transfer.lock.hashlock),
                repr(transfer),
            )

        channel = self.assetmanager.get_channel_by_partner_address(transfer.sender)
        channel.register_transfer(transfer)  # raises if the transfer is invalid

        if transfer.target == self.assetmanager.raiden.address:
            secret_request_task = EndMediatedTransferTask(
                self,
                transfer,
            )
            secret_request_task.start()

        else:
            transfer_task = MediateTransferTask(
                self,
                transfer,
                0,  # TODO: calculate the fee
            )
            transfer_task.start()

    def on_directtransfer_message(self, transfer):
        if transfer.sender not in self.assetmanager.partneraddress_channel:
            raise RuntimeError('Received message for inexisting channel.')

        channel = self.assetmanager.partneraddress_channel[transfer.sender]
        channel.register_transfer(transfer)

    def on_exchangerequest_message(self, message):
        # if matches any own order
        # if signed for me and fee:
            # broadcast
        pass
