# -*- coding: utf8 -*-
import logging

import gevent
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
        self.endtask_transfer_mapping = dict()

        self.on_task_completed_callbacks = list()
        self.on_result_callbacks = list()

    def register_task_for_hashlock(self, task, hashlock):
        self.transfertasks[hashlock] = task

    def on_hashlock_result(self, hashlock, success):
        task = self.transfertasks[hashlock]
        del self.transfertasks[hashlock]

        callbacks_to_remove = list()
        for callback in self.on_task_completed_callbacks:
            result = callback(task, success)

            if result is True:
                callbacks_to_remove.append(callback)

        for callback in callbacks_to_remove:
            self.on_task_completed_callbacks.remove(callback)

        if task in self.endtask_transfer_mapping:
            transfer = self.endtask_transfer_mapping[task]
            for callback in self.on_result_callbacks:
                gevent.spawn(
                    callback(
                        transfer.asset,
                        transfer.recipient,
                        transfer.initiator,
                        transfer.transfered_amount,
                        hashlock
                    )
                )
            del self.endtask_transfer_mapping[task]

    def register_callback_for_result(self, callback):
        self.on_result_callbacks.append(callback)

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
            channel.register_transfer(direct_transfer)
            channel.on_task_completed_callbacks.append(callback)

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
