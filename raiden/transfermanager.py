# -*- coding: utf-8 -*-
import logging
import random
from collections import namedtuple

import gevent
from gevent.event import AsyncResult
from ethereum import slogging

from raiden.tasks import (
    StartMediatedTransferTask,
    MediateTransferTask,
    EndMediatedTransferTask,
    ExchangeTask,
)
from raiden.utils import pex, sha3

log = slogging.get_logger(__name__)  # pylint: disable=invalid-name
Exchange = namedtuple('Exchange', (
    'identifier',
    'from_asset',
    'from_amount',
    'from_nodeaddress',  # the node' address of the owner of the `from_asset`
    'to_asset',
    'to_amount',
    'to_nodeaddress',  # the node' address of the owner of the `to_asset`
))
ExchangeKey = namedtuple('ExchangeKey', (
    'from_asset',
    'from_amount',
))


class UnknownAddress(Exception):
    pass


class UnknownAssetAddress(Exception):
    def __init__(self, address):
        Exception.__init__(
            self,
            'Message with unknown asset address {} received'.format(pex(address))
        )


class TransferManager(object):
    """ Manages all transfers done through this node. """

    def __init__(self, assetmanager):
        self.assetmanager = assetmanager

        self.transfertasks = dict()
        self.exchanges = dict()  #: mapping for pending exchanges
        self.endtask_transfer_mapping = dict()

        self.on_task_completed_callbacks = list()
        self.on_result_callbacks = list()

    # TODO: Move registration to raiden_service.py:Raiden. This is used to
    # dispatch messages by hashlock and to expose callbacks to applications
    # built on top of raiden, since hashlocks can be shared among assets this
    # should be moved to an upper layer.
    def register_task_for_hashlock(self, task, hashlock):
        """ Register the task to receive messages based on hashlock.

        Registration is required otherwise the task won't receive any messages
        from the protocol, un-registering is done by the `on_hashlock_result`
        function.

        Note:
            Messages are dispatched solely on the hashlock value (being part of
            the message, eg. SecretRequest, or calculated from the message
            content, eg.  RevealSecret), this means the sender needs to be
            checked for the received messages.
        """
        self.transfertasks[hashlock] = task

    def on_hashlock_result(self, hashlock, success):
        """ Set the result for a transfer based on hashlock.

        This function will also call the registered callbacks and de-register
        the task.
        """
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
            if task in self.endtask_transfer_mapping:
                transfer = self.endtask_transfer_mapping[task]
                for callback in self.on_result_callbacks:
                    gevent.spawn(
                        callback(
                            transfer.asset,
                            transfer.recipient,
                            transfer.initiator,
                            transfer.transferred_amount,
                            hashlock
                        )
                    )
            del self.endtask_transfer_mapping[task]

    def register_callback_for_result(self, callback):
        self.on_result_callbacks.append(callback)

    def create_default_identifier(self, target):
        """
        The default message identifier value is the first 8 bytes of the sha3 of:
            - Our Address
            - Our target address
            - The asset address
            - A random 8 byte number for uniqueness
        """
        hash_ = sha3("{}{}{}{}".format(
            self.assetmanager.raiden.address,
            target,
            self.assetmanager.asset_address,
            random.randint(0, 18446744073709551614L)
        ))
        return int(hash_[0:8].encode('hex'), 16)

    def transfer_async(self, amount, target, identifier=None, callback=None):
        """ Transfer `amount` between this node and `target`.

        This method will start an asyncronous transfer, the transfer might fail
        or succeed depending on a couple of factors:
            - Existence of a path that can be used, through the usage of direct
            or intermediary channels.
            - Network speed, making the transfer suficiently fast so it doesn't
            timeout.
        """

        # Create a default identifier value
        if identifier is None:
            identifier = self.create_default_identifier(target)

        direct_channel = self.assetmanager.partneraddress_channel.get(target)

        if direct_channel:
            async_result = self._direct_or_mediated_transfer(
                amount,
                identifier,
                direct_channel,
                callback,
            )
            return async_result

        else:
            async_result = self._mediated_transfer(
                amount,
                identifier,
                target,
                callback,
            )

            return async_result

    def _direct_or_mediated_transfer(self, amount, identifier, direct_channel, callback):
        """ Check the direct channel and if possible use it, otherwise start a
        mediated transfer.
        """

        if not direct_channel.isopen:
            log.info(
                'DIRECT CHANNEL %s > %s is closed',
                pex(direct_channel.our_state.address),
                pex(direct_channel.partner_state.address),
            )

            async_result = self._mediated_transfer(
                amount,
                identifier,
                direct_channel.partner_state.address,
                callback,
            )
            return async_result

        elif amount > direct_channel.distributable:
            log.info(
                'DIRECT CHANNEL %s > %s doesnt have enough funds [%s]',
                pex(direct_channel.our_state.address),
                pex(direct_channel.partner_state.address),
                amount,
            )

            async_result = self._mediated_transfer(
                amount,
                identifier,
                direct_channel.partner_state.address,
                callback,
            )
            return async_result

        else:
            direct_transfer = direct_channel.create_directtransfer(amount, identifier)
            self.assetmanager.raiden.sign(direct_transfer)
            direct_channel.register_transfer(direct_transfer)

            if callback:
                direct_channel.on_task_completed_callbacks.append(callback)

            async_result = self.assetmanager.raiden.protocol.send_async(
                direct_channel.partner_state.address,
                direct_transfer,
            )
            return async_result

    def _mediated_transfer(self, amount, identifier, target, callback):
        asunc_result = AsyncResult()
        task = StartMediatedTransferTask(
            self.assetmanager.raiden,
            self.assetmanager.asset_address,
            amount,
            identifier,
            target,
            asunc_result,
        )
        task.start()

        if callback:
            self.on_task_completed_callbacks.append(callback)

        return asunc_result

    def on_mediatedtransfer_message(self, transfer):
        if transfer.sender not in self.assetmanager.partneraddress_channel:
            # Log a warning and don't process further
            if log.isEnabledFor(logging.WARN):
                log.warn(
                    'Received mediated transfer message from unknown channel.'
                    'Sender: %s',
                    pex(transfer.sender),
                )
            raise UnknownAddress

        raiden = self.assetmanager.raiden
        asset_address = self.assetmanager.asset_address

        channel = self.assetmanager.get_channel_by_partner_address(transfer.sender)
        channel.register_transfer(transfer)  # raises if the transfer is invalid

        exchange_key = ExchangeKey(transfer.asset, transfer.lock.amount)
        if exchange_key in self.exchanges:
            exchange = self.exchanges[exchange_key]

            if log.isEnabledFor(logging.DEBUG):
                log.debug(
                    'EXCHANGE TRANSFER RECEIVED node:%s %s > %s hashlock:%s'
                    ' from_asset:%s from_amount:%s to_asset:%s to_amount:%s [%s]',
                    pex(self.assetmanager.raiden.address),
                    pex(transfer.sender),
                    pex(self.assetmanager.raiden.address),
                    pex(transfer.lock.hashlock),
                    pex(exchange.from_asset),
                    exchange.from_amount,
                    pex(exchange.to_asset),
                    exchange.to_amount,
                    repr(transfer),
                )

            exchange_task = ExchangeTask(
                raiden,
                from_mediated_transfer=transfer,
                to_asset=exchange.to_asset,
                to_amount=exchange.to_amount,
                target=exchange.from_nodeaddress,
            )
            exchange_task.start()

        elif transfer.target == self.assetmanager.raiden.address:
            if log.isEnabledFor(logging.DEBUG):
                log.debug(
                    'MEDIATED TRANSFER RECEIVED node:%s %s > %s hashlock:%s [%s]',
                    pex(self.assetmanager.raiden.address),
                    pex(transfer.sender),
                    pex(self.assetmanager.raiden.address),
                    pex(transfer.lock.hashlock),
                    repr(transfer),
                )

            try:
                self.assetmanager.raiden.message_for_task(
                    transfer,
                    transfer.lock.hashlock
                )
            except UnknownAddress:
                # assumes that the registered task(s) tooks care of the message
                # (used for exchanges)
                secret_request_task = EndMediatedTransferTask(
                    raiden,
                    asset_address,
                    transfer,
                )
                secret_request_task.start()

        else:
            if log.isEnabledFor(logging.DEBUG):
                log.debug(
                    'TRANSFER TO BE MEDIATED RECEIVED node:%s %s > %s hashlock:%s [%s]',
                    pex(self.assetmanager.raiden.address),
                    pex(transfer.sender),
                    pex(self.assetmanager.raiden.address),
                    pex(transfer.lock.hashlock),
                    repr(transfer),
                )

            transfer_task = MediateTransferTask(
                raiden,
                asset_address,
                transfer,
                0,  # TODO: calculate the fee
            )
            transfer_task.start()

    def on_directtransfer_message(self, transfer):
        if transfer.sender not in self.assetmanager.partneraddress_channel:
            # Log a warning and don't process further
            if log.isEnabledFor(logging.WARN):
                log.warn(
                    'Received direct transfer message from unknown sender %s',
                    pex(transfer.sender),
                )
            raise UnknownAddress

        channel = self.assetmanager.partneraddress_channel[transfer.sender]
        channel.register_transfer(transfer)

    def on_exchangerequest_message(self, message):
        # if matches any own order
        # if signed for me and fee:
            # broadcast
        pass
