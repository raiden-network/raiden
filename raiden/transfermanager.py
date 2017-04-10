# -*- coding: utf-8 -*-
import logging
import random
from collections import namedtuple

from gevent.event import AsyncResult
from ethereum import slogging

from raiden.tasks import (
    StartMediatedTransferTask,
    MediateTransferTask,
    EndMediatedTransferTask,
    ExchangeTask,
)
from raiden.utils import pex

log = slogging.get_logger(__name__)  # pylint: disable=invalid-name
Exchange = namedtuple('Exchange', (
    'identifier',
    'from_token',
    'from_amount',
    'from_nodeaddress',  # the node' address of the owner of the `from_token`
    'to_token',
    'to_amount',
    'to_nodeaddress',  # the node' address of the owner of the `to_token`
))
ExchangeKey = namedtuple('ExchangeKey', (
    'from_token',
    'from_amount',
))


class UnknownAddress(Exception):
    pass


class TransferWhenClosed(Exception):
    pass


class UnknownTokenAddress(Exception):
    def __init__(self, address):
        Exception.__init__(
            self,
            'Message with unknown token address {} received'.format(pex(address))
        )


class TransferManager(object):
    """ Manages all transfers done through this node. """

    def __init__(self, tokenmanager):
        self.tokenmanager = tokenmanager

        # map hashlock to a task, this dictionary is used to dispatch protocol
        # messages
        self.transfertasks = dict()
        self.exchanges = dict()  #: mapping for pending exchanges
        self.endtask_transfer_mapping = dict()

    # TODO: Move registration to raiden_service.py:Raiden. This is used to
    # dispatch messages by hashlock and to expose callbacks to applications
    # built on top of raiden, since hashlocks can be shared among tokens this
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
        """ Called once a task reaches a final state. """
        del self.transfertasks[hashlock]

    def transfer_async(self, amount, target, identifier=None):
        """ Transfer `amount` between this node and `target`.

        This method will start an asyncronous transfer, the transfer might fail
        or succeed depending on a couple of factors:
            - Existence of a path that can be used, through the usage of direct
            or intermediary channels.
            - Network speed, making the transfer suficiently fast so it doesn't
            timeout.
        """
        direct_channel = self.tokenmanager.partneraddress_channel.get(target)

        if direct_channel:
            async_result = self._direct_or_mediated_transfer(
                amount,
                identifier,
                direct_channel,
            )
            return async_result

        else:
            async_result = self._mediated_transfer(
                amount,
                identifier,
                target,
            )

            return async_result

    def _direct_or_mediated_transfer(self, amount, identifier, direct_channel):
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
            )
            return async_result

        else:
            direct_transfer = direct_channel.create_directtransfer(amount, identifier)
            self.tokenmanager.raiden.sign(direct_transfer)
            direct_channel.register_transfer(direct_transfer)

            async_result = self.tokenmanager.raiden.protocol.send_async(
                direct_channel.partner_state.address,
                direct_transfer,
            )
            return async_result

    def _mediated_transfer(self, amount, identifier, target):
        async_result = AsyncResult()
        task = StartMediatedTransferTask(
            self.tokenmanager.raiden,
            self.tokenmanager.token_address,
            amount,
            identifier,
            target,
            async_result,
        )
        task.start()

        return async_result

    def on_mediatedtransfer_message(self, transfer):
        if transfer.sender not in self.tokenmanager.partneraddress_channel:
            if log.isEnabledFor(logging.WARN):
                log.warn(
                    'Received mediated transfer message from unknown channel.'
                    'Sender: %s',
                    pex(transfer.sender),
                )
            raise UnknownAddress

        raiden = self.tokenmanager.raiden
        token_address = self.tokenmanager.token_address

        channel = self.tokenmanager.get_channel_by_partner_address(transfer.sender)
        if not channel.isopen:
            if log.isEnabledFor(logging.WARN):
                log.warn(
                    'Received mediated transfer message from %s after channel closing',
                    pex(transfer.sender),
                )
            raise TransferWhenClosed
        channel.register_transfer(transfer)  # raises if the transfer is invalid

        exchange_key = ExchangeKey(transfer.token, transfer.lock.amount)
        if exchange_key in self.exchanges:
            exchange = self.exchanges[exchange_key]

            if log.isEnabledFor(logging.DEBUG):
                log.debug(
                    'EXCHANGE TRANSFER RECEIVED node:%s %s > %s hashlock:%s'
                    ' from_token:%s from_amount:%s to_token:%s to_amount:%s [%s]',
                    pex(self.tokenmanager.raiden.address),
                    pex(transfer.sender),
                    pex(self.tokenmanager.raiden.address),
                    pex(transfer.lock.hashlock),
                    pex(exchange.from_token),
                    exchange.from_amount,
                    pex(exchange.to_token),
                    exchange.to_amount,
                    repr(transfer),
                )

            exchange_task = ExchangeTask(
                raiden,
                from_mediated_transfer=transfer,
                to_token=exchange.to_token,
                to_amount=exchange.to_amount,
                target=exchange.from_nodeaddress,
            )
            exchange_task.start()

        elif transfer.target == self.tokenmanager.raiden.address:
            if log.isEnabledFor(logging.DEBUG):
                log.debug(
                    'MEDIATED TRANSFER RECEIVED node:%s %s > %s hashlock:%s [%s]',
                    pex(self.tokenmanager.raiden.address),
                    pex(transfer.sender),
                    pex(self.tokenmanager.raiden.address),
                    pex(transfer.lock.hashlock),
                    repr(transfer),
                )

            try:
                self.tokenmanager.raiden.message_for_task(
                    transfer,
                    transfer.lock.hashlock
                )
            except UnknownAddress:
                # assumes that the registered task(s) tooks care of the message
                # (used for exchanges)
                secret_request_task = EndMediatedTransferTask(
                    raiden,
                    token_address,
                    transfer,
                )
                secret_request_task.start()

        else:
            if log.isEnabledFor(logging.DEBUG):
                log.debug(
                    'TRANSFER TO BE MEDIATED RECEIVED node:%s %s > %s hashlock:%s [%s]',
                    pex(self.tokenmanager.raiden.address),
                    pex(transfer.sender),
                    pex(self.tokenmanager.raiden.address),
                    pex(transfer.lock.hashlock),
                    repr(transfer),
                )

            transfer_task = MediateTransferTask(
                raiden,
                token_address,
                transfer,
                0,  # TODO: calculate the fee
            )
            transfer_task.start()

    def on_directtransfer_message(self, transfer):
        if transfer.sender not in self.tokenmanager.partneraddress_channel:
            if log.isEnabledFor(logging.WARN):
                log.warn(
                    'Received direct transfer message from unknown sender %s',
                    pex(transfer.sender),
                )
            raise UnknownAddress

        channel = self.tokenmanager.partneraddress_channel[transfer.sender]

        if not channel.isopen:
            if log.isEnabledFor(logging.WARN):
                log.warn(
                    'Received direct transfer message from %s after channel closing',
                    pex(transfer.sender),
                )
            raise TransferWhenClosed
        channel.register_transfer(transfer)

    def on_exchangerequest_message(self, message):
        # if matches any own order
        # if signed for me and fee:
            # broadcast
        pass
