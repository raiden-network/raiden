# -*- coding: utf8 -*-
import random
import time

import gevent
from gevent.event import AsyncResult
from pyethapp.jsonrpc import address_decoder, data_decoder, quantity_encoder

from ethereum import slogging
from ethereum.utils import sha3

from raiden.messages import (
    RefundTransfer,
    Secret,
    SecretRequest,
    TransferTimeout,
)
from raiden.blockchain.events import decode_topic
from raiden.utils import lpex, pex

__all__ = (
    'LogListenerTask',
    'StartMediatedTransferTask',
    'MediateTransferTask',
    'EndMediatedTransferTask',
)

log = slogging.get_logger(__name__)  # pylint: disable=invalid-name


class Task(gevent.Greenlet):
    def __init__(self):
        super(Task, self).__init__()
        self.event = None

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


class LogListenerTask(Task):
    def __init__(self, jsonrpc_client, filter_id, callback, contract_translator):
        super(LogListenerTask, self).__init__()

        self.client = jsonrpc_client
        self.filter_id = filter_id
        self.callback = callback
        self.contract_translator = contract_translator

        self.stop_event = AsyncResult()
        self.sleep_time = 0.5

    def _run(self):  # pylint: disable=method-hidden
        stop = None

        while stop is None:
            filter_changes = self.client.call(
                'eth_getFilterChanges',
                quantity_encoder(self.filter_id),
            )

            for log_event in filter_changes:
                topics = [
                    decode_topic(topic)
                    for topic in log_event['topics']
                ]
                data = data_decoder(log_event['data'])

                event = self.contract_translator.decode_event(topics, data)
                if event is not None:
                    originating_contract = address_decoder(log_event['address'])
                    self.callback(originating_contract, event)

            stop = self.stop_event.wait(self.sleep_time)

    def stop(self):
        self.stop_event.set(True)


class StartMediatedTransferTask(Task):
    def __init__(self, transfermanager, amount, target):
        super(StartMediatedTransferTask, self).__init__()
        self.amount = amount
        self.address = transfermanager.assetmanager.raiden.address
        self.target = target
        self.transfermanager = transfermanager

    def __repr__(self):
        return '<{} {}>'.format(
            self.__class__.__name__,
            pex(self.address),
        )

    def _run(self):  # pylint: disable=method-hidden,too-many-locals
        amount = self.amount
        target = self.target
        raiden = self.transfermanager.assetmanager.raiden

        fee = 0
        # there are no guarantees that the next_hop will follow the same route
        routes = self.transfermanager.assetmanager.get_best_routes(
            amount,
            target,
            lock_timeout=None,
        )

        for path, channel in routes:
            # try a new secret
            secret = sha3(hex(random.getrandbits(256)))
            hashlock = sha3(secret)
            self.transfermanager.register_task_for_hashlock(self, hashlock)

            lock_expiration = (
                raiden.chain.block_number + channel.settle_timeout - raiden.config['reveal_timeout']
            )

            mediated_transfer = channel.create_mediatedtransfer(
                raiden.address,
                target,
                fee,
                amount,
                lock_expiration,
                hashlock,
            )
            raiden.sign(mediated_transfer)
            channel.register_transfer(mediated_transfer)

            response = self.send_and_wait_valid(raiden, path, mediated_transfer)

            # `next_hop` timedout
            if response is None:
                self.transfermanager.on_hashlock_result(hashlock, False)

            # someone down the line timedout / couldn't proceed
            elif isinstance(response, (RefundTransfer, TransferTimeout)):
                self.transfermanager.on_hashlock_result(hashlock, False)

            # `target` received the MediatedTransfer
            elif response.sender == target and isinstance(response, SecretRequest):
                secret_message = Secret(secret)
                raiden.sign(secret_message)
                raiden.send(target, secret_message)

                # this might cause synchronization problems, since it can take
                # a while for the partner to receive the secret
                channel.claim_locked(secret)

                self.transfermanager.on_hashlock_result(hashlock, True)

                # done, don't try a new path
                return
            else:
                log.error('Unexpected response {}'.format(repr(response)))
                self.transfermanager.on_hashlock_result(hashlock, False)

    def send_and_wait_valid(self, raiden, path, mediated_transfer):  # pylint: disable=no-self-use
        """ Send the `mediated_transfer` and wait for either a message from
        `target` or the `next_hop`.

        Validate the message received and discards the invalid ones. The most
        important case being next_hop sending a SecretRequest.
        """
        message_timeout = raiden.config['msg_timeout']
        next_hop = path[1]
        target = path[-1]

        transfer_details = 'path:{} hash:{}'.format(
            lpex(path),
            pex(mediated_transfer.hash),
        )
        log.debug('MEDIATED TRANSFER STARTED {}'.format(transfer_details))

        current_time = time.time()
        limit_time = current_time + message_timeout

        self.event = AsyncResult()
        raiden.send(next_hop, mediated_transfer)

        while current_time <= limit_time:
            response = self.event.wait(limit_time - current_time)

            # critical write section
            self.event = AsyncResult()  # reset so that a new value can be received
            # /critical write section

            current_time = time.time()

            if response is None:
                log.debug('MEDIATED TRANSFER TIMED OUT {}'.format(transfer_details))
                return None

            if response.sender == next_hop:
                if isinstance(response, (RefundTransfer, TransferTimeout)):
                    return response
                else:
                    log.info('Partner {} sent an invalid message'.format(pex(next_hop)))
                    return None

            if response.sender == target:
                if isinstance(response, SecretRequest):
                    return response
                else:
                    log.info('target {} sent an invalid message'.format(pex(target)))
                    return None

            log.error('Invalid message ignoring. {}'.format(repr(response)))

        return None


class MediateTransferTask(Task):  # pylint: disable=too-many-instance-attributes
    def __init__(self, transfermanager, originating_transfer, fee):
        super(MediateTransferTask, self).__init__()

        self.address = transfermanager.assetmanager.raiden.address
        self.transfermanager = transfermanager
        self.fee = fee
        self.originating_transfer = originating_transfer

        hashlock = originating_transfer.lock.hashlock
        self.transfermanager.register_task_for_hashlock(self, hashlock)

    def __repr__(self):
        return '<{} {}>'.format(
            self.__class__.__name__,
            pex(self.address)
        )

    def _run(self):  # pylint: disable=method-hidden,too-many-locals,too-many-branches,too-many-statements
        fee = self.fee
        transfer = self.originating_transfer

        originating_channel = self.transfermanager.assetmanager.channels[transfer.sender]
        channels_reveal = [originating_channel]

        raiden = self.transfermanager.assetmanager.raiden
        lock_expiration = transfer.lock.expiration - raiden.config['reveal_timeout']
        lock_timeout = lock_expiration - raiden.chain.block_number

        # there are no guarantees that the next_hop will follow the same route
        routes = self.transfermanager.assetmanager.get_best_routes(
            transfer.lock.amount,
            transfer.target,
            lock_timeout,
        )

        for path, channel in routes:
            next_hop = path[1]

            mediated_transfer = channel.create_mediatedtransfer(
                transfer.initiator,
                transfer.target,
                fee,
                transfer.lock.amount,
                lock_expiration,
                transfer.lock.hashlock,
            )
            raiden.sign(mediated_transfer)

            channels_reveal.append(channel)
            channel.register_transfer(mediated_transfer)

            response = self.send_and_wait_valid(raiden, path, mediated_transfer)

            if response is None:
                timeout = channel.create_timeouttransfer_for(transfer)
                raiden.send(transfer.sender, timeout)
                self.transfermanager.on_hashlock_result(transfer.hashlock, False)
                return

            if isinstance(response, RefundTransfer):
                if response.lock.amount != transfer.amount:
                    log.info('Partner {} sent an refund message with an invalid amount'.format(
                        pex(next_hop),
                    ))
                    timeout = channel.create_timeouttransfer_for(transfer)
                    raiden.send(transfer.sender, timeout)
                    self.transfermanager.on_hashlock_result(transfer.hashlock, False)
                    return
                else:
                    channel.register_transfer(response)

            elif isinstance(response, Secret):
                secret_message = Secret(response.secret)
                raiden.sign(secret_message)

                # send the secret to all nodes, including the ones that sent a RefundTransfer
                for reveal_to in channels_reveal:
                    # do not send the secret to the initiator
                    if reveal_to.partner_state.address != transfer.initiator:
                        raiden.send(reveal_to.partner_state.address, secret_message)

                    reveal_to.claim_locked(response.secret)

                self.transfermanager.on_hashlock_result(transfer.lock.hashlock, True)
                return

        # No suitable path avaiable (e.g. insufficient distributable, no active node)
        # Send RefundTransfer to the originating node, this has the effect of
        # backtracking in the graph search of the raiden network.
        from_address = transfer.sender
        from_channel = self.assetmanager.channels[from_address]

        refund_transfer = from_channel.create_refundtransfer_for(transfer)
        from_channel.register_transfer(refund_transfer)

        raiden.sign(refund_transfer)
        raiden.send(from_address, refund_transfer)

        log.debug('REFUND MEDIATED TRANSFER from={} {}'.format(
            pex(from_address),
            pex(raiden.address),
        ))

        self.transfermanager.on_hashlock_result(transfer.hashlock, False)
        return

    def send_and_wait_valid(self, raiden, path, mediated_transfer):
        message_timeout = raiden.config['msg_timeout']
        next_hop = path[1]

        transfer_details = 'path:{} hash:{} initiator:{}'.format(
            lpex(path),
            pex(mediated_transfer.hash),
            pex(mediated_transfer.initiator),
        )
        log.debug('MEDIATED TRANSFER {}'.format(transfer_details))

        current_time = time.time()
        limit_time = current_time + message_timeout

        self.event = AsyncResult()
        raiden.send(next_hop, mediated_transfer)

        while current_time <= limit_time:
            response = self.event.wait(limit_time - current_time)

            # critical write section
            self.event = AsyncResult()  # reset so that a new value can be received
            # /critical write section

            current_time = time.time()

            if response is None:
                log.error('MEDIATED TRANSFER TIMED OUT {} timeout:{}'.format(
                    transfer_details,
                    message_timeout,
                ))
                return None

            if isinstance(response, Secret):
                if response.hashlock != mediated_transfer.lock.hashlock:
                    log.error('Secret doesnt match the hashlock, ignoring.')
                    continue

                return response

            if response.target != raiden.address or response.sender != next_hop:
                log.error('Invalid message supplied to the task. {}'.format(repr(response)))
                continue

            if isinstance(response, RefundTransfer):
                return response

            log.error('Partner sent an invalid message. {}'.format(repr(response)))

        return None


class EndMediatedTransferTask(Task):
    """ Task that request a secret for a registered transfer. """

    def __init__(self, transfermanager, originating_transfer):
        super(EndMediatedTransferTask, self).__init__()

        self.address = transfermanager.assetmanager.raiden.address
        self.transfermanager = transfermanager
        self.originating_transfer = originating_transfer

        hashlock = originating_transfer.lock.hashlock
        self.transfermanager.register_task_for_hashlock(self, hashlock)

    def __repr__(self):
        return '<{} {}>'.format(
            self.__class__.__name__,
            pex(self.address),
        )

    def _run(self):  # pylint: disable=method-hidden
        transfer = self.originating_transfer
        raiden = self.transfermanager.assetmanager.raiden
        channel = self.transfermanager.assetmanager.channels[transfer.sender]

        transfer_details = '{} -> {} hash:{}'.format(
            pex(transfer.initiator),
            pex(transfer.target),
            pex(transfer.hash),
        )
        log.debug('END MEDIATED TRANSFER {}'.format(transfer_details))

        secret_request = SecretRequest(transfer.lock.hashlock)
        raiden.sign(secret_request)
        raiden.send(transfer.initiator, secret_request)

        self.event = AsyncResult()
        response = self.event.wait(raiden.config['msg_timeout'])

        if response is None:
            log.error('SECRETREQUEST TIMED OUT!')
            self.transfermanager.on_hashlock_result(transfer.hashlock, False)
            return

        if not isinstance(response, Secret):
            raise Exception('Invalid message received.')

        if sha3(response.secret) != transfer.lock.hashlock:
            raise Exception('Invalid secret received.')

        channel.claim_locked(response.secret)  # raises if the secret is invalid

        # propagate the secret backwards
        secret = Secret(response.secret)
        raiden.sign(secret)
        raiden.send(transfer.sender, secret)

        self.transfermanager.on_hashlock_result(transfer.lock.hashlock, True)
        return
