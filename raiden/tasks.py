# -*- coding: utf8 -*-
import random
import time

import gevent
from gevent.event import AsyncResult
from gevent.timeout import Timeout

from ethereum import slogging
from ethereum.utils import sha3

from raiden.messages import (
    RefundTransfer,
    Secret,
    SecretRequest,
    TransferTimeout,
)
from raiden.utils import lpex, pex

__all__ = (
    'LogListenerTask',
    'StartMediatedTransferTask',
    'MediateTransferTask',
    'EndMediatedTransferTask',
)

log = slogging.get_logger(__name__)  # pylint: disable=invalid-name
REMOVE_CALLBACK = object()
DEFAULT_EVENTS_POLL_TIMEOUT = 0.5


class Task(gevent.Greenlet):
    """ Base class used to created tasks.

    Note:
        Always call super().__init__().
    """

    def __init__(self):
        super(Task, self).__init__()
        self.response_message = None

    def on_completion(self, success):
        self.transfermanager.on_task_completed(self, success)
        return success

    def on_response(self, msg):
        # we might have timed out before
        if self.response_message.ready():
            log.debug(
                'ALREADY HAD EVENT %s %s now %s',
                self,
                self.response_message.get(),
                msg,
            )
        else:
            log.debug(
                'RESPONSE MESSAGE RECEIVED %s %s %s',
                repr(self),
                id(self.response_message),
                msg,
            )

            self.response_message.set(msg)


class LogListenerTask(Task):
    """ Task for polling for filter changes. """

    def __init__(self, listener_name, filter_, callback, contract_translator,
                 events_poll_timeout=DEFAULT_EVENTS_POLL_TIMEOUT):
        """
        Args:
            listener_name (str): A name to distinguish listener tasks.
            filter_ (raiden.network.rpc.client.Filter): A proxy for calling the
                blockchain's filter api.
            callback (function): A function to be called once an event happens.
            contract_translator (ethereum.abi.ContractTranslator): A contract
                translator to decode the event data.
            events_poll_timeout (float): How long the tasks should sleep before
                polling again.
        """
        super(LogListenerTask, self).__init__()

        self.listener_name = listener_name
        self.filter_ = filter_
        self.callback = callback
        self.contract_translator = contract_translator

        self.stop_event = AsyncResult()
        self.sleep_time = events_poll_timeout

        # exposes the AsyncResult timer, this allows us to raise the timeout
        # inside this Task to force an update:
        #
        #   task.kill(task.timeout)
        #
        self.timeout = None

    def __repr__(self):
        return '<LogListenerTask {}>'.format(self.listener_name)

    def _run(self):  # pylint: disable=method-hidden
        stop = None

        while stop is None:
            filter_changes = self.filter_.changes()

            for log_event in filter_changes:
                log.debug('New Events', task=self.listener_name)

                event = self.contract_translator.decode_event(
                    log_event['topics'],
                    log_event['data'],
                )

                if event is not None:
                    originating_contract = log_event['address']

                    try:
                        self.callback(originating_contract, event)
                    except:
                        log.exception('unexpected exception on log listener')

            self.timeout = Timeout(self.sleep_time)  # wait() will call cancel()
            stop = self.stop_event.wait(self.timeout)

    def stop(self):
        self.stop_event.set(True)


class AlarmTask(Task):
    """ Task to notify when a block is mined. """

    def __init__(self, chain):
        super(AlarmTask, self).__init__()

        self.callbacks = list()
        self.stop_event = AsyncResult()
        self.wait_time = 0.5
        self.chain = chain
        self.last_block_number = self.chain.block_number()

    def register_callback(self, callback):
        """ Register a new callback.

        Note:
            This callback will be executed in the AlarmTask context and for
            this reason it should not block, otherwise we can miss block
            changes.
        """
        if not callable(callback):
            raise ValueError('callback is not a callable')

        self.callbacks.append(callback)

    def _run(self):  # pylint: disable=method-hidden
        stop = None
        result = None
        last_loop = time.time()
        log.debug('starting block number', block_number=self.last_block_number)

        while stop is None:
            current_block = self.chain.block_number()

            if current_block > self.last_block_number + 1:
                difference = current_block - self.last_block_number - 1
                log.error(
                    'alarm missed %s blocks',
                    difference,
                )

            if current_block != self.last_block_number:
                self.last_block_number = current_block
                log.debug('new block', number=current_block, timestamp=last_loop)

                remove = list()
                for callback in self.callbacks:
                    try:
                        result = callback(current_block)
                    except:
                        log.exception('unexpected exception on alarm')
                    else:
                        if result is REMOVE_CALLBACK:
                            remove.append(callback)

                for callback in remove:
                    self.callbacks.remove(callback)

            # we want this task to iterate in the tick of `wait_time`, so take
            # into account how long we spent executing one tick.
            work_time = time.time() - last_loop
            if work_time > self.wait_time:
                log.warning(
                    'alarm loop is taking longer than the wait time',
                    work_time=work_time,
                    wait_time=self.wait_time,
                )
                sleep_time = 0.001
            else:
                sleep_time = self.wait_time - work_time

            stop = self.stop_event.wait(sleep_time)
            last_loop = time.time()

    def stop(self):
        self.stop_event.set(True)


class StartMediatedTransferTask(Task):
    def __init__(self, transfermanager, amount, target, done_result):
        super(StartMediatedTransferTask, self).__init__()
        self.amount = amount
        self.address = transfermanager.assetmanager.raiden.address
        self.target = target
        self.transfermanager = transfermanager
        self.done_result = done_result

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

        log.debug(
            'START MEDIATED TRANSFER initiator:%s target:%s',
            pex(self.address),
            pex(self.target),
        )

        for path, forward_channel in routes:
            # try a new secret
            secret = sha3(hex(random.getrandbits(256)))
            hashlock = sha3(secret)

            next_hop = path[1]

            log.debug(
                'START MEDIATED TRANSFER NEW PATH path:%s hashlock:%s',
                lpex(path),
                pex(hashlock),
            )

            self.transfermanager.register_task_for_hashlock(self, hashlock)

            lock_expiration = (
                raiden.chain.block_number() +
                forward_channel.settle_timeout -
                raiden.config['reveal_timeout']
            )

            mediated_transfer = forward_channel.create_mediatedtransfer(
                raiden.address,
                target,
                fee,
                amount,
                lock_expiration,
                hashlock,
            )
            raiden.sign(mediated_transfer)
            forward_channel.register_transfer(mediated_transfer)

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
                raiden.send_async(target, secret_message)

                # register the secret now and just incur with the additional
                # overhead of retrying until the `next_hop` receives the secret
                # forward_channel.register_secret(secret)

                # wait until `next_hop` received the secret to syncronize our
                # state (otherwise we can send a new transfer with an invalid
                # locksroot while the secret is in transit that will incur into
                # additional retry/timeout latency)
                next_hop = path[1]
                while True:
                    response = self.response_message.wait()
                    # critical write section
                    self.response_message = AsyncResult()
                    # /critical write section
                    if isinstance(response, Secret) and response.sender == next_hop:
                        # critical read/write section
                        # The channel and it's queue must be locked, a transfer
                        # must not be created while we update the balance_proof.
                        forward_channel.claim_lock(secret)
                        raiden.send_async(next_hop, secret_message)
                        # /critical write section

                        self.transfermanager.on_hashlock_result(hashlock, True)
                        self.done_result.set(True)

                        return

                    log.error(
                        'Invalid message ignoring. %s',
                        repr(response),
                    )
            else:
                log.error(
                    'Unexpected response %s',
                    repr(response),
                )
                self.transfermanager.on_hashlock_result(hashlock, False)

        log.debug(
            'START MEDIATED TRANSFER FAILED initiator:%s target:%s',
            pex(self.address),
            pex(self.target),
        )
        self.done_result.set(False)  # all paths failed

    def send_and_wait_valid(self, raiden, path, mediated_transfer):  # pylint: disable=no-self-use
        """ Send the `mediated_transfer` and wait for either a message from
        `target` or the `next_hop`.

        Validate the message received and discards the invalid ones. The most
        important case being next_hop sending a SecretRequest.
        """
        message_timeout = raiden.config['msg_timeout']
        next_hop = path[1]
        target = path[-1]

        current_time = time.time()
        limit_time = current_time + message_timeout

        # this event is used by the transfermanager to notify the task that a
        # response was received
        self.response_message = AsyncResult()

        raiden.send_async(next_hop, mediated_transfer)

        while current_time <= limit_time:
            # wait for a response message (not the Ack for the transfer)
            response = self.response_message.wait(limit_time - current_time)

            # reset so that a value can be received either because the current
            # result was invalid or because we will wait for the next message.
            #
            # critical write section
            self.response_message = AsyncResult()
            # /critical write section

            if response is None:
                log.debug(
                    'MEDIATED TRANSFER TIMED OUT hashlock:%s',
                    pex(mediated_transfer.lock.hashlock),
                )
                return None

            if response.sender == next_hop:
                if isinstance(response, (RefundTransfer, TransferTimeout)):
                    return response
                else:
                    log.info(
                        'Partner %s sent an invalid message',
                        pex(next_hop),
                    )
                    return None

            if response.sender == target:
                if isinstance(response, SecretRequest):
                    return response
                else:
                    log.info(
                        'target %s sent an invalid message',
                        pex(target),
                    )
                    return None

            current_time = time.time()
            log.error(
                'Invalid message ignoring. %s',
                repr(response),
            )

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

        assetmanager = self.transfermanager.assetmanager
        raiden = assetmanager.raiden
        originating_channel = assetmanager.partneraddress_channel[transfer.sender]

        assetmanager.register_channel_for_hashlock(
            originating_channel,
            transfer.lock.hashlock,
        )

        lock_expiration = transfer.lock.expiration - raiden.config['reveal_timeout']
        lock_timeout = lock_expiration - raiden.chain.block_number()

        # there are no guarantees that the next_hop will follow the same route
        routes = assetmanager.get_best_routes(
            transfer.lock.amount,
            transfer.target,
            lock_timeout,
        )

        log.debug(
            'MEDIATED TRANSFER initiator:%s node:%s target:%s',
            pex(transfer.initiator),
            pex(self.address),
            pex(transfer.target),
        )

        for path, forward_channel in routes:
            next_hop = path[1]

            mediated_transfer = forward_channel.create_mediatedtransfer(
                transfer.initiator,
                transfer.target,
                fee,
                transfer.lock.amount,
                lock_expiration,
                transfer.lock.hashlock,
            )
            raiden.sign(mediated_transfer)

            log.debug(
                'MEDIATED TRANSFER NEW PATH path:{} hashlock:{}',
                lpex(path),
                pex(transfer.lock.hashlock),
            )

            # Using assetmanager to register the interest because it outlives
            # this task, the secret handling will happend only _once_
            assetmanager.register_channel_for_hashlock(
                forward_channel,
                transfer.lock.hashlock,
            )
            forward_channel.register_transfer(mediated_transfer)

            response = self.send_and_wait_valid(raiden, path, mediated_transfer)

            if response is None:
                timeout_message = forward_channel.create_timeouttransfer_for(transfer)
                raiden.send_async(transfer.sender, timeout_message)
                self.transfermanager.on_hashlock_result(transfer.lock.hashlock, False)
                return

            if isinstance(response, RefundTransfer):
                if response.lock.amount != transfer.amount:
                    log.info(
                        'Partner %s sent an refund message with an invalid amount',
                        pex(next_hop),
                    )
                    timeout_message = forward_channel.create_timeouttransfer_for(transfer)
                    raiden.send_async(transfer.sender, timeout_message)
                    self.transfermanager.on_hashlock_result(transfer.lock.hashlock, False)
                    return
                else:
                    forward_channel.register_transfer(response)

            elif isinstance(response, Secret):
                # update all channels and propagate the secret (this doesnt claim the lock yet)
                assetmanager.handle_secret(response.secret)

                # wait for the secret from `sender`
                while True:
                    response = self.response_message.wait()
                    # critical write section
                    self.response_message = AsyncResult()
                    # /critical write section

                    # NOTE: this relies on the fact RaindenService dispatches
                    # messages based on the `hashlock` calculated from the
                    # secret, so we know this `response` message secret matches
                    # the secret from the `next_hop`
                    if isinstance(response, Secret) and response.sender == transfer.sender:
                        originating_channel.claim_lock(response.secret)
                        self.transfermanager.on_hashlock_result(transfer.lock.hashlock, True)
                        return

        # No suitable path avaiable (e.g. insufficient distributable, no active node)
        # Send RefundTransfer to the originating node, this has the effect of
        # backtracking in the graph search of the raiden network.
        from_address = transfer.sender
        from_channel = assetmanager.partneraddress_channel[from_address]

        refund_transfer = from_channel.create_refundtransfer_for(transfer)
        from_channel.register_transfer(refund_transfer)

        raiden.sign(refund_transfer)
        raiden.send_async(from_address, refund_transfer)

        log.debug(
            'REFUND MEDIATED TRANSFER from=%s node:%s hashlock:%s',
            pex(from_address),
            pex(raiden.address),
            pex(transfer.lock.hashlock),
        )

        self.transfermanager.on_hashlock_result(transfer.lock.hashlock, False)
        return

    def send_and_wait_valid(self, raiden, path, mediated_transfer):
        message_timeout = raiden.config['msg_timeout']
        next_hop = path[1]

        current_time = time.time()
        limit_time = current_time + message_timeout

        self.response_message = AsyncResult()
        raiden.send_async(next_hop, mediated_transfer)

        while current_time <= limit_time:
            response = self.response_message.wait(limit_time - current_time)

            # critical write section
            self.response_message = AsyncResult()  # reset so that a new value can be received
            # /critical write section

            current_time = time.time()

            if response is None:
                log.error(
                    'MEDIATED TRANSFER TIMED OUT node:%s timeout:%s msghash:%s hashlock:%s',
                    pex(raiden.address),
                    message_timeout,
                    pex(mediated_transfer.hash),
                    pex(mediated_transfer.lock.hashlock),
                )
                return None

            if isinstance(response, Secret):
                if sha3(response.secret) != mediated_transfer.lock.hashlock:
                    log.error('Secret doesnt match the hashlock, ignoring.')
                    continue

                return response

            if response.target != raiden.address or response.sender != next_hop:
                log.error('Invalid message supplied to the task. %s', repr(response))
                continue

            if isinstance(response, RefundTransfer):
                return response

            log.error('Partner sent an invalid message. %s', repr(response))

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
        mediated_transfer = self.originating_transfer
        assetmanager = self.transfermanager.assetmanager
        originating_channel = assetmanager.get_channel_by_partner_address(mediated_transfer.sender)
        raiden = assetmanager.raiden

        log.debug(
            'END MEDIATED TRANSFER %s -> %s msghash:%s hashlock:%s',
            pex(mediated_transfer.target),
            pex(mediated_transfer.initiator),
            pex(mediated_transfer.hash),
            pex(mediated_transfer.lock.hashlock),
        )

        secret_request = SecretRequest(mediated_transfer.lock.hashlock)
        raiden.sign(secret_request)

        response = self.send_and_wait_valid(raiden, mediated_transfer, secret_request)

        if response is None:
            timeout_message = originating_channel.create_timeouttransfer_for(mediated_transfer)
            raiden.send_async(mediated_transfer.sender, timeout_message)
            self.transfermanager.on_hashlock_result(mediated_transfer.lock.hashlock, False)
            return

        # register the secret so that a balance proof can be created but don't
        # claim until our partner has informed us that it's internal state is
        # updated
        originating_channel.register_secret(response.secret)

        secret_message = Secret(response.secret)
        raiden.sign(secret_message)
        raiden.send_async(mediated_transfer.sender, secret_message)

        # wait for the secret from `sender` to claim the lock
        while True:
            response = self.response_message.wait()
            # critical write section
            self.response_message = AsyncResult()
            # /critical write section

            if isinstance(response, Secret) and response.sender == mediated_transfer.sender:
                originating_channel.claim_lock(response.secret)
                self.transfermanager.on_hashlock_result(mediated_transfer.lock.hashlock, True)
                return

    def send_and_wait_valid(self, raiden, mediated_transfer, secret_request):
        message_timeout = raiden.config['msg_timeout']

        current_time = time.time()
        limit_time = current_time + message_timeout

        self.response_message = AsyncResult()
        raiden.send_async(mediated_transfer.initiator, secret_request)

        while current_time <= limit_time:
            response = self.response_message.wait(limit_time - current_time)

            # critical write section
            self.response_message = AsyncResult()
            # /critical write section

            if response is None:
                log.error(
                    'SECRETREQUEST TIMED OUT node:%s msghash:%s hashlock:%s',
                    pex(raiden.address),
                    pex(secret_request.hash),
                    pex(mediated_transfer.lock.hashlock),
                )
                return None

            if isinstance(response, Secret):
                if sha3(response.secret) != mediated_transfer.lock.hashlock:
                    log.error('Secret doesnt match the hashlock, ignoring.')
                    continue

                return response

        return None
