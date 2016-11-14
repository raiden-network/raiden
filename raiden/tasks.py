# -*- coding: utf-8 -*-
# pylint: disable=too-many-lines
import logging
import random
import time

import gevent
from gevent.event import AsyncResult
from gevent.queue import Empty, Queue
from gevent.timeout import Timeout

from random import randint

from ethereum import slogging
from ethereum.utils import sha3

from raiden.messages import (
    MediatedTransfer,
    RefundTransfer,
    RevealSecret,
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
DEFAULT_HEALTHCHECK_POLL_TIMEOUT = 1
ESTIMATED_BLOCK_TIME = 7
TIMEOUT = object()


class Task(gevent.Greenlet):
    """ Base class used to created tasks.

    Note:
        Always call super().__init__().
    """

    def __init__(self):
        super(Task, self).__init__()
        self.response_queue = Queue()

    def on_completion(self, success):
        self.transfermanager.on_task_completed(self, success)
        return success

    def on_response(self, response):
        """ Add a new response message to the task queue. """
        if log.isEnabledFor(logging.DEBUG):
            log.debug(
                'RESPONSE MESSAGE RECEIVED %s %s',
                repr(self),
                response,
            )

        self.response_queue.put(response)


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
        # pylint: disable=too-many-arguments

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
                    except:  # pylint: disable=bare-except
                        log.exception('unexpected exception on log listener')

            self.timeout = Timeout(self.sleep_time)  # wait() will call cancel()
            stop = self.stop_event.wait(self.timeout)

    def stop_and_wait(self):
        self.stop_event.set(True)
        gevent.wait(self)

    def stop_async(self):
        self.stop_event.set(True)


class HealthcheckTask(Task):
    """ Task for checking if all of our open channels are healthy """

    def __init__(
            self,
            raiden,
            send_ping_time,
            max_unresponsive_time,
            sleep_time=DEFAULT_HEALTHCHECK_POLL_TIMEOUT):
        """ Initialize a HealthcheckTask that will monitor open channels for
             responsiveness.

             :param raiden RaidenService: The Raiden service which will give us
                                          access to the protocol object and to
                                          the asset manager
             :param int sleep_time: Time in seconds between each healthcheck task
             :param int send_ping_time: Time in seconds after not having received
                                        a message from an address at which to send
                                        a Ping.
             :param int max_unresponsive_time: Time in seconds after not having received
                                               a message from an address at which it
                                               should be deleted.
         """
        super(HealthcheckTask, self).__init__()

        self.protocol = raiden.protocol
        self.raiden = raiden

        self.stop_event = AsyncResult()
        self.sleep_time = sleep_time
        self.send_ping_time = send_ping_time
        self.max_unresponsive_time = max_unresponsive_time

    def _run(self):  # pylint: disable=method-hidden
        stop = None
        while stop is None:
            keys_to_remove = []
            for key, queue in self.protocol.address_queue.iteritems():
                receiver_address = key[0]
                asset_address = key[1]
                if queue.empty():
                    elapsed_time = (
                        time.time() - self.protocol.last_received_time[receiver_address]
                    )
                    # Add a randomized delay in the loop to not clog the network
                    gevent.sleep(randint(0, int(0.2 * self.send_ping_time)))
                    if elapsed_time > self.max_unresponsive_time:
                        # remove the node from the graph
                        asset_manager = self.raiden.get_manager_by_asset_address(
                            asset_address
                        )
                        asset_manager.channelgraph.remove_path(
                            self.protocol.raiden.address,
                            receiver_address
                        )
                        # remove the node from the queue
                        keys_to_remove.append(key)
                    elif elapsed_time > self.send_ping_time:
                        self.protocol.send_ping(receiver_address)

            for key in keys_to_remove:
                self.protocol.address_queue.pop(key)

            self.timeout = Timeout(self.sleep_time)  # wait() will call cancel()
            stop = self.stop_event.wait(self.timeout)

    def stop_and_wait(self):
        self.stop_event.set(True)
        gevent.wait(self)

    def stop_async(self):
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
                    except:  # pylint: disable=bare-except
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

    def stop_and_wait(self):
        self.stop_event.set(True)
        gevent.wait(self)

    def stop_async(self):
        self.stop_event.set(True)


class BaseMediatedTransferTask(Task):
    def _send_and_wait_time(self, raiden, recipient, transfer, timeout):
        """ Utility to handle multiple messages for the same hashlock while
        properly handling expiration timeouts.
        """

        current_time = time.time()
        limit_time = current_time + timeout

        raiden.send_async(recipient, transfer)

        while current_time <= limit_time:
            # wait for a response message (not the Ack for the transfer)
            try:
                response = self.response_queue.get(
                    timeout=limit_time - current_time,
                )
            except Empty:
                yield TIMEOUT
                return

            yield response

            current_time = time.time()

        if log.isEnabledFor(logging.DEBUG):
            log.debug(
                'TIMED OUT %s %s',
                self.__class__,
                pex(transfer),
            )

    def _send_and_wait_block(self, raiden, recipient, transfer, expiration_block):
        """ Utility to handle multiple messages and timeout on a blocknumber. """
        raiden.send_async(recipient, transfer)

        current_block = raiden.chain.block_number()
        while current_block < expiration_block:
            try:
                response = self.response_queue.get(
                    timeout=DEFAULT_EVENTS_POLL_TIMEOUT
                )
            except Empty:
                pass
            else:
                if response:
                    yield response

            current_block = raiden.chain.block_number()

        if log.isEnabledFor(logging.DEBUG):
            log.debug(
                'TIMED OUT ON BLOCK %s %s %s',
                current_block,
                self.__class__,
                pex(transfer),
            )

        yield TIMEOUT

    def _wait_for_unlock_or_close(self, raiden, assetmanager, channel, mediated_transfer):  # noqa
        """ Wait for a Secret message from our partner to update the local
        state, if the Secret message is not sent within time the channel will
        be closed.

        Note:
            Must be called only once the secret is known.
            Must call `on_hashlock_result` after this function returns.
        """

        if not isinstance(mediated_transfer, MediatedTransfer):
            raise ValueError('MediatedTransfer expected.')

        block_to_close = mediated_transfer.lock.expiration - raiden.config['reveal_timeout']
        hashlock = mediated_transfer.lock.hashlock
        identifier = mediated_transfer.identifier
        asset = mediated_transfer.asset

        while channel.our_state.balance_proof.is_unclaimed(hashlock):
            current_block = raiden.chain.block_number()

            if current_block > block_to_close:
                if log.isEnabledFor(logging.WARN):
                    log.warn(
                        'Closing channel (%s, %s) to prevent expiration of lock %s %s',
                        pex(channel.our_state.address),
                        pex(channel.partner_state.address),
                        pex(hashlock),
                        repr(self),
                    )

                channel.netting_channel.close(
                    channel.our_state.address,
                    channel.our_state.balance_proof.transfer,
                    channel.partner_state.balance_proof.transfer,
                )
                return

            try:
                response = self.response_queue.get(
                    timeout=DEFAULT_EVENTS_POLL_TIMEOUT
                )
            except Empty:
                pass
            else:
                if isinstance(response, Secret):
                    if response.identifier == identifier and response.asset == asset:
                        assetmanager.handle_secretmessage(response)
                    else:
                        assetmanager.handle_secret(identifier, response.secret)

                        if log.isEnabledFor(logging.ERROR):
                            log.error(
                                'Invalid Secret message received, expected message'
                                ' for asset=%s identifier=%s received=%s',
                                asset,
                                identifier,
                                response,
                            )
                elif isinstance(response, RevealSecret):
                    assetmanager.handle_secret(identifier, response.secret)

                elif log.isEnabledFor(logging.ERROR):
                    log.error(
                        'Invalid message ignoring. %s %s',
                        repr(response),
                        repr(self),
                    )

    def _wait_expiration(self, raiden, transfer, sleep=DEFAULT_EVENTS_POLL_TIMEOUT):
        """ Utility to wait until the expiration block.

        For a chain A-B-C, if an attacker controls A and C a mediated transfer
        can be done through B and C will wait for/send a timeout, for that
        reason B must not unregister the hashlock from the transfermanager
        until the lock has expired, otherwise the revealed secret wouldnt be
        caught.
        """
        # pylint: disable=no-self-use

        expiration = transfer.lock.expiration + 1

        while True:
            current_block = raiden.chain.block_number()

            if current_block > expiration:
                return

            gevent.sleep(sleep)


# Note: send_and_wait_valid methods are used to check the message type and
# sender only, this can be improved by using a encrypted connection between the
# nodes making the signature validation unnecessary


class StartMediatedTransferTask(BaseMediatedTransferTask):
    def __init__(self, raiden, asset_address, amount, identifier, target, done_result):
        # pylint: disable=too-many-arguments

        super(StartMediatedTransferTask, self).__init__()

        self.raiden = raiden
        self.asset_address = asset_address
        self.amount = amount
        self.identifier = identifier
        self.target = target
        self.done_result = done_result

    def __repr__(self):
        return '<{} {} asset:{}>'.format(
            self.__class__.__name__,
            pex(self.raiden.address),
            pex(self.asset_address),
        )

    def _run(self):  # noqa pylint: disable=method-hidden,too-many-locals
        raiden = self.raiden
        amount = self.amount
        identifier = self.identifier
        target = self.target

        node_address = raiden.address
        assetmanager = raiden.get_manager_by_asset_address(self.asset_address)
        transfermanager = assetmanager.transfermanager

        fee = 0
        # there are no guarantees that the next_hop will follow the same route
        routes = assetmanager.get_best_routes(
            amount,
            target,
            lock_timeout=None,
        )

        if log.isEnabledFor(logging.DEBUG):
            log.debug(
                'START MEDIATED TRANSFER initiator:%s target:%s',
                pex(node_address),
                pex(target),
            )

        for path, forward_channel in routes:
            # never reuse the last secret, discard it to avoid losing asset
            secret = sha3(hex(random.getrandbits(256)))
            hashlock = sha3(secret)

            if log.isEnabledFor(logging.DEBUG):
                log.debug(
                    'START MEDIATED TRANSFER NEW PATH path:%s hashlock:%s',
                    lpex(path),
                    pex(hashlock),
                )

            transfermanager.register_task_for_hashlock(self, hashlock)
            assetmanager.register_channel_for_hashlock(forward_channel, hashlock)

            lock_timeout = forward_channel.settle_timeout - forward_channel.reveal_timeout
            lock_expiration = raiden.chain.block_number() + lock_timeout

            mediated_transfer = forward_channel.create_mediatedtransfer(
                node_address,
                target,
                fee,
                amount,
                identifier,
                lock_expiration,
                hashlock,
            )
            raiden.sign(mediated_transfer)
            forward_channel.register_transfer(mediated_transfer)

            for response in self.send_and_iter_valid(raiden, path, mediated_transfer):
                valid_secretrequest = (
                    isinstance(response, SecretRequest) and
                    response.amount == amount and
                    response.hashlock == hashlock and
                    response.identifier == identifier
                )

                if valid_secretrequest:
                    # This node must reveal the Secret starting with the
                    # end-of-chain, the `next_hop` can not be trusted to reveal the
                    # secret to the other nodes.
                    revealsecret_message = RevealSecret(secret)
                    raiden.sign(revealsecret_message)

                    # we cannot wait for ever since the `target` might
                    # intentionally _not_ send the Ack, blocking us from
                    # unlocking the asset.
                    wait = (
                        ESTIMATED_BLOCK_TIME * lock_timeout / .6
                    )

                    raiden.send_and_wait(target, revealsecret_message, wait)

                    # target has acknowledged the RevealSecret, we can update
                    # the chain in the forward direction
                    assetmanager.handle_secret(
                        identifier,
                        secret,
                    )

                    # call the callbacks and unregister the task
                    transfermanager.on_hashlock_result(hashlock, True)

                    # the transfer is done when the lock is unlocked and the Secret
                    # message is sent (doesn't imply the other nodes in the chain
                    # have unlocked/withdrawn)
                    self.done_result.set(True)

                    return

                # someone down the line timed out / couldn't proceed, try next
                # path, stop listening for messages for the current hashlock
                else:
                    # the initiator can unregister right away because it knowns
                    # no one else can reveal the secret
                    transfermanager.on_hashlock_result(hashlock, False)
                    del assetmanager.hashlock_channel[hashlock]
                    break

        if log.isEnabledFor(logging.DEBUG):
            log.debug(
                'START MEDIATED TRANSFER FAILED initiator:%s target:%s',
                pex(node_address),
                pex(self.target),
            )

        # all routes failed, consider:
        # - if the target is a good node to have a channel:
        #   - deposit/reopen/open a channel with target
        # - if the target has a direct channel with good nodes and there is
        #   sufficient funds to complete the transfer
        #   - open the required channels with these nodes
        self.done_result.set(False)

    def send_and_iter_valid(self, raiden, path, mediated_transfer):  # noqa pylint: disable=no-self-use
        """ Send the `mediated_transfer` and wait for either a message from
        `target` or the `next_hop`.
        """
        next_hop = path[1]
        target = path[-1]

        response_iterator = self._send_and_wait_time(
            raiden,
            mediated_transfer.recipient,
            mediated_transfer,
            raiden.config['msg_timeout'],
        )

        for response in response_iterator:
            refund_or_timeout = (
                isinstance(response, (RefundTransfer, TransferTimeout)) and
                response.sender == next_hop
            )

            secret_request = (
                isinstance(response, SecretRequest) and
                response.sender == target
            )

            timeout = response is TIMEOUT

            if refund_or_timeout or secret_request or timeout:
                yield response
            elif log.isEnabledFor(logging.ERROR):
                log.error(
                    'Invalid message ignoring. %s',
                    repr(response),
                )

        return


class MediateTransferTask(BaseMediatedTransferTask):
    def __init__(self, raiden, asset_address, originating_transfer, fee):
        super(MediateTransferTask, self).__init__()

        self.raiden = raiden
        self.asset_address = asset_address
        self.originating_transfer = originating_transfer
        self.fee = fee

    def __repr__(self):
        return '<{} {} asset:{}>'.format(
            self.__class__.__name__,
            pex(self.raiden.address),
            pex(self.asset_address),
        )

    def _run(self):  # noqa
        # pylint: disable=method-hidden,too-many-locals,too-many-branches,too-many-statements
        raiden = self.raiden
        fee = self.fee
        originating_transfer = self.originating_transfer

        raiden = self.raiden
        assetmanager = raiden.get_manager_by_asset_address(self.asset_address)
        transfermanager = assetmanager.transfermanager
        from_address = originating_transfer.sender
        originating_channel = assetmanager.partneraddress_channel[from_address]
        hashlock = originating_transfer.lock.hashlock

        transfermanager.register_task_for_hashlock(self, hashlock)
        assetmanager.register_channel_for_hashlock(originating_channel, hashlock)

        # there are no guarantees that the next_hop will follow the same route
        routes = assetmanager.get_best_routes(
            originating_transfer.lock.amount,
            originating_transfer.target,
        )

        if log.isEnabledFor(logging.DEBUG):
            log.debug(
                'MEDIATED TRANSFER initiator:%s node:%s target:%s',
                pex(originating_transfer.initiator),
                pex(raiden.address),
                pex(originating_transfer.target),
            )

        maximum_expiration = (
            originating_channel.settle_timeout +
            raiden.chain.block_number() -
            2  # decrement as a safety measure to avoid limit errors
        )

        # Ignore locks that expire after settle_timeout
        if originating_transfer.lock.expiration > maximum_expiration:
            if log.isEnabledFor(logging.ERROR):
                log.debug(
                    'lock_expiration is too large, ignore the mediated transfer',
                    initiator=pex(originating_transfer.initiator),
                    node=pex(self.address),
                    target=pex(originating_transfer.target),
                )

            # Notes:
            # - The node didn't send a transfer forward, so it can not lose
            #   asset.
            # - It's quiting early, so it wont claim the lock if the secret is
            #   revealed.
            # - The previous_node knowns the settle_timeout because this value
            #   is in the smart contract.
            # - It's not sending a RefundTransfer to the previous_node, so it
            #   will force a retry with a new path/different hashlock, this
            #   could make the bad behaving node lose it's fees but it will
            #   also increase latency.
            return

        for path, forward_channel in routes:
            current_block_number = raiden.chain.block_number()

            # Dont forward the mediated transfer to the next_hop if we cannot
            # decrease the expiration by `reveal_timeout`, this is time
            # required to learn the secret through the blockchain that needs to
            # consider DoS attacks.
            lock_timeout = originating_transfer.lock.expiration - current_block_number
            if lock_timeout < forward_channel.reveal_timeout:
                if log.isEnabledFor(logging.INFO):
                    log.info(
                        'transfer.lock_expiration is smaller than'
                        ' reveal_timeout, channel/path cannot be used',
                        lock_timeout=originating_transfer.lock.expiration,
                        reveal_timeout=forward_channel.reveal_timeout,
                        settle_timeout=forward_channel.settle_timeout,
                        nodeid=pex(path[0]),
                        partner=pex(path[1]),
                    )
                continue

            new_lock_timeout = lock_timeout - forward_channel.reveal_timeout

            # Our partner won't accept a locked transfer that can expire after
            # the settlement period, otherwise the secret could be revealed
            # after channel is settled and asset would be lost, in that case
            # decrease the expiration by an amount larger than reveal_timeout.
            if new_lock_timeout > forward_channel.settle_timeout:
                new_lock_timeout = forward_channel.settle_timeout - 2  # arbitrary decrement

                if log.isEnabledFor(logging.DEBUG):
                    log.debug(
                        'lock_expiration would be too large, decrement more so'
                        ' that the channel/path can be used',
                        lock_timeout=lock_timeout,
                        new_lock_timeout=new_lock_timeout,
                        nodeid=pex(path[0]),
                        partner=pex(path[1]),
                    )

            new_lock_expiration = current_block_number + new_lock_timeout
            mediated_transfer = forward_channel.create_mediatedtransfer(
                originating_transfer.initiator,
                originating_transfer.target,
                fee,
                originating_transfer.lock.amount,
                originating_transfer.identifier,
                new_lock_expiration,
                hashlock,
            )
            raiden.sign(mediated_transfer)

            if log.isEnabledFor(logging.DEBUG):
                log.debug(
                    'MEDIATED TRANSFER NEW PATH path:%s hashlock:%s',
                    lpex(path),
                    pex(hashlock),
                )

            assetmanager.register_channel_for_hashlock(
                forward_channel,
                hashlock,
            )
            forward_channel.register_transfer(mediated_transfer)

            for response in self.send_and_iter_valid(raiden, path, mediated_transfer):
                valid_refund = (
                    isinstance(response, RefundTransfer) and
                    response.lock.amount == originating_transfer.lock.amount
                )

                if isinstance(response, RevealSecret):
                    assetmanager.handle_secret(
                        originating_transfer.identifier,
                        response.secret,
                    )

                    self._wait_for_unlock_or_close(
                        raiden,
                        assetmanager,
                        originating_channel,
                        originating_transfer,
                    )

                elif isinstance(response, Secret):
                    assetmanager.handle_secretmessage(response)

                    # Secret might be from a different node, wait for the
                    # update from `from_address`
                    self._wait_for_unlock_or_close(
                        raiden,
                        assetmanager,
                        originating_channel,
                        originating_transfer,
                    )

                    transfermanager.on_hashlock_result(hashlock, True)
                    return

                elif valid_refund:
                    forward_channel.register_transfer(response)
                    break

                else:
                    timeout_message = originating_channel.create_timeouttransfer_for(
                        originating_transfer,
                    )
                    raiden.send_async(
                        originating_transfer.sender,
                        timeout_message,
                    )

                    self._wait_expiration(
                        raiden,
                        originating_transfer,
                    )
                    transfermanager.on_hashlock_result(hashlock, False)

                    return

        # No suitable path avaiable (e.g. insufficient distributable, no active node)
        # Send RefundTransfer to the originating node, this has the effect of
        # backtracking in the graph search of the raiden network.

        if log.isEnabledFor(logging.DEBUG):
            log.debug(
                'REFUND MEDIATED TRANSFER from=%s node:%s hashlock:%s',
                pex(from_address),
                pex(raiden.address),
                pex(hashlock),
            )

        refund_transfer = originating_channel.create_refundtransfer_for(
            originating_transfer,
        )
        raiden.sign(refund_transfer)

        originating_channel.register_transfer(refund_transfer)
        raiden.send_async(from_address, refund_transfer)

        self._wait_expiration(
            raiden,
            originating_transfer,
        )
        transfermanager.on_hashlock_result(hashlock, False)

    def send_and_iter_valid(self, raiden, path, mediated_transfer):
        response_iterator = self._send_and_wait_time(
            raiden,
            mediated_transfer.recipient,
            mediated_transfer,
            raiden.config['msg_timeout'],
        )

        for response in response_iterator:

            timeout = response is TIMEOUT
            secret = isinstance(response, (Secret, RevealSecret))

            refund_or_timeout = (
                isinstance(response, (RefundTransfer, TransferTimeout)) and
                response.sender == path[0]
            )

            if timeout or secret or refund_or_timeout:
                yield response

            elif log.isEnabledFor(logging.ERROR):
                log.error(
                    'Partner sent an invalid message. %s',
                    repr(response),
                )


class EndMediatedTransferTask(BaseMediatedTransferTask):
    """ Task that requests a secret for a registered transfer. """

    def __init__(self, raiden, asset_address, originating_transfer):
        super(EndMediatedTransferTask, self).__init__()

        self.raiden = raiden
        self.asset_address = asset_address
        self.originating_transfer = originating_transfer

    def __repr__(self):
        return '<{} {} asset:{}>'.format(
            self.__class__.__name__,
            pex(self.raiden.address),
            pex(self.asset_address),
        )

    def _run(self):  # pylint: disable=method-hidden
        raiden = self.raiden
        originating_transfer = self.originating_transfer
        hashlock = originating_transfer.lock.hashlock

        assetmanager = raiden.get_manager_by_asset_address(self.asset_address)
        transfermanager = assetmanager.transfermanager
        originating_channel = assetmanager.get_channel_by_partner_address(
            originating_transfer.sender,
        )

        transfermanager.register_task_for_hashlock(self, hashlock)
        assetmanager.register_channel_for_hashlock(originating_channel, hashlock)

        if log.isEnabledFor(logging.DEBUG):
            log.debug(
                'END MEDIATED TRANSFER %s -> %s msghash:%s hashlock:%s',
                pex(originating_transfer.target),
                pex(originating_transfer.initiator),
                pex(originating_transfer.hash),
                pex(originating_transfer.lock.hashlock),
            )

        secret_request = SecretRequest(
            originating_transfer.identifier,
            originating_transfer.lock.hashlock,
            originating_transfer.lock.amount,
        )
        raiden.sign(secret_request)

        # If the transfer timed out in the initiator a new hashlock will be
        # created and this task will not receive a secret, this is fine because
        # the task will eventually exit once a blocktimeout happens and a new
        # task will be created for the new hashlock
        valid_messages_iterator = self.send_secretrequest_and_iter_valid(
            raiden,
            originating_transfer,
            secret_request,
        )

        for response in valid_messages_iterator:

            # at this point a Secret message is not valid
            if isinstance(response, RevealSecret):
                assetmanager.handle_secret(
                    originating_transfer.identifier,
                    response.secret,
                )

                self._wait_for_unlock_or_close(
                    raiden,
                    assetmanager,
                    originating_channel,
                    originating_transfer,
                )
                transfermanager.on_hashlock_result(hashlock, True)
                return

            elif response is TIMEOUT:
                # this task timeouts on a blocknumber, at this point all the other
                # nodes have timedout
                transfermanager.on_hashlock_result(originating_transfer.lock.hashlock, False)
                break

    def send_secretrequest_and_iter_valid(self, raiden, originating_transfer, secret_request):
        # pylint: disable=invalid-name

        # keep this task alive up to the expiration block
        response_iterator = self._send_and_wait_block(
            raiden,
            originating_transfer.initiator,
            secret_request,
            originating_transfer.lock.expiration,
        )

        # a Secret message is not valid here since the secret needs to first be
        # revealed to the target
        for response in response_iterator:

            if isinstance(response, RevealSecret):
                yield response
                break

            elif response is TIMEOUT:
                if log.isEnabledFor(logging.ERROR):
                    log.error(
                        'SECRETREQUEST TIMED OUT node:%s msghash:%s hashlock:%s',
                        pex(raiden.address),
                        pex(secret_request.hash),
                        pex(originating_transfer.lock.hashlock),
                    )

                yield response

            elif log.isEnabledFor(logging.ERROR):
                log.error(
                    'INVALID MESSAGE RECEIVED %s',
                    repr(response),
                )


class StartExchangeTask(BaseMediatedTransferTask):
    """ Initiator task, responsible to choose a random secret, initiate the
    asset exchange by sending a mediated transfer to the counterparty and
    revealing the secret once the exchange can be complete.
    """

    def __init__(self, identifier, raiden, from_asset, from_amount, to_asset, to_amount, target):
        # pylint: disable=too-many-arguments

        super(StartExchangeTask, self).__init__()

        self.identifier = identifier
        self.raiden = raiden
        self.from_asset = from_asset
        self.from_amount = from_amount
        self.to_asset = to_asset
        self.to_amount = to_amount
        self.target = target

    def __repr__(self):
        return '<{} {} from_asset:{} to_asset:{}>'.format(
            self.__class__.__name__,
            pex(self.raiden.address),
            pex(self.from_asset),
            pex(self.to_asset),
        )

    def _run(self):  # pylint: disable=method-hidden,too-many-locals
        identifier = self.identifier
        raiden = self.raiden
        from_asset = self.from_asset
        from_amount = self.from_amount
        to_asset = self.to_asset
        to_amount = self.to_amount
        target = self.target

        from_assetmanager = raiden.get_manager_by_asset_address(from_asset)
        to_assetmanager = raiden.get_manager_by_asset_address(to_asset)

        from_transfermanager = from_assetmanager.transfermanager

        from_routes = from_assetmanager.get_best_routes(
            from_amount,
            target,
            lock_timeout=None,
        )
        fee = 0

        for path, from_channel in from_routes:
            # for each new path a new secret must be used
            secret = sha3(hex(random.getrandbits(256)))
            hashlock = sha3(secret)

            from_transfermanager.register_task_for_hashlock(self, hashlock)
            from_assetmanager.register_channel_for_hashlock(from_channel, hashlock)

            lock_expiration = (
                raiden.chain.block_number() +
                from_channel.settle_timeout -
                raiden.config['reveal_timeout']
            )

            from_mediated_transfer = from_channel.create_mediatedtransfer(
                raiden.address,
                target,
                fee,
                from_amount,
                identifier,
                lock_expiration,
                hashlock,
            )
            raiden.sign(from_mediated_transfer)
            from_channel.register_transfer(from_mediated_transfer)

            # wait for the SecretRequest and MediatedTransfer
            to_mediated_transfer = self.send_and_wait_valid_state(
                raiden,
                path,
                from_mediated_transfer,
                to_asset,
                to_amount,
            )

            if to_mediated_transfer is None:
                # the initiator can unregister right away since it knows the
                # secret wont be revealed
                from_transfermanager.on_hashlock_result(hashlock, False)
                del from_assetmanager.hashlock_channel[hashlock]

            elif isinstance(to_mediated_transfer, MediatedTransfer):
                to_hop = to_mediated_transfer.sender

                # reveal the secret to the `to_hop` and `target`
                self.reveal_secret(
                    self.raiden,
                    secret,
                    last_node=to_hop,
                    exchange_node=target,
                )

                to_channel = to_assetmanager.get_channel_by_partner_address(
                    to_mediated_transfer.sender
                )

                # now the secret can be revealed forward (`from_hop`)
                from_assetmanager.handle_secret(identifier, secret)
                to_assetmanager.handle_secret(identifier, secret)

                self._wait_for_unlock_or_close(
                    raiden,
                    to_assetmanager,
                    to_channel,
                    to_mediated_transfer,
                )

                from_transfermanager.on_hashlock_result(hashlock, True)
                self.done_result.set(True)

    def send_and_wait_valid_state(  # noqa
            self,
            raiden,
            path,
            from_asset_transfer,
            to_asset,
            to_amount):
        """ Start the exchange by sending the first mediated transfer to the
        taker and wait for mediated transfer for the exchanged asset.

        This method will validate the messages received, discard the invalid
        ones, and wait until a valid state is reached. The valid state is
        reached when a mediated transfer for `to_asset` with `to_amount` tokens
        and a SecretRequest from the taker are received.

        Returns:
            None: when the timeout was reached.
            MediatedTransfer: when a valid state is reached.
            RefundTransfer/TransferTimeout: when an invalid state is reached by
                our partner.
        """
        # pylint: disable=too-many-arguments

        next_hop = path[1]
        taker_address = path[-1]  # taker_address and next_hop might be equal

        # a valid state must have a secret request from the maker and a valid
        # mediated transfer for the new asset
        received_secretrequest = False
        mediated_transfer = None

        response_iterator = self._send_and_wait_time(
            raiden,
            from_asset_transfer.recipient,
            from_asset_transfer,
            raiden.config['msg_timeout'],
        )

        for response in response_iterator:

            if response is None:
                if log.isEnabledFor(logging.DEBUG):
                    log.debug(
                        'EXCHANGE TRANSFER TIMED OUT hashlock:%s',
                        pex(from_asset_transfer.lock.hashlock),
                    )

                return None

            # The MediatedTransfer might be from `next_hop` or most likely from
            # a different node.
            #
            # The other participant must not use a direct transfer to finish
            # the asset exchange, ignore it
            if isinstance(response, MediatedTransfer) and response.asset == to_asset:
                # XXX: allow multiple transfers to add up to the correct amount
                if response.lock.amount == to_amount:
                    mediated_transfer = response

            elif isinstance(response, SecretRequest) and response.sender == taker_address:
                received_secretrequest = True

            # next_hop could send the MediatedTransfer, this is handled in a
            # previous if
            elif response.sender == next_hop:
                if isinstance(response, (RefundTransfer, TransferTimeout)):
                    return response
                else:
                    if log.isEnabledFor(logging.INFO):
                        log.info(
                            'Partner %s sent an invalid message %s',
                            pex(next_hop),
                            repr(response),
                        )

                    return None

            elif log.isEnabledFor(logging.ERROR):
                log.error(
                    'Invalid message ignoring. %s',
                    repr(response),
                )

            if mediated_transfer and received_secretrequest:
                return mediated_transfer

        return None

    def reveal_secret(self, raiden, secret, last_node, exchange_node):
        """ Reveal the `secret` to both participants.

        The secret must be revealed backwards to get the incentives right
        (first mediator would not forward the secret and get the transfer to
        itself).

        With exchanges there is an additional failure point, if a node is
        mediating both asset transfers it can intercept the transfer (as in not
        revealing the secret to others), for this reason it is not sufficient
        to just send the Secret backwards, the Secret must also be sent to the
        exchange_node.
        """
        # pylint: disable=no-self-use

        reveal_secret = RevealSecret(secret)
        raiden.sign(reveal_secret)

        # first reveal the secret to the last_node in the chain, proceed after
        # ack
        raiden.send_and_wait(last_node, reveal_secret, timeout=None)  # XXX: wait for expiration

        # the last_node has acknowledged the Secret, so we know the exchange
        # has kicked-off, reveal the secret to the exchange_node to
        # avoid interceptions but dont wait
        raiden.send_async(exchange_node, reveal_secret)


class ExchangeTask(BaseMediatedTransferTask):
    """ Counterparty task, responsible to receive a MediatedTransfer for the
    from_transfer and forward a to_transfer with the same hashlock.
    """

    def __init__(self, raiden, from_mediated_transfer, to_asset, to_amount, target):
        # pylint: disable=too-many-arguments

        super(ExchangeTask, self).__init__()

        self.raiden = raiden
        self.from_mediated_transfer = from_mediated_transfer
        self.target = target

        self.to_amount = to_amount
        self.to_asset = to_asset

    def __repr__(self):
        return '<{} {} from_asset:{} to_asset:{}>'.format(
            self.__class__.__name__,
            pex(self.raiden.address),
            pex(self.from_mediated_transfer.asset),
            pex(self.to_asset),
        )

    def _run(self):  # pylint: disable=method-hidden,too-many-locals
        fee = 0
        raiden = self.raiden

        from_mediated_transfer = self.from_mediated_transfer
        hashlock = from_mediated_transfer.lock.hashlock

        from_asset = from_mediated_transfer.asset
        to_asset = self.to_asset
        to_amount = self.to_amount

        to_assetmanager = raiden.get_manager_by_asset_address(to_asset)
        from_assetmanager = raiden.get_manager_by_asset_address(from_asset)
        from_transfermanager = from_assetmanager.transfermanager

        from_channel = from_assetmanager.get_channel_by_partner_address(
            from_mediated_transfer.sender,
        )

        from_transfermanager.register_task_for_hashlock(self, hashlock)
        from_assetmanager.register_channel_for_hashlock(from_channel, hashlock)

        lock_expiration = from_mediated_transfer.lock.expiration - raiden.config['reveal_timeout']
        lock_timeout = lock_expiration - raiden.chain.block_number()

        to_routes = to_assetmanager.get_best_routes(
            from_mediated_transfer.lock.amount,
            from_mediated_transfer.initiator,  # route back to the initiator
            lock_timeout,
        )

        if log.isEnabledFor(logging.DEBUG):
            log.debug(
                'EXCHANGE TRANSFER %s -> %s msghash:%s hashlock:%s',
                pex(from_mediated_transfer.target),
                pex(from_mediated_transfer.initiator),
                pex(from_mediated_transfer.hash),
                pex(hashlock),
            )

        secret_request = SecretRequest(
            from_mediated_transfer.identifier,
            from_mediated_transfer.lock.hashlock,
            from_mediated_transfer.lock.amount,
        )
        raiden.sign(secret_request)
        raiden.send_async(from_mediated_transfer.initiator, secret_request)

        for path, to_channel in to_routes:
            to_next_hop = path[1]

            to_mediated_transfer = to_channel.create_mediatedtransfer(
                raiden.address,  # this node is the new initiator
                from_mediated_transfer.initiator,  # the initiator is the target for the to_asset
                fee,
                to_amount,
                lock_expiration,
                hashlock,  # use the original hashlock
            )
            raiden.sign(to_mediated_transfer)

            if log.isEnabledFor(logging.DEBUG):
                log.debug(
                    'MEDIATED TRANSFER NEW PATH path:%s hashlock:%s',
                    lpex(path),
                    pex(from_mediated_transfer.lock.hashlock),
                )

            # Using assetmanager to register the interest because it outlives
            # this task, the secret handling will happen only _once_
            to_assetmanager.register_channel_for_hashlock(
                to_channel,
                hashlock,
            )
            to_channel.register_transfer(to_mediated_transfer)

            response = self.send_and_wait_valid(raiden, to_mediated_transfer)

            if log.isEnabledFor(logging.DEBUG):
                log.debug(
                    'EXCHANGE TRANSFER NEW PATH path:%s hashlock:%s',
                    lpex(path),
                    pex(hashlock),
                )

            # only refunds for `from_asset` must be considered (check send_and_wait_valid)
            if isinstance(response, RefundTransfer):
                if response.lock.amount != to_mediated_transfer.amount:
                    log.info(
                        'Partner %s sent an invalid refund message with an invalid amount',
                        pex(to_next_hop),
                    )
                    timeout_message = from_channel.create_timeouttransfer_for(
                        from_mediated_transfer
                    )
                    raiden.send_async(from_mediated_transfer.sender, timeout_message)
                    self.transfermanager.on_hashlock_result(hashlock, False)
                    return
                else:
                    to_channel.register_transfer(response)

            elif isinstance(response, Secret):
                # this node is receiving the from_asset and sending the
                # to_asset, meaning that it can claim the to_asset but it needs
                # a Secret message to claim the from_asset
                to_assetmanager.handle_secretmessage(response)
                from_assetmanager.handle_secretmessage(response)

                self._wait_for_unlock_or_close(
                    raiden,
                    from_assetmanager,
                    from_channel,
                    from_mediated_transfer,
                )

    def send_and_wait_valid(self, raiden, mediated_transfer):
        response_iterator = self._send_and_wait_time(
            raiden,
            mediated_transfer.recipient,
            mediated_transfer,
            raiden.config['msg_timeout'],
        )

        for response in response_iterator:
            if response is None:
                log.error(
                    'EXCHANGE TIMED OUT node:%s hashlock:%s',
                    pex(raiden.address),
                    pex(mediated_transfer.lock.hashlock),
                )
                return None

            if isinstance(response, Secret):
                if sha3(response.secret) != mediated_transfer.lock.hashlock:
                    log.error('Secret doesnt match the hashlock, ignoring.')
                    continue

                return response

            # first check that the message is from a known/valid sender/asset
            valid_target = response.target == raiden.address
            valid_sender = response.sender == mediated_transfer.recipient
            valid_asset = response.asset == mediated_transfer.asset

            if not valid_target or not valid_sender or not valid_asset:
                log.error(
                    'Invalid message [%s] supplied to the task, ignoring.',
                    repr(response),
                )
                continue

            if isinstance(response, RefundTransfer):
                return response

        return None
