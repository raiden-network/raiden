# -*- coding: utf-8 -*-
import random
import time

from ethereum import slogging

import gevent
from gevent.event import AsyncResult
from gevent.queue import Queue
from gevent.timeout import Timeout

from raiden.settings import (
    DEFAULT_HEALTHCHECK_POLL_TIMEOUT,
)

REMOVE_CALLBACK = object()
log = slogging.get_logger(__name__)  # pylint: disable=invalid-name


class Task(gevent.Greenlet):
    """ Base class used to created tasks.

    Note:
        Always call super().__init__().
    """

    def __init__(self):
        super(Task, self).__init__()
        self.response_queue = Queue()


class HealthcheckTask(Task):
    """ Task for checking if all of our open channels are healthy """

    def __init__(
            self,
            raiden,
            send_ping_time,
            max_unresponsive_time,
            sleep_time=DEFAULT_HEALTHCHECK_POLL_TIMEOUT):

        """
        Initialize a HealthcheckTask that will monitor open channels for
        responsiveness.

        Args:
            raiden (RaidenService): The Raiden service which will give us
                access to the protocol object and to the token manager.
            sleep_time (int): Time in seconds between each healthcheck task.
            send_ping_time (int): Time in seconds after not having received a
                message from an address at which to send a Ping.
            max_unresponsive_time (int): Time in seconds after not having
                received a message from an address at which it should be
                deleted.
         """
        super(HealthcheckTask, self).__init__()

        self.protocol = raiden.protocol
        self.raiden = raiden

        self.stop_event = AsyncResult()
        self.sleep_time = sleep_time
        self.send_ping_time = send_ping_time
        self.max_unresponsive_time = max_unresponsive_time
        self.timeout = None

    def _run(self):  # pylint: disable=method-hidden
        stop = None
        sleep_upper_bound = int(0.2 * self.send_ping_time)

        while stop is None:
            keys_to_remove = []
            for key, queue in self.protocol.address_queue.iteritems():
                receiver_address = key[0]
                token_address = key[1]
                if queue.empty():
                    last_time = self.protocol.last_received_time[receiver_address]
                    elapsed_time = time.time() - last_time

                    # Add a randomized delay in the loop to not clog the network
                    gevent.sleep(random.randint(0, sleep_upper_bound))

                    if elapsed_time > self.max_unresponsive_time:
                        graph = self.raiden.channelgraphs[token_address]
                        graph.remove_path(self.protocol.raiden.address, receiver_address)
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
        self.chain = chain
        self.last_block_number = self.chain.block_number()

        # TODO: Start with a larger wait_time and decrease it as the
        # probability of a new block increases.
        self.wait_time = 0.5

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
