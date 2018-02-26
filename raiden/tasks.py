# -*- coding: utf-8 -*-
import time

from ethereum import slogging

import gevent
from gevent.event import AsyncResult
from gevent.queue import (
    Queue,
)
from raiden.exceptions import RaidenShuttingDown

REMOVE_CALLBACK = object()
log = slogging.get_logger(__name__)  # pylint: disable=invalid-name


class Task(gevent.Greenlet):
    """ Base class used to created tasks.

    Note:
        Always call super().__init__().
    """

    def __init__(self):
        super().__init__()
        self.response_queue = Queue()


class AlarmTask(Task):
    """ Task to notify when a block is mined. """

    def __init__(self, chain):
        super().__init__()

        self.callbacks = list()
        self.stop_event = AsyncResult()
        self.chain = chain
        self.last_block_number = None

        # TODO: Start with a larger wait_time and decrease it as the
        # probability of a new block increases.
        self.wait_time = 0.5
        self.last_loop = time.time()

    def register_callback(self, callback):
        """ Register a new callback.

        Note:
            The callback will be executed in the AlarmTask context and for
            this reason it should not block, otherwise we can miss block
            changes.
        """
        if not callable(callback):
            raise ValueError('callback is not a callable')

        self.callbacks.append(callback)

    def remove_callback(self, callback):
        """Remove callback from the list of callbacks if it exists"""
        if callback in self.callbacks:
            self.callbacks.remove(callback)

    def _run(self):  # pylint: disable=method-hidden
        log.debug('starting block number', block_number=self.last_block_number)

        sleep_time = 0
        while self.stop_event.wait(sleep_time) is not True:
            try:
                self.poll_for_new_block()
            except RaidenShuttingDown:
                break

            # we want this task to iterate in the tick of `wait_time`, so take
            # into account how long we spent executing one tick.
            self.last_loop = time.time()
            work_time = self.last_loop - self.last_loop
            if work_time > self.wait_time:
                log.warning(
                    'alarm loop is taking longer than the wait time',
                    work_time=work_time,
                    wait_time=self.wait_time,
                )
                sleep_time = 0.001
            else:
                sleep_time = self.wait_time - work_time

        # stopping
        self.callbacks = list()

    def poll_for_new_block(self):
        current_block = self.chain.block_number()

        if current_block > self.last_block_number + 1:
            difference = current_block - self.last_block_number - 1
            log.error(
                'alarm missed %s blocks',
                difference,
            )

        if current_block != self.last_block_number:
            log.debug(
                'new block',
                number=current_block,
                timestamp=self.last_loop,
            )

            self.last_block_number = current_block
            remove = list()
            for callback in self.callbacks:
                try:
                    result = callback(current_block)
                except RaidenShuttingDown:
                    break
                except:  # pylint: disable=bare-except # noqa
                    log.exception('unexpected exception on alarm')
                else:
                    if result is REMOVE_CALLBACK:
                        remove.append(callback)

            for callback in remove:
                self.callbacks.remove(callback)

    def start(self):
        self.last_block_number = self.chain.block_number()
        super().start()

    def stop_and_wait(self):
        self.stop_event.set(True)
        gevent.wait(self)

    def stop_async(self):
        self.stop_event.set(True)
