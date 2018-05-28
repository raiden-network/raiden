# -*- coding: utf-8 -*-
# -*- coding: utf-8 -*-
import random

import gevent
from gevent.event import (
    _AbstractLinkable,
    Event,
)


def event_first_of(*events):
    """ Waits until one of `events` is set.

    The event returned is /not/ cleared with any of the `events`, this value
    must not be reused if the clearing behavior is used.
    """
    first_finished = Event()

    if not all(isinstance(e, _AbstractLinkable) for e in events):
        raise ValueError('all events must be linkable')

    for event in events:
        event.rawlink(lambda _: first_finished.set())

    return first_finished


def timeout_exponential_backoff(retries, timeout, maximum):
    """ Timeouts generator with an exponential backoff strategy.

    Timeouts start spaced by `timeout`, after `retries` exponentially increase
    the retry delays until `maximum`, then maximum is returned indefinitely.
    """
    yield timeout

    tries = 1
    while tries < retries:
        tries += 1
        yield timeout

    while timeout < maximum:
        timeout = min(timeout * 2, maximum)
        yield timeout

    while True:
        yield maximum


def timeout_two_stage(retries, timeout1, timeout2):
    """ Timeouts generator with a two stage strategy

    Timeouts start spaced by `timeout1`, after `retries` increase
    to `timeout2` which is repeated indefinitely.
    """
    for _ in range(retries):
        yield timeout1
    while True:
        yield timeout2


def retry(protocol, messagedata, message_id, recipient, event_stop, timeout_backoff):
    """ Send messagedata until it's acknowledged.

    Exit when:

    - The message is delivered.
    - Event_stop is set.
    - The iterator timeout_backoff runs out.

    Returns:
        bool: True if the message was acknowledged, False otherwise.
    """

    async_result = protocol.maybe_sendraw_with_result(
        recipient,
        messagedata,
        message_id,
    )

    event_quit = event_first_of(
        async_result,
        event_stop,
    )

    for timeout in timeout_backoff:

        if event_quit.wait(timeout=timeout) is True:
            break

        protocol.maybe_sendraw_with_result(
            recipient,
            messagedata,
            message_id,
        )

    return async_result.ready()


def wait_recovery(event_stop, event_healthy):
    event_first_of(
        event_stop,
        event_healthy,
    ).wait()

    if event_stop.is_set():
        return

    # There may be multiple threads waiting, do not restart them all at
    # once to avoid message flood.
    gevent.sleep(random.random())


def retry_with_recovery(
        protocol,
        messagedata,
        message_id,
        recipient,
        event_stop,
        event_healthy,
        event_unhealthy,
        backoff,
):
    """ Send messagedata while the node is healthy until it's acknowledged.

    Note:
        backoff must be an infinite iterator, otherwise this task will
        become a hot loop.
    """

    # The underlying unhealthy will be cleared, care must be taken to properly
    # clear stop_or_unhealthy too.
    stop_or_unhealthy = event_first_of(
        event_stop,
        event_unhealthy,
    )

    acknowledged = False
    while not event_stop.is_set() and not acknowledged:

        # Packets must not be sent to an unhealthy node, nor should the task
        # wait for it to become available if the message has been acknowledged.
        if event_unhealthy.is_set():
            wait_recovery(
                event_stop,
                event_healthy,
            )

            # Assume wait_recovery returned because unhealthy was cleared and
            # continue execution, this is safe to do because event_stop is
            # checked below.
            stop_or_unhealthy.clear()

            if event_stop.is_set():
                return acknowledged

        acknowledged = retry(
            protocol,
            messagedata,
            message_id,
            recipient,

            # retry will stop when this event is set, allowing this task to
            # wait for recovery when the node becomes unhealthy or to quit if
            # the stop event is set.
            stop_or_unhealthy,

            # Intentionally reusing backoff to restart from the last
            # timeout/number of iterations.
            backoff,
        )

    return acknowledged
