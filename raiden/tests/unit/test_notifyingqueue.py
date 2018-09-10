import gevent
from gevent.event import Event

from raiden.network.transport.udp.udp_utils import event_first_of
from raiden.utils.notifying_queue import NotifyingQueue


def add_element_to_queue(queue, element):
    queue.put(element)


def test_copy():
    queue = NotifyingQueue()
    assert queue.copy() == []

    queue.put(1)
    assert queue.copy() == [1]
    assert queue.peek() == 1, 'copy must preserve the queue'

    queue.put(2)
    assert queue.copy() == [1, 2], 'copy must preserve the items order'


def test_event_must_be_set():
    queue = NotifyingQueue()
    event_stop = Event()

    data_or_stop = event_first_of(
        queue,
        event_stop,
    )

    spawn_after_seconds = 1
    element = 1
    gevent.spawn_later(spawn_after_seconds, add_element_to_queue, queue, element)
    assert data_or_stop.wait()


def test_not_empty():
    queue = NotifyingQueue(items=[1, 2])
    assert queue.is_set()
