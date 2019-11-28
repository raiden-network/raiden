from typing import Iterable, List, TypeVar

from gevent.event import Event, _AbstractLinkable
from gevent.queue import Queue

T = TypeVar("T")


def event_first_of(*events: _AbstractLinkable) -> Event:
    """ Waits until one of `events` is set.

    The event returned is /not/ cleared with any of the `events`, this value
    must not be reused if the clearing behavior is used.
    """
    first_finished = Event()

    if not all(isinstance(e, _AbstractLinkable) for e in events):
        raise ValueError("all events must be linkable")

    for event in events:
        event.rawlink(lambda _: first_finished.set())

    return first_finished


class NotifyingQueue(Event):
    """This is not the same as a JoinableQueue. Here, instead of waiting for
    all the work to be processed, the wait is for work to be available.
    """

    def __init__(self, maxsize: int = None, items: Iterable[T] = ()) -> None:
        super().__init__()
        self._queue = Queue(maxsize, items)

        if items:
            self.set()

    def put(self, item: T) -> None:
        """ Add new item to the queue. """
        self._queue.put(item)
        self.set()

    def get(self, block: bool = True, timeout: float = None) -> T:
        """ Removes and returns an item from the queue. """
        value = self._queue.get(block, timeout)
        if self._queue.empty():
            self.clear()
        return value

    def peek(self, block: bool = True, timeout: float = None) -> T:
        return self._queue.peek(block, timeout)

    def __len__(self) -> int:
        return len(self._queue)

    def copy(self) -> List[T]:
        """ Copies the current queue items. """
        copy = self._queue.copy()

        result = list()
        while not copy.empty():
            result.append(copy.get_nowait())
        return result
