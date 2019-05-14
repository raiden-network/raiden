from typing import Iterable, List, TypeVar

from gevent.event import Event
from gevent.queue import Queue

T = TypeVar("T")


class NotifyingQueue(Event):
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
