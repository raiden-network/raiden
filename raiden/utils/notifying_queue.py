from typing import Generic, Iterable, List, TypeVar

from gevent.event import Event
from gevent.queue import Queue

T = TypeVar("T")


class NotifyingQueue(Event, Generic[T]):
    """This is not the same as a JoinableQueue. Here, instead of waiting for
    all the work to be processed, the wait is for work to be available.
    """

    def __init__(self, maxsize: int = None, items: Iterable[T] = ()) -> None:
        super().__init__()
        self.queue = Queue(maxsize, items)

        if items:
            self.set()

    def put(self, item: T) -> None:
        """Add new item to the queue."""
        self.queue.put(item)
        self.set()

    def get(self, block: bool = True, timeout: float = None) -> T:
        """Removes and returns an item from the queue."""
        value = self.queue.get(block, timeout)
        if self.queue.empty():
            self.clear()
        return value

    def peek(self, block: bool = True, timeout: float = None) -> T:
        return self.queue.peek(block, timeout)

    def __len__(self) -> int:
        return len(self.queue)

    def copy(self) -> List[T]:
        """Copies the current queue items."""
        copy = self.queue.copy()

        result = []
        while not copy.empty():
            result.append(copy.get_nowait())
        return result

    def __repr__(self) -> str:
        return f"NotifyingQueue(id={id(self)}, num_items={len(self.queue)})"
