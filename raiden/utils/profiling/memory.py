import guppy
from gevent import Greenlet
from gevent.event import Event
from structlog import get_logger

log = get_logger(__name__)


class MemoryLogger:
    def __init__(self, interval: float) -> None:
        self._interval = interval
        self._greenlet = Greenlet(self._run)
        self._greenlet.name = "MemoryLogger"
        self._stop = Event()

    def start(self) -> Greenlet:
        self._greenlet.start()
        return self._greenlet

    def stop(self):
        self._stop.set()

    def _run(self) -> None:
        while not self._stop.is_set():
            heap = guppy.hpy().heap()
            log.debug("Memory report", size=heap.domisize, objects=heap.count)
            self._stop.wait(self._interval)
