from typing import Any

import gevent
from gevent.event import AsyncResult

from raiden.utils.runnable import Runnable


class RunnableTest(Runnable):
    def __init__(self):
        super().__init__()

    def start(self):
        self._stop_event = AsyncResult()
        super().start()

    def _run(self, *args: Any, **kwargs: Any) -> None:
        while self._stop_event and self._stop_event.wait(0.5) is not True:
            gevent.sleep(0.1)
        return

    def stop(self):
        if self._stop_event:
            self._stop_event.set(True)


def test_runnable_and_gevent_join_all():
    """Test that runnable adheres to the greenlet interface for gevent.joinall()

    Regression test for https://github.com/raiden-network/raiden/issues/5327
    """
    a = RunnableTest()
    a.start()
    a.stop()
    gevent.joinall({a}, raise_error=True)
