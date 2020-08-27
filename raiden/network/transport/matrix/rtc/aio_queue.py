from asyncio import Future
from typing import Any, Callable, Dict

import gevent
from gevent.lock import Semaphore
from gevent.queue import Empty, Queue

from raiden.network.transport.matrix.rtc import aiogevent
from raiden.network.transport.matrix.rtc.web_rtc import RTCPartner
from raiden.utils.typing import Address


def make_wrapped_greenlet(target: Callable, *args: Any, **kwargs: Any) -> Future:
    glet = gevent.Greenlet(target, *args, **kwargs)
    wrapped_glet = aiogevent.wrap_greenlet(glet)
    glet.start()
    return wrapped_glet


class AGTransceiver:
    def __init__(self) -> None:
        self.peer_connections: Dict[Address, RTCPartner] = dict()
        self.event_to_aio_queue = AGQueue()
        self.event_to_gevent_queue = AGQueue()

    def send_event_to_aio(self, event: Dict[str, Any]) -> None:
        self.event_to_aio_queue.put(event)

    async def aget_event(self, timeout):
        try:
            event = await self.event_to_aio_queue.aget(timeout)
        except Empty:
            return {"type": "timeout"}
        return event

    async def send_event_to_gevent(self, event) -> None:
        await self.event_to_gevent_queue.aput(event)


class AGQueue(Queue):
    async def aget(self, timeout):
        return await make_wrapped_greenlet(self.get, timeout=timeout)

    async def aput(self, item: Any) -> None:
        await make_wrapped_greenlet(self.put, item)


class AGLock:
    def __init__(self):
        self.lock = Semaphore()

    async def __aenter__(self):
        await make_wrapped_greenlet(self.lock.acquire)

    async def __aexit__(self, _1, _2, _3):
        await make_wrapped_greenlet(self.lock.release)

    def __enter__(self):
        self.lock.acquire()

    def __exit__(self, _1, _2, _3):
        self.lock.release()
