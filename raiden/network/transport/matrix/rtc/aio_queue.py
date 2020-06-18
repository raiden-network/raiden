import gevent
from gevent.lock import Semaphore
from gevent.queue import Queue

from raiden.network.transport.matrix.rtc import aiogevent


def make_wrapped_greenlet(target, *args, **kwargs):
    glet = gevent.Greenlet(target, *args, **kwargs)
    wrapped_glet = aiogevent.wrap_greenlet(glet)
    glet.start()
    return wrapped_glet


class AGTransceiver:
    def __init__(self):
        self.peer_connections = dict()
        self.event_to_aio_queue = AGQueue()
        self.event_to_gevent_queue = AGQueue()
        self.message_to_aio_queue = AGQueue()
        self.message_to_gevent_queue = AGQueue()

    def send_event_to_aio(self, event):
        self.event_to_aio_queue.put(event)

    async def aget_event(self):
        event = await self.event_to_aio_queue.aget()
        return event

    async def send_event_to_gevent(self, event):
        await self.event_to_gevent_queue.aput(event)

    def send_message_to_aio(self, message):
        self.message_to_aio_queue.put(message)

    async def send_message_to_gevent(self, message):
        await self.message_to_gevent_queue.aput(message)


class AGQueue(Queue):
    async def aget(self):
        return await make_wrapped_greenlet(self.get)

    async def aput(self, item):
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
