import asyncio

import gevent
import pytest

from raiden.network.transport.matrix.rtc import aiogevent

asyncio.set_event_loop_policy(aiogevent.EventLoopPolicy())


@pytest.fixture(autouse=True)
def asyncio_loop():

    asyncio_greenlet = gevent.spawn(asyncio.get_event_loop().run_forever)

    yield

    gevent.kill(asyncio_greenlet)
