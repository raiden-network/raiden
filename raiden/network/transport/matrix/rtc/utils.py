import asyncio
from asyncio import AbstractEventLoop

import gevent
import structlog
from gevent.timeout import Timeout

from raiden.exceptions import RaidenUnrecoverableError
from raiden.network.transport.matrix.rtc import aiogevent
from raiden.utils.typing import Type

ASYNCIO_LOOP_RUNNING_TIMEOUT = 10

log = structlog.get_logger(__name__)


def setup_asyncio_event_loop(
    exception: Type[Exception] = RaidenUnrecoverableError,
) -> AbstractEventLoop:
    asyncio.set_event_loop_policy(aiogevent.EventLoopPolicy())
    new_event_loop = asyncio.new_event_loop()
    gevent.spawn(new_event_loop.run_forever)
    gevent.sleep(0.05)
    if not new_event_loop.is_running():
        log.debug("Asyncio loop not running yet. Waiting.")
        with Timeout(ASYNCIO_LOOP_RUNNING_TIMEOUT, exception):
            while not new_event_loop.is_running():
                gevent.sleep(0.05)

    return new_event_loop
