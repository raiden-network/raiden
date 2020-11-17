import asyncio
from asyncio import Future

import gevent
from gevent import Greenlet

from raiden.network.transport.matrix.rtc import aiogevent
from raiden.network.transport.matrix.rtc.aiogevent import yield_future
from raiden.utils.typing import Any, Callable, Coroutine, Optional


def setup_asyncio_event_loop() -> None:
    asyncio.set_event_loop_policy(aiogevent.EventLoopPolicy())
    gevent.spawn(asyncio.get_event_loop().run_forever)


def spawn_coroutine(
    coroutine: Coroutine,
    callback: Optional[Callable[[Any, Any], None]],
    **kwargs: Any,
) -> Greenlet:
    """Spawns a greenlet which runs a coroutine inside waiting for the result"""

    return gevent.spawn(wait_for_future, asyncio.ensure_future(coroutine), callback, **kwargs)


def wait_for_future(future: Future, callback: Callable, **kwargs: Any) -> None:
    """yield future and call callback with the result"""
    result = yield_future(future)
    if callback is not None:
        callback(result, **kwargs)
