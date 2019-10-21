import gevent
from gevent import Greenlet

from raiden.raiden_service import RaidenService
from raiden.utils.typing import Any, BlockNumber, Callable, Optional
from raiden.waiting import wait_for_block


def _timeout_task(  # pragma: no unittest
    throw: Callable,
    exception_to_throw: Exception,
    raiden: RaidenService,
    block_number: BlockNumber,
    retry_timeout: float,
) -> None:
    wait_for_block(raiden, block_number, retry_timeout)
    throw(exception_to_throw)


class BlockTimeout:  # pragma: no unittest
    def __init__(
        self,
        exception_to_throw: Exception,
        raiden: RaidenService,
        block_number: BlockNumber,
        retry_timeout: float,
    ) -> None:
        self.exception_to_throw = exception_to_throw
        self.raiden = raiden
        self.block_number = block_number
        self.retry_timeout = retry_timeout
        self._task: Optional[Greenlet] = None

    def __enter__(self) -> None:
        self._task = gevent.spawn(
            _timeout_task,
            gevent.getcurrent().throw,
            self.exception_to_throw,
            self.raiden,
            self.block_number,
            self.retry_timeout,
        )

    def __exit__(self, exc_type: Any, exc_value: Any, traceback: Any) -> None:
        if self._task:
            self._task.kill()
