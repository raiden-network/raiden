import gc
import traceback

import gevent
import pytest
import structlog
from gevent import Greenlet

from raiden.utils.typing import List

log = structlog.get_logger(__name__)


def print_tracebacks(tasks: List[Greenlet]) -> None:
    header = (
        "--------------------------------------------------\n"
        "--------------- Pending Greenlets ----------------\n"
        "--------------------------------------------------\n"
    )

    print(header)
    for task in tasks:
        formated_traceback = "".join(traceback.format_stack(task.gr_frame))
        print(f"\n{task.name}\n\nTraceback:\n{formated_traceback}")


@pytest.fixture(autouse=True)
def cleanup_tasks() -> None:
    log.debug("cleanup_tasks started")

    tasks = [
        running_task
        for running_task in gc.get_objects()
        if isinstance(running_task, gevent.Greenlet) and not running_task.dead
    ]

    if tasks:
        print_tracebacks(tasks)

        # Kill the pending greenlets hoping that the next tests will run
        # without interference
        gevent.killall(tasks, timeout=10)

        # Fail the insulting test because it has to be fixed
        msg = (
            "The test finished and left running greenlets behind. This improper "
            "cleanup will cause flakiness in the build. E.g.: Two tests in "
            "sequence could run a server on the same port, a hanging greenlet "
            "from the previous tests could send packet to the new server and "
            "mess things up. Kill all greenlets to make sure that no left-over "
            "state from a previous test interferes with a new one. Please make "
            "sure all greenlets are stopped before the test ends."
        )
        raise AssertionError(msg)
