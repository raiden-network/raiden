import gc

import gevent
import pytest
import structlog

log = structlog.get_logger(__name__)


@pytest.fixture(autouse=True)
def cleanup_tasks() -> None:
    yield

    log.debug("cleanup_tasks started")

    tasks = [
        running_task
        for running_task in gc.get_objects()
        if isinstance(running_task, gevent.Greenlet) and not running_task.dead
    ]

    if tasks:
        log.debug("Pending greenlets", tracebacks="\n".join(gevent.util.format_run_info()))

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
