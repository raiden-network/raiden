import traceback

import gevent
import structlog
from gevent.event import AsyncResult

log = structlog.get_logger(__name__)


def raise_on_failure(raiden_apps, test_function, **kwargs):
    """Wait on the result for the test function and any of the apps.

    This utility should be used for happy path testing with more than one app.
    This will raise if any of the apps is killed.
    """
    result = AsyncResult()

    # Do not use `link` or `link_value`, an app an be stopped to test restarts.
    for app in raiden_apps:
        assert app.raiden, "The RaidenService must be started"
        app.raiden.link_exception(result)

    test_greenlet = gevent.spawn(test_function, **kwargs)
    test_greenlet.link(result)

    # Returns if either happens:
    # - The test finished (successfully or not)
    # - One of the apps crashed during the test
    try:
        result.get()
    except:  # noqa
        # Print the stack trace of the running test to know in which line the
        # test is waiting.
        #
        # This may print a duplicated stack trace, when the test fails.
        log.exception("Test failed")
        log.debug(
            "Test stacktrace",
            test_traceback="".join(traceback.format_stack(test_greenlet.gr_frame)),
        )
        log.exception("Pending greenlets", tracebacks="\n".join(gevent.util.format_run_info()))

        raise
