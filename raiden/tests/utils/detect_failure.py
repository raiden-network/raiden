import traceback
from functools import wraps

import gevent
import structlog
from gevent.event import AsyncResult

log = structlog.get_logger(__name__)


def raise_on_failure(test_function):
    """Wait on the result for the test function and any of the apps.

    This decorator should be used for happy path testing with more than one app.
    This will raise if any of the apps is killed.
    """

    @wraps(test_function)
    def wrapper(**kwargs):
        result = AsyncResult()
        apps = kwargs.get("raiden_network", kwargs.get("raiden_chain"))
        if not apps:
            raise Exception(
                f"Can't use `raise_on_failure` on test function {test_function.__name__} "
                "which uses neither `raiden_network` nor `raiden_chain` fixtures."
            )

        # Do not use `link` or `link_value`, an app an be stopped to test restarts.
        for app in apps:
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
            log.exception(
                "Test failed",
                test_traceback="".join(traceback.format_stack(test_greenlet.gr_frame)),
                all_tracebacks="\n".join(gevent.util.format_run_info()),
            )

            raise

    return wrapper
