import traceback

import gevent
from gevent.event import AsyncResult


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
        # Always print the stack trace of the test greenlet. The stack trace of
        # the greenlet that was killed is always printed, because the test
        # itself may be killed with anassert its stack trace may be printed
        # twice, however this is necessary for tests which a app was killed,
        # otherwise the state of the test is unknown.
        print("".join(traceback.format_stack(test_greenlet.gr_frame)))

        raise
