import gevent
from gevent.event import AsyncResult


def raise_on_failure(raiden_apps, test_function, **kwargs):
    """Wait on the result for the test function and any of the apps.

    This utility should be used for happy path testing with more than one app.
    This will raise if any of the apps is killed.
    """
    result = AsyncResult()

    for app in raiden_apps:
        assert app.raiden
        app.raiden.link(result)

    gevent.spawn(test_function, **kwargs).link(result)
    result.get()
