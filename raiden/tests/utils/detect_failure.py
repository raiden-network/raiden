import traceback
from functools import wraps
from typing import Any, Callable, Set

import gevent
import pytest
import structlog
from gevent.event import AsyncResult

from raiden.raiden_service import RaidenService
from raiden.utils.runnable import Runnable
from raiden.utils.typing import List

log = structlog.get_logger(__name__)


def raise_on_failure(test_function: Callable) -> Callable:
    """Wait on the result for the test function and any of the apps.

    This decorator should be used for happy path testing with more than one app.
    This will raise if any of the apps is killed.
    """

    @wraps(test_function)
    def wrapper(**kwargs: Any) -> None:
        result = AsyncResult()

        raiden_services: List[RaidenService] = list()
        raiden_services.extend(app.raiden for app in kwargs.get("raiden_network", list()))
        raiden_services.extend(app.raiden for app in kwargs.get("raiden_chain", list()))

        api_server = kwargs.get("api_server_test_instance")
        if api_server:
            raiden_services.append(api_server.rest_api.raiden_api.raiden)

        for raiden in raiden_services:
            assert raiden, "The RaidenService must be started"

        runnables: Set[Runnable] = set()
        runnables.update(kwargs.get("matrix_transports", list()))
        runnables.update(raiden_services)

        restart_node = kwargs.get("restart_node", None)
        if restart_node is not None:
            restart_node.link_exception_to(result)

        for task in runnables:
            task.greenlet.link_exception(result)

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

    wrapper._decorated_raise_on_failure = True  # type: ignore
    return wrapper


expect_failure = pytest.mark.expect_failure
