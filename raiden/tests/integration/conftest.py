import pytest

from raiden.tests.integration.fixtures.blockchain import *  # noqa: F401,F403
from raiden.tests.integration.fixtures.raiden_network import *  # noqa: F401,F403
from raiden.tests.integration.fixtures.smartcontracts import *  # noqa: F401,F403
from raiden.tests.integration.fixtures.transport import *  # noqa: F401,F403


def pytest_collection_modifyitems(items):
    """Use ``flaky`` to rerun tests failing with ``RetryTestError``"""
    # We don't want this in every test's namespace, so import locally
    from raiden.tests.integration.exception import RetryTestError

    for item in items:
        item.add_marker(
            pytest.mark.flaky(
                rerun_filter=lambda err, *args: issubclass(err[0], RetryTestError), max_runs=3
            )
        )
        item.add_marker(pytest.mark.asyncio)


def pytest_configure(config):
    config.addinivalue_line("markers", "expect_failure")


def pytest_collection_finish(session):
    def unsafe(item):
        has_nodes = "raiden_network" in item.fixturenames or "raiden_chain" in item.fixturenames
        is_secure = getattr(item.function, "_decorated_raise_on_failure", False)
        is_exempt = item.get_closest_marker("expect_failure") is not None
        return has_nodes and not (is_secure or is_exempt)

    unsafe_tests = [item.originalname or item.name for item in session.items if unsafe(item)]

    if unsafe_tests:
        unsafe_tests_list = "\n- ".join(unsafe_tests)
        pytest.exit(
            f"\nERROR: Found {len(unsafe_tests)} tests with no clear node failure policy."
            f"\nPlease decorate each of them with either @raise_on_failure or @expect_failure."
            f"\n- {unsafe_tests_list}"
        )
