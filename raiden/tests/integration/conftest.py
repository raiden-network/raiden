import pytest

from raiden.tests.integration.fixtures.blockchain import *  # noqa: F401,F403
from raiden.tests.integration.fixtures.raiden_network import *  # noqa: F401,F403
from raiden.tests.integration.fixtures.smartcontracts import *  # noqa: F401,F403
from raiden.tests.integration.fixtures.transport import *  # noqa: F401,F403


def pytest_configure(config):
    config.addinivalue_line("markers", "expect_failure")


def pytest_collection_finish(session):
    def unsafe(item):
        has_runnable = (
            "raiden_network" in item.fixturenames
            or "raiden_chain" in item.fixturenames
            or "api_server_test_instance" in item.fixturenames
            or "matrix_transports" in item.fixturenames
        )
        is_secure = getattr(item.function, "_decorated_raise_on_failure", False)
        is_exempt = item.get_closest_marker("expect_failure") is not None
        return has_runnable and not (is_secure or is_exempt)

    unsafe_tests = [item.originalname or item.name for item in session.items if unsafe(item)]

    if unsafe_tests:
        unsafe_tests_list = "\n- ".join(unsafe_tests)
        pytest.exit(
            f"\nERROR: Found {len(unsafe_tests)} tests with no clear node failure policy."
            f"\nPlease decorate each of them with either @raise_on_failure or @expect_failure."
            f"\n- {unsafe_tests_list}"
        )
