import contextlib
import shlex
import subprocess
import time

import pytest

from raiden.tests.integration.fixtures.blockchain import *  # noqa: F401,F403
from raiden.tests.integration.fixtures.raiden_network import *  # noqa: F401,F403
from raiden.tests.integration.fixtures.smartcontracts import *  # noqa: F401,F403
from raiden.tests.integration.fixtures.transport import *  # noqa: F401,F403

from . import _codespeed


def pytest_addoption(parser):
    parser.addoption(
        "--codespeed-url",
        action="store",
        default=None,
        help="the URL of a running Codespeed instance, " "e.g. http://127.0.0.1:8000",
    )
    parser.addoption(
        "--output-benchmark-results",
        action="store",
        default=None,
        help="the path to write benchmark results to",
    )


def pytest_collection_modifyitems(items):
    for item in items:
        item.add_marker(pytest.mark.asyncio)


_TIMES = {}


_COMMIT_ID = subprocess.check_output(shlex.split("git rev-parse HEAD")).decode().strip()


# "git branch --show-current" would be simpler, but CI git version is too old for that.
_BRANCH = subprocess.check_output(shlex.split("git rev-parse --abbrev-ref HEAD")).decode().strip()


@pytest.fixture
def bench(request):
    node_name = request.node.name

    @contextlib.contextmanager
    def wrapper(s=None):
        t1 = time.perf_counter()
        yield
        t2 = time.perf_counter()
        dt = t2 - t1
        bench_name = "%s[%s]" % (node_name, s) if s is not None else node_name
        print(f"{bench_name}: {dt}")
        _TIMES[bench_name] = dt

        url = request.config.getoption("--codespeed-url")
        if url is not None:
            _codespeed.post_result(url, _COMMIT_ID, _BRANCH, bench_name, dt)

        path = request.config.getoption("--output-benchmark-results")
        if path is not None:
            with open(path, "a") as f:
                f.write(f"{bench_name}, {dt}\n")

    return wrapper


def pytest_terminal_summary(
    terminalreporter, exitstatus, config
):  # pylint: disable=unused-argument
    terminalreporter.section("benchmark report")
    for bench_name, time_ in _TIMES.items():
        terminalreporter.write_line(f"{bench_name}: {time_}")
