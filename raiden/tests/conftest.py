# pylint: disable=wrong-import-position,redefined-outer-name,unused-wildcard-import,wildcard-import
from gevent import monkey  # isort:skip # noqa

monkey.patch_all(subprocess=False, thread=False)  # isort:skip # noqa

import signal  # isort:skip # noqa
import pytest  # isort:skip

# Execute these before the other imports because rewrites can't work after the
# module has been imported.
pytest.register_assert_rewrite("raiden.tests.utils.eth_node")  # isort:skip
pytest.register_assert_rewrite("raiden.tests.utils.factories")  # isort:skip
pytest.register_assert_rewrite("raiden.tests.utils.messages")  # isort:skip
pytest.register_assert_rewrite("raiden.tests.utils.network")  # isort:skip
pytest.register_assert_rewrite("raiden.tests.utils.protocol")  # isort:skip
pytest.register_assert_rewrite("raiden.tests.utils.smartcontracts")  # isort:skip
pytest.register_assert_rewrite("raiden.tests.utils.smoketest")  # isort:skip
pytest.register_assert_rewrite("raiden.tests.utils.transfer")  # isort:skip

import datetime
import os
import re
import sys
import tempfile
from pathlib import Path

import gevent
from _pytest.pathlib import LOCK_TIMEOUT, ensure_reset_dir, make_numbered_dir_with_cleanup
from _pytest.tmpdir import get_user

from raiden.constants import EthClient
from raiden.log_config import configure_logging
from raiden.tests.fixtures.blockchain import *  # noqa: F401,F403
from raiden.tests.fixtures.variables import *  # noqa: F401,F403
from raiden.tests.utils.transport import make_requests_insecure
from raiden.utils.cli import LogLevelConfigType
from raiden.utils.debugging import enable_gevent_monitoring_signal


def pytest_addoption(parser):
    parser.addoption(
        "--blockchain-type", choices=[client.value for client in EthClient], default="geth"
    )

    parser.addoption(
        "--log-config", action="store", default=None, help="Configure tests log output"
    )

    parser.addoption(
        "--plain-log",
        action="store_true",
        default=False,
        help="Do not colorize console log output",
    )

    parser.addoption(
        "--base-port",
        action="store",
        default=8500,
        type="int",
        help="Base port number to use for tests.",
    )
    parser.addoption("--timeout", type=float)
    parser.addini(
        "timeout", "Timeout in seconds before failing the test and printing the gevent stacks."
    )


@pytest.fixture(scope="session", autouse=True)
def auto_enable_gevent_monitoring_signal():
    enable_gevent_monitoring_signal()


@pytest.fixture(scope="session", autouse=True)
def enable_greenlet_debugger(request):
    """ Enable the pdb debugger for gevent's greenlets.

    This extends the flag `--pdb` from pytest to enable debugging of greenlets
    which have raised an exception to the top-level. Without this hook the
    exception raised in a greenlet is printed, and the thread state is
    discarded. Making it impossible to execute a post_mortem
    """
    if request.config.option.usepdb:
        import pdb
        import bdb

        # Do not run pdb again if an exception hits top-level for a second
        # greenlet and the previous pdb session is still running
        enabled = False
        hub = gevent.get_hub()

        def debugger(context, type_, value, tb):
            # Always print the exception, because once the pdb REPL is started
            # we cannot retrieve it with `sys.exc_info()`.
            #
            # Using gevent's hub print_exception because it properly handles
            # corner cases.
            hub.print_exception(context, type_, value, tb)

            # Don't enter nested sessions
            # Ignore exceptions used to quit the debugger / interpreter
            nonlocal enabled
            if not enabled and type_ not in (bdb.BdbQuit, KeyboardInterrupt):
                enabled = True
                pdb.post_mortem()  # pylint: disable=no-member
                enabled = False

        # Hooking the debugger on the hub error handler. Exceptions that are
        # not handled on a given greenlet are forwarded to the
        # parent.handle_error, until the hub is reached.
        #
        # Note: for this to work properly, it's really important to use
        # gevent's spawn function.
        hub.handle_error = debugger


@pytest.fixture(autouse=True)
def logging_level(request, logs_storage):
    """ Configure the structlog level for each test run.

    For integration tests this also sets the geth verbosity.
    """
    # disable pytest's built in log capture, otherwise logs are printed twice
    request.config.option.showcapture = "no"

    if request.config.option.log_cli_level:
        level = request.config.option.log_cli_level
    elif request.config.option.verbose > 3:
        level = "DEBUG"
    elif request.config.option.verbose > 1:
        level = "INFO"
    else:
        level = "WARNING"

    if request.config.option.log_config:
        config_converter = LogLevelConfigType()
        logging_levels = config_converter.convert(
            value=request.config.option.log_config, param=None, ctx=None
        )
    else:
        logging_levels = {"": level}

    # configure_logging requires the path to exist
    os.makedirs(logs_storage, exist_ok=True)

    time = datetime.datetime.utcnow().isoformat()
    debug_path = os.path.join(logs_storage, f"raiden-debug_{time}.log")

    configure_logging(
        logging_levels,
        colorize=not request.config.option.plain_log,
        log_file=request.config.option.log_file,
        cache_logger_on_first_use=False,
        debug_log_file_name=debug_path,
    )


@pytest.fixture(scope="session", autouse=True)
def dont_exit_pytest():
    """ Raiden will quit on any unhandled exception.

    This allows the test suite to finish in case an exception is unhandled.
    """
    gevent.get_hub().NOT_ERROR = (gevent.GreenletExit, SystemExit)


@pytest.fixture(scope="session", autouse=True)
def insecure_tls():
    make_requests_insecure()


@pytest.hookimpl(hookwrapper=True, trylast=True)
def pytest_runtest_call(item):
    """ More feedback for flaky tests.

    In verbose mode this outputs 'FLAKY' every time a test marked as flaky fails.
    This doesn't work under xdist and will therefore show no output.
    """
    yield
    is_xdist = "PYTEST_XDIST_WORKER" in os.environ
    is_flaky_test = item.get_closest_marker("flaky") is not None
    if is_flaky_test and not is_xdist:
        if item.config.option.verbose > 0:
            capmanager = item.config.pluginmanager.getplugin("capturemanager")
            with capmanager.global_and_fixture_disabled():
                item.config.pluginmanager.get_plugin("terminalreporter")._tw.write(
                    "FLAKY ", yellow=True
                )


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_setup(item):
    timeout = item.config.getvalue("timeout")
    marker = item.get_closest_marker("timeout")

    if marker is not None:
        # This marker supports only one argument, it may be positional or
        # keyword
        if len(marker.args) == 1:
            timeout = marker.args[0]
        else:
            timeout = marker.kwargs["timeout"]

    if isinstance(timeout, (int, float)) and timeout > 0:

        def handler(signum, frame):  # pylint: disable=unused-argument
            gevent.util.print_run_info()
            pytest.fail(f"Timeout >{timeout}s")

        def cancel():
            signal.setitimer(signal.ITIMER_REAL, 0)
            signal.signal(signal.SIGALRM, signal.SIG_DFL)

        item.cancel_timeout = cancel
        signal.signal(signal.SIGALRM, handler)
        signal.setitimer(signal.ITIMER_REAL, timeout)

    yield


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_teardown(item):
    yield

    cancel = getattr(item, "cancel_timeout", None)
    if cancel:
        cancel()


def pytest_generate_tests(metafunc):
    fixtures = metafunc.fixturenames

    if "transport" in fixtures:
        parmeterize_private_rooms = True
        transport_and_privacy = list()
        number_of_transports = list()

        # Filter existing parametrization which is already done in the test
        for mark in metafunc.definition.own_markers:
            if mark.name == "parametrize":
                # Check if 'private_rooms' gets parameterized
                if "private_rooms" in mark.args[0]:
                    parmeterize_private_rooms = False
                # Check if more than one transport is used
                if "number_of_transports" == mark.args[0]:
                    number_of_transports = mark.args[1]

        if "public_and_private_rooms" in fixtures:
            if number_of_transports:
                transport_and_privacy.extend(
                    [
                        ("matrix", [False for _ in range(number_of_transports[0])]),
                        ("matrix", [True for _ in range(number_of_transports[0])]),
                    ]
                )
            else:
                transport_and_privacy.extend([("matrix", False), ("matrix", True)])
        else:
            if number_of_transports:
                transport_and_privacy.extend(
                    [("matrix", [False for _ in range(number_of_transports[0])])]
                )
            else:
                transport_and_privacy.append(("matrix", False))

        if not parmeterize_private_rooms or "private_rooms" not in fixtures:
            # If the test does not expect the private_rooms parameter or parametrizes
            # `private_rooms` itself, only give he transport values
            metafunc.parametrize(
                "transport",
                list(set(transport_type for transport_type, _ in transport_and_privacy)),
            )

        else:
            metafunc.parametrize("transport,private_rooms", transport_and_privacy)


if sys.platform == "darwin":
    # On macOS the temp directory base path is already very long.
    # To avoid failures on ipc tests (ipc path length is limited to 104/108 chars on macOS/linux)
    # we override the pytest tmpdir machinery to produce shorter paths.

    @pytest.fixture(scope="session", autouse=True)
    def _tmpdir_short():
        """Shorten tmpdir paths"""
        from _pytest.tmpdir import TempPathFactory

        def getbasetemp(self):
            """ return base temporary directory. """
            if self._basetemp is None:
                if self._given_basetemp is not None:
                    basetemp = Path(self._given_basetemp)
                    ensure_reset_dir(basetemp)
                else:
                    from_env = os.environ.get("PYTEST_DEBUG_TEMPROOT")
                    temproot = Path(from_env or tempfile.gettempdir())
                    user = get_user() or "unknown"
                    # use a sub-directory in the temproot to speed-up
                    # make_numbered_dir() call
                    rootdir = temproot.joinpath(f"pyt-{user}")
                    rootdir.mkdir(exist_ok=True)
                    basetemp = make_numbered_dir_with_cleanup(
                        prefix="", root=rootdir, keep=3, lock_timeout=LOCK_TIMEOUT
                    )
                assert basetemp is not None
                self._basetemp = t = basetemp
                self._trace("new basetemp", t)
                return t
            else:
                return self._basetemp

        TempPathFactory.getbasetemp = getbasetemp

    @pytest.fixture
    def tmpdir(request, tmpdir_factory):
        """Return a temporary directory path object
        which is unique to each test function invocation,
        created as a sub directory of the base temporary
        directory.  The returned object is a `py.path.local`_
        path object.
        """
        name = request.node.name
        name = re.sub(r"[\W]", "_", name)
        MAXVAL = 15
        if len(name) > MAXVAL:
            name = name[:MAXVAL]
        tdir = tmpdir_factory.mktemp(name, numbered=True)
        return tdir
