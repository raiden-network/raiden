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

import contextlib
import datetime
import os
import re
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import gevent
from _pytest.pathlib import LOCK_TIMEOUT, ensure_reset_dir, make_numbered_dir_with_cleanup
from _pytest.tmpdir import get_user

from raiden.constants import (
    HIGHEST_SUPPORTED_GETH_VERSION,
    HIGHEST_SUPPORTED_PARITY_VERSION,
    LOWEST_SUPPORTED_GETH_VERSION,
    LOWEST_SUPPORTED_PARITY_VERSION,
    EthClient,
)
from raiden.log_config import configure_logging
from raiden.tests.fixtures.blockchain import *  # noqa: F401,F403
from raiden.tests.fixtures.variables import *  # noqa: F401,F403
from raiden.tests.utils.transport import make_requests_insecure
from raiden.utils.cli import LogLevelConfigType
from raiden.utils.debugging import enable_gevent_monitoring_signal
from raiden.utils.ethereum_clients import is_supported_client


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

    # The goal here is to ensure the test runner will print something to the
    # stdout, this should be done frequently enough for the runner to /not/ get
    # killed by the CI. The settings bellow are defined in such a way to
    # guarantee that the test fails before the CI kill the runner.
    #
    # When something is printed depends on the verbosity used. If the tests are
    # executed with verbosity zero (the default), the only phase that prints to
    # the stdout is pytest_runtest_call.
    #
    # Consider the following:
    #
    # 1. test1.setup
    # 2. test1.call
    # 3. test1.teardown
    # 4. test2.setup
    # 5. test2.call
    # 6. test2.teardown
    #
    # From the start of step 3 until the end of step 5 there will be no output,
    # which is a full test cycle. Because of this, the settings bellow are
    # define in terms of their addition being smaller than the CI settings.
    #
    # Higher verbosities change the analysis above, however this is set for the
    # worst case.

    timeout_limit_setup_and_call_help = (
        "This setting defines the timeout in seconds for the setup *and* call "
        "phases of a test. Every test will be allowed to use at most "
        "`timeout_limit_setup_and_call` seconds to complete these phases. This "
        "setting together with the timeout_limit_teardown defines the total "
        "runtime for a single test. The total timeout must be lower than the no "
        "output timeout of the continuous integration."
    )
    parser.addini("timeout_limit_for_setup_and_call", timeout_limit_setup_and_call_help)

    timeout_limit_teardown_help = (
        "This setting defines the timeout in seconds for the teardown phase. It "
        "must be a non-zero value to allow for proper cleanup of fixtures. This "
        "setting together with the timeout_limit_setup_and_call defines the "
        "total runtime for a single test. The total timeout must be lower than "
        "the no output timeout of the continuous integration."
    )
    parser.addini("timeout_limit_teardown", timeout_limit_teardown_help)


@pytest.fixture(autouse=True, scope="session")
def check_geth_version_for_tests(blockchain_type):
    if blockchain_type != "geth":
        return

    geth_version_string, _ = subprocess.Popen(
        ["geth", "version"], stdout=subprocess.PIPE, stderr=subprocess.PIPE
    ).communicate()
    supported, _, our_version = is_supported_client(geth_version_string.decode())
    if not supported:
        sys.exit(
            f"You are trying to run tests with an unsupported GETH version. "
            f"Your Version: {our_version} "
            f"Min Supported Version {LOWEST_SUPPORTED_GETH_VERSION} "
            f"Max Supported Version {HIGHEST_SUPPORTED_GETH_VERSION}"
        )


@pytest.fixture(autouse=True, scope="session")
def check_parity_version_for_tests(blockchain_type):
    if blockchain_type != "parity":
        return

    parity_version_string, _ = subprocess.Popen(
        ["parity", "--version"], stdout=subprocess.PIPE, stderr=subprocess.PIPE
    ).communicate()
    supported, _, our_version = is_supported_client(parity_version_string.decode())
    if not supported:
        sys.exit(
            f"You are trying to run tests with an unsupported PARITY version. "
            f"Your Version: {our_version} "
            f"Min Supported Version {LOWEST_SUPPORTED_PARITY_VERSION} "
            f"Max Supported Version {HIGHEST_SUPPORTED_PARITY_VERSION}"
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


@contextlib.contextmanager
def timeout_for_setup_and_call(item):
    """Sets a timeout up to `item.remaining_timeout`, if the timeout is reached
    an exception is raised, otherwise the amount of time used by the run is
    deducted from the `item.remaining_timeout`.

    This function is only used for setup and call, which share the same
    timeout. The teardown must have a separate timeout, because even if either
    the setup or the call timedout the teardown must still be called to do
    fixture clean up.
    """

    def report():
        gevent.util.print_run_info()
        pytest.fail(f"Setup and Call timeout >{item.timeout_setup_and_call}s")

    def handler(signum, frame):  # pylint: disable=unused-argument
        report()

    # The handler must be installed before the timer is set, otherwise it is
    # possible for the default handler to be used, which would not raise our
    # exception. This can happen if the setup phase uses most of the available
    # time, leaving just enough for the call to install the new timer and get
    # the event.
    signal.signal(signal.SIGALRM, handler)

    # Negative values are invalid and will raise an exception.
    #
    # This is not a problem because:
    # - pytest_runtest_setup is the first called, it follows the call to
    # pytest_runtest_protocol, which validates and sets the timeout values.
    # - pytest_runtest_call is the second call, and it will only run if the
    # setup was succesfull, i.e. a timeout did not happen. This implies that
    # the remaining_timeout is positive.
    remaining_timeout = item.remaining_timeout

    started_at = time.time()
    signal.setitimer(signal.ITIMER_REAL, remaining_timeout)

    yield

    # The timer must be disabled *before* the handler is unset, otherwise it is
    # possible for a timeout event to be handled by the default handler.
    signal.setitimer(signal.ITIMER_REAL, 0)
    signal.signal(signal.SIGALRM, signal.SIG_DFL)

    elapsed = time.time() - started_at

    # It is possible for elapsed to be negative, this can happen if the
    # time.time clock and the clock used by the signal are different. To
    # guarantee the next iteration will only have positive values, raise an
    # exception, failling the setup and skiping the call.
    item.remaining_timeout -= elapsed
    if item.remaining_timeout < 0:
        report()


def timeout_from_marker(marker):
    """Return None or the value of the timeout."""
    timeout = None

    if marker is not None:
        if len(marker.args) == 1 and len(marker.kwargs) == 0:
            timeout = marker.args[0]
        elif len(marker.args) == 0 and len(marker.kwargs) == 1 and "timeout" in marker.kwargs:
            timeout = marker.kwargs["timeout"]
        else:
            raise Exception(
                "Invalid marker. It must have only one argument for the "
                "timeout, which may be named or not."
            )

    return timeout


def set_item_timeouts(item):
    """Limit the tests runtime

    The timeout is read from the following places (last one takes precedence):
    * setup.cfg (ini).
    * pytest timeout marker at the specific test.
    """
    timeout_limit_setup_and_call = item.config.getini("timeout_limit_for_setup_and_call")

    if timeout_limit_setup_and_call == "":
        raise Exception("timeout_limit_for_setup_and_call must be set in setup.cfg")

    timeout_limit_setup_and_call = float(timeout_limit_setup_and_call)

    timeout_limit_teardown = item.config.getini("timeout_limit_teardown")

    if timeout_limit_teardown == "":
        raise Exception("timeout_limit_teardown must be set in setup.cfg")

    timeout_limit_teardown = float(timeout_limit_teardown)

    timeout_teardown = timeout_limit_teardown

    # There is no marker to configure the teardown timeout
    marker = item.get_closest_marker("timeout")
    timeout_setup_and_call = timeout_from_marker(marker) or timeout_limit_setup_and_call

    if timeout_setup_and_call > timeout_limit_setup_and_call:
        raise Exception(
            f"Invalid value for the timeout marker {timeout_setup_and_call}. This "
            f"value must be smaller than {timeout_limit_setup_and_call}. This is "
            f"necessary because the runtime of a test has to be synchronized with "
            f"the continuous integration output timeout, e.g. no_output_timeout "
            f"in CircleCI. If the timeout is larger than that value the whole "
            f"build will be killed because of the lack of output, this will not "
            f"produce a failure report nor log files, which makes the build run "
            f"useless."
        )

    if timeout_setup_and_call <= 0:
        raise Exception("timeout must not be negative")

    if timeout_teardown <= 0:
        raise Exception("timeout_limit_teardown must not be negative")

    item.timeout_setup_and_call = timeout_setup_and_call
    item.remaining_timeout = timeout_setup_and_call
    item.timeout_teardown = timeout_teardown


@pytest.hookimpl()
def pytest_runtest_protocol(item, nextitem):  # pylint:disable=unused-argument
    # The timeouts cannot be configured in the pytest_runtest_setup, because if
    # the required value is not set, an exception is raised, but then it is
    # swallowed by the `CallInfo.from_call`
    set_item_timeouts(item)


# Pytest's test protocol is defined by `pytest.runner:pytest_runtest_protocol`,
# it has three steps where exceptions can safely be raised at:
#
# - setup
# - call
# - teardown
#
# Below one hook for each of the steps is used. This is necessary to guarantee
# that a Timeout exception will be raised only inside these steps that handle
# exceptions, otherwise the test executor could be killed by the timeout
# exception.


@pytest.hookimpl(hookwrapper=True, trylast=True)
def pytest_runtest_setup(item):

    with timeout_for_setup_and_call(item):
        yield


@pytest.hookimpl(hookwrapper=True, trylast=True)
def pytest_runtest_call(item):
    """ More feedback for flaky tests.

    In verbose mode this outputs 'FLAKY' every time a test marked as flaky fails.

    This doesn't happen when:

    - Tests are executed under xdist.
    - The fixture setup fails.
    """

    # pytest_runtest_call is only called if the test setup finished
    # succesfully, this means the code below may not be executed if the fixture
    # setup has timedout already.
    with timeout_for_setup_and_call(item):
        outcome = yield

        did_fail = isinstance(outcome._excinfo, tuple) and isinstance(
            outcome._excinfo[1], BaseException
        )
        is_xdist = "PYTEST_XDIST_WORKER" in os.environ
        is_flaky_test = item.get_closest_marker("flaky") is not None

        should_print = (
            did_fail and item.config.option.verbose > 0 and is_flaky_test and not is_xdist
        )

        if should_print:
            capmanager = item.config.pluginmanager.getplugin("capturemanager")
            with capmanager.global_and_fixture_disabled():
                item.config.pluginmanager.get_plugin("terminalreporter")._tw.write(
                    "FLAKY ", yellow=True
                )


@pytest.hookimpl(hookwrapper=True, trylast=True)
def pytest_runtest_teardown(item):
    # The teardown must be executed to clear up the fixtures, even if the
    # fixture setup itself failed. Because of this the timeout for the teardown
    # is different than the timeout for the setup and call.

    def report():
        gevent.util.print_run_info()
        pytest.fail(
            f"Teardown timeout >{item.timeout_setup_and_call}s. This must not happen, when "
            f"the teardown times out not all finalizers got a chance to run. This "
            f"means not all fixtures are cleaned up, which can make subsequent "
            f"tests flaky. This would be the case for pending greenlets which are "
            f"not cleared by previous run."
        )

    def handler(signum, frame):  # pylint: disable=unused-argument
        report()

    # The order of the signal setup/teardown is important, check
    # timeout_for_setup_and_call for details
    signal.signal(signal.SIGALRM, handler)
    signal.setitimer(signal.ITIMER_REAL, item.timeout_teardown)

    yield

    signal.setitimer(signal.ITIMER_REAL, 0)
    signal.signal(signal.SIGALRM, signal.SIG_DFL)


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
