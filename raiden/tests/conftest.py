# pylint: disable=wrong-import-position,redefined-outer-name,unused-wildcard-import,wildcard-import
from gevent import monkey  # isort:skip # noqa
monkey.patch_all()  # isort:skip # noqa

import datetime
import os
import re
import sys
import tempfile
from pathlib import Path

import gevent
import pytest
from _pytest.pathlib import LOCK_TIMEOUT, ensure_reset_dir, make_numbered_dir_with_cleanup
from _pytest.tmpdir import get_user

from raiden.log_config import configure_logging
from raiden.settings import SUPPORTED_ETH_CLIENTS
from raiden.tests.fixtures.variables import *  # noqa: F401,F403
from raiden.tests.utils.transport import make_requests_insecure
from raiden.utils.cli import LogLevelConfigType


def pytest_addoption(parser):
    parser.addoption(
        '--blockchain-type',
        choices=SUPPORTED_ETH_CLIENTS,
        default='geth',
    )

    parser.addoption(
        '--log-config',
        action='store',
        default=None,
        help='Configure tests log output',
    )

    parser.addoption(
        '--plain-log',
        action='store_true',
        default=False,
        help='Do not colorize console log output',
    )

    parser.addoption(
        '--transport',
        choices=('none', 'udp', 'matrix', 'all'),
        default='matrix',
        help='Run integration tests with udp, with matrix, with both or not at all.',
    )

    parser.addoption(
        '--gevent-monitoring-signal',
        action='store_true',
        dest='gevent_monitoring_signal',
        default=False,
        help='Install a SIGUSR1 signal handler to print gevent run_info.',
    )


@pytest.fixture(scope='session', autouse=True)
def enable_gevent_monitoring_signal(request):
    """ Install a signal handler for SIGUSR1 that executes gevent.util.print_run_info().
    This can help evaluating the gevent greenlet tree.
    See http://www.gevent.org/monitoring.html for more information.

    Usage:
        pytest [...] --gevent-monitoring-signal
        # while test is running (or stopped in a pdb session):
        kill -SIGUSR1 $(pidof -x pytest)
    """
    if request.config.option.gevent_monitoring_signal:
        import gevent.util
        import signal
        signal.signal(signal.SIGUSR1, gevent.util.print_run_info)


@pytest.fixture(scope='session', autouse=True)
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


@pytest.fixture(autouse=True, scope='session')
def logging_level(request):
    """ Configure the structlog level.

    For integration tests this also sets the geth verbosity.
    """
    # disable pytest's built in log capture, otherwise logs are printed twice
    request.config.option.showcapture = 'no'

    if request.config.option.log_cli_level:
        level = request.config.option.log_cli_level
    elif request.config.option.verbose > 3:
        level = 'DEBUG'
    elif request.config.option.verbose > 1:
        level = 'INFO'
    else:
        level = 'WARNING'

    if request.config.option.log_config:
        config_converter = LogLevelConfigType()
        logging_levels = config_converter.convert(
            value=request.config.option.log_config,
            param=None,
            ctx=None,
        )
    else:
        logging_levels = {'': level}

    time = datetime.datetime.utcnow().isoformat()
    debug_path = os.path.join(
        tempfile.gettempdir(),
        f'raiden-debug_{time}.log',
    )
    configure_logging(
        logging_levels,
        colorize=not request.config.option.plain_log,
        log_file=request.config.option.log_file,
        cache_logger_on_first_use=False,
        debug_log_file_name=debug_path,
    )


@pytest.fixture(scope='session', autouse=True)
def dont_exit_pytest():
    """ Raiden will quit on any unhandled exception.

    This allows the test suite to finish in case an exception is unhandled.
    """
    gevent.get_hub().NOT_ERROR = (gevent.GreenletExit, SystemExit)


@pytest.fixture(scope='session', autouse=True)
def insecure_tls():
    make_requests_insecure()


# Convert `--transport all` to two separate invocations with `matrix` and `udp`
def pytest_generate_tests(metafunc):
    if 'transport' in metafunc.fixturenames:
        transport = metafunc.config.getoption('transport')
        transport_and_privacy = list()

        # avoid collecting test if 'skip_if_not_*'
        if transport in ('udp', 'all') and 'skip_if_not_matrix' not in metafunc.fixturenames:
            transport_and_privacy.append(('udp', None))

        if transport in ('matrix', 'all') and 'skip_if_not_udp' not in metafunc.fixturenames:
            if 'public_and_private_rooms' in metafunc.fixturenames:
                transport_and_privacy.extend([('matrix', False), ('matrix', True)])
            else:
                transport_and_privacy.append(('matrix', False))

        if 'private_rooms' in metafunc.fixturenames:
            metafunc.parametrize('transport,private_rooms', transport_and_privacy)
        else:
            # If the test function isn't taking the `private_rooms` fixture only give the
            # transport values
            metafunc.parametrize(
                'transport',
                list(set(transport_type for transport_type, _ in transport_and_privacy)),
            )


if sys.platform == 'darwin':
    # On macOS the temp directory base path is already very long.
    # To avoid failures on ipc tests (ipc path length is limited to 104/108 chars on macOS/linux)
    # we override the pytest tmpdir machinery to produce shorter paths.

    @pytest.fixture(scope='session', autouse=True)
    def _tmpdir_short(request):
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
                    rootdir = temproot.joinpath("pyt-{}".format(user))
                    rootdir.mkdir(exist_ok=True)
                    basetemp = make_numbered_dir_with_cleanup(
                        prefix="",
                        root=rootdir,
                        keep=3,
                        lock_timeout=LOCK_TIMEOUT,
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
        name = re.sub(r'[\W]', '_', name)
        MAXVAL = 15
        if len(name) > MAXVAL:
            name = name[:MAXVAL]
        tdir = tmpdir_factory.mktemp(name, numbered=True)
        return tdir
