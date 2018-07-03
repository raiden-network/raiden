# pylint: disable=wrong-import-position,redefined-outer-name,unused-wildcard-import,wildcard-import
import re

import gevent
import py
import sys
from gevent import monkey
monkey.patch_all()

import pytest

from raiden.utils.cli import LogLevelConfigType
from raiden.exceptions import RaidenShuttingDown
from raiden.tests.fixtures.variables import *  # noqa: F401,F403
from raiden.log_config import configure_logging


def pytest_addoption(parser):
    parser.addoption(
        '--blockchain-type',
        choices=['geth', 'tester'],
        default='tester',
    )

    parser.addoption(
        '--initial-port',
        type=int,
        default=29870,
        help='Base port number used to avoid conflicts while running parallel tests.',
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
        default='udp',
        help='Run integration tests with udp, with matrix, with both or not at all.',
    )

    parser.addoption(
        '--local-matrix',
        dest='local_matrix',
        default='.synapse/run_synapse.sh',
        help="Command to run the local matrix server, or 'none', "
             "default: '.synapse/run_synapse.sh'",
    )

    parser.addoption(
        '--matrix-server',
        action='store',
        dest='matrix_server',
        default='http://localhost:8008',
        help="Host name of local matrix server if used, default: 'http://localhost:8008'",
    )


@pytest.fixture(autouse=True, scope='session')
def logging_level(request):
    """ Configure the structlog level.

    For integration tests this also sets the geth verbosity.
    """
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

    configure_logging(
        logging_levels,
        colorize=not request.config.option.plain_log,
        log_file=request.config.option.log_file,
    )


@pytest.fixture(scope='session', autouse=True)
def validate_solidity_compiler():
    """ Check the solc prior to running any test. """
    from raiden.blockchain.abi import validate_solc
    validate_solc()


@pytest.fixture(scope='session', autouse=True)
def dont_exit_pytest():
    """ Raiden will quit on any unhandled exception.

    This allows the test suite to finish in case an exception is unhandled.
    """
    gevent.get_hub().SYSTEM_ERROR = BaseException
    gevent.get_hub().NOT_ERROR = (gevent.GreenletExit, SystemExit, RaidenShuttingDown)


if sys.platform == 'darwin':
    # On macOS the temp directory base path is already very long.
    # To avoid failures on ipc tests (ipc path length is limited to 104/108 chars on macOS/linux)
    # we override the pytest tmpdir machinery to produce shorter paths.

    @pytest.fixture(scope='session', autouse=True)
    def _tmpdir_short(request):
        """Shorten tmpdir paths"""
        from _pytest.tmpdir import TempdirFactory

        def getbasetemp(self):
            """ return base temporary directory. """
            try:
                return self._basetemp
            except AttributeError:
                basetemp = self.config.option.basetemp
                if basetemp:
                    basetemp = py.path.local(basetemp)
                    if basetemp.check():
                        basetemp.remove()
                    basetemp.mkdir()
                else:
                    rootdir = py.path.local.get_temproot()
                    rootdir.ensure(dir=1)
                    basetemp = py.path.local.make_numbered_dir(prefix='pyt', rootdir=rootdir)
                self._basetemp = t = basetemp.realpath()
                self.trace('new basetemp', t)
                return t

        TempdirFactory.getbasetemp = getbasetemp
        try:
            delattr(request.config._tmpdirhandler, '_basetemp')
        except AttributeError:
            pass

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
        return tmpdir_factory.mktemp(name, numbered=True)
