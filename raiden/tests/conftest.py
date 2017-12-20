# -*- coding: utf-8 -*-
# pylint: disable=wrong-import-position,redefined-outer-name,unused-wildcard-import,wildcard-import
import re

import gevent
import py
import sys
from gevent import monkey
monkey.patch_all()

import pytest
from ethereum import slogging
from ethereum.tools.keys import PBKDF2_CONSTANTS

from raiden.tests.fixtures import *  # noqa: F401,F403

gevent.get_hub().SYSTEM_ERROR = BaseException
PBKDF2_CONSTANTS['c'] = 100

CATCH_LOG_HANDLER_NAME = 'catch_log_handler'


def pytest_addoption(parser):
    parser.addoption(
        '--blockchain-type',
        choices=['geth'],
        default='geth',
    )

    parser.addoption(
        '--blockchain-cache',
        action='store_true',
        default=False,
    )

    parser.addoption(
        '--initial-port',
        type=int,
        default=29870,
        help='Base port number used to avoid conflicts while running parallel tests.',
    )

    parser.addoption(
        '--log-config',
        default=None,
    )

    parser.addoption(
        '--profiler',
        default=None,
        choices=['cpu', 'sample'],
    )


@pytest.fixture(autouse=True)
def profiler(request, tmpdir):
    if request.config.option.profiler == 'cpu':
        from raiden.utils.profiling.cpu import CpuProfiler
        profiler = CpuProfiler(str(tmpdir))
        profiler.start()

        yield

        profiler.stop()

    elif request.config.option.profiler == 'sample':
        from raiden.utils.profiling.sampler import SampleProfiler
        profiler = SampleProfiler(str(tmpdir))
        profiler.start()

        yield

        profiler.stop()

    else:
        # do nothing, but yield a valid generator otherwise the autouse fixture
        # will fail
        yield


@pytest.fixture(autouse=True)
def logging_level(request):
    """ Configure the logging level.

    For integration tests this also sets the geth verbosity.
    """
    if request.config.option.log_format is not None:
        slogging.PRINT_FORMAT = request.config.option.log_format
    if request.config.option.log_config is not None:
        slogging.configure(request.config.option.log_config)

    elif request.config.option.verbose > 5:
        slogging.configure(':TRACE')

    elif request.config.option.verbose > 3:
        slogging.configure(':DEBUG')

    elif request.config.option.verbose > 1:
        slogging.configure(':INFO')

    else:
        slogging.configure(':WARNING')


@pytest.fixture(scope='session', autouse=True)
def enable_greenlet_debugger(request):
    if request.config.option.usepdb:
        from raiden.utils.debug import enable_greenlet_debugger
        enable_greenlet_debugger()


@pytest.fixture(scope='session', autouse=True)
def validate_solidity_compiler():
    """ Check the solc prior to running any test. """
    from raiden.blockchain.abi import validate_solc
    validate_solc()


# Connect catchlog's handler to slogging's root logger
@pytest.hookimpl(hookwrapper=True, trylast=True)
def pytest_runtest_call(item):
    catchlog_handler = getattr(item, CATCH_LOG_HANDLER_NAME, None)
    if catchlog_handler and catchlog_handler not in slogging.rootLogger.handlers:
        slogging.rootLogger.addHandler(catchlog_handler)

    yield

    if catchlog_handler and catchlog_handler in slogging.rootLogger.handlers:
        slogging.rootLogger.removeHandler(catchlog_handler)


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
