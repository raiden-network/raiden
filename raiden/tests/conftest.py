# -*- coding: utf-8 -*-
# pylint: disable=wrong-import-position,redefined-outer-name,unused-wildcard-import,wildcard-import
import gevent
from gevent import monkey
monkey.patch_all()

import pytest
from ethereum import slogging
from ethereum.keys import PBKDF2_CONSTANTS
from ethereum import processblock
from ethereum import tester

from raiden.network.rpc.client import GAS_LIMIT
from raiden.tests.fixtures import *  # noqa: F401,F403

gevent.get_hub().SYSTEM_ERROR = BaseException
PBKDF2_CONSTANTS['c'] = 100

CATCH_LOG_HANDLER_NAME = 'catch_log_handler'


def pytest_addoption(parser):
    parser.addoption(
        '--blockchain-type',
        choices=['geth', 'tester'],
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
        from pyethapp.utils import enable_greenlet_debugger
        enable_greenlet_debugger()


@pytest.fixture(scope='session', autouse=True)
def monkey_patch_tester():
    original_apply_transaction = processblock.apply_transaction

    def apply_transaction(block, transaction):
        start_gas = block.gas_used
        result = original_apply_transaction(block, transaction)
        end_gas = block.gas_used

        assert end_gas - start_gas <= GAS_LIMIT

        return result

    tester.processblock.apply_transaction = apply_transaction


# Connect catchlog's handler to slogging's root logger
@pytest.hookimpl(hookwrapper=True, trylast=True)
def pytest_runtest_call(item):
    catchlog_handler = getattr(item, CATCH_LOG_HANDLER_NAME, None)
    if catchlog_handler and catchlog_handler not in slogging.rootLogger.handlers:
        slogging.rootLogger.addHandler(catchlog_handler)

    yield

    if catchlog_handler and catchlog_handler in slogging.rootLogger.handlers:
        slogging.rootLogger.removeHandler(catchlog_handler)
