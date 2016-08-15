# -*- coding: utf8 -*-
import pytest
import gevent
import gevent.monkey
from ethereum import slogging
from ethereum.keys import PBKDF2_CONSTANTS

# we need to use fixture for the default values otherwise
# pytest.mark.parametrize won't work (pytest 2.9.2)

# pylint: disable=redefined-outer-name,too-many-arguments,unused-argument,too-many-locals

# otherwise running hydrachain will block the test
gevent.monkey.patch_socket()
gevent.get_hub().SYSTEM_ERROR = BaseException
PBKDF2_CONSTANTS['c'] = 100


def pytest_addoption(parser):
    parser.addoption(
        '--blockchain-type',
        choices=['hydrachain', 'geth', 'tester', 'mock'],
        default='geth',
    )

    # might not work with all the hydrachain's loggers
    parser.addoption(
        '--log-config',
        default=None,
    )


@pytest.fixture(autouse=True)
def logging_level(request):
    """ Set ups the test logging level.

    For integration tests this also sets the geth verbosity.
    """
    if request.config.option.log_config is not None:
        slogging.configure(request.config.option.log_config)
        return

    if request.config.option.verbose > 0:
        slogging.configure(':DEBUG')


@pytest.fixture(scope='session', autouse=True)
def enable_greenlet_debugger(request):
    if request.config.option.usepdb:
        from pyethapp.utils import enable_greenlet_debugger
        enable_greenlet_debugger()
