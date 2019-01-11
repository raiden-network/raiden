from gevent import monkey  # isort:skip # noqa
monkey.patch_all()  # isort:skip # noqa

import gc

import gevent
import pytest

from raiden_contracts.tests.fixtures import *  # noqa
from raiden_libs.test.fixtures.address import *  # noqa
from raiden_libs.test.fixtures.client import *  # noqa
from raiden_libs.test.fixtures.web3 import *  # noqa

from pathfinding_service.tests.fixtures import *  # isort:skip # noqa


def pytest_addoption(parser):
    parser.addoption(
        "--faucet-private-key",
        default='aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
        dest='faucet_private_key',
        help="The private key to an address with sufficient tokens to run the tests.",
    )


def _get_running_greenlets():
    return [
            obj
            for obj in gc.get_objects()
            if isinstance(obj, gevent.Greenlet) and obj and not obj.dead
    ]


@pytest.fixture(autouse=True)
def no_greenlets_left():
    """ Check that no greenlets run at the end of a test

    It's easy to forget to properly stop all greenlets or to introduce a subtle
    bug in the shutdown process. Left over greenlets will cause other tests to
    fail, which is hard to track down. To avoid this, this function will look
    for such greenlets after each test and make the test fail if any greenlet
    is still running.
    """
    yield
    tasks = _get_running_greenlets()
    # give all tasks the chance to clean themselves up
    gevent.joinall(tasks, timeout=1)
    tasks = _get_running_greenlets()
    for task in tasks:
        print(task, bool(task), task.dead)
    # kill greenlets, so that the following tests will have a clean state
    gevent.killall(tasks)
    if tasks:
        print('The following greenlets are still running after the test:', tasks)
    assert not tasks, 'All greenlets must be stopped at the end of a test.'
