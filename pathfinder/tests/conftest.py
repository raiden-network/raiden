from gevent import monkey
monkey.patch_all()

from raiden_contracts.tests.fixtures import *  # noqa
from raiden_libs.test.fixtures.address import *  # noqa
from raiden_libs.test.fixtures.web3 import *  # noqa
from raiden_libs.test.fixtures.client import *  # noqa
from pathfinder.tests.fixtures import *  # flake8: noqa


def pytest_addoption(parser):
    parser.addoption(
        "--faucet-private-key",
        default='aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
        dest='faucet_private_key',
        help="The private key to an address with sufficient tokens to run tests on a real network."
    )
