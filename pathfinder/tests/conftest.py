from gevent import monkey  # isort:skip # noqa
monkey.patch_all()  # isort:skip # noqa

from raiden_contracts.tests.fixtures import *  # noqa
from raiden_libs.test.fixtures.address import *  # noqa
from raiden_libs.test.fixtures.client import *  # noqa
from raiden_libs.test.fixtures.web3 import *  # noqa
from pathfinder.tests.fixtures import *  # isort:skip # noqa


def pytest_addoption(parser):
    parser.addoption(
        "--faucet-private-key",
        default='aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
        dest='faucet_private_key',
        help="The private key to an address with sufficient tokens to run the tests.",
    )
