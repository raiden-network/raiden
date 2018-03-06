from pathfinder.tests.fixtures import *  # flake8: noqa

from gevent import monkey
monkey.patch_all()


def pytest_addoption(parser):
    parser.addoption(
        "--no-tester",
        action="store_false",
        default=True,
        dest='use_tester',
        help="Use a real RPC endpoint instead of the tester chain."
    )
    parser.addoption(
        "--faucet-private-key",
        default='aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
        dest='faucet_private_key',
        help="The private key to an address with sufficient tokens to run tests on a real network."
    )
