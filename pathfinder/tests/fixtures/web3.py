import pytest
from eth_tester import EthereumTester, PyEthereum16Backend
from web3 import HTTPProvider, Web3
from web3.providers.eth_tester import EthereumTesterProvider

from pathfinder.config import WEB3_PROVIDER_DEFAULT
from pathfinder.tests.config import FAUCET_ALLOWANCE


@pytest.fixture(scope='session')
def use_tester(request):
    return request.config.getoption('use_tester')


@pytest.fixture(scope='session')
def web3(use_tester: bool, faucet_private_key: str, faucet_address: str):
    if use_tester:
        tester = EthereumTester(PyEthereum16Backend())

        provider = EthereumTesterProvider(tester)
        web3 = Web3(provider)

        # add faucet account to tester
        res = tester.add_account(faucet_private_key)
        assert res == faucet_address

        # make faucet rich
        web3.eth.sendTransaction({'to': faucet_address, 'value': FAUCET_ALLOWANCE})

    else:
        rpc = HTTPProvider(WEB3_PROVIDER_DEFAULT)
        web3 = Web3(rpc)

    yield web3
