import ethereum
import pytest
from eth_utils import decode_hex
from web3 import EthereumTesterProvider, Web3, HTTPProvider

from pathfinder.config import WEB3_PROVIDER_DEFAULT
from pathfinder.tests.config import FAUCET_ALLOWANCE


@pytest.fixture(scope='session')
def use_tester(request):
    return request.config.getoption('use_tester')


@pytest.fixture(scope='session')
def web3(use_tester: bool, faucet_private_key: str, faucet_address: str):
    if use_tester:
        provider = EthereumTesterProvider()
        web3 = Web3(provider)

        # add faucet account to tester
        ethereum.tester.accounts.append(decode_hex(faucet_address))
        ethereum.tester.keys.append(decode_hex(faucet_private_key))

        # make faucet rich
        web3.eth.sendTransaction({'to': faucet_address, 'value': FAUCET_ALLOWANCE})

    else:
        rpc = HTTPProvider(WEB3_PROVIDER_DEFAULT)
        web3 = Web3(rpc)

    yield web3

    if use_tester:
        ethereum.tester.accounts.remove(decode_hex(faucet_address))
        ethereum.tester.keys.remove(decode_hex(faucet_private_key))
