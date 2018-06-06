"""eth-tester specific fixtures"""
import pytest
import gevent
from eth_utils import encode_hex, to_checksum_address, decode_hex, denoms
from raiden.utils import privatekey_to_address

from raiden_libs.test.fixtures.web3 import *  # noqa
from raiden_libs.test.fixtures.address import *  # noqa


@pytest.fixture
def fund_accounts(web3, blockchain_type, faucet_address, private_keys, ethereum_tester):
    [
        ethereum_tester.add_account(encode_hex(key))
        for key in private_keys
        if to_checksum_address(privatekey_to_address(key)) not in ethereum_tester.get_accounts()
    ]
    [ethereum_tester.send_transaction({
        'from': faucet_address,
        'to': to_checksum_address(privatekey_to_address(key)),
        'gas': 21000,
        'value': 1 * denoms.ether,
    }) for key in private_keys]


@pytest.fixture
def spawn_autominer(web3):
    from gevent.event import Event

    class Miner(gevent.Greenlet):
        def __init__(self, web3, mine_sleep=1):
            super().__init__()
            self.web3 = web3
            self.mine_sleep = mine_sleep
            self.stop = Event()

        def _run(self):
            while self.stop.is_set() is False:
                #  tester miner sleeps for 1 sec by default, which is the same
                #  period as tester geth is using
                #  (see: raiden/tests/utils/blockchain.py:geth_bare_genesis())
                self.web3.testing.mine(1)
                gevent.sleep(self.mine_sleep)
    miner = Miner(web3)
    miner.start()
    yield miner
    miner.stop.set()
    miner.join()


@pytest.fixture
def deploy_key(faucet_private_key):
    return decode_hex(faucet_private_key)


@pytest.fixture
def init_blockchain(
    revert_chain,
    spawn_autominer,
    fund_accounts,
):
    pass
