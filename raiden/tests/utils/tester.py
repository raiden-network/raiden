import gevent
from gevent.event import Event
from eth_utils import encode_hex, to_checksum_address
from raiden.utils import privatekey_to_address

from raiden.tests.fixtures.variables import DEFAULT_BALANCE


def fund_accounts(web3, private_keys, ethereum_tester):
    faucet = ethereum_tester.get_accounts()[0]

    for key in private_keys:
        address = to_checksum_address(privatekey_to_address(key))

        if address not in ethereum_tester.get_accounts():
            ethereum_tester.add_account(encode_hex(key))

        ethereum_tester.send_transaction({
            'from': faucet,
            'to': address,
            'gas': 21000,
            'value': DEFAULT_BALANCE,
        })


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
            #  (see: raiden/tests/utils/geth.py:geth_generate_poa_genesis())
            self.web3.testing.mine(1)
            gevent.sleep(self.mine_sleep)
