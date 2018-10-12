from os import urandom

# increase block gas limit
import eth_tester.backends.pyevm.main as pyevm_main
from coincurve import PrivateKey
from eth_tester import EthereumTester, PyEVMBackend
from eth_utils import encode_hex
from web3 import EthereumTesterProvider, Web3

from raiden.constants import TRANSACTION_GAS_LIMIT
from raiden.transfer.balance_proof import pack_balance_proof
from raiden.transfer.utils import hash_balance_data
from raiden_contracts.contract_manager import CONTRACTS_SOURCE_DIRS, ContractManager
from raiden_contracts.utils.utils import get_pending_transfers_tree
from raiden_libs.utils.signing import eth_sign

pyevm_main.GENESIS_GAS_LIMIT = 6 * 10 ** 6


class ContractTester:
    def __init__(self, generate_keys=0):
        self.tester = EthereumTester(PyEVMBackend())
        self.web3 = Web3(EthereumTesterProvider(self.tester))
        if generate_keys > 0:
            generated_keys = [urandom(32) for _ in range(generate_keys)]
            self.private_keys = [PrivateKey(key) for key in generated_keys]
            self.accounts = [
                self.tester.add_account(f'{encode_hex(key)}')
                for key in generated_keys
            ]
            for account in self.accounts:
                self.tester.send_transaction({
                    'from': self.tester.get_accounts()[0],
                    'to': account,
                    'value': 10 ** 21,
                    'gas': 21000,
                })
        else:
            self.accounts = self.tester.get_accounts()
        self.contract_manager = ContractManager(CONTRACTS_SOURCE_DIRS)
        self.name_to_creation_hash = dict()
        self.name_to_contract = dict()

    def deploy_contract(self, name, **kwargs):
        data = self.contract_manager.get_contract(name)
        contract = self.web3.eth.contract(abi=data['abi'], bytecode=data['bin'])
        transaction = contract.constructor(**kwargs).buildTransaction({
            'from': self.accounts[0],
            'gas': 5900000,
        })
        self.name_to_creation_hash[name] = self.web3.eth.sendTransaction(transaction)
        self.name_to_contract[name] = self.web3.eth.contract(
            address=self.contract_address(name),
            abi=data['abi'],
        )

    def contract_address(self, name):
        tx_hash = self.name_to_creation_hash[name]
        return self.web3.eth.getTransactionReceipt(tx_hash)['contractAddress']

    def call_transaction(self, contract, function, **kwargs):
        sender = kwargs.pop('sender', self.accounts[0])
        tx_hash = self.name_to_contract[contract].functions[function](**kwargs).transact({
            'from': sender,
        })
        return self.web3.eth.getTransactionReceipt(tx_hash)


def find_max_pending_transfers(gas_limit):
    """Measure gas consumption of TokenNetwork.unlock() depending on number of
    pending transfers and find the maximum number of pending transfers so
    gas_limit is not exceeded."""

    tester = ContractTester(generate_keys=2)

    tester.deploy_contract('SecretRegistry')

    tester.deploy_contract(
        'HumanStandardToken',
        _initialAmount=100000,
        _decimalUnits=3,
        _tokenName='SomeToken',
        _tokenSymbol='SMT',
    )

    tester.deploy_contract(
        'TokenNetwork',
        _token_address=tester.contract_address('HumanStandardToken'),
        _secret_registry=tester.contract_address('SecretRegistry'),
        _chain_id=1,
        _settlement_timeout_min=100,
        _settlement_timeout_max=200,
    )

    tester.call_transaction(
        'HumanStandardToken',
        'transfer',
        _to=tester.accounts[1],
        _value=10000,
    )

    receipt = tester.call_transaction(
        'TokenNetwork',
        'openChannel',
        participant1=tester.accounts[0],
        participant2=tester.accounts[1],
        settle_timeout=150,
    )

    channel_identifier = int(encode_hex(receipt['logs'][0]['topics'][1]), 16)

    tester.call_transaction(
        'HumanStandardToken',
        'approve',
        sender=tester.accounts[0],
        _spender=tester.contract_address('TokenNetwork'),
        _value=10000,
    )

    tester.call_transaction(
        'HumanStandardToken',
        'approve',
        sender=tester.accounts[1],
        _spender=tester.contract_address('TokenNetwork'),
        _value=5000,
    )

    tester.call_transaction(
        'TokenNetwork',
        'setTotalDeposit',
        channel_identifier=channel_identifier,
        participant=tester.accounts[0],
        total_deposit=5000,
        partner=tester.accounts[1],
    )

    tester.call_transaction(
        'TokenNetwork',
        'setTotalDeposit',
        channel_identifier=channel_identifier,
        participant=tester.accounts[1],
        total_deposit=2000,
        partner=tester.accounts[0],
    )

    print("Measuring unlock()'s gas cost for different Merkle tree widths, can take a while...")

    before_closing = tester.tester.take_snapshot()
    enough = 0
    too_much = 1024

    nonce = 10
    additional_hash = urandom(32)
    token_network_identifier = tester.contract_address('TokenNetwork')

    while enough + 1 < too_much:
        tree_size = (enough + too_much) // 2
        tester.tester.revert_to_snapshot(before_closing)

        pending_transfers_tree = get_pending_transfers_tree(
            tester.web3,
            unlockable_amounts=[1] * tree_size,
        )

        balance_hash = hash_balance_data(3000, 2000, pending_transfers_tree.merkle_root)
        data_to_sign = pack_balance_proof(
            nonce=nonce,
            balance_hash=balance_hash,
            additional_hash=additional_hash,
            channel_identifier=channel_identifier,
            token_network_identifier=token_network_identifier,
            chain_id=1,
        )
        signature = eth_sign(privkey=tester.private_keys[1], data=data_to_sign)

        tester.call_transaction(
            'TokenNetwork',
            'closeChannel',
            channel_identifier=channel_identifier,
            partner=tester.accounts[1],
            balance_hash=balance_hash,
            nonce=nonce,
            additional_hash=additional_hash,
            signature=signature,
        )

        tester.tester.mine_blocks(160)  # close settlement window

        tester.call_transaction(
            'TokenNetwork',
            'settleChannel',
            channel_identifier=channel_identifier,
            participant1=tester.accounts[0],
            participant1_transferred_amount=0,
            participant1_locked_amount=0,
            participant1_locksroot=b'\x00' * 32,
            participant2=tester.accounts[1],
            participant2_transferred_amount=3000,
            participant2_locked_amount=2000,
            participant2_locksroot=pending_transfers_tree.merkle_root,
        )

        receipt = tester.call_transaction(
            'TokenNetwork',
            'unlock',
            channel_identifier=channel_identifier,
            participant=tester.accounts[0],
            partner=tester.accounts[1],
            merkle_tree_leaves=pending_transfers_tree.packed_transfers,
        )
        gas_used = receipt['gasUsed']

        if gas_used <= gas_limit:
            enough = tree_size
            print(f'{tree_size} pending transfers work ({gas_used} gas needed to unlock)')
        else:
            too_much = tree_size
            print(f'{tree_size} pending transfers are too much ({gas_used} gas needed to unlock)')


if __name__ == '__main__':
    find_max_pending_transfers(TRANSACTION_GAS_LIMIT)
