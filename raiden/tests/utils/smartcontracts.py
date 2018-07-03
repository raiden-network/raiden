from binascii import unhexlify

from eth_utils import (
    remove_0x_prefix,
    to_canonical_address,
)
from raiden_contracts.constants import CONTRACT_HUMAN_STANDARD_TOKEN
from raiden_contracts.contract_manager import ContractManager, CONTRACTS_SOURCE_DIRS

from raiden.network.blockchain_service import BlockChainService
from raiden.network.rpc.client import JSONRPCClient
from raiden.utils import typing


def deploy_tokens_and_fund_accounts(
        token_amount: int,
        number_of_tokens: int,
        deploy_service: BlockChainService,
        participants: typing.List[typing.Address],
) -> typing.List[typing.TokenAddress]:
    """ Deploy `number_of_tokens` ERC20 token instances with `token_amount` minted and
    distributed among `blockchain_services`. Optionally the instances will be registered with
    the raiden registry.

    Args:
        token_amount (int): number of units that will be created per token
        number_of_tokens (int): number of token instances that will be created
        deploy_service (BlockChainService): the blockchain connection that will deploy
        participants (list(address)): participant addresses that will receive tokens
    """
    result = list()

    manager = ContractManager(CONTRACTS_SOURCE_DIRS)
    token_interface = manager.abi[CONTRACT_HUMAN_STANDARD_TOKEN]
    web3 = deploy_service.client.web3
    token = web3.eth.contract(
        abi=token_interface['abi'],
        bytecode=token_interface['bin'],
    )

    for _ in range(number_of_tokens):
        transaction = token.constructor(token_amount, 2, 'raiden', 'Rd').buildTransaction()
        transaction['nonce'] = deploy_service.client.nonce()
        signed_txn = web3.eth.account.signTransaction(
            transaction,
            deploy_service.client.privkey,
        )
        tx_hash = web3.eth.sendRawTransaction(signed_txn.rawTransaction)
        deploy_service.client.poll(tx_hash)
        receipt = deploy_service.client.get_transaction_receipt(tx_hash)
        token_address = unhexlify(remove_0x_prefix(receipt['contractAddress']))

        result.append(token_address)

        # only the creator of the token starts with a balance (deploy_service),
        # transfer from the creator to the other nodes
        for transfer_to in participants:
            deploy_service.token(token_address).transfer(
                transfer_to,
                token_amount // len(participants),
            )

    return result


def deploy_contract_web3(
        contract_name: str,
        deploy_client: JSONRPCClient,
        *args,
) -> typing.Address:
    manager = ContractManager(CONTRACTS_SOURCE_DIRS)
    contract_interface = manager.abi[contract_name]

    tx_hash = deploy_client.send_transaction(
        to=typing.Address(b''),
        data=contract_interface['bin'],
    )
    tx_hash = unhexlify(tx_hash)

    deploy_client.poll(tx_hash)
    receipt = deploy_client.get_transaction_receipt(tx_hash)

    contract_address = receipt['contractAddress']
    return to_canonical_address(contract_address)
