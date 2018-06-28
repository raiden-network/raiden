from binascii import unhexlify

from eth_utils import to_canonical_address
from raiden_contracts.contract_manager import CONTRACT_MANAGER

from raiden.network.blockchain_service import BlockChainService
from raiden.utils import get_contract_path
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
    for _ in range(number_of_tokens):
        token_address = deploy_service.deploy_contract(
            contract_name='HumanStandardToken',
            contract_path=get_contract_path('HumanStandardToken.sol'),
            constructor_parameters=(token_amount, 'raiden', 2, 'Rd'),
        )
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
        deploy_client: BlockChainService,
        *args,
) -> typing.Address:
    web3 = deploy_client.web3

    contract_interface = CONTRACT_MANAGER.abi[contract_name]

    # Submit the transaction that deploys the contract
    tx_hash = deploy_client.send_transaction(
        to=typing.Address(b''),
        data=contract_interface['bin'],
    )
    tx_hash = unhexlify(tx_hash)

    deploy_client.poll(tx_hash)
    receipt = web3.eth.getTransactionReceipt(tx_hash)

    contract_address = receipt['contractAddress']
    return to_canonical_address(contract_address)
