from eth_utils import to_canonical_address
from raiden_contracts.constants import CONTRACT_HUMAN_STANDARD_TOKEN
from raiden_contracts.contract_manager import CONTRACT_MANAGER

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
    for _ in range(number_of_tokens):
        token_address = deploy_contract_web3(
            CONTRACT_HUMAN_STANDARD_TOKEN,
            deploy_service.client,
            num_confirmations=None,
            constructor_arguments=(
                token_amount,
                2,
                'raiden',
                'Rd',
            ),
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
        deploy_client: JSONRPCClient,
        num_confirmations: int = None,
        constructor_arguments: typing.Tuple[typing.Any, ...] = (),
) -> typing.Address:
    compiled = {
        contract_name: CONTRACT_MANAGER.get_contract(contract_name),
    }
    contract_proxy = deploy_client.deploy_solidity_contract(
        contract_name,
        compiled,
        constructor_parameters=constructor_arguments,
        confirmations=num_confirmations,
    )
    return typing.Address(to_canonical_address(contract_proxy.contract.address))
