from eth_utils import to_normalized_address
from web3.exceptions import BadFunctionCallOutput

from raiden.exceptions import AddressWrongContract, ContractVersionMismatch
from raiden.network.proxies import PaymentChannel, TokenNetwork
from raiden.network.rpc.smartcontract_proxy import ContractProxy
from raiden.transfer.state import NettingChannelState
from raiden.utils.typing import Address, BlockHash


def compare_contract_versions(
        proxy: ContractProxy,
        expected_version: str,
        contract_name: str,
        address: Address,
) -> None:
    """Compare version strings of a contract.

    If not matching raise ContractVersionMismatch. Also may raise AddressWrongContract
    if the contract contains no code."""
    assert isinstance(expected_version, str)
    try:
        deployed_version = proxy.contract.functions.contract_version().call()
    except BadFunctionCallOutput:
        raise AddressWrongContract('')

    deployed_version = deployed_version.replace('_', '0')
    expected_version = expected_version.replace('_', '0')

    deployed = [int(x) for x in deployed_version.split('.')]
    expected = [int(x) for x in expected_version.split('.')]

    if deployed != expected:
        raise ContractVersionMismatch(
            f'Provided {contract_name} contract ({to_normalized_address(address)}) '
            f'version mismatch. Expected: {expected_version} Got: {deployed_version}',
        )


def get_onchain_locksroots(
        raiden,
        channel_state: NettingChannelState,
        block_hash: BlockHash,
):
    payment_channel: PaymentChannel = raiden.chain.payment_channel(
        token_network_address=channel_state.token_network_identifier,
        channel_id=channel_state.identifier,
    )
    token_network: TokenNetwork = payment_channel.token_network
    participants_details = token_network.detail_participants(
        participant1=channel_state.our_state.address,
        participant2=channel_state.partner_state.address,
        block_identifier=block_hash,
        channel_identifier=channel_state.identifier,
    )

    our_details = participants_details.our_details
    our_locksroot = our_details.locksroot

    partner_details = participants_details.partner_details
    partner_locksroot = partner_details.locksroot

    return our_locksroot, partner_locksroot
