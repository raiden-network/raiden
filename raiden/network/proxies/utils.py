from eth_utils import to_normalized_address
from web3.exceptions import BadFunctionCallOutput

from raiden.exceptions import AddressWrongContract, ContractVersionMismatch
from raiden.network.rpc.smartcontract_proxy import ContractProxy
from raiden.utils import CHAIN_ID_UNSPECIFIED, CanonicalIdentifier
from raiden.utils.typing import (
    Address,
    BlockSpecification,
    ChannelID,
    Locksroot,
    TokenNetworkAddress,
    Tuple,
)


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
        token_network_address: TokenNetworkAddress,
        channel_identifier: ChannelID,
        participant1: Address,
        participant2: Address,
        block_identifier: BlockSpecification,
) -> Tuple[Locksroot, Locksroot]:
    payment_channel = raiden.chain.payment_channel(
        canonical_identifier=CanonicalIdentifier(
            chain_identifier=CHAIN_ID_UNSPECIFIED,
            token_network_address=token_network_address,
            channel_identifier=channel_identifier,
        ),
    )
    token_network = payment_channel.token_network

    participants_details = token_network.detail_participants(
        participant1=participant1,
        participant2=participant2,
        channel_identifier=channel_identifier,
        block_identifier=block_identifier,
    )

    our_details = participants_details.our_details
    our_locksroot = our_details.locksroot

    partner_details = participants_details.partner_details
    partner_locksroot = partner_details.locksroot

    return our_locksroot, partner_locksroot
