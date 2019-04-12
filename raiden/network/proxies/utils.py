from typing import TYPE_CHECKING

from eth_utils import to_normalized_address
from web3.exceptions import BadFunctionCallOutput

from raiden.exceptions import AddressWrongContract, ContractVersionMismatch
from raiden.network.rpc.smartcontract_proxy import ContractProxy
from raiden.utils import CanonicalIdentifier
from raiden.utils.typing import Address, BlockSpecification, Locksroot, Tuple

if TYPE_CHECKING:
    # pylint: disable=unused-import
    from raiden.network.blockchain_service import BlockChainService


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
        chain: 'BlockChainService',
        canonical_identifier: CanonicalIdentifier,
        participant1: Address,
        participant2: Address,
        block_identifier: BlockSpecification,
) -> Tuple[Locksroot, Locksroot]:
    """Return the locksroot for `participant1` and `participant2` at `block_identifier`."""
    payment_channel = chain.payment_channel(canonical_identifier=canonical_identifier)
    token_network = payment_channel.token_network

    # This will not raise RaidenRecoverableError because we are providing the channel_identifier
    participants_details = token_network.detail_participants(
        participant1=participant1,
        participant2=participant2,
        channel_identifier=canonical_identifier.channel_identifier,
        block_identifier=block_identifier,
    )

    our_details = participants_details.our_details
    our_locksroot = our_details.locksroot

    partner_details = participants_details.partner_details
    partner_locksroot = partner_details.locksroot

    return our_locksroot, partner_locksroot
