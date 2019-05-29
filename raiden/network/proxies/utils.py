from contextlib import contextmanager
from typing import TYPE_CHECKING

from eth_utils import to_normalized_address
from structlog import BoundLoggerBase
from web3.exceptions import BadFunctionCallOutput

from raiden.exceptions import AddressWrongContract, ContractVersionMismatch
from raiden.network.rpc.smartcontract_proxy import ContractProxy
from raiden.transfer.identifiers import CanonicalIdentifier
from raiden.utils.typing import Address, Any, BlockSpecification, Dict, Generator, Locksroot, Tuple

if TYPE_CHECKING:
    # pylint: disable=unused-import
    from raiden.network.blockchain_service import BlockChainService


def compare_contract_versions(
    proxy: ContractProxy, expected_version: str, contract_name: str, address: Address
) -> None:
    """Compare version strings of a contract.

    If not matching raise ContractVersionMismatch. Also may raise AddressWrongContract
    if the contract contains no code."""
    assert isinstance(expected_version, str)
    try:
        deployed_version = proxy.contract.functions.contract_version().call()
    except BadFunctionCallOutput:
        raise AddressWrongContract("")

    deployed_version = deployed_version.replace("_", "0")
    expected_version = expected_version.replace("_", "0")

    deployed = [int(x) for x in deployed_version.split(".")]
    expected = [int(x) for x in expected_version.split(".")]

    if deployed != expected:
        raise ContractVersionMismatch(
            f"Provided {contract_name} contract ({to_normalized_address(address)}) "
            f"version mismatch. Expected: {expected_version} Got: {deployed_version}"
        )


def get_onchain_locksroots(
    chain: "BlockChainService",
    canonical_identifier: CanonicalIdentifier,
    participant1: Address,
    participant2: Address,
    block_identifier: BlockSpecification,
) -> Tuple[Locksroot, Locksroot]:
    """Return the locksroot for `participant1` and `participant2` at
    `block_identifier`.

    This is resolving a corner case where the current node view of the channel
    state does not reflect what the blockchain contains. E.g. for a channel
    A->B:

    - A sends a LockedTransfer to B
    - B sends a Refund to A
    - B goes offline
    - A sends a LockExpired to B
      Here:
      (1) the lock is removed from A's state
      (2) B never received the message
    - A closes the channel with B's refund
    - Here a few things may happen:
      (1) B never cames back online, and updateTransfer is never called.
      (2) B is using monitoring services, which use the known LockExpired
          balance proof.
      (3) B cames back online and aclls updateTransfer with the LockExpired
          message (For some transports B will never receive the LockExpired message
          because the channel is closed already, and message retries may be
          disabled).
    - When channel is settled A must query the blockchain to figure out which
      locksroot was used.
    """
    payment_channel = chain.payment_channel(canonical_identifier=canonical_identifier)
    token_network = payment_channel.token_network

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


@contextmanager
def log_transaction(log: BoundLoggerBase, description: str, details: Dict[Any, Any]) -> Generator:
    try:
        log.debug("Entered", description=description, **details)
        yield
    except:  # noqa
        log.critical("Failed", description=description, **details)
        log.exception("Failed because of")
        raise
    else:
        log.debug("Exited", description=description, **details)
