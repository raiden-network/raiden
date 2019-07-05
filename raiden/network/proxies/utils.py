from contextlib import contextmanager
from typing import TYPE_CHECKING

from eth_utils import decode_hex, to_hex
from structlog import BoundLoggerBase

from raiden.constants import GENESIS_BLOCK_NUMBER
from raiden.exceptions import RaidenUnrecoverableError
from raiden.transfer.identifiers import CanonicalIdentifier
from raiden.utils.filters import decode_event, get_filter_args_for_specific_event_from_channel
from raiden.utils.typing import (
    Address,
    Any,
    BlockSpecification,
    ChannelID,
    Dict,
    Generator,
    Locksroot,
    NoReturn,
    Optional,
    T_BlockHash,
    Tuple,
)
from raiden_contracts.constants import CONTRACT_TOKEN_NETWORK, ChannelEvent
from raiden_contracts.contract_manager import ContractManager

if TYPE_CHECKING:
    # pylint: disable=unused-import
    from raiden.network.blockchain_service import BlockChainService
    from raiden.network.proxies.token_network import TokenNetwork


def get_channel_participants_from_open_event(
    token_network: "TokenNetwork", channel_identifier: ChannelID, contract_manager: ContractManager
) -> Optional[Tuple[Address, Address]]:
    # FIXME: Issue #3958
    from_block = GENESIS_BLOCK_NUMBER

    # For this check it is perfectly fine to use a `latest` block number.
    # Because the filter is looking just for the OPENED event.
    to_block = "latest"

    filter_args = get_filter_args_for_specific_event_from_channel(
        token_network_address=token_network.address,
        channel_identifier=channel_identifier,
        event_name=ChannelEvent.OPENED,
        contract_manager=contract_manager,
        from_block=from_block,
        to_block=to_block,
    )

    events = token_network.proxy.contract.web3.eth.getLogs(filter_args)

    # There must be only one channel open event per channel identifier
    if len(events) != 1:
        return None

    event = decode_event(contract_manager.get_contract_abi(CONTRACT_TOKEN_NETWORK), events[0])
    participant1 = Address(decode_hex(event["args"]["participant1"]))
    participant2 = Address(decode_hex(event["args"]["participant2"]))

    return participant1, participant2


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


def raise_on_call_returned_empty(given_block_identifier: BlockSpecification) -> NoReturn:
    """Format a message and raise RaidenUnrecoverableError."""
    # We know that the given address has code because this is checked
    # in the constructor
    if isinstance(given_block_identifier, T_BlockHash):
        given_block_identifier = to_hex(given_block_identifier)

    msg = (
        f"Either the given address is for a different smart contract, "
        f"or the contract was not yet deployed at the block "
        f"{given_block_identifier}. Either way this call should never "
        f"happened."
    )
    raise RaidenUnrecoverableError(msg)
