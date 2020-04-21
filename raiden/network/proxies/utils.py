from typing import TYPE_CHECKING

from raiden.exceptions import RaidenUnrecoverableError
from raiden.transfer.state import NettingChannelState
from raiden.utils.formatting import format_block_id
from raiden.utils.typing import Address, BlockIdentifier, Locksroot, NoReturn, Tuple

if TYPE_CHECKING:
    # pylint: disable=unused-import
    from raiden.network.proxies.proxy_manager import ProxyManager


def get_onchain_locksroots(
    proxy_manager: "ProxyManager",
    channel_state: NettingChannelState,
    participant1: Address,
    participant2: Address,
    block_identifier: BlockIdentifier,
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
    payment_channel = proxy_manager.payment_channel(
        channel_state=channel_state, block_identifier=block_identifier
    )
    token_network = payment_channel.token_network

    participants_details = token_network.detail_participants(
        participant1=participant1,
        participant2=participant2,
        channel_identifier=channel_state.canonical_identifier.channel_identifier,
        block_identifier=block_identifier,
    )

    our_details = participants_details.our_details
    our_locksroot = our_details.locksroot

    partner_details = participants_details.partner_details
    partner_locksroot = partner_details.locksroot

    return our_locksroot, partner_locksroot


def raise_on_call_returned_empty(given_block_identifier: BlockIdentifier) -> NoReturn:
    """Format a message and raise RaidenUnrecoverableError."""
    # We know that the given address has code because this is checked
    # in the constructor
    msg = (
        f"Either the given address is for a different smart contract, "
        f"or the contract was not yet deployed at the block "
        f"{format_block_id(given_block_identifier)}. Either way this call "
        f"should never have happened."
    )
    raise RaidenUnrecoverableError(msg)
