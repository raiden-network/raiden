from raiden.exceptions import RaidenUnrecoverableError
from raiden.utils.formatting import format_block_id
from raiden.utils.typing import BlockIdentifier, NoReturn


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
