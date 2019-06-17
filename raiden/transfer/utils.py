import random
from random import Random
from typing import TYPE_CHECKING

from web3 import Web3

from raiden.constants import EMPTY_HASH, LOCKSROOT_OF_NO_LOCKS
from raiden.utils.typing import Any, BalanceHash, Locksroot, SecretHash, TokenAmount, Union

if TYPE_CHECKING:
    # pylint: disable=unused-import
    from raiden.transfer.mediated_transfer.state_change import ReceiveSecretReveal  # noqa: F401
    from raiden.transfer.state_change import ContractReceiveSecretReveal  # noqa: F401


def hash_balance_data(
    transferred_amount: TokenAmount, locked_amount: TokenAmount, locksroot: Locksroot
) -> BalanceHash:
    assert locksroot != b""
    assert len(locksroot) == 32
    if transferred_amount == 0 and locked_amount == 0 and locksroot == LOCKSROOT_OF_NO_LOCKS:
        return BalanceHash(EMPTY_HASH)

    return Web3.soliditySha3(  # pylint: disable=no-value-for-parameter
        ["uint256", "uint256", "bytes32"], [transferred_amount, locked_amount, locksroot]
    )


def pseudo_random_generator_from_json(data: Any) -> Random:
    # JSON serializes a tuple as a list
    pseudo_random_generator = random.Random()
    state = list(data["pseudo_random_generator"])  # copy
    state[1] = tuple(state[1])  # fix type
    pseudo_random_generator.setstate(tuple(state))

    return pseudo_random_generator


def is_valid_secret_reveal(
    state_change: Union["ContractReceiveSecretReveal", "ReceiveSecretReveal"],
    transfer_secrethash: SecretHash,
) -> bool:
    return state_change.secrethash == transfer_secrethash
