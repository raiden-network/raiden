from eth_utils import denoms

from raiden.utils.typing import TokenAmount

DEFAULT_PASSPHRASE = "notsosecret"  # Geth's account passphrase
DEFAULT_BALANCE = TokenAmount(denoms.ether * 10)  # pylint: disable=no-member
