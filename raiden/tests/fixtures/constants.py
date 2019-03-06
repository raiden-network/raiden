from eth_utils import denoms

DEFAULT_PASSPHRASE = 'notsosecret'  # Geth's account passphrase

DEFAULT_BALANCE = denoms.ether * 10  # pylint: disable=no-member
DEFAULT_BALANCE_BIN = str(DEFAULT_BALANCE)
