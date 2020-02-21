from eth_keys import keys

from raiden.utils.predicates import ishash
from raiden.utils.typing import Address, PublicKey


def privatekey_to_publickey(private_key_bin: bytes) -> PublicKey:
    """ Returns public key in bitcoins 'bin' encoding. """
    if not ishash(private_key_bin):
        raise ValueError("private_key_bin format mismatch. maybe hex encoded?")
    return keys.PrivateKey(private_key_bin).public_key.to_bytes()


def privatekey_to_address(private_key_bin: bytes) -> Address:
    return keys.PrivateKey(private_key_bin).public_key.to_canonical_address()
