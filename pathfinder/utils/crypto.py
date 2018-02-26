from coincurve import PrivateKey, PublicKey

from eth_utils import to_checksum_address, encode_hex, keccak, remove_0x_prefix


def public_key_to_address(pubkey) -> str:
    if isinstance(pubkey, PublicKey):
        pubkey = pubkey.format(compressed=False)
    assert isinstance(pubkey, bytes)
    return encode_hex(keccak(pubkey[1:])[-20:])


def private_key_to_address(private_key: str) -> str:
    return to_checksum_address(
        public_key_to_address(PrivateKey.from_hex(remove_0x_prefix(private_key)).public_key)
    )
